//! Rooted in-memory file tree backing the bytes-to-bytes IPA path.

use crate::store::{Store, StoreKind, StoreStat};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Default mode for directories created implicitly (by `new` and by
/// `create_dir_all`); `set_permissions` can override it later, so zip
/// directory modes replay on output.
const DEFAULT_DIR_MODE: u32 = 0o40755;

/// Predicate deciding whether a visited entry prunes its whole subtree.
/// `true` skips the entry: never yielded, never descended into.
type PruneFn<'a> = &'a dyn Fn(&Path, StoreKind) -> bool;

/// [`PruneFn`] when traversal is unconditional, `None` otherwise.
type MaybePruneFn<'a> = Option<PruneFn<'a>>;

enum Node {
    Dir {
        unix_mode: Option<u32>,
    },
    File {
        bytes: Vec<u8>,
        unix_mode: Option<u32>,
    },
    Symlink {
        target: Vec<u8>,
        unix_mode: Option<u32>,
    },
}

impl Node {
    fn kind(&self) -> StoreKind {
        match self {
            Node::Dir { .. } => StoreKind::Dir,
            Node::File { .. } => StoreKind::File,
            Node::Symlink { .. } => StoreKind::Symlink,
        }
    }

    fn unix_mode(&self) -> Option<u32> {
        match self {
            Node::Dir { unix_mode } => *unix_mode,
            Node::File { unix_mode, .. } => *unix_mode,
            Node::Symlink { unix_mode, .. } => *unix_mode,
        }
    }

    fn len(&self) -> u64 {
        match self {
            Node::Dir { .. } => 0,
            Node::File { bytes, .. } => bytes.len() as u64,
            Node::Symlink { target, .. } => target.len() as u64,
        }
    }
}

/// In-memory store keyed by normalized root-relative paths. Children iterate
/// in sorted order (BTreeMap), so walks are deterministic regardless of input
/// zip entry order.
///
/// The map lives behind a `Mutex` so `MemStore: Sync` — required because the
/// generic sign stage compiles its rayon arm on non-wasm targets (the
/// native round-trip tests run this store there). Every method locks and
/// unlocks internally; no guard is ever returned or nested, so no deadlock
/// is possible and the uncontended lock costs nanoseconds next to signing.
pub(crate) struct MemStore {
    nodes: Mutex<BTreeMap<PathBuf, Node>>,
}

fn io_error(kind: std::io::ErrorKind, msg: String) -> Error {
    Error::Io(std::io::Error::new(kind, msg))
}

/// `NotFound`-shaped io error, identical to what `fs::symlink_metadata`
/// produces for a missing path, so `exists()`/`is_dir()` call sites behave
/// the same.
fn not_found(path: &Path) -> Error {
    io_error(
        std::io::ErrorKind::NotFound,
        format!("No such file or directory: {}", path.display()),
    )
}

impl MemStore {
    /// New store seeded with the root directory at the empty key.
    pub(crate) fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            PathBuf::new(),
            Node::Dir {
                unix_mode: Some(DEFAULT_DIR_MODE),
            },
        );
        Self {
            nodes: Mutex::new(nodes),
        }
    }

    /// Lock with poison recovery: `BTreeMap` stays memory-consistent after a
    /// panic, and the operation in flight simply fails closed at a higher
    /// layer.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<PathBuf, Node>> {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Root-relative key for `path`, rejecting absolute paths, `..`, `.` and
    /// empty components. The empty path is the extraction root itself (a
    /// `Dir`), mirroring `validate_output_path`/`resolve_relative` intent.
    fn normalize(path: &Path) -> Result<PathBuf> {
        let raw = path.to_str().ok_or_else(|| {
            io_error(
                std::io::ErrorKind::InvalidInput,
                format!("Path is not valid UTF-8: {}", path.display()),
            )
        })?;
        if raw.is_empty() {
            return Ok(PathBuf::new());
        }
        if path.is_absolute() {
            return Err(io_error(
                std::io::ErrorKind::InvalidInput,
                format!("Absolute paths are not allowed: {}", path.display()),
            ));
        }
        let mut out = PathBuf::new();
        for seg in raw.split('/') {
            match seg {
                "" | "." => {
                    return Err(io_error(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Path contains an empty or `.` component: {}",
                            path.display()
                        ),
                    ))
                }
                ".." => {
                    return Err(io_error(
                        std::io::ErrorKind::InvalidInput,
                        format!("Path escapes the store root: {}", path.display()),
                    ))
                }
                other => out.push(other),
            }
        }
        Ok(out)
    }

    /// Every proper ancestor of `key`, root-first. Fails when an existing
    /// ancestor is not a directory (the in-memory twin of the native
    /// TOCTOU/symlink component checks).
    fn check_ancestors_dir(nodes: &BTreeMap<PathBuf, Node>, key: &Path) -> Result<()> {
        let mut cur = PathBuf::new();
        let comps: Vec<_> = key.components().collect();
        // Everything except the final component is an ancestor.
        for comp in &comps[..comps.len().saturating_sub(1)] {
            cur.push(comp.as_os_str());
            match nodes.get(&cur) {
                Some(Node::Dir { .. }) => {}
                Some(other) => {
                    return Err(io_error(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Path component is not a directory: {} ({:?})",
                            cur.display(),
                            other.kind()
                        ),
                    ))
                }
                None => {
                    return Err(not_found(&cur));
                }
            }
        }
        Ok(())
    }

    /// Immediate children of `dir` in sorted name order.
    fn children(nodes: &BTreeMap<PathBuf, Node>, dir: &Path) -> Vec<(PathBuf, PathBuf, StoreKind)> {
        let mut out: Vec<(PathBuf, PathBuf, StoreKind)> = Vec::new();
        for (key, node) in nodes {
            if *key == dir {
                continue;
            }
            if !key.starts_with(dir) {
                continue;
            }
            let Some(parent) = key.parent() else { continue };
            if parent != dir {
                continue;
            }
            let Some(name) = key.file_name() else {
                continue;
            };
            out.push((dir.join(name), name.into(), node.kind()));
        }
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out
    }

    /// Shared pre-order traversal. `include_root` mirrors `WalkDir` with and
    /// without `min_depth(1)`; `prune` returning `true` skips the whole
    /// subtree — never yielded, never descended into.
    fn walk_inner(
        &self,
        root: &Path,
        include_root: bool,
        prune: MaybePruneFn<'_>,
    ) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        let key = Self::normalize(root)?;
        let nodes = self.lock();
        let mut out = Vec::new();
        let Some(root_node) = nodes.get(&key) else {
            out.push(Err(not_found(root)));
            return Ok(out);
        };
        let root_kind = root_node.kind();
        if include_root {
            out.push(Ok((key.clone(), root_kind)));
        }
        Self::walk_children(&nodes, &key, prune, &mut out);
        Ok(out)
    }

    fn walk_children(
        nodes: &BTreeMap<PathBuf, Node>,
        dir: &Path,
        prune: MaybePruneFn<'_>,
        out: &mut Vec<Result<(PathBuf, StoreKind)>>,
    ) {
        for (path, _, kind) in Self::children(nodes, dir) {
            if let Some(prune) = prune {
                if prune(&path, kind) {
                    continue;
                }
            }
            out.push(Ok((path.clone(), kind)));
            if kind == StoreKind::Dir {
                Self::walk_children(nodes, &path, prune, out);
            }
        }
    }
}

impl Store for MemStore {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let key = Self::normalize(path)?;
        let nodes = self.lock();
        match nodes.get(&key) {
            Some(Node::File { bytes, .. }) => Ok(bytes.clone()),
            _ => Err(not_found(path)),
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn crate::store::ReadSeek>> {
        let key = Self::normalize(path)?;
        let nodes = self.lock();
        match nodes.get(&key) {
            Some(Node::File { bytes, .. }) => Ok(Box::new(Cursor::new(bytes.clone()))),
            _ => Err(not_found(path)),
        }
    }

    fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        let key = Self::normalize(path)?;
        let mut nodes = self.lock();
        Self::check_ancestors_dir(&nodes, &key)?;
        nodes.insert(
            key,
            Node::File {
                bytes: data.to_vec(),
                unix_mode: None,
            },
        );
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        let key = Self::normalize(path)?;
        let mut nodes = self.lock();
        if key.as_os_str().is_empty() {
            return Ok(());
        }
        let comps: Vec<_> = key.components().collect();
        let mut cur = PathBuf::new();
        for comp in &comps {
            cur.push(comp.as_os_str());
            match nodes.get(&cur) {
                Some(Node::Dir { .. }) => {}
                Some(other) => {
                    return Err(io_error(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Cannot create directory, path component is {:?}: {}",
                            other.kind(),
                            cur.display()
                        ),
                    ))
                }
                None => {
                    nodes.insert(
                        cur.clone(),
                        Node::Dir {
                            unix_mode: Some(DEFAULT_DIR_MODE),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>> {
        let key = Self::normalize(path)?;
        let nodes = self.lock();
        if !matches!(nodes.get(&key), Some(Node::Dir { .. })) {
            return Err(not_found(path));
        }
        Ok(Self::children(&nodes, &key)
            .into_iter()
            .map(|(_, name, kind)| (name.to_string_lossy().into_owned(), kind))
            .collect())
    }

    fn metadata(&self, path: &Path) -> Result<StoreStat> {
        let key = Self::normalize(path)?;
        let nodes = self.lock();
        match nodes.get(&key) {
            Some(node) => Ok(StoreStat {
                kind: node.kind(),
                len: node.len(),
                unix_mode: node.unix_mode(),
            }),
            None => Err(not_found(path)),
        }
    }

    fn walk(&self, root: &Path) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        // Root-inclusive pre-order, exactly what `WalkDir` yields: the root
        // entry arrives first (`create_ipa` depends on it) and every key
        // strictly under it follows, children sorted by file name. Inner
        // results are always `Ok` — an in-memory tree cannot fail mid-walk.
        self.walk_inner(root, true, None)
    }

    fn walk_pruned(
        &self,
        root: &Path,
        prune: &dyn Fn(&Path, StoreKind) -> bool,
    ) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        // `WalkDir::filter_entry` + `min_depth(1)`: the root is never
        // yielded, and a pruned subtree is never visited at all.
        self.walk_inner(root, false, Some(prune))
    }

    fn read_link(&self, path: &Path) -> Result<Vec<u8>> {
        let key = Self::normalize(path)?;
        let nodes = self.lock();
        match nodes.get(&key) {
            Some(Node::Symlink { target, .. }) => Ok(target.clone()),
            _ => Err(not_found(path)),
        }
    }

    fn symlink(&self, target: &[u8], path: &Path) -> Result<()> {
        let key = Self::normalize(path)?;
        let mut nodes = self.lock();
        Self::check_ancestors_dir(&nodes, &key)?;
        nodes.insert(
            key,
            Node::Symlink {
                target: target.to_vec(),
                unix_mode: None,
            },
        );
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        let key = Self::normalize(path)?;
        let mut nodes = self.lock();
        match nodes.get(&key) {
            Some(Node::Dir { .. }) => Err(io_error(
                std::io::ErrorKind::IsADirectory,
                format!("Is a directory: {}", path.display()),
            )),
            Some(_) => {
                nodes.remove(&key);
                Ok(())
            }
            None => Err(not_found(path)),
        }
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        let key = Self::normalize(path)?;
        let mut nodes = self.lock();
        let unix_mode = Some(mode);
        match nodes.get_mut(&key) {
            Some(Node::Dir { unix_mode: m }) => *m = unix_mode,
            Some(Node::File { unix_mode: m, .. }) => *m = unix_mode,
            Some(Node::Symlink { unix_mode: m, .. }) => *m = unix_mode,
            None => return Err(not_found(path)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> MemStore {
        MemStore::new()
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn normalize_rejects_escaping_and_absolute_and_dot_paths() {
        assert_eq!(MemStore::normalize(Path::new("")).unwrap(), PathBuf::new());
        assert_eq!(
            MemStore::normalize(Path::new("Payload/App.app")).unwrap(),
            p("Payload/App.app")
        );
        for bad in [
            "../escape",
            "Payload/../escape",
            "/abs/path",
            "./rel",
            "a/./b",
            "a//b",
        ] {
            let err = MemStore::normalize(Path::new(bad)).unwrap_err();
            let Error::Io(e) = err else {
                panic!("expected io error for {bad}")
            };
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{bad}");
        }
    }

    #[test]
    fn new_seeds_root_directory_with_default_mode() {
        let s = store();
        let stat = s.metadata(Path::new("")).unwrap();
        assert!(stat.is_dir());
        assert_eq!(stat.unix_mode, Some(0o40755));
        assert_eq!(s.list(Path::new("")).unwrap(), Vec::new());
    }

    #[test]
    fn create_dir_all_creates_ancestors_and_conflicts_on_file() {
        let s = store();
        s.create_dir_all(Path::new("Payload/App.app/Frameworks"))
            .unwrap();
        for d in ["Payload", "Payload/App.app", "Payload/App.app/Frameworks"] {
            assert!(s.metadata(Path::new(d)).unwrap().is_dir(), "{d}");
        }
        s.write(Path::new("Payload/Blocker"), b"x").unwrap();
        let err = s
            .create_dir_all(Path::new("Payload/Blocker/under"))
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn write_refuses_when_an_ancestor_is_a_symlink() {
        let s = store();
        s.create_dir_all(Path::new("real")).unwrap();
        s.symlink(b"real", Path::new("link")).unwrap();
        let err = s.write(Path::new("link/inside.txt"), b"data").unwrap_err();
        let Error::Io(e) = err else {
            panic!("expected io error")
        };
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        // The symlink target itself is untouched and still readable.
        assert_eq!(s.read_link(Path::new("link")).unwrap(), b"real");
        // Writing through the real directory still works.
        s.write(Path::new("real/inside.txt"), b"data").unwrap();
        assert_eq!(s.read(Path::new("real/inside.txt")).unwrap(), b"data");
    }

    #[test]
    fn walk_yields_root_first_then_sorted_dfs() {
        let s = store();
        s.create_dir_all(Path::new("Payload/App.app/Frameworks/Fw.framework"))
            .unwrap();
        // Insertion order deliberately unsorted; BTreeMap keys must reorder.
        s.write(Path::new("Payload/App.app/zzz.txt"), b"z").unwrap();
        s.write(Path::new("Payload/App.app/aaa.txt"), b"a").unwrap();
        s.write(Path::new("Payload/App.app/Frameworks/lib.dylib"), b"d")
            .unwrap();
        s.write(
            Path::new("Payload/App.app/Frameworks/Fw.framework/Fw"),
            b"f",
        )
        .unwrap();

        let entries: Vec<(PathBuf, StoreKind)> = s
            .walk(Path::new("Payload/App.app"))
            .unwrap()
            .into_iter()
            .map(|e| e.unwrap())
            .collect();

        let paths: Vec<String> = entries
            .iter()
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries[0].0, p("Payload/App.app"), "root must be first");
        assert_eq!(entries[0].1, StoreKind::Dir);
        assert_eq!(
            &paths[1..],
            &[
                "Payload/App.app/Frameworks",
                "Payload/App.app/Frameworks/Fw.framework",
                "Payload/App.app/Frameworks/Fw.framework/Fw",
                "Payload/App.app/Frameworks/lib.dylib",
                "Payload/App.app/aaa.txt",
                "Payload/App.app/zzz.txt",
            ]
        );
        // Pre-order: a parent inside the walk root appears before its
        // children (parents above the root are outside the walk by design).
        for (i, (path, _)) in entries.iter().enumerate().skip(1) {
            let Some(parent) = path.parent() else {
                continue;
            };
            if parent == Path::new("Payload/App.app") {
                continue;
            }
            let idx = paths
                .iter()
                .position(|x| x == &parent.to_string_lossy().into_owned());
            assert!(idx.unwrap() < i, "{} before its parent", path.display());
        }
    }

    #[test]
    fn walk_pruned_never_yields_root_or_pruned_subtree() {
        let s = store();
        s.create_dir_all(Path::new("Payload/secret/inner")).unwrap();
        s.create_dir_all(Path::new("Payload/keep")).unwrap();
        s.write(Path::new("Payload/secret/inner/poison.bin"), b"x")
            .unwrap();
        s.write(Path::new("Payload/keep/good.dylib"), b"g").unwrap();
        s.write(Path::new("Payload/top.txt"), b"t").unwrap();

        let entries: Vec<(PathBuf, StoreKind)> = s
            .walk_pruned(Path::new("Payload"), &|p, _| p.ends_with("secret"))
            .unwrap()
            .into_iter()
            .map(|e| e.unwrap())
            .collect();
        let paths: Vec<String> = entries
            .iter()
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            paths,
            vec![
                "Payload/keep".to_string(),
                "Payload/keep/good.dylib".to_string(),
                "Payload/top.txt".to_string(),
            ],
            "root absent, pruned subtree neither yielded nor descended"
        );
    }

    #[test]
    fn walk_pruned_prunes_a_single_entry_by_kind() {
        let s = store();
        s.create_dir_all(Path::new("a/b")).unwrap();
        s.write(Path::new("a/b/keep.txt"), b"k").unwrap();
        s.write(Path::new("a/b/skip.txt"), b"s").unwrap();
        let paths: Vec<String> = s
            .walk_pruned(Path::new("a"), &|_, kind| kind == StoreKind::File)
            .unwrap()
            .into_iter()
            .map(|e| e.unwrap().0.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths, vec!["a/b".to_string()]);
    }

    #[test]
    fn metadata_missing_answers_not_found_and_exists_false() {
        let s = store();
        let err = s.metadata(Path::new("nope")).unwrap_err();
        let Error::Io(e) = err else {
            panic!("expected io error")
        };
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        assert!(!s.exists(Path::new("nope")));
        s.write(Path::new("here"), b"12345").unwrap();
        let stat = s.metadata(Path::new("here")).unwrap();
        assert!(stat.is_file());
        assert_eq!(stat.len, 5);
        assert!(s.exists(Path::new("here")));
    }

    #[test]
    fn read_link_round_trips_raw_target_bytes() {
        let s = store();
        s.create_dir_all(Path::new("d")).unwrap();
        s.symlink(b"../elsewhere/Fw", Path::new("d/Fw")).unwrap();
        assert_eq!(s.read_link(Path::new("d/Fw")).unwrap(), b"../elsewhere/Fw");
        assert!(s.metadata(Path::new("d/Fw")).unwrap().is_symlink());
        // Non-symlink read_link is NotFound-shaped, as fs::read_link is.
        s.write(Path::new("d/file"), b"x").unwrap();
        let Error::Io(e) = s.read_link(Path::new("d/file")).unwrap_err() else {
            panic!("expected io error")
        };
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        // Long (4096+) targets are stored verbatim here; rejection is the
        // extract layer's job.
        let long = vec![b'x'; 5000];
        s.symlink(&long, Path::new("d/long")).unwrap();
        assert_eq!(s.read_link(Path::new("d/long")).unwrap(), long);
    }

    #[test]
    fn open_reads_back_written_bytes() {
        use std::io::Read;
        let s = store();
        s.create_dir_all(Path::new("d")).unwrap();
        s.write(Path::new("d/bin"), b"hello bytes").unwrap();
        let mut r = s.open(Path::new("d/bin")).unwrap();
        let mut out = String::new();
        r.read_to_string(&mut out).unwrap();
        assert_eq!(out, "hello bytes");
        assert!(s.open(Path::new("d/missing")).is_err());
    }

    #[test]
    fn list_returns_sorted_children_with_kinds() {
        let s = store();
        s.create_dir_all(Path::new("d/sub")).unwrap();
        s.write(Path::new("d/zz"), b"").unwrap();
        s.write(Path::new("d/aa"), b"").unwrap();
        s.symlink(b"aa", Path::new("d/link")).unwrap();
        assert_eq!(
            s.list(Path::new("d")).unwrap(),
            vec![
                ("aa".to_string(), StoreKind::File),
                ("link".to_string(), StoreKind::Symlink),
                ("sub".to_string(), StoreKind::Dir),
                ("zz".to_string(), StoreKind::File),
            ]
        );
    }

    #[test]
    fn permissions_round_trip_and_remove_file_drops_the_node() {
        let s = store();
        s.create_dir_all(Path::new("d")).unwrap();
        s.set_permissions(Path::new("d"), 0o40700).unwrap();
        assert_eq!(s.metadata(Path::new("d")).unwrap().unix_mode, Some(0o40700));
        s.write(Path::new("d/f"), b"x").unwrap();
        s.set_permissions(Path::new("d/f"), 0o100755).unwrap();
        assert_eq!(
            s.metadata(Path::new("d/f")).unwrap().unix_mode,
            Some(0o100755)
        );
        s.remove_file(Path::new("d/f")).unwrap();
        assert!(!s.exists(Path::new("d/f")));
        assert!(s.remove_file(Path::new("d/f")).is_err());
    }
}
