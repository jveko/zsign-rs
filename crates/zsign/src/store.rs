//! Storage abstraction separating the sign flow's IO primitives from the
//! medium they run on: `FsStore` wraps the filesystem, `MemStore` (in
//! `ipa::mem_store`) is an in-memory tree used by the bytes-to-bytes path.

use crate::{Error, Result};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

/// Kind of a directory entry, reported lstat-style: a symlink is `Symlink`
/// even when its target is a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreKind {
    File,
    Dir,
    Symlink,
}

/// lstat-style metadata for one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreStat {
    pub kind: StoreKind,
    pub len: u64,
    /// Unix mode bits when the medium carries them; `None` when it does not.
    pub unix_mode: Option<u32>,
}

impl StoreStat {
    pub fn is_dir(&self) -> bool {
        self.kind == StoreKind::Dir
    }
    pub fn is_file(&self) -> bool {
        self.kind == StoreKind::File
    }
    pub fn is_symlink(&self) -> bool {
        self.kind == StoreKind::Symlink
    }
}

/// Object-safe combination of [`Read`] and [`Seek`], used as `open`'s
/// returned reader. A `dyn Read + Seek` trait object is not expressible
/// (only auto traits may appear as additional trait-object bounds), so the
/// pair is expressed as a blanket-implemented supertrait instead.
pub(crate) trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

/// Every IO primitive the sign flow needs. Paths are root-relative keys.
///
/// Methods take `&self` so rayon closures capture a shared `&S` exactly as
/// they capture `&self` today; the `Sync` supertrait discharges rayon's
/// bounds (`FsStore` is a unit struct; `MemStore` locks internally for the
/// duration of one method).
pub(crate) trait Store: Sync {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    /// Owned reader over an existing file: native returns `File` so `io::copy`
    /// callers never buffer the whole file; `MemStore` returns an owned
    /// `Cursor` (one transient per-call copy, bounded by a single file).
    fn open(&self, path: &Path) -> Result<Box<dyn ReadSeek>>;
    fn write(&self, path: &Path, data: &[u8]) -> Result<()>;
    fn create_dir_all(&self, path: &Path) -> Result<()>;
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>>;
    /// lstat: metadata of the entry itself, never following a final symlink.
    fn metadata(&self, path: &Path) -> Result<StoreStat>;
    /// Pre-order walk (parent before children) under `root`, **root
    /// included first** — exactly what `WalkDir` yields, so root handling
    /// stays per-site: `write_tree` needs the root entry (`create_ipa` maps
    /// the empty relative path to `Some("Payload/{app}")` at
    /// `archive.rs:260-266`, pinned by `archive.rs:865`), while the two
    /// historical `min_depth(1)` sites skip it explicitly. Per-entry
    /// results preserve each site's current WalkDir error handling:
    /// propagating sites write `let e = e?;`, skipping sites write
    /// `let Ok(e) = e else { continue };`.
    fn walk(&self, root: &Path) -> Result<Vec<Result<(PathBuf, StoreKind)>>>;
    /// Pruned walk mirroring `WalkDir::filter_entry` + `min_depth(1)` (the
    /// root is never yielded, as in the source chain at `mod.rs:1326`):
    /// `prune` returning `false` skips the whole subtree — never visited,
    /// never yielded, and any error inside it never surfaces.
    fn walk_pruned(
        &self,
        root: &Path,
        prune: &dyn Fn(&Path, StoreKind) -> bool,
    ) -> Result<Vec<Result<(PathBuf, StoreKind)>>>;
    /// Raw target bytes of a symlink, without following it.
    fn read_link(&self, path: &Path) -> Result<Vec<u8>>;
    fn symlink(&self, target: &[u8], path: &Path) -> Result<()>;
    fn remove_file(&self, path: &Path) -> Result<()>;
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;

    /// `path.exists()` semantics: any failure answers `false`.
    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
}

/// Filesystem-backed store: every method delegates to `std::fs`/`WalkDir`
/// exactly as the native flow does today. Stateless, hence `Sync` and
/// lock-free — the native rayon paths pay nothing for the abstraction.
pub(crate) struct FsStore;

impl Store for FsStore {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }
    fn open(&self, path: &Path) -> Result<Box<dyn ReadSeek>> {
        Ok(Box::new(std::fs::File::open(path)?))
    }
    fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        Ok(std::fs::write(path, data)?)
    }
    fn create_dir_all(&self, path: &Path) -> Result<()> {
        Ok(std::fs::create_dir_all(path)?)
    }
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let kind = if ft.is_dir() {
                StoreKind::Dir
            } else if ft.is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            };
            out.push((entry.file_name().to_string_lossy().into_owned(), kind));
        }
        Ok(out)
    }
    fn metadata(&self, path: &Path) -> Result<StoreStat> {
        let md = std::fs::symlink_metadata(path)?;
        let kind = if md.is_symlink() {
            StoreKind::Symlink
        } else if md.is_dir() {
            StoreKind::Dir
        } else {
            StoreKind::File
        };
        let unix_mode = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                Some(md.permissions().mode())
            }
            #[cfg(not(unix))]
            {
                None
            }
        };
        Ok(StoreStat {
            kind,
            len: md.len(),
            unix_mode,
        })
    }
    fn walk(&self, root: &Path) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        // Mirrors the call sites' WalkDir usage 1:1: follow_links(false),
        // pre-order with the root yielded FIRST (root handling stays
        // per-site — create_ipa needs the root entry, archive.rs:260-266;
        // the min_depth(1) sites skip it themselves). Entry errors are
        // preserved as inner results: `write_tree` (archive.rs:349-356) and
        // the CodeResources scan (code_resources.rs:150-161) propagate them
        // with the message "Failed to walk directory: {e}" — reproduce that
        // exact format here; the min_depth(1) sites skip them
        // (filter_map(|e| e.ok()) at mod.rs:968-970, :1147-1149).
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.push(Err(Error::Io(std::io::Error::other(format!(
                        "Failed to walk directory: {}",
                        e
                    )))));
                    continue;
                }
            };
            let ft = entry.file_type();
            let kind = if ft.is_dir() {
                StoreKind::Dir
            } else if ft.is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            };
            out.push(Ok((entry.path().to_path_buf(), kind)));
        }
        Ok(out)
    }
    fn walk_pruned(
        &self,
        root: &Path,
        prune: &dyn Fn(&Path, StoreKind) -> bool,
    ) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        // WalkDir::filter_entry semantics: a pruned subtree is never
        // descended into, so errors inside it never surface — identical to
        // find_immediate_macho_binaries today (mod.rs:1326-1346).
        let kind_of = |ft: std::fs::FileType| {
            if ft.is_dir() {
                StoreKind::Dir
            } else if ft.is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            }
        };
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| prune(e.path(), kind_of(e.file_type())))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.push(Err(Error::Io(std::io::Error::other(format!(
                        "Failed to walk directory: {}",
                        e
                    )))));
                    continue;
                }
            };
            out.push(Ok((entry.path().to_path_buf(), kind_of(entry.file_type()))));
        }
        Ok(out)
    }
    fn read_link(&self, path: &Path) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Ok(std::fs::read_link(path)?.as_os_str().as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            // Exactly what hash_symlink_entry's non-unix arm produces today
            // (bundle/code_resources.rs:281-290); the Error::SymlinkNotSupported
            // variant exists but is constructed nowhere in the workspace.
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "Symlinks not supported on this platform: {}",
                    path.display()
                ),
            )))
        }
    }
    fn symlink(&self, target: &[u8], path: &Path) -> Result<()> {
        let target = std::str::from_utf8(target)
            .map_err(|_| Error::Io(std::io::Error::other("symlink target is not valid UTF-8")))?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, path)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (target, path);
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Symlinks not supported on this platform",
            )))
        }
    }
    fn remove_file(&self, path: &Path) -> Result<()> {
        Ok(std::fs::remove_file(path)?)
    }
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Ok(())
        }
    }
}
