#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::verify::{check_code_pages, CodeDirectory};

fuzz_target!(|data: &[u8]| {
    let Ok(cd) = CodeDirectory::parse(data) else {
        return;
    };
    let _ = cd.identifier();
    let _ = cd.team_id();
    let _ = cd.cdhash();
    let _ = cd.cdhash_sha256();
    let _ = cd.effective_code_limit();
    let _ = cd.code_hashes();
    let _ = check_code_pages(&cd, data);
});
