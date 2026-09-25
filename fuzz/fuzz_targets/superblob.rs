#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::constants::CSSLOT_REQUIREMENTS;
use zsign_core::codesign::verify::{
    check_special_slots, parse_requirements, parse_superblob, SignatureInputs,
};

fuzz_target!(|data: &[u8]| {
    let Ok(blob) = parse_superblob(data) else {
        return;
    };
    let mut inputs = SignatureInputs::none();
    let (info_plist, code_resources) = data.split_at(data.len() / 2);
    inputs.info_plist = Some(info_plist);
    inputs.code_resources = Some(code_resources);
    for entry in &blob.entries {
        let _ = entry.payload();
        if entry.slot == CSSLOT_REQUIREMENTS {
            let _ = parse_requirements(entry.blob);
        }
    }
    if let Some(cd) = &blob.code_directory {
        let _ = cd.identifier();
        let _ = cd.team_id();
        let _ = cd.raw();
        let _ = cd.cdhash();
        let _ = cd.cdhash_sha256();
        let _ = cd.effective_code_limit();
        let _ = cd.code_hashes();
        let _ = check_special_slots(cd, &inputs, &blob);
    }
    for cd in &blob.alternate_code_directories {
        let _ = cd.cdhash();
        let _ = cd.effective_code_limit();
    }
});
