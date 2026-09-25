#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::verify::SignatureInputs;
use zsign_core::crypto::cms_verify::verify_code_signature;
use zsign_core::macho::verify_macho;

fuzz_target!(|data: &[u8]| {
    let _ = verify_macho(data, &SignatureInputs::none());
    let zero = [0u8; 32];
    let _ = verify_code_signature(data, data, None, &zero);
});
