#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::der::plist_to_der;

fuzz_target!(|data: &[u8]| {
    let _ = plist_to_der(data);
});
