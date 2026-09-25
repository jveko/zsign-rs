#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::crypto::SigningCredentials;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let password_len = declared_len.min(data.len() - 4);
    let password = String::from_utf8_lossy(&data[4..4 + password_len]);
    // PBKDF2 iteration counts up to 10 million are in-range by design; slow inputs are expected here.
    let _ = SigningCredentials::from_p12(&data[4 + password_len..], &password);
});
