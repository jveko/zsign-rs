#![no_main]

use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;
use zsign_core::provisioning::{
    extract_entitlements_from_profile, validate_and_extract_profile, ProfileRequest,
};

fuzz_target!(|data: &[u8]| {
    let Ok(now) = OffsetDateTime::from_unix_timestamp(1_800_000_000) else {
        return;
    };
    let request = ProfileRequest {
        now: Some(now),
        ..ProfileRequest::default()
    };
    let _ = validate_and_extract_profile(data, &request);
    let _ = extract_entitlements_from_profile(data);
});
