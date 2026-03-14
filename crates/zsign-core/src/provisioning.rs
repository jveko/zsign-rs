//! Provisioning profile parsing utilities.

/// Extract entitlements from a provisioning profile (mobileprovision file).
///
/// Provisioning profiles are CMS-signed XML plists. This extracts the
/// Entitlements dictionary and converts it back to XML plist format.
pub fn extract_entitlements_from_profile(profile_data: &[u8]) -> Option<Vec<u8>> {
    let plist_start = profile_data.windows(6).position(|w| w == b"<?xml ")?;
    let plist_end = profile_data.windows(8).rposition(|w| w == b"</plist>")? + 8;
    if plist_start >= plist_end {
        return None;
    }
    let plist_slice = &profile_data[plist_start..plist_end];
    let plist: plist::Value = plist::from_bytes(plist_slice).ok()?;
    let dict = plist.as_dictionary()?;
    let entitlements = dict.get("Entitlements")?;
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, entitlements).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_entitlements_no_xml() {
        assert!(extract_entitlements_from_profile(b"not xml data").is_none());
    }

    #[test]
    fn test_extract_entitlements_no_entitlements_key() {
        let profile = br#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Name</key>
    <string>Test</string>
</dict>
</plist>"#;
        assert!(extract_entitlements_from_profile(profile).is_none());
    }

    #[test]
    fn test_extract_entitlements_valid() {
        let profile = br#"BINARY HEADER<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Entitlements</key>
    <dict>
        <key>get-task-allow</key>
        <true/>
    </dict>
</dict>
</plist>BINARY FOOTER"#;
        let result = extract_entitlements_from_profile(profile);
        assert!(result.is_some());
        let xml = String::from_utf8(result.unwrap()).unwrap();
        assert!(xml.contains("get-task-allow"));
    }
}
