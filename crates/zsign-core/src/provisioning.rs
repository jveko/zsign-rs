//! Provisioning profile parsing utilities.

use crate::{Error, Result};

/// Extract entitlements from a provisioning profile (mobileprovision file).
///
/// Provisioning profiles are CMS-signed XML plists. This extracts the
/// Entitlements dictionary and converts it back to XML plist format.
///
/// Returns `Ok(None)` if the plist is valid but contains no `Entitlements` key.
/// Returns `Err` for parse failures (no XML found, invalid plist, serialization error).
pub fn extract_entitlements_from_profile(profile_data: &[u8]) -> Result<Option<Vec<u8>>> {
    let plist_start = profile_data
        .windows(6)
        .position(|w| w == b"<?xml ")
        .ok_or_else(|| Error::ProvisioningProfile("No XML plist found in profile data".into()))?;
    let plist_end = profile_data
        .windows(8)
        .rposition(|w| w == b"</plist>")
        .ok_or_else(|| Error::ProvisioningProfile("No closing </plist> tag found".into()))?
        + 8;
    if plist_start >= plist_end {
        return Err(Error::ProvisioningProfile(
            "Invalid plist boundaries".into(),
        ));
    }
    let plist_slice = &profile_data[plist_start..plist_end];
    let plist: plist::Value = plist::from_bytes(plist_slice)
        .map_err(|e| Error::ProvisioningProfile(format!("Failed to parse plist: {}", e)))?;
    let dict = plist
        .as_dictionary()
        .ok_or_else(|| Error::ProvisioningProfile("Profile plist is not a dictionary".into()))?;
    let entitlements = match dict.get("Entitlements") {
        Some(ent) => ent,
        None => return Ok(None),
    };
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, entitlements).map_err(|e| {
        Error::ProvisioningProfile(format!("Failed to serialize entitlements: {}", e))
    })?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_entitlements_no_xml() {
        let result = extract_entitlements_from_profile(b"not xml data");
        assert!(result.is_err());
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
        let result = extract_entitlements_from_profile(profile);
        assert!(matches!(result, Ok(None)));
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
        assert!(result.is_ok());
        let xml = String::from_utf8(result.unwrap().unwrap()).unwrap();
        assert!(xml.contains("get-task-allow"));
    }
}
