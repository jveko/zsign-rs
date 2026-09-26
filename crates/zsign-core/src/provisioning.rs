//! Provisioning profile parsing and validation utilities.
//!
//! Profiles are CMS-signed XML plists. [`extract_entitlements_from_profile`]
//! is the historical unvalidated extractor (raw byte scan — kept byte-for-byte
//! for existing consumers); [`validate_and_extract_profile`] verifies the CMS
//! envelope against Apple's roots (or injected anchors) and validates the
//! profile fields before any consumer touches them.

use crate::crypto::cms_verify::{self, TrustAnchors};
use crate::{Error, Result};
use std::time::SystemTime;
use time::OffsetDateTime;

/// Inputs that scope *when* and *against what* a profile is validated.
///
/// Every field is optional: an omitted check simply does not run, so callers
/// validate only the context they have. A bypass (`allow-unsafe`) is a
/// caller-side choice — keep calling [`extract_entitlements_from_profile`] for
/// unvalidated extraction.
///
/// ```ignore
/// let request = ProfileRequest {
///     now: None, // wall clock on native; error on wasm32 (pass Date.now() / 1000)
///     expected_team_id: Some("TESTTEAM".into()),
///     target_bundle_id: Some("com.example.app".into()),
///     ..Default::default()
/// };
/// let info = validate_and_extract_profile(&profile_bytes, &request)?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct ProfileRequest {
    /// Verification instant consumed by both the CMS chain check and the
    /// profile window check — one instant for both, so a caller cannot
    /// validate the chain at one time and the window at another. `None` uses
    /// the wall clock on native targets and is an error on wasm32 (pass
    /// `Date.now() / 1000` there).
    pub now: Option<OffsetDateTime>,
    /// Trust anchors for the profile's CMS chain. `None` uses Apple's root —
    /// production profiles are Apple-signed.
    pub anchors: Option<TrustAnchors>,
    /// Team ID of the signing certificate; the profile must belong to it.
    pub expected_team_id: Option<String>,
    /// Target app's `CFBundleIdentifier`; the profile App ID must cover it.
    pub target_bundle_id: Option<String>,
    /// Target device UDID; must be listed in `ProvisionedDevices` unless the
    /// profile carries `ProvisionsAllDevices`. A profile carrying neither key
    /// (App Store distribution) has no device list, so the check is skipped.
    pub target_device_udid: Option<String>,
}

/// A CMS-verified, validated provisioning profile.
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    /// `Name` — present and validated.
    pub name: String,
    /// `TeamIdentifier` array (empty when the key is absent).
    pub team_identifiers: Vec<String>,
    /// `Entitlements['application-identifier']`, falling back to
    /// `Entitlements['com.apple.application-identifier']` (macOS).
    pub application_identifier: Option<String>,
    /// `CreationDate`, when present.
    pub creation_date: Option<OffsetDateTime>,
    /// `ExpirationDate` — present and validated against the request clock.
    pub expiration_date: OffsetDateTime,
    /// `ProvisionsAllDevices` (Enterprise / Developer ID profiles).
    pub provisions_all_devices: bool,
    /// `ProvisionedDevices`, when present.
    pub provisioned_devices: Option<Vec<String>>,
    /// Entitlements re-serialized as XML plist — the same bytes
    /// [`extract_entitlements_from_profile`] would return.
    pub entitlements_xml: Option<Vec<u8>>,
    /// CMS verification report: signer, chain, warnings (e.g. SHA-1 digests).
    pub cms: cms_verify::CmsVerifyReport,
}

/// Verifies a provisioning profile's CMS envelope and validates its fields.
///
/// Checks, in order: CMS signature/chain/anchoring at the request instant;
/// required `Name`/`ExpirationDate`; `CreationDate <= now <= ExpirationDate`;
/// team match (when `expected_team_id` is set); App-ID coverage of
/// `target_bundle_id` (when set); device registration for
/// `target_device_udid` (when set — `ProvisionsAllDevices` takes precedence
/// over the device list, and an App Store profile carries neither key).
///
/// # Errors
///
/// Returns [`Error::Verification`] for a malformed CMS envelope or, on wasm32,
/// when `now` is `None`; browser callers must pass `Date.now() / 1000`.
/// Returns [`Error::ProvisioningProfile`] for every failed check. Window, team,
/// App-ID-coverage, and device failures name the profile, the offending
/// value, and the remedy; structural malformations (missing/non-conforming
/// keys) name the offending key or value.
pub fn validate_and_extract_profile(
    profile_data: &[u8],
    request: &ProfileRequest,
) -> Result<ProfileInfo> {
    let now = cms_verify::resolve_now(request.now)?;
    let envelope = match &request.anchors {
        Some(anchors) => {
            cms_verify::verify_cms_envelope_with_anchors(profile_data, Some(now), anchors)?
        }
        None => cms_verify::verify_cms_envelope(profile_data, Some(now))?,
    };
    if !envelope.report.valid {
        return Err(Error::ProvisioningProfile(format!(
            "CMS verification failed: {}",
            envelope.report.errors.join("; ")
        )));
    }
    let content = envelope.content.ok_or_else(|| {
        Error::ProvisioningProfile(
            "Profile CMS verification produced no attached plist content".into(),
        )
    })?;
    let value: plist::Value = plist::from_bytes(&content)
        .map_err(|e| Error::ProvisioningProfile(format!("Failed to parse profile plist: {e}")))?;
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::ProvisioningProfile("Profile plist is not a dictionary".into()))?;

    let name = required_string(dict, "Name")?;
    let expiration_date = required_date(dict, "ExpirationDate", &name)?;
    let creation_date = optional_date(dict, "CreationDate", &name)?;
    let team_identifiers = string_array(dict, "TeamIdentifier")?;
    let application_identifier = entitlement_string(dict, "application-identifier")
        .or_else(|| entitlement_string(dict, "com.apple.application-identifier"));
    let provisions_all_devices = match dict.get("ProvisionsAllDevices") {
        None => false,
        Some(v) => v.as_boolean().ok_or_else(|| {
            Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" has a non-boolean ProvisionsAllDevices"
            ))
        })?,
    };
    let provisioned_devices = match dict.get("ProvisionedDevices") {
        None => None,
        Some(v) => Some(string_values(v, "ProvisionedDevices")?),
    };

    if now > expiration_date {
        return Err(Error::ProvisioningProfile(format!(
            "Provisioning profile \"{name}\" expired on {}; renew it in the Apple developer \
             portal (Certificates, Identifiers & Profiles) and re-download it",
            fmt_date(expiration_date)
        )));
    }
    if let Some(created) = creation_date {
        if now < created {
            return Err(Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" is not valid until {}; wait until then, or \
                 re-download it from the Apple developer portal",
                fmt_date(created)
            )));
        }
    }

    if let Some(expected) = &request.expected_team_id {
        let mut teams = team_identifiers.clone();
        for t in string_array(dict, "ApplicationIdentifierPrefix")? {
            if !teams.contains(&t) {
                teams.push(t);
            }
        }
        if let Some(t) = entitlement_string(dict, "com.apple.developer.team-identifier") {
            if !teams.contains(&t) {
                teams.push(t);
            }
        }
        if !teams.iter().any(|t| t == expected) {
            let listed = if teams.is_empty() {
                "no team identifiers".to_string()
            } else {
                teams.join(", ")
            };
            return Err(Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" is for {listed}, not the signing team {expected}"
            )));
        }
    }

    if let Some(target) = &request.target_bundle_id {
        if target.is_empty() {
            return Err(Error::ProvisioningProfile(
                "Target bundle identifier must not be empty".into(),
            ));
        }
        if target.contains('*') {
            return Err(Error::ProvisioningProfile(format!(
                "Target bundle identifier \"{target}\" must not contain a wildcard"
            )));
        }
        let app_id = application_identifier.clone().ok_or_else(|| {
            Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" has no application-identifier entitlement; \
                 cannot check coverage of \"{target}\""
            ))
        })?;
        let app_id_prefix = string_array(dict, "ApplicationIdentifierPrefix")?
            .into_iter()
            .next()
            .or_else(|| team_identifiers.first().cloned());
        if !app_id_covers(&app_id, app_id_prefix.as_deref(), target)? {
            return Err(Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" App ID {app_id} does not cover bundle \
                 identifier {target}; use a profile whose App ID matches it"
            )));
        }
    }

    if !provisions_all_devices {
        if let (Some(udid), Some(devices)) = (&request.target_device_udid, &provisioned_devices) {
            if !devices.iter().any(|d| d == udid) {
                return Err(Error::ProvisioningProfile(format!(
                    "Device {udid} is not registered for provisioning profile \"{name}\"; \
                     register it in the Apple developer portal and re-download the profile"
                )));
            }
        }
    }

    let entitlements_xml = entitlements_to_xml(dict)?;

    Ok(ProfileInfo {
        name,
        team_identifiers,
        application_identifier,
        creation_date,
        expiration_date,
        provisions_all_devices,
        provisioned_devices,
        entitlements_xml,
        cms: envelope.report,
    })
}

fn required_string(dict: &plist::Dictionary, key: &str) -> Result<String> {
    dict.get(key)
        .and_then(|v| v.as_string())
        .map(str::to_owned)
        .ok_or_else(|| Error::ProvisioningProfile(format!("Profile is missing the {key}")))
}

fn required_date(dict: &plist::Dictionary, key: &str, name: &str) -> Result<OffsetDateTime> {
    let date = dict.get(key).and_then(|v| v.as_date()).ok_or_else(|| {
        Error::ProvisioningProfile(format!("Provisioning profile \"{name}\" has no {key}"))
    })?;
    plist_date_to_offset(date).ok_or_else(|| {
        Error::ProvisioningProfile(format!(
            "Provisioning profile \"{name}\" has an unparseable {key}"
        ))
    })
}

fn optional_date(
    dict: &plist::Dictionary,
    key: &str,
    name: &str,
) -> Result<Option<OffsetDateTime>> {
    match dict.get(key) {
        None => Ok(None),
        Some(v) => {
            let date = v.as_date().ok_or_else(|| {
                Error::ProvisioningProfile(format!(
                    "Provisioning profile \"{name}\" has a non-date {key}"
                ))
            })?;
            plist_date_to_offset(date).map(Some).ok_or_else(|| {
                Error::ProvisioningProfile(format!(
                    "Provisioning profile \"{name}\" has an unparseable {key}"
                ))
            })
        }
    }
}

/// `plist::Date` (a `SystemTime` newtype, `Copy`) in RFC 3339; `None` before
/// 1970 or outside the `time` crate's range — no real profile predates 1970.
fn plist_date_to_offset(date: plist::Date) -> Option<OffsetDateTime> {
    let system: SystemTime = date.into();
    let seconds = system
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

fn fmt_date(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

fn string_array(dict: &plist::Dictionary, key: &str) -> Result<Vec<String>> {
    match dict.get(key) {
        None => Ok(Vec::new()),
        Some(v) => string_values(v, key),
    }
}

fn string_values(value: &plist::Value, key: &str) -> Result<Vec<String>> {
    let arr = value
        .as_array()
        .ok_or_else(|| Error::ProvisioningProfile(format!("Profile {key} is not an array")))?;
    arr.iter()
        .map(|item| {
            item.as_string().map(str::to_owned).ok_or_else(|| {
                Error::ProvisioningProfile(format!("Profile {key} contains a non-string entry"))
            })
        })
        .collect()
}

fn entitlement_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get("Entitlements")?
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(str::to_owned)
}

/// Apple App IDs are `PREFIX.search`: `PREFIX` is the fixed team prefix
/// (`ApplicationIdentifierPrefix`/`TeamIdentifier`) and `search` is either
/// exact or a single trailing `*` (QA1713 / Team Administration Guide). The
/// candidate compared against the profile is the full `PREFIX.bundle_id`
/// (design §4.3) — a bundle id under any other prefix never matches.
fn app_id_covers(app_id: &str, app_id_prefix: Option<&str>, bundle_id: &str) -> Result<bool> {
    let prefix = app_id_prefix.ok_or_else(|| {
        Error::ProvisioningProfile(
            "Profile has no App ID prefix (ApplicationIdentifierPrefix or TeamIdentifier); \
             cannot check bundle coverage"
                .into(),
        )
    })?;
    if prefix.is_empty() || prefix.contains('.') || prefix.contains('*') {
        return Err(Error::ProvisioningProfile(format!(
            "App ID prefix \"{prefix}\" is malformed: a team prefix is a fixed, wildcard-free \
             string without dots"
        )));
    }
    let rest = app_id
        .strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('.'))
        .ok_or_else(|| {
            Error::ProvisioningProfile(format!(
                "App ID \"{app_id}\" does not start with the profile's App ID prefix {prefix}"
            ))
        })?;
    let stars = rest.matches('*').count();
    if stars == 0 {
        return Ok(rest == bundle_id);
    }
    if stars > 1 || !rest.ends_with('*') {
        return Err(Error::ProvisioningProfile(format!(
            "App ID \"{app_id}\" contains a wildcard Apple cannot produce: a single trailing \
             '*' is required"
        )));
    }
    Ok(bundle_id.starts_with(&rest[..rest.len() - 1]))
}

/// Serializes the `Entitlements` dictionary back to XML plist bytes, or
/// `Ok(None)` when the profile carries no `Entitlements` key.
fn entitlements_to_xml(dict: &plist::Dictionary) -> Result<Option<Vec<u8>>> {
    let Some(ent) = dict.get("Entitlements") else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, ent).map_err(|e| {
        Error::ProvisioningProfile(format!("Failed to serialize entitlements: {}", e))
    })?;
    Ok(Some(buf))
}

/// Extract entitlements from a provisioning profile (mobileprovision file).
///
/// Provisioning profiles are CMS-signed XML plists. This extracts the
/// Entitlements dictionary and converts it back to XML plist format.
///
/// This is the historical unvalidated extractor: it byte-scans for the plist
/// and trusts whatever it finds — no CMS verification, no expiry check. Callers
/// that must reject forged or expired profiles use
/// [`validate_and_extract_profile`].
///
/// Returns `Ok(None)` if the plist is valid but contains no `Entitlements` key.
/// Returns `Err` for parse failures (no XML found, invalid plist, serialization error).
pub fn extract_entitlements_from_profile(profile_data: &[u8]) -> Result<Option<Vec<u8>>> {
    let plist = profile_document(profile_data)?;
    let dict = plist
        .as_dictionary()
        .ok_or_else(|| Error::ProvisioningProfile("Profile plist is not a dictionary".into()))?;
    entitlements_to_xml(dict)
}

/// Reads the XML document embedded in a provisioning profile WITHOUT any
/// cryptographic or expiry validation. For metadata that only needs to be
/// consistent with the profile bytes about to be embedded (App ID prefix,
/// team, distribution shape); trust decisions belong to
/// [`validate_and_extract_profile`].
///
/// Returns [`Err`] when no embedded XML plist is found, no closing
/// `</plist>` tag is found, the boundaries are inverted, or the slice fails
/// to parse. The document is returned as-is; a dictionary guarantee belongs
/// to the caller that needs one.
pub fn profile_document(profile_data: &[u8]) -> Result<plist::Value> {
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
    let plist: plist::Value = plist::from_bytes(&profile_data[plist_start..plist_end])
        .map_err(|e| Error::ProvisioningProfile(format!("Failed to parse plist: {}", e)))?;
    Ok(plist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_document_returns_full_profile_dict() {
        // Wrapped in binary noise, as a real CMS-wrapped profile is.
        let profile = br#"BINARY HEADER<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Name</key>
    <string>Test Profile</string>
    <key>TeamIdentifier</key>
    <array><string>TESTTEAM</string></array>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>TESTTEAM.com.test.app</string>
    </dict>
</dict>
</plist>BINARY FOOTER"#;
        let doc = profile_document(profile).expect("the embedded plist must parse");
        let dict = doc
            .as_dictionary()
            .expect("the document must be a dictionary");
        assert_eq!(
            dict.get("Name").unwrap().as_string().unwrap(),
            "Test Profile"
        );
        assert_eq!(
            dict.get("TeamIdentifier").unwrap().as_array().unwrap()[0]
                .as_string()
                .unwrap(),
            "TESTTEAM"
        );
        assert_eq!(
            dict.get("Entitlements")
                .unwrap()
                .as_dictionary()
                .unwrap()
                .get("application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM.com.test.app"
        );
    }

    #[test]
    fn profile_document_rejects_data_without_plist() {
        assert!(profile_document(b"not xml data").is_err());
    }

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

    // ---- validated extraction fixtures ----

    use crate::crypto::cms::{sign_attached_content, TestDigest};
    use crate::crypto::cms_verify::TrustAnchors;
    use der::Decode;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::{Duration as StdDuration, UNIX_EPOCH};
    use time::OffsetDateTime;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    const T_2025: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z
    const T_2026_START: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z
    const T_2026_APR: i64 = 1_775_001_600; // 2026-04-01T00:00:00Z
    const T_2026_JUL: i64 = 1_782_864_000; // 2026-07-01T00:00:00Z
    const T_2027: i64 = 1_798_761_600; // 2027-01-01T00:00:00Z

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    struct SignedProfile {
        data: Vec<u8>,
        anchors: TrustAnchors,
    }

    /// Test CA plus a profile-shaped leaf (no EKU; `Profile::Leaf` supplies
    /// KU digitalSignature and CA=false), chain validity 2020..2030 so every
    /// injected instant below stays inside the chain window.
    fn signed_profile(plist_xml: &str) -> SignedProfile {
        let to_time =
            |unix: u64| Time::try_from(UNIX_EPOCH + StdDuration::from_secs(unix)).unwrap();
        let root_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let root_signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(root_key.clone());
        let root_name = Name::from_str("CN=zsn3 profile test root").unwrap();
        let root_pub = SubjectPublicKeyInfoOwned::from_der(
            root_key
                .to_public_key()
                .to_public_key_der()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let root_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(31u32),
            Validity {
                not_before: to_time(1_577_836_800),
                not_after: to_time(1_893_456_000),
            },
            root_name.clone(),
            root_pub,
            &root_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let leaf_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let leaf_name = Name::from_str("CN=zsn3 profile test leaf").unwrap();
        let leaf_pub = SubjectPublicKeyInfoOwned::from_der(
            leaf_key
                .to_public_key()
                .to_public_key_der()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let leaf_cert = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(32u32),
            Validity {
                not_before: to_time(1_577_836_800),
                not_after: to_time(1_893_456_000),
            },
            leaf_name,
            leaf_pub,
            &root_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let data = sign_attached_content(
            plist_xml.as_bytes(),
            &leaf_cert,
            std::slice::from_ref(&root_cert),
            &leaf_key,
            TestDigest::Sha256,
        )
        .unwrap();
        SignedProfile {
            data,
            anchors: TrustAnchors::from_certificates(vec![root_cert]),
        }
    }

    /// A well-formed profile plist: Name/CreationDate/ExpirationDate
    /// 2026-01-01..2026-07-01, team TESTTEAM, explicit App ID, plus `extra`
    /// keys injected before `</dict>`.
    fn plist_xml(extra: &str) -> String {
        format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                concat!(
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
                    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
                ),
                "<plist version=\"1.0\">\n<dict>\n",
                "  <key>Name</key>\n  <string>Test Profile</string>\n",
                "  <key>CreationDate</key>\n  <date>2026-01-01T00:00:00Z</date>\n",
                "  <key>ExpirationDate</key>\n  <date>2026-07-01T00:00:00Z</date>\n",
                concat!(
                    "  <key>TeamIdentifier</key>\n  <array>\n",
                    "    <string>TESTTEAM</string>\n  </array>\n",
                ),
                "  <key>Entitlements</key>\n  <dict>\n",
                concat!(
                    "    <key>application-identifier</key>\n",
                    "    <string>TESTTEAM.com.example.app</string>\n",
                ),
                "    <key>get-task-allow</key>\n    <true/>\n",
                "  </dict>\n",
                "{}",
                "</dict>\n</plist>\n"
            ),
            extra
        )
    }

    fn request(sp: &SignedProfile, now_unix: i64) -> ProfileRequest {
        ProfileRequest {
            now: Some(at(now_unix)),
            anchors: Some(sp.anchors.clone()),
            ..Default::default()
        }
    }

    #[test]
    fn forged_plaintext_profile_is_rejected_but_legacy_extractor_is_unchanged() {
        let xml = plist_xml("");
        // Legacy contract: raw scan, no verification — unchanged.
        let legacy = String::from_utf8(
            extract_entitlements_from_profile(xml.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(legacy.contains("get-task-allow"));
        // New API: no CMS envelope at all.
        let req = ProfileRequest {
            now: Some(at(T_2026_APR)),
            ..Default::default()
        };
        let err = validate_and_extract_profile(xml.as_bytes(), &req).unwrap_err();
        assert!(matches!(err, crate::Error::Verification(_)), "got: {err}");
    }

    #[test]
    fn valid_profile_verifies_and_exposes_every_field() {
        let sp = signed_profile(&plist_xml(concat!(
            "  <key>ProvisionedDevices</key>\n  <array>\n",
            "    <string>UDID-ONE</string>\n  </array>\n",
        )));
        let info = validate_and_extract_profile(&sp.data, &request(&sp, T_2026_APR)).unwrap();

        assert_eq!(info.name, "Test Profile");
        assert_eq!(info.team_identifiers, ["TESTTEAM".to_string()]);
        assert_eq!(
            info.application_identifier.as_deref(),
            Some("TESTTEAM.com.example.app")
        );
        assert_eq!(info.creation_date, Some(at(T_2026_START)));
        assert_eq!(info.expiration_date, at(T_2026_JUL));
        assert!(!info.provisions_all_devices);
        assert_eq!(info.provisioned_devices, Some(vec!["UDID-ONE".to_string()]));
        let xml = String::from_utf8(info.entitlements_xml.clone().unwrap()).unwrap();
        assert!(xml.contains("get-task-allow"));
        assert!(info.cms.valid);
        assert!(info.cms.signer_subject.is_some());
    }

    #[test]
    fn synthetic_profile_is_rejected_against_production_anchors() {
        let sp = signed_profile(&plist_xml(""));
        let info = ProfileRequest {
            now: Some(at(T_2026_APR)),
            ..Default::default()
        };
        let err = validate_and_extract_profile(&sp.data, &info).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CMS verification failed"), "{msg}");
        assert!(msg.contains("anchored"), "{msg}");
    }

    #[test]
    fn tampered_profile_is_rejected() {
        let sp = signed_profile(&plist_xml(""));
        let mut data = sp.data.clone();
        let needle = plist_xml("");
        let idx = data
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())
            .expect("plist embedded as eContent");
        data[idx] = b'!';
        let err = validate_and_extract_profile(&data, &request(&sp, T_2026_APR)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CMS verification failed"), "{msg}");
        assert!(msg.contains("messageDigest"), "{msg}");
    }

    #[test]
    fn expired_profile_names_profile_date_and_remedy() {
        let sp = signed_profile(&plist_xml(""));
        let err = validate_and_extract_profile(&sp.data, &request(&sp, T_2027)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expired"), "{msg}");
        assert!(msg.contains("Test Profile"), "{msg}");
        assert!(msg.contains("2026-07-01"), "{msg}");
        assert!(msg.contains("renew"), "{msg}");
    }

    #[test]
    fn not_yet_valid_profile_is_rejected() {
        let sp = signed_profile(&plist_xml(""));
        let err = validate_and_extract_profile(&sp.data, &request(&sp, T_2025)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not valid until"), "{msg}");
        assert!(msg.contains("2026-01-01"), "{msg}");
    }

    #[test]
    fn team_mismatch_is_rejected_and_match_passes() {
        let sp = signed_profile(&plist_xml(""));
        let mut req = request(&sp, T_2026_APR);
        req.expected_team_id = Some("OTHERTEAM".to_string());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("OTHERTEAM"), "{msg}");
        assert!(msg.contains("TESTTEAM"), "{msg}");
        let mut ok_req = request(&sp, T_2026_APR);
        ok_req.expected_team_id = Some("TESTTEAM".to_string());
        assert!(validate_and_extract_profile(&sp.data, &ok_req).is_ok());
    }

    #[test]
    fn team_match_accepts_the_union_of_team_sources() {
        let prefix_only = signed_profile(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<plist version=\"1.0\">\n<dict>\n",
            "<key>Name</key><string>Test Profile</string>\n",
            "<key>ExpirationDate</key><date>2026-07-01T00:00:00Z</date>\n",
            "<key>ApplicationIdentifierPrefix</key>\n<array>\n",
            "<string>TESTTEAM</string>\n</array>\n",
            "<key>Entitlements</key>\n<dict>\n",
            "<key>application-identifier</key>\n",
            "<string>TESTTEAM.com.example.app</string>\n",
            "</dict>\n</dict>\n</plist>\n",
        ));
        let mut req = request(&prefix_only, T_2026_APR);
        req.expected_team_id = Some("TESTTEAM".to_string());
        assert!(validate_and_extract_profile(&prefix_only.data, &req).is_ok());
        let with_entitlement = signed_profile(
            &plist_xml("")
                .replace(
                    "    <string>TESTTEAM</string>\n  </array>",
                    "    <string>WRONGTEAM</string>\n  </array>",
                )
                .replace(
                    "    <key>get-task-allow</key>\n    <true/>\n",
                    concat!(
                        "    <key>get-task-allow</key>\n    <true/>\n",
                        "    <key>com.apple.developer.team-identifier</key>\n",
                        "    <string>TESTTEAM</string>\n",
                    ),
                ),
        );
        let mut req = request(&with_entitlement, T_2026_APR);
        req.expected_team_id = Some("TESTTEAM".to_string());
        assert!(validate_and_extract_profile(&with_entitlement.data, &req).is_ok());
        let wrong_only = signed_profile(&plist_xml("").replace(
            "    <string>TESTTEAM</string>\n  </array>",
            "    <string>WRONGTEAM</string>\n  </array>",
        ));
        let mut req = request(&wrong_only, T_2026_APR);
        req.expected_team_id = Some("TESTTEAM".to_string());
        let err = validate_and_extract_profile(&wrong_only.data, &req).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("WRONGTEAM"), "{msg}");
        assert!(msg.contains("not the signing team TESTTEAM"), "{msg}");
    }

    #[test]
    fn explicit_app_id_covers_only_the_matching_bundle() {
        let sp = signed_profile(&plist_xml(""));
        let mut ok_req = request(&sp, T_2026_APR);
        ok_req.target_bundle_id = Some("com.example.app".to_string());
        assert!(validate_and_extract_profile(&sp.data, &ok_req).is_ok());
        let mut bad_req = request(&sp, T_2026_APR);
        bad_req.target_bundle_id = Some("com.example.other".to_string());
        let err = validate_and_extract_profile(&sp.data, &bad_req).unwrap_err();
        assert!(err.to_string().contains("does not cover"), "{err}");
    }

    #[test]
    fn wildcard_app_id_covers_by_trailing_star_only() {
        let sp = signed_profile(
            &plist_xml("").replace("TESTTEAM.com.example.app", "TESTTEAM.com.foo.*"),
        );
        let mut covered = request(&sp, T_2026_APR);
        covered.target_bundle_id = Some("com.foo.bar".to_string());
        assert!(validate_and_extract_profile(&sp.data, &covered).is_ok());
        let mut not_covered = request(&sp, T_2026_APR);
        not_covered.target_bundle_id = Some("com.foobar".to_string());
        let err = validate_and_extract_profile(&sp.data, &not_covered).unwrap_err();
        assert!(err.to_string().contains("does not cover"), "{err}");
        let sp_any =
            signed_profile(&plist_xml("").replace("TESTTEAM.com.example.app", "TESTTEAM.*"));
        let mut any_req = request(&sp_any, T_2026_APR);
        any_req.target_bundle_id = Some("com.anything.at.all".to_string());
        assert!(validate_and_extract_profile(&sp_any.data, &any_req).is_ok());
    }

    #[test]
    fn malformed_wildcard_app_id_is_rejected() {
        let sp = signed_profile(
            &plist_xml("").replace("TESTTEAM.com.example.app", "TESTTEAM.com.*.bar"),
        );
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some("com.example.app".to_string());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        assert!(err.to_string().contains("single trailing"), "{err}");
    }

    #[test]
    fn app_id_under_a_foreign_prefix_is_rejected() {
        let foreign = signed_profile(&plist_xml("").replace(
            "    <string>TESTTEAM.com.example.app</string>",
            "    <string>OTHERTEAM.com.example.app</string>",
        ));
        let mut req = request(&foreign, T_2026_APR);
        req.target_bundle_id = Some("com.example.app".to_string());
        let err = validate_and_extract_profile(&foreign.data, &req).unwrap_err();
        assert!(err.to_string().contains("does not start with"), "{err}");
    }

    #[test]
    fn macos_application_identifier_entitlement_is_used() {
        let mac = plist_xml("").replace(
            concat!(
                "    <key>application-identifier</key>\n",
                "    <string>TESTTEAM.com.example.app</string>\n",
            ),
            concat!(
                "    <key>com.apple.application-identifier</key>\n",
                "    <string>TESTTEAM.com.example.app</string>\n",
            ),
        );
        assert!(!mac.contains("\n    <key>application-identifier</key>"));
        let sp = signed_profile(&mac);
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some("com.example.app".to_string());
        assert!(validate_and_extract_profile(&sp.data, &req).is_ok());
    }

    #[test]
    fn target_bundle_id_must_not_wildcard() {
        let sp = signed_profile(&plist_xml(""));
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some("com.example.*".to_string());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        assert!(
            err.to_string().contains("must not contain a wildcard"),
            "{err}"
        );
    }

    #[test]
    fn empty_target_bundle_id_is_rejected() {
        let sp = signed_profile(&plist_xml(""));
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some(String::new());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn malformed_device_and_team_arrays_fail_closed() {
        let bad_devices = signed_profile(&plist_xml(
            "  <key>ProvisionedDevices</key>\n  <string>not-an-array</string>\n",
        ));
        let err =
            validate_and_extract_profile(&bad_devices.data, &request(&bad_devices, T_2026_APR))
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("ProvisionedDevices is not an array"),
            "{err}"
        );

        let bad_team = signed_profile(&plist_xml("").replace(
            "    <string>TESTTEAM</string>\n  </array>",
            "    <string>TESTTEAM</string>\n    <integer>7</integer>\n  </array>",
        ));
        let err = validate_and_extract_profile(&bad_team.data, &request(&bad_team, T_2026_APR))
            .unwrap_err();
        assert!(err.to_string().contains("non-string entry"), "{err}");
    }

    #[test]
    fn device_registration_checks_follow_provisions_all_devices_precedence() {
        let devices_only = signed_profile(&plist_xml(concat!(
            "  <key>ProvisionedDevices</key>\n  <array>\n",
            "    <string>UDID-ONE</string>\n  </array>\n",
        )));
        let mut listed = request(&devices_only, T_2026_APR);
        listed.target_device_udid = Some("UDID-ONE".to_string());
        assert!(validate_and_extract_profile(&devices_only.data, &listed).is_ok());
        let mut unlisted = request(&devices_only, T_2026_APR);
        unlisted.target_device_udid = Some("UDID-TWO".to_string());
        let err = validate_and_extract_profile(&devices_only.data, &unlisted).unwrap_err();
        assert!(err.to_string().contains("not registered"), "{err}");
        let all_devices = signed_profile(&plist_xml(concat!(
            "  <key>ProvisionedDevices</key>\n  <array>\n",
            "    <string>UDID-ONE</string>\n  </array>\n",
            "  <key>ProvisionsAllDevices</key>\n  <true/>\n",
        )));
        let mut all_req = request(&all_devices, T_2026_APR);
        all_req.target_device_udid = Some("UDID-TWO".to_string());
        assert!(validate_and_extract_profile(&all_devices.data, &all_req).is_ok());
        let app_store = signed_profile(&plist_xml(""));
        let mut store_req = request(&app_store, T_2026_APR);
        store_req.target_device_udid = Some("UDID-TWO".to_string());
        assert!(validate_and_extract_profile(&app_store.data, &store_req).is_ok());
        let malformed = signed_profile(&plist_xml(
            "  <key>ProvisionsAllDevices</key>\n  <string>yes</string>\n",
        ));
        let err = validate_and_extract_profile(&malformed.data, &request(&malformed, T_2026_APR))
            .unwrap_err();
        assert!(err.to_string().contains("non-boolean"), "{err}");
    }

    #[test]
    fn missing_name_or_expiration_date_is_rejected() {
        let no_name = signed_profile(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<plist version=\"1.0\">\n<dict>\n",
            "<key>ExpirationDate</key><date>2026-07-01T00:00:00Z</date>\n",
            "</dict>\n</plist>\n",
        ));
        let err = validate_and_extract_profile(&no_name.data, &request(&no_name, T_2026_APR))
            .unwrap_err();
        assert!(err.to_string().contains("missing the Name"), "{err}");
        let no_exp = signed_profile(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<plist version=\"1.0\">\n<dict>\n",
            "<key>Name</key><string>Test Profile</string>\n",
            "<key>CreationDate</key><date>2026-01-01T00:00:00Z</date>\n",
            "</dict>\n</plist>\n",
        ));
        let err =
            validate_and_extract_profile(&no_exp.data, &request(&no_exp, T_2026_APR)).unwrap_err();
        assert!(err.to_string().contains("has no ExpirationDate"), "{err}");
    }

    #[test]
    fn profile_window_is_driven_by_request_now_not_wall_clock() {
        let sp = signed_profile(&plist_xml(""));
        // Fixed instant inside the 2026-01-01..2026-07-01 window — passes
        // whatever today's date is.
        assert!(validate_and_extract_profile(&sp.data, &request(&sp, T_2026_APR)).is_ok());
        // One instant after ExpirationDate — rejected.
        let err = validate_and_extract_profile(&sp.data, &request(&sp, T_2027)).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        // One instant before CreationDate — rejected as not yet valid.
        let err = validate_and_extract_profile(&sp.data, &request(&sp, T_2025)).unwrap_err();
        assert!(err.to_string().contains("not valid until"), "{err}");
    }
}
