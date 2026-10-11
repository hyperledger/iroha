//! Fixed mobile shared-library policy, including immutable public application trust.

fn main() {
    wallet_runtime_trust();
    if matches!(
        std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("android")
    ) {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-z,max-page-size=16384");
    }
}
fn parse_wallet_runtime_trust(
    authority: Option<&str>,
    value: Option<&str>,
) -> Result<Option<(&'static str, [u8; 32])>, &'static str> {
    let (authority, value) = match (authority, value) {
        (None, None) => return Ok(None),
        (Some("bpng-taira-v7"), Some(value)) => ("BpngTairaV7", value),
        (Some("cbsi-release-v1"), Some(value)) => ("CbsiReleaseV1", value),
        (Some("application-release-v1"), Some(value)) => ("ApplicationReleaseV1", value),
        _ => return Err("expected an exact application authority and public key pair"),
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err("expected one nonzero lowercase 32-byte Ed25519 public key");
    }
    let mut key = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        key[index] =
            u8::from_str_radix(std::str::from_utf8(pair).expect("validated ASCII hex"), 16)
                .expect("validated lowercase hex");
    }
    Ok(Some((authority, key)))
}
fn wallet_runtime_trust() {
    const INPUT: &str = "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX";
    const AUTHORITY: &str = "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY";
    let read = |name| {
        println!("cargo:rerun-if-env-changed={name}");
        match std::env::var(name) {
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => panic!("{name} is not valid UTF-8"),
            Ok(value) => Some(value),
        }
    };
    let authority = read(AUTHORITY);
    let value = read(INPUT);
    let key = parse_wallet_runtime_trust(authority.as_deref(), value.as_deref())
        .unwrap_or_else(|error| panic!("{AUTHORITY}/{INPUT}: {error}"));
    let source = key.map_or_else(
        || "None".to_owned(),
        |(authority, key)| format!("Some((RuntimeAuthority::{authority}, {key:?}))"),
    );
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"))
        .join("kagemusha_wallet_runtime_trust.rs");
    std::fs::write(path, format!("// Immutable public authority and key selected by the native artifact build owner.\nconst INSTALLED_RUNTIME_TRUST: Option<(RuntimeAuthority, [u8; 32])> = {source};\n"))
        .expect("write immutable native wallet installation policy");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_public_build_selection_disables_original_installation() {
        assert_eq!(parse_wallet_runtime_trust(None, None), Ok(None));
    }
    #[test]
    fn configured_malformed_public_selection_refuses_the_native_build() {
        for key in [
            "".to_owned(),
            "0".repeat(64),
            "A".repeat(64),
            "g".repeat(64),
            "1".repeat(63),
            "1".repeat(65),
            format!("{}\n", "1".repeat(64)),
        ] {
            for authority in ["bpng-taira-v7", "cbsi-release-v1", "application-release-v1"] {
                assert!(parse_wallet_runtime_trust(Some(authority), Some(&key)).is_err());
            }
        }
    }
    #[test]
    fn native_build_selection_retains_exact_public_key_bytes() {
        let selected = (0u8..32)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for (authority, variant) in [
            ("bpng-taira-v7", "BpngTairaV7"),
            ("cbsi-release-v1", "CbsiReleaseV1"),
            ("application-release-v1", "ApplicationReleaseV1"),
        ] {
            assert_eq!(
                parse_wallet_runtime_trust(Some(authority), Some(&selected)),
                Ok(Some((variant, std::array::from_fn(|index| index as u8))))
            );
        }
    }
    #[test]
    fn partial_unknown_or_normalized_authority_never_selects_a_profile() {
        let key = "1".repeat(64);
        assert!(parse_wallet_runtime_trust(None, Some(&key)).is_err());
        for authority in ["bpng-taira-v7", "cbsi-release-v1", "application-release-v1"] {
            assert!(parse_wallet_runtime_trust(Some(authority), None).is_err());
        }
        for authority in [
            "",
            "bpng",
            "bpng-taira-v6",
            "cbsi",
            "BPNG-TAIRA-V7",
            "bpng-taira-v7\n",
            " cbsi-release-v1",
        ] {
            assert!(parse_wallet_runtime_trust(Some(authority), Some(&key)).is_err());
        }
    }
}
