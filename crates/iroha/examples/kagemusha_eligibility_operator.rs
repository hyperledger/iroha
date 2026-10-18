//! Disposable local scheme-operator eligibility adapter for physical enrollment campaigns.
//!
//! An authenticated HTTPS supervisor sends one bounded canonical request on stdin and reads the
//! exact signed response on stdout. The selected private directory contains `template.norito`,
//! `signer.key` (32 raw Ed25519 bytes), and atomically published `current.json`. This test-scope
//! owner never represents bank KYC. Unknown subjects, foreign assets and unavailable reads refuse.
use iroha::kagemusha_enrollment::{
    CurrentEnrollmentEligibilityV1, EnrollmentEligibilityMiddlewareErrorV1 as Error,
    answer_enrollment_eligibility_v1, sign_enrollment_eligibility_v1,
};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey};
use iroha_data_model::kagemusha::{
    KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1, KagemushaEligibilityAuthorityV1,
    KagemushaEligibilityPolicyTemplateV1, KagemushaEligibilityRequestV1,
    KagemushaWalletAssetScopeV1,
};
use iroha_fs::PrivateDirectory;
use norito::json::Value;
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const TABLE_MAX: usize = 1 << 20;
const HELP: &str = "kagemusha_eligibility_operator ABSOLUTE_PRIVATE_DIRECTORY\n\nOne authenticated transport request on stdin; canonical response on stdout. Requires explicitly selected SchemeOperator template.norito, matching raw Ed25519 signer.key, and current.json. Publish the entire current table atomically. No environment configuration, implicit approvals, state creation or credential logging.";

type Result<T> = std::result::Result<T, Error>;

fn now() -> Result<u64> {
    let value = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_millis(),
    )
    .map_err(|_| Error::Clock)?;
    if value == 0 {
        return Err(Error::Clock);
    }
    Ok(value)
}

fn exact_keys(value: &Value, wanted: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or(Error::Unavailable)?;
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if actual != wanted.iter().copied().collect() {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn digest(value: &Value) -> Result<[u8; 32]> {
    let text = value.as_str().ok_or(Error::Unavailable)?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Unavailable);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| Error::Unavailable)?;
    if bytes == [0; 32] {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}

/// One complete current image binds approval and freeze to the exact account, actor and asset.
/// Every record is validated, including duplicates, before any selected record is returned.
fn lookup(
    bytes: &[u8],
    template: &[u8],
    asset: &[u8; 32],
    request: &KagemushaEligibilityRequestV1,
    observed_at_ms: u64,
) -> Result<CurrentEnrollmentEligibilityV1> {
    if bytes.len() > TABLE_MAX {
        return Err(Error::Unavailable);
    }
    let value: Value = norito::json::from_slice(bytes).map_err(|_| Error::Unavailable)?;
    exact_keys(&value, &["version", "templateHex", "records"])?;
    if value["version"].as_u64() != Some(1)
        || value["templateHex"].as_str() != Some(hex::encode(template).as_str())
        || observed_at_ms == 0
    {
        return Err(Error::Unavailable);
    }
    let rows = value["records"].as_array().ok_or(Error::Unavailable)?;
    if rows.is_empty() || rows.len() > 4096 {
        return Err(Error::Unavailable);
    }
    let mut identities = BTreeSet::new();
    let mut selected = None;
    for row in rows {
        exact_keys(
            row,
            &[
                "assetDigest",
                "accountDigest",
                "actorDigest",
                "approved",
                "frozen",
                "revision",
            ],
        )?;
        let identity = (
            digest(&row["assetDigest"])?,
            digest(&row["accountDigest"])?,
            digest(&row["actorDigest"])?,
        );
        if !identities.insert(identity) {
            return Err(Error::Unavailable);
        }
        let current = CurrentEnrollmentEligibilityV1 {
            approved: row["approved"].as_bool().ok_or(Error::Unavailable)?,
            frozen: row["frozen"].as_bool().ok_or(Error::Unavailable)?,
            revision: row["revision"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or(Error::Unavailable)?,
            observed_at_ms,
        };
        if identity == (*asset, request.account_digest, request.actor_digest) {
            selected = Some(current);
        }
    }
    selected.ok_or(Error::Unavailable)
}

fn answer(directory: &PrivateDirectory, request: &[u8]) -> Result<Vec<u8>> {
    let template_original = directory
        .read("template.norito", KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)
        .map_err(|_| Error::Unavailable)?;
    let template = KagemushaEligibilityPolicyTemplateV1::decode_canonical(&template_original)
        .map_err(|_| Error::InvalidRequest)?;
    if !matches!(
        template.authority,
        KagemushaEligibilityAuthorityV1::SchemeOperator { .. }
    ) {
        return Err(Error::InvalidRequest);
    }
    let key_original = directory
        .read("signer.key", 32)
        .map_err(|_| Error::Signing)?;
    if key_original.len() != 32 {
        return Err(Error::Signing);
    }
    let key = KeyPair::from_private_key(
        PrivateKey::from_bytes(Algorithm::Ed25519, &key_original).map_err(|_| Error::Signing)?,
    )
    .map_err(|_| Error::Signing)?;
    if key.public_key().to_bytes().1 != template.public_key {
        return Err(Error::Signing);
    }
    answer_enrollment_eligibility_v1(
        &template,
        request,
        now,
        |asset: &KagemushaWalletAssetScopeV1, _, request| {
            // One admitted private leaf supplies the entire current-state image. Reopen it for
            // every request; atomic replacement is the operator's sole update operation.
            let bytes = directory
                .read("current.json", TABLE_MAX)
                .map_err(|_| Error::Unavailable)?;
            lookup(
                &bytes,
                &template_original,
                &asset.asset_digest(),
                request,
                now()?,
            )
        },
        |message| sign_enrollment_eligibility_v1(&key, message),
    )
}

fn execute(path: &Path, input: impl Read) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(Error::Unavailable);
    }
    let directory = PrivateDirectory::open(path).map_err(|_| Error::Unavailable)?;
    let mut original = Vec::with_capacity(KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1);
    input
        .take((KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1) as u64)
        .read_to_end(&mut original)
        .map_err(|_| Error::Unavailable)?;
    if original.is_empty() || original.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 {
        return Err(Error::InvalidRequest);
    }
    answer(&directory, &original)
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 1 && arguments[0] == "--help" {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if arguments.len() != 1 {
        eprintln!("invalid arguments; use --help");
        return ExitCode::FAILURE;
    }
    let result = execute(Path::new(&arguments[0]), std::io::stdin().lock());
    result.map_or_else(
        |_| {
            // Protocol errors, paths, signatures and request bodies are never logged.
            eprintln!("current eligibility unavailable");
            ExitCode::FAILURE
        },
        |original| match std::io::stdout().lock().write_all(&original) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::kagemusha::KagemushaEligibilityPurposeV1;
    fn request() -> KagemushaEligibilityRequestV1 {
        KagemushaEligibilityRequestV1 {
            version: 1,
            policy_digest: [1; 32],
            account_digest: [2; 32],
            actor_digest: [3; 32],
            attempt_id: [4; 32],
            nonce: [5; 32],
            operation_digest: [6; 32],
            purpose: KagemushaEligibilityPurposeV1::PreKeyPermit,
            requested_at_ms: 1000,
            expires_at_ms: 2000,
        }
    }
    fn table(approved: bool, frozen: bool, revision: u64) -> Value {
        fn object(rows: Vec<(&str, Value)>) -> Value {
            Value::Object(rows.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
        }
        object(vec![
            ("version", Value::from(1u64)),
            ("templateHex", Value::String("0102".into())),
            (
                "records",
                Value::Array(vec![object(vec![
                    ("assetDigest", Value::String(hex::encode([7; 32]))),
                    ("accountDigest", Value::String(hex::encode([2; 32]))),
                    ("actorDigest", Value::String(hex::encode([3; 32]))),
                    ("approved", Value::Bool(approved)),
                    ("frozen", Value::Bool(frozen)),
                    ("revision", Value::from(revision)),
                ])]),
            ),
        ])
    }
    fn bytes(value: &Value) -> Vec<u8> {
        norito::json::to_vec(value).unwrap()
    }
    #[test]
    fn reads_current_flags_and_revision_without_cached_approval() {
        for (approved, frozen, revision) in [
            (true, false, 1),
            (false, false, 2),
            (true, true, 3),
            (false, true, 4),
        ] {
            let got = lookup(
                &bytes(&table(approved, frozen, revision)),
                &[1, 2],
                &[7; 32],
                &request(),
                1200,
            )
            .unwrap();
            assert_eq!(
                got,
                CurrentEnrollmentEligibilityV1 {
                    approved,
                    frozen,
                    revision,
                    observed_at_ms: 1200
                }
            );
        }
    }
    #[test]
    fn refuses_unknown_subject_actor_asset_and_selected_policy() {
        let original = bytes(&table(true, false, 1));
        assert!(lookup(&original, &[1, 3], &[7; 32], &request(), 1200).is_err());
        assert!(lookup(&original, &[1, 2], &[8; 32], &request(), 1200).is_err());
        let mut foreign = request();
        foreign.actor_digest = [8; 32];
        assert!(lookup(&original, &[1, 2], &[7; 32], &foreign, 1200).is_err());
        foreign = request();
        foreign.account_digest = [8; 32];
        assert!(lookup(&original, &[1, 2], &[7; 32], &foreign, 1200).is_err());
    }
    #[test]
    fn refuses_ambiguous_or_malformed_table_before_returning_selected_record() {
        assert!(
            lookup(
                &bytes(&table(true, false, 0)),
                &[1, 2],
                &[7; 32],
                &request(),
                1200
            )
            .is_err()
        );
        let mut extra = table(true, false, 1);
        extra
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::Bool(true));
        assert!(lookup(&bytes(&extra), &[1, 2], &[7; 32], &request(), 1200).is_err());
        for field in ["approved", "frozen", "revision"] {
            let mut invalid = table(true, false, 1);
            invalid
                .as_object_mut()
                .unwrap()
                .get_mut("records")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]
                .as_object_mut()
                .unwrap()
                .insert(field.into(), Value::String("invalid".into()));
            assert!(lookup(&bytes(&invalid), &[1, 2], &[7; 32], &request(), 1200).is_err());
        }
        let mut value = table(true, false, 1);
        let rows = value
            .as_object_mut()
            .unwrap()
            .get_mut("records")
            .unwrap()
            .as_array_mut()
            .unwrap();
        rows.push(rows[0].clone());
        assert!(lookup(&bytes(&value), &[1, 2], &[7; 32], &request(), 1200).is_err());
        assert!(lookup(b"{}", &[1, 2], &[7; 32], &request(), 1200).is_err());
        assert!(
            lookup(
                &bytes(&table(true, false, 1)),
                &[1, 2],
                &[7; 32],
                &request(),
                0
            )
            .is_err()
        );
    }
    #[test]
    fn time_and_digest_guards_require_canonical_positive_values() {
        assert!(now().unwrap() > 0);
        for invalid in [
            "0".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            assert!(digest(&Value::String(invalid)).is_err());
        }
        assert_eq!(
            digest(&Value::String(hex::encode([9; 32]))).unwrap(),
            [9; 32]
        );
    }
    fn private_fixture() -> (
        tempfile::TempDir,
        PrivateDirectory,
        KagemushaEligibilityPolicyTemplateV1,
        KagemushaWalletAssetScopeV1,
        KagemushaEligibilityRequestV1,
        Vec<u8>,
    ) {
        use iroha_data_model::kagemusha::KagemushaEligibilityObservationV1;
        use iroha_data_model::{asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1};
        let temporary = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let directory =
            PrivateDirectory::open_exact(temporary.path().canonicalize().unwrap()).unwrap();
        let key = KeyPair::from_private_key(
            PrivateKey::from_bytes(Algorithm::Ed25519, &[17; 32]).unwrap(),
        )
        .unwrap();
        let template = KagemushaEligibilityPolicyTemplateV1 {
            version: 1,
            network_id: [1; 32],
            scheme_id: [2; 32],
            revision: 1,
            authority: KagemushaEligibilityAuthorityV1::SchemeOperator {
                operator_digest: [4; 32],
            },
            public_key: key.public_key().to_bytes().1.try_into().unwrap(),
            maximum_response_ms: 60000,
        };
        let mut uuid = [3; 16];
        uuid[6] = 0x43;
        uuid[8] = 0x83;
        let asset = KagemushaWalletAssetScopeV1::new(
            AssetDefinitionId::from_uuid_bytes(uuid).unwrap(),
            &AxtAssetIncarnationV1::try_from_bytes(*iroha_crypto::Hash::new([3; 32]).as_ref())
                .unwrap(),
            2,
        )
        .unwrap();
        let mut request = request();
        request.policy_digest = template.for_asset(&asset).unwrap().policy_digest().unwrap();
        request.requested_at_ms = now().unwrap();
        request.expires_at_ms = request.requested_at_ms + 60000;
        let original = KagemushaEligibilityObservationV1 {
            version: 1,
            asset: asset.clone(),
            request,
        }
        .encode_canonical(&template)
        .unwrap();
        directory
            .write_atomic(
                "template.norito",
                &template.encode_canonical().unwrap(),
                iroha_fs::PublishMode::CreateNew,
            )
            .unwrap();
        directory
            .write_atomic("signer.key", &[17; 32], iroha_fs::PublishMode::CreateNew)
            .unwrap();
        (temporary, directory, template, asset, request, original)
    }
    fn publish_current(
        directory: &PrivateDirectory,
        template: &KagemushaEligibilityPolicyTemplateV1,
        asset: &KagemushaWalletAssetScopeV1,
        approved: bool,
        frozen: bool,
        revision: u64,
    ) {
        let mut value = table(approved, frozen, revision);
        value.as_object_mut().unwrap().insert(
            "templateHex".into(),
            Value::String(hex::encode(template.encode_canonical().unwrap())),
        );
        value
            .as_object_mut()
            .unwrap()
            .get_mut("records")
            .unwrap()
            .as_array_mut()
            .unwrap()[0]
            .as_object_mut()
            .unwrap()
            .insert(
                "assetDigest".into(),
                Value::String(hex::encode(asset.asset_digest())),
            );
        let mode = if directory
            .read_optional("current.json", TABLE_MAX)
            .unwrap()
            .is_some()
        {
            iroha_fs::PublishMode::Replace
        } else {
            iroha_fs::PublishMode::CreateNew
        };
        directory
            .write_atomic("current.json", &bytes(&value), mode)
            .unwrap();
    }
    #[test]
    fn actual_private_current_table_yields_verified_signatures_and_freeze_wins_on_next_request() {
        use iroha_data_model::kagemusha::{
            KagemushaEligibilityDecisionV1 as D, KagemushaEligibilityResponseV1,
        };
        let (_temporary, directory, template, asset, request, original) = private_fixture();
        let policy = template.for_asset(&asset).unwrap();
        for (approved, frozen, revision, expected) in [
            (true, false, 1, D::ApprovedUnfrozen),
            (false, false, 2, D::NotApproved),
            (true, true, 3, D::Frozen),
            (false, true, 4, D::Frozen),
        ] {
            publish_current(&directory, &template, &asset, approved, frozen, revision);
            let output = execute(directory.path(), &original[..]).unwrap();
            let response = KagemushaEligibilityResponseV1::decode_canonical(
                &output,
                &policy,
                &request,
                now().unwrap(),
            )
            .unwrap();
            assert_eq!(response.body.decision, expected);
            assert_eq!(response.body.source_revision, revision);
            assert!(response.body.observed_at_ms >= request.requested_at_ms);
        }
    }
    #[test]
    fn missing_current_unknown_subject_bad_key_and_bank_authority_never_emit_a_response() {
        let (_temporary, directory, template, asset, _, original) = private_fixture();
        assert!(answer(&directory, &original).is_err());
        publish_current(&directory, &template, &asset, true, false, 1);
        assert!(execute(directory.path(), &[][..]).is_err());
        assert!(execute(directory.path(), &vec![0; 2049][..]).is_err());
        assert!(execute(Path::new("relative"), &original[..]).is_err());
        let mut foreign = asset.clone();
        foreign.scale += 1;
        publish_current(&directory, &template, &foreign, true, false, 2);
        assert!(answer(&directory, &original).is_err());
        publish_current(&directory, &template, &asset, true, false, 3);
        directory
            .write_atomic("signer.key", &[18; 32], iroha_fs::PublishMode::Replace)
            .unwrap();
        assert!(answer(&directory, &original).is_err());
        directory
            .write_atomic("signer.key", &[17; 32], iroha_fs::PublishMode::Replace)
            .unwrap();
        let mut bank = template;
        bank.authority = KagemushaEligibilityAuthorityV1::Bank { fi_digest: [4; 32] };
        directory
            .write_atomic(
                "template.norito",
                &bank.encode_canonical().unwrap(),
                iroha_fs::PublishMode::Replace,
            )
            .unwrap();
        assert!(answer(&directory, &original).is_err());
    }
}
