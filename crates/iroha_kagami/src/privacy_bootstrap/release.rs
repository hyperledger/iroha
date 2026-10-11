//! Secret-free composition of the exact first-release Taira privacy inputs.
use super::{
    MAX_INSTRUCTIONS_JSON_BYTES_V1, MAX_REPORT_JSON_BYTES_V1, create_new_file, read_bounded,
    remove_created_file_if_unchanged_v1, resolved_new_output_path_v1,
    validate_taira_privacy_bootstrap_v1,
};
use clap::Args as ClapArgs;
use color_eyre::eyre::{WrapErr as _, bail, eyre};
use iroha_core_privacy::privacy_engines::bootle_lantern::issuer::{
    TairaBootleLanternBrokerQualificationInputsV1,
    derive_taira_bootle_lantern_broker_qualification_digest_v1,
    taira_bootle_lantern_broker_contract_digest_v1,
    taira_bootle_lantern_issuer_profile_contract_digest_v1,
};
use iroha_crypto::sha256;
use iroha_data_model::{
    NetworkId,
    account::address::ChainDiscriminantGuard,
    isi::{
        InstructionBox,
        privacy::{
            RegisterPrivacyBootleLanternIssuerPolicyV1, RegisterPrivacyProtocolActivationV1,
            TransitionPrivacyProtocolLifecycleV1,
        },
    },
    privacy::{
        BootleLanternIssuerPolicyLifecycleV1, PrivacyProtocolIdV1, privacy_exact12_matrix_bytes_v1,
    },
};
use iroha_genesis::validate_genesis_manifest_json;
use norito::json::{Map as JsonMap, Value as JsonValue};
use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
};
const MAX_TEMPLATE_BYTES_V1: u64 = 8 * 1024 * 1024;
const MAX_BROKER_EXPORT_BYTES_V1: u64 = 4 * 1024 * 1024;
const CHAIN_ID_V1: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
const CHAIN_DISCRIMINANT_V1: u64 = 369;
const GENESIS_AUTHORITY_V1: &str = "testuﾛ1PｵEmｷjMZZﾑﾙeｱﾁﾎﾅﾂﾊmECepdbﾎｳ2uWﾃｸﾊﾘvｵi2ｦP1Y18A";
const GENESIS_ALIAS_BOOTSTRAP_AUTHORITY_V1: &str =
    "testuﾛ1NヰﾋhM25ｳﾙﾁUｺﾂxｼqPﾙPﾅPdNｼﾖ2oﾉﾀdJﾘZﾖ3pTｳ1MLRWYG";
const GENESIS_ALIAS_BOOTSTRAP_ROLE_ID_V1: &str = "nevo_taira_alias_bootstrap";
const NEVO_PUBLIC_INPUT_SCHEMA_V1: &str = "iroha.taira.nevo-reset-public-inputs.v2";
const NEVO_FEE_ASSET_DEFINITION_ID_V1: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
const NEVO_FEE_SPONSOR_PROGRAM_NAME_V1: &str = "cbsi_web";
const PROVIDER_HANDLE_V1: &str = "runtime://privacy/bootle-lantern/taira-primary";
const PROVIDER_REVISION_V1: u64 = 1;
const AUTHORIZATION_LIFETIME_BLOCKS_V1: u64 = 300;
const MAX_INFLIGHT_V1: u64 = 2;
const ISSUER_ID_DOMAIN_V1: &[u8] = b"iroha.taira.privacy.bootle-lantern.issuer.v1";
const POLICY_ID_DOMAIN_V1: &[u8] = b"iroha.taira.privacy.bootle-lantern.policy.v1";
const BROKER_EXPORT_SCHEMA_V1: &str = "iroha.taira.privacy.bootle-lantern-broker-public.v1";
const ROLLOUT_PLAN_PATH_V1: &str = "configs/soranexus/taira/privacy_rollout_plan_v1.json";
const ROLLOUT_PLAN_SHA256_V1: &str =
    "7cde3248ec1c88819590bd8846b04e31d8f45f86a08b081ce602f1a964f345b2";
const CANONICAL_ROLLOUT_PLAN_V1: &[u8] =
    include_bytes!("../../../../configs/soranexus/taira/privacy_rollout_plan_v1.json");
const CANONICAL_CARGO_LOCK_V1: &[u8] = include_bytes!("../../../../Cargo.lock");
const CANONICAL_PLAN_TEMPLATE_V1: &[u8] =
    include_bytes!("../../../../configs/soranexus/taira/privacy_bootstrap_plan.json");
const CANONICAL_CONFIG_TEMPLATE_V1: &[u8] =
    include_bytes!("../../../../configs/soranexus/taira/config.toml");
const CANONICAL_GENESIS_TEMPLATE_V1: &[u8] =
    include_bytes!("../../../../configs/soranexus/taira/genesis.template.json");
const CANONICAL_NEVO_OVERLAY_V1: &[u8] =
    include_bytes!("../../../../configs/soranexus/taira/nevo_genesis_overlay.template.json");
#[cfg(test)]
const GOLDEN_NEVO_UNSIGNED_V2: &[u8] =
    include_bytes!("../../tests/fixtures/taira_nevo_v2/unsigned-genesis.template.json");
#[cfg(test)]
const GOLDEN_NEVO_REVIEW_V2: &[u8] =
    include_bytes!("../../tests/fixtures/taira_nevo_v2/review.json");
const GOLDEN_NEVO_ONBOARDING_V2: &str = "testuﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP";
const GOLDEN_NEVO_API_SIGNER_V2: &str = "testuﾛ1NﾑﾅpﾐTm5Yfﾕ3ｦSヰﾏBｶA5ｻﾔｽｱｼDkDｸkVZBｳﾈyｽﾜヰ9NA1NP";
const GOLDEN_NEVO_INORI_V2: &str = "testuﾛ1QDｺ4ヰｶtBﾂSAﾐﾒｱK8jW7yﾔfｵﾒzｴiﾕｿtﾅFQ4ﾏvヰAｴ3MF4N9";
const GOLDEN_NEVO_EPR_GUARD_V2: &str = "testuﾛ1Q1ヰﾁﾏ3ﾕmヰGmdLbﾜｦｦﾜF3qﾗﾇ2heEQ6vYｽ9tbEQLuCMJYJT";
/// Inputs for native validation of one reviewed Taira NEVO genesis source template.
#[derive(Debug, ClapArgs)]
pub(super) struct ValidateTairaNevoReviewV1Args {
    /// Exact non-signable NEVO genesis source template bound by the review manifest.
    #[arg(long)]
    unsigned_genesis: PathBuf,
    /// Deterministic public NEVO review manifest binding the genesis source template.
    #[arg(long)]
    review: PathBuf,
}
/// Inputs and fresh output paths for one complete Taira privacy release set.
#[derive(Debug, ClapArgs)]
pub(super) struct RenderTairaReleaseV1Args {
    /// Exact-12 instruction JSON emitted by `emit-taira-v1`.
    #[arg(long)]
    activation_instructions: PathBuf,
    /// Digest report emitted together with the exact-12 instructions.
    #[arg(long)]
    activation_report: PathBuf,
    /// Canonical public JSON emitted by the qualified peer-1 broker.
    #[arg(long)]
    broker_public_export: PathBuf,
    /// Canonical disabled Taira privacy plan template.
    #[arg(long)]
    plan_template: PathBuf,
    /// Canonical disabled peer-1 Taira config template.
    #[arg(long)]
    config_template: PathBuf,
    /// Canonical non-signable Taira genesis source template without privacy bootstrap instructions.
    #[arg(long)]
    genesis_template: PathBuf,
    /// Deterministic public NEVO review manifest binding the genesis template.
    #[arg(long)]
    nevo_review: PathBuf,
    /// Fresh output path for the complete public release plan.
    #[arg(long)]
    plan_output: PathBuf,
    /// Fresh output path for the complete peer-1 release config.
    #[arg(long)]
    config_output: PathBuf,
    /// Fresh `.template.json` output path for the overlaid release genesis source template.
    #[arg(long)]
    genesis_output: PathBuf,
    /// Fresh output path for the verified canonical public broker export.
    #[arg(long)]
    broker_public_output: PathBuf,
}
#[derive(Debug)]
struct BrokerPublicMaterialV1 {
    network_id: String,
    public_export_sha256: String,
    qualification_policy_digest_hex: String,
    issuer_parameter_id_hex: String,
    issuer_parameter_digest_hex: String,
    policy_record_digest_hex: String,
    instruction_norito_sha256: String,
}
#[derive(Debug)]
struct ReleaseArtifactsV1 {
    plan: Vec<u8>,
    config: Vec<u8>,
    genesis: Vec<u8>,
    broker_public: Vec<u8>,
    native_recomposition_passed: bool,
}
pub(super) fn validate_taira_nevo_review_v1<T: Write>(
    args: &ValidateTairaNevoReviewV1Args,
    writer: &mut std::io::BufWriter<T>,
) -> color_eyre::Result<()> {
    let unsigned_genesis = read_bounded(
        &args.unsigned_genesis,
        MAX_TEMPLATE_BYTES_V1,
        "Taira NEVO unsigned genesis",
    )?;
    let review = read_bounded(
        &args.review,
        MAX_TEMPLATE_BYTES_V1,
        "Taira NEVO reset review",
    )?;
    let recomposed = render_release_genesis_v1(&unsigned_genesis, Some(&review))?;
    if recomposed != unsigned_genesis {
        bail!("Taira NEVO native recomposition changed the reviewed unsigned genesis");
    }
    let status = norito::json!({
        "status": "validated",
        "unsigned_genesis_sha256": (hex::encode(sha256(&unsigned_genesis))),
        "review_sha256": (hex::encode(sha256(&review))),
        "native_recomposition_passed": true,
    });
    writeln!(writer, "{}", norito::json::to_json(&status)?)?;
    Ok(())
}
pub(super) fn render_taira_release_v1<T: Write>(
    args: &RenderTairaReleaseV1Args,
    writer: &mut std::io::BufWriter<T>,
) -> color_eyre::Result<()> {
    for (label, path) in [
        ("Taira genesis source input", &args.genesis_template),
        ("Taira genesis source output", &args.genesis_output),
    ] {
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".template.json"))
        {
            bail!("{label} must use the `.template.json` suffix");
        }
    }
    let activation_instructions = read_bounded(
        &args.activation_instructions,
        MAX_INSTRUCTIONS_JSON_BYTES_V1,
        "Taira privacy activation instructions",
    )?;
    let activation_report = read_bounded(
        &args.activation_report,
        MAX_REPORT_JSON_BYTES_V1,
        "Taira privacy activation report",
    )?;
    let broker_export = read_bounded(
        &args.broker_public_export,
        MAX_BROKER_EXPORT_BYTES_V1,
        "Taira Bootle/Lantern broker public export",
    )?;
    let plan_template = read_bounded(
        &args.plan_template,
        MAX_TEMPLATE_BYTES_V1,
        "Taira privacy plan template",
    )?;
    let config_template = read_bounded(
        &args.config_template,
        MAX_TEMPLATE_BYTES_V1,
        "Taira config template",
    )?;
    let genesis_template = read_bounded(
        &args.genesis_template,
        MAX_TEMPLATE_BYTES_V1,
        "Taira genesis template",
    )?;
    let nevo_review = read_bounded(
        &args.nevo_review,
        MAX_TEMPLATE_BYTES_V1,
        "Taira NEVO reset review",
    )?;
    let artifacts = compose_release_artifacts_v1(
        &activation_instructions,
        &activation_report,
        &broker_export,
        &plan_template,
        &config_template,
        &genesis_template,
        Some(&nevo_review),
    )?;
    write_new_artifact_set_v1([
        (
            &args.plan_output,
            artifacts.plan.as_slice(),
            "Taira privacy release plan",
        ),
        (
            &args.config_output,
            artifacts.config.as_slice(),
            "Taira peer-1 release config",
        ),
        (
            &args.genesis_output,
            artifacts.genesis.as_slice(),
            "Taira privacy release genesis source template",
        ),
        (
            &args.broker_public_output,
            artifacts.broker_public.as_slice(),
            "verified Taira broker public export",
        ),
    ])?;
    let status = norito::json!({
        "status": "rendered",
        "plan_path": (args.plan_output.display().to_string()),
        "plan_sha256": (hex::encode(sha256(&artifacts.plan))),
        "config_path": (args.config_output.display().to_string()),
        "config_sha256": (hex::encode(sha256(&artifacts.config))),
        "genesis_source_template_path": (args.genesis_output.display().to_string()),
        "genesis_source_template_sha256": (hex::encode(sha256(&artifacts.genesis))),
        "native_recomposition_passed": (artifacts.native_recomposition_passed),
        "broker_public_path": (args.broker_public_output.display().to_string()),
        "broker_public_sha256": (hex::encode(sha256(&artifacts.broker_public))),
        "qualification_activation_protocol_count": (PrivacyProtocolIdV1::COUNT as u64),
        "qualification_activation_instruction_count": (super::BOOTSTRAP_INSTRUCTION_COUNT_V1 as u64),
        "genesis_privacy_instruction_count": 0_u64,
        "rollout_state": "not-executed",
    });
    writeln!(writer, "{}", norito::json::to_json(&status)?)?;
    Ok(())
}
fn compose_release_artifacts_v1(
    activation_instructions: &[u8],
    activation_report: &[u8],
    broker_export: &[u8],
    plan_template: &[u8],
    config_template: &[u8],
    genesis_template: &[u8],
    nevo_review: Option<&[u8]>,
) -> color_eyre::Result<ReleaseArtifactsV1> {
    validate_taira_privacy_bootstrap_v1(activation_instructions, activation_report)?;
    let broker = parse_broker_public_export_v1(broker_export)?;
    let plan = render_release_plan_v1(plan_template, &broker)?;
    let config = render_release_config_v1(config_template, &broker)?;
    let genesis = render_release_genesis_v1(genesis_template, nevo_review)?;
    Ok(ReleaseArtifactsV1 {
        plan,
        config,
        genesis,
        broker_public: broker_export.to_vec(),
        native_recomposition_passed: nevo_review.is_some(),
    })
}
fn validate_nevo_review_v1(genesis: &[u8], review: &[u8]) -> color_eyre::Result<()> {
    let value: JsonValue =
        norito::json::from_slice(review).wrap_err("Taira NEVO review is not strict JSON")?;
    let root = object_v1(&value, "Taira NEVO review")?;
    expect_exact_keys_v1(
        root,
        &[
            "schema",
            "chain",
            "chain_discriminant",
            "state",
            "public_inputs_sha256",
            "base_genesis_sha256",
            "base_config_sha256",
            "unsigned_genesis_sha256",
            "public_identities",
            "credential_hash_bindings",
            "genesis_overlay",
            "secret_boundary",
            "required_next_steps",
        ],
        "Taira NEVO review",
    )?;
    expect_string_v1(
        root,
        "schema",
        "iroha.taira.nevo-reset-review.v3",
        "Taira NEVO review",
    )?;
    expect_string_v1(root, "chain", CHAIN_ID_V1, "Taira NEVO review")?;
    expect_u64_v1(
        root,
        "chain_discriminant",
        CHAIN_DISCRIMINANT_V1,
        "Taira NEVO review",
    )?;
    expect_string_v1(
        root,
        "state",
        "unsigned_operator_review_required",
        "Taira NEVO review",
    )?;
    let digest_fields = [
        "public_inputs_sha256",
        "base_genesis_sha256",
        "base_config_sha256",
        "unsigned_genesis_sha256",
    ];
    for field in digest_fields {
        fixed_nonzero_sha256_v1(
            string_field_v1(root, field, "Taira NEVO review")?,
            &format!("Taira NEVO review {field}"),
        )?;
    }
    if string_field_v1(root, "base_genesis_sha256", "Taira NEVO review")?
        != hex::encode(sha256(CANONICAL_GENESIS_TEMPLATE_V1))
        || string_field_v1(root, "base_config_sha256", "Taira NEVO review")?
            != hex::encode(sha256(CANONICAL_CONFIG_TEMPLATE_V1))
        || string_field_v1(root, "unsigned_genesis_sha256", "Taira NEVO review")?
            != hex::encode(sha256(genesis))
    {
        bail!("Taira NEVO review digest chain differs from source templates or genesis");
    }

    let identities = object_field_v1(root, "public_identities", "Taira NEVO review")?;
    expect_exact_keys_v1(
        identities,
        &[
            "onboarding_authority_account_id",
            "api_signer_account_id",
            "dpn_inori_account_id",
            "dpn_epr_guard_account_id",
        ],
        "Taira NEVO public identities",
    )?;
    let onboarding = string_field_v1(
        identities,
        "onboarding_authority_account_id",
        "Taira NEVO public identities",
    )?;
    let api_signer = string_field_v1(
        identities,
        "api_signer_account_id",
        "Taira NEVO public identities",
    )?;
    let dpn_inori = string_field_v1(
        identities,
        "dpn_inori_account_id",
        "Taira NEVO public identities",
    )?;
    let dpn_epr_guard = string_field_v1(
        identities,
        "dpn_epr_guard_account_id",
        "Taira NEVO public identities",
    )?;
    let public_identities = [onboarding, api_signer, dpn_inori, dpn_epr_guard];
    if public_identities.iter().any(|identity| identity.is_empty())
        || public_identities.into_iter().collect::<BTreeSet<_>>().len() != 4
    {
        bail!("Taira NEVO review must bind four distinct public account identities");
    }

    let bindings = root
        .get("credential_hash_bindings")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("Taira NEVO credential bindings must be an array"))?;
    if bindings.len() != 2 {
        bail!("Taira NEVO review must bind exactly two onboarding credentials");
    }
    let mut token_hashes = Vec::with_capacity(2);
    let mut distinct_token_hashes = BTreeSet::new();
    for (binding, dataspace) in bindings.iter().zip(["is2", "dpn"]) {
        let binding = object_v1(binding, "Taira NEVO credential binding")?;
        expect_exact_keys_v1(
            binding,
            &["scope", "token_hash"],
            "Taira NEVO credential binding",
        )?;
        let scope = object_field_v1(binding, "scope", "Taira NEVO credential binding")?;
        expect_exact_keys_v1(scope, &["dataspace"], "Taira NEVO credential scope")?;
        expect_string_v1(scope, "dataspace", dataspace, "Taira NEVO credential scope")?;
        let token_hash = string_field_v1(binding, "token_hash", "Taira NEVO credential binding")?;
        let Some(digest) = token_hash.strip_prefix("blake3:") else {
            bail!("Taira NEVO credential hash must use the blake3 prefix");
        };
        fixed_nonzero_sha256_v1(digest, "Taira NEVO credential hash")?;
        token_hashes.push(token_hash.to_owned());
        distinct_token_hashes.insert(token_hash);
    }
    if distinct_token_hashes.len() != 2 {
        bail!("Taira NEVO credential hashes must be distinct");
    }
    let expected_public_inputs_sha256 = nevo_public_inputs_sha256_v1(
        onboarding,
        api_signer,
        dpn_inori,
        dpn_epr_guard,
        &token_hashes[0],
        &token_hashes[1],
    )?;
    expect_string_v1(
        root,
        "public_inputs_sha256",
        &expected_public_inputs_sha256,
        "Taira NEVO review",
    )?;

    let overlay = object_field_v1(root, "genesis_overlay", "Taira NEVO review")?;
    let expected_program_id = format!("{GENESIS_AUTHORITY_V1}/{NEVO_FEE_SPONSOR_PROGRAM_NAME_V1}");
    let expected_overlay = norito::json!({
        "transaction_count": (1_u64),
        "instruction_count": (29_u64),
        "dataspace_roots": [
            {"alias": "dpn", "id": (10_u64)},
            {"alias": "is2", "id": (8_477_022_798_449_861_195_u64)},
        ],
        "domain": "nevo.dpn",
        "fee_asset_definition_id": NEVO_FEE_ASSET_DEFINITION_ID_V1,
        "account_funding_amount": "1000000",
        "fee_sponsor_program_id": (expected_program_id),
        "fee_sponsor_beneficiaries": [
            (onboarding), (api_signer), (dpn_inori), (dpn_epr_guard),
        ],
        "account_aliases": [
            {"alias": "admin@universal", "target_account_id": (api_signer), "role": "primary"},
            {"alias": "inori@universal", "target_account_id": (dpn_inori), "role": "primary"},
            {"alias": "source_guard@universal", "target_account_id": (dpn_epr_guard), "role": "primary"},
        ],
        "genesis_alias_bootstrap": {
            "authority_account_id": GENESIS_ALIAS_BOOTSTRAP_AUTHORITY_V1,
            "authority_source": "base_config.genesis.public_key",
            "role_id": GENESIS_ALIAS_BOOTSTRAP_ROLE_ID_V1,
            "permissions": [
                {
                    "name": "CanManageAccountAlias",
                    "payload": {"scope": {"scope": "alias", "value": {
                        "canonical_name": {
                            "label": "admin", "domain": null, "dataspace": "universal",
                        },
                        "dataspace_id": 0_u64,
                    }}},
                },
                {
                    "name": "CanManageAccountAlias",
                    "payload": {"scope": {"scope": "alias", "value": {
                        "canonical_name": {
                            "label": "inori", "domain": null, "dataspace": "universal",
                        },
                        "dataspace_id": 0_u64,
                    }}},
                },
                {
                    "name": "CanManageAccountAlias",
                    "payload": {"scope": {"scope": "alias", "value": {
                        "canonical_name": {
                            "label": "source_guard", "domain": null, "dataspace": "universal",
                        },
                        "dataspace_id": 0_u64,
                    }}},
                },
                {
                    "name": "CanManageAccountAlias",
                    "payload": {"scope": {"scope": "dataspace", "value": 10_u64}},
                },
                {
                    "name": "CanManageAccountAlias",
                    "payload": {"scope": {
                        "scope": "dataspace",
                        "value": 8_477_022_798_449_861_195_u64,
                    }},
                },
                {
                    "name": "CanManageAccountAlias",
                    "payload": {"scope": {"scope": "domain", "value": "nevo.dpn"}},
                },
            ],
            "registered_before_alias_intents": true,
            "unregistered_after_alias_intents": true,
        },
        "contract_code_management_permission_grant": {
            "account_id": (api_signer),
            "permission": "CanManageSmartContractCode",
            "payload": null,
        },
        "dpn_permission_grants": [
            {"account_id": (api_signer), "permissions": ["DpnAdmin", "DpnUser"]},
            {"account_id": (dpn_inori), "permissions": ["DpnInori", "DpnSettlement", "DpnUser"]},
            {"account_id": (dpn_epr_guard), "permissions": ["DpnEprGuard"]},
        ],
        "dpn_settlement_holder_account_id": (dpn_inori),
        "ensure_alias_derived_owner_permissions": [
            "CanManageAccountAlias",
            "CanDelegateAccountAliasResolution",
            "CanResolveAccountAlias",
        ],
    });
    if expected_overlay.as_object() != Some(overlay) {
        bail!("Taira NEVO genesis overlay inventory is not exact");
    }

    let boundary = object_field_v1(root, "secret_boundary", "Taira NEVO review")?;
    expect_exact_keys_v1(
        boundary,
        &[
            "raw_tokens_accepted",
            "private_keys_accepted",
            "genesis_signed",
        ],
        "Taira NEVO secret boundary",
    )?;
    if boundary
        .values()
        .any(|value| value.as_bool() != Some(false))
    {
        bail!("Taira NEVO review must remain unsigned and secret-free");
    }
    if string_array_field_v1(root, "required_next_steps", "Taira NEVO review")?
        != [
            "review the exact unsigned genesis and this digest record",
            "bind validator runtime credentials to these exact token hashes",
            "validate the unsigned manifest with the source-matched Kagami binary",
            "sign only through the independently provisioned digest-pinned external signer",
            "deploy and pin the reviewed NEVO contract after the reset finalizes",
            "initialize the application factoring policy after API deployment",
        ]
    {
        bail!("Taira NEVO required-next-step inventory is not exact");
    }
    let actual_genesis: JsonValue =
        norito::json::from_slice(genesis).wrap_err("Taira NEVO genesis is not strict JSON")?;
    if expected_nevo_genesis_v1(onboarding, api_signer, dpn_inori, dpn_epr_guard)? != actual_genesis
    {
        bail!(
            "Taira NEVO genesis differs from native exact overlay recomposition over the source template"
        );
    }
    Ok(())
}

fn nevo_public_inputs_sha256_v1(
    onboarding: &str,
    api_signer: &str,
    dpn_inori: &str,
    dpn_epr_guard: &str,
    is2_token_hash: &str,
    dpn_token_hash: &str,
) -> color_eyre::Result<String> {
    // Python's source composer hashes sort-key, compact UTF-8 JSON plus one LF.
    // Keep the insertion order lexical so this native derivation is byte-identical.
    let inputs = norito::json!({
        "api_signer_account_id": (api_signer),
        "dpn_onboarding_token_hash": (dpn_token_hash),
        "dpn_epr_guard_account_id": (dpn_epr_guard),
        "dpn_inori_account_id": (dpn_inori),
        "is2_onboarding_token_hash": (is2_token_hash),
        "onboarding_authority_account_id": (onboarding),
        "schema": NEVO_PUBLIC_INPUT_SCHEMA_V1,
    });
    let mut canonical = norito::json::to_json(&inputs)
        .wrap_err("failed to render native Taira NEVO public inputs")?;
    canonical.push('\n');
    Ok(hex::encode(sha256(canonical.as_bytes())))
}

fn replace_nevo_golden_identity_v2(value: &mut JsonValue, source: &str, target: &str) -> usize {
    match value {
        JsonValue::String(text) => {
            let count = text.matches(source).count();
            if count != 0 {
                *text = text.replace(source, target);
            }
            count
        }
        JsonValue::Array(values) => values
            .iter_mut()
            .map(|value| replace_nevo_golden_identity_v2(value, source, target))
            .sum(),
        JsonValue::Object(fields) => fields
            .values_mut()
            .map(|value| replace_nevo_golden_identity_v2(value, source, target))
            .sum(),
        _ => 0,
    }
}

fn expected_nevo_genesis_v1(
    onboarding: &str,
    api_signer: &str,
    dpn_inori: &str,
    dpn_epr_guard: &str,
) -> color_eyre::Result<JsonValue> {
    let mut expected: JsonValue = norito::json::from_slice(CANONICAL_GENESIS_TEMPLATE_V1)
        .wrap_err("failed to decode the canonical Taira genesis template")?;
    let mut overlay: JsonValue = norito::json::from_slice(CANONICAL_NEVO_OVERLAY_V1)
        .wrap_err("failed to decode the canonical NEVO overlay transaction")?;
    let fields = object_v1(&overlay, "canonical NEVO overlay")?;
    expect_exact_keys_v1(
        fields,
        &["instructions", "ivm_triggers", "topology"],
        "canonical NEVO overlay",
    )?;
    if fields
        .get("instructions")
        .and_then(JsonValue::as_array)
        .map(Vec::len)
        != Some(29)
        || fields
            .get("ivm_triggers")
            .and_then(JsonValue::as_array)
            .map(Vec::len)
            != Some(0)
        || fields
            .get("topology")
            .and_then(JsonValue::as_array)
            .map(Vec::len)
            != Some(0)
    {
        bail!(
            "canonical NEVO overlay must contain exactly 29 instructions and no triggers or topology"
        );
    }
    let expected_transactions = expected
        .as_object_mut()
        .and_then(|root| root.get_mut("transactions"))
        .and_then(JsonValue::as_array_mut)
        .ok_or_else(|| eyre!("canonical Taira genesis template omitted transactions"))?;
    for (source, target, label) in [
        (GOLDEN_NEVO_ONBOARDING_V2, onboarding, "onboarding"),
        (GOLDEN_NEVO_API_SIGNER_V2, api_signer, "API signer"),
        (GOLDEN_NEVO_INORI_V2, dpn_inori, "Inori"),
        (GOLDEN_NEVO_EPR_GUARD_V2, dpn_epr_guard, "EPR guard"),
    ] {
        if replace_nevo_golden_identity_v2(&mut overlay, source, target) == 0 {
            bail!("canonical NEVO overlay omitted the {label} identity");
        }
    }
    expected_transactions.push(overlay);
    Ok(expected)
}

fn parse_broker_public_export_v1(bytes: &[u8]) -> color_eyre::Result<BrokerPublicMaterialV1> {
    let export: JsonValue = norito::json::from_slice(bytes)
        .wrap_err("Taira Bootle/Lantern broker public export is not strict JSON")?;
    let canonical = format!("{}\n", norito::json::to_json(&export)?);
    if canonical.as_bytes() != bytes {
        bail!("Taira Bootle/Lantern broker public export is not in canonical emitted form");
    }
    let fields = object_v1(&export, "broker public export")?;
    expect_exact_keys_v1(
        fields,
        &[
            "authorization_lifetime_blocks",
            "broker_contract_digest_hex",
            "chain_id",
            "issuer_id_hex",
            "issuer_parameter_digest_hex",
            "issuer_parameter_id_hex",
            "issuer_profile_digest_hex",
            "network_id",
            "policy_id_hex",
            "policy_record_digest_hex",
            "registration_instruction",
            "registration_instruction_norito_hex",
            "registration_instruction_norito_sha256",
            "runtime_provider_handle",
            "runtime_provider_policy_digest_hex",
            "runtime_provider_revision",
            "schema",
            "stable_principal_digest_hex",
        ],
        "broker public export",
    )?;
    expect_string_v1(
        fields,
        "schema",
        BROKER_EXPORT_SCHEMA_V1,
        "broker public export",
    )?;
    expect_string_v1(fields, "chain_id", CHAIN_ID_V1, "broker public export")?;
    let network_id_text = string_field_v1(fields, "network_id", "broker public export")?;
    let network_id = network_id_text
        .parse::<NetworkId>()
        .wrap_err("broker public export network_id is not canonical")?;
    if network_id.as_bytes().iter().all(|byte| *byte == 0) {
        bail!("broker public export network_id must be non-zero");
    }
    if network_id.to_string() != network_id_text {
        bail!("broker public export network_id is not in canonical emitted form");
    }
    expect_string_v1(
        fields,
        "runtime_provider_handle",
        PROVIDER_HANDLE_V1,
        "broker public export",
    )?;
    expect_u64_v1(
        fields,
        "runtime_provider_revision",
        PROVIDER_REVISION_V1,
        "broker public export",
    )?;
    expect_u64_v1(
        fields,
        "authorization_lifetime_blocks",
        AUTHORIZATION_LIFETIME_BLOCKS_V1,
        "broker public export",
    )?;
    let expected_issuer_id = hex::encode(sha256(ISSUER_ID_DOMAIN_V1));
    let expected_policy_id = hex::encode(sha256(POLICY_ID_DOMAIN_V1));
    expect_string_v1(
        fields,
        "issuer_id_hex",
        &expected_issuer_id,
        "broker public export",
    )?;
    expect_string_v1(
        fields,
        "policy_id_hex",
        &expected_policy_id,
        "broker public export",
    )?;
    for field in [
        "runtime_provider_policy_digest_hex",
        "issuer_parameter_id_hex",
        "issuer_parameter_digest_hex",
        "policy_record_digest_hex",
        "stable_principal_digest_hex",
        "issuer_profile_digest_hex",
        "broker_contract_digest_hex",
        "registration_instruction_norito_sha256",
    ] {
        fixed_nonzero_sha256_v1(
            string_field_v1(fields, field, "broker public export")?,
            field,
        )?;
    }
    let instruction_hex = string_field_v1(
        fields,
        "registration_instruction_norito_hex",
        "broker public export",
    )?;
    if instruction_hex.is_empty()
        || instruction_hex.len() % 2 != 0
        || !instruction_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("broker registration instruction must be non-empty canonical lowercase hex");
    }
    let instruction_bytes = hex::decode(instruction_hex)
        .wrap_err("failed to decode broker registration instruction hex")?;
    let claimed_instruction_sha256 = string_field_v1(
        fields,
        "registration_instruction_norito_sha256",
        "broker public export",
    )?;
    if hex::encode(sha256(&instruction_bytes)) != claimed_instruction_sha256 {
        bail!("broker registration instruction SHA-256 does not match its boxed Norito bytes");
    }
    let instruction = norito::decode_from_bytes::<InstructionBox>(&instruction_bytes)
        .wrap_err("broker registration instruction is not a canonical instruction box")?;
    if norito::to_bytes(&instruction)
        .wrap_err("failed to re-encode broker registration instruction box")?
        != instruction_bytes
    {
        bail!("broker registration instruction box is not canonical Norito");
    }
    let registration = instruction
        .as_any()
        .downcast_ref::<RegisterPrivacyBootleLanternIssuerPolicyV1>()
        .ok_or_else(|| eyre!("broker export does not contain the issuer-policy registration"))?;
    registration
        .policy
        .validate()
        .map_err(|source| eyre!("broker issuer policy is invalid: {source}"))?;
    if registration.policy.epoch != 1
        || registration.policy.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active
        || registration.policy.required_disclosure_bitmap != 0
    {
        bail!(
            "broker issuer policy differs from the exact first-release lifecycle and disclosure policy"
        );
    }
    if hex::encode(registration.policy.issuer_id.as_bytes()) != expected_issuer_id
        || hex::encode(registration.policy.policy_id.as_bytes()) != expected_policy_id
    {
        bail!("broker issuer-policy identity differs from the exact Taira identity");
    }
    let issuer_parameter_id_hex = hex::encode(registration.policy.issuer_parameter_id.as_bytes());
    let issuer_parameter_digest_hex =
        hex::encode(registration.policy.issuer_parameter_digest.as_bytes());
    let policy_record_digest_hex = hex::encode(registration.policy.record_digest.as_bytes());
    for (field, expected) in [
        ("issuer_parameter_id_hex", issuer_parameter_id_hex.as_str()),
        (
            "issuer_parameter_digest_hex",
            issuer_parameter_digest_hex.as_str(),
        ),
        (
            "policy_record_digest_hex",
            policy_record_digest_hex.as_str(),
        ),
    ] {
        expect_string_v1(fields, field, expected, "broker public export")?;
    }
    expect_string_v1(
        fields,
        "issuer_profile_digest_hex",
        &hex::encode(taira_bootle_lantern_issuer_profile_contract_digest_v1()),
        "broker public export",
    )?;
    expect_string_v1(
        fields,
        "broker_contract_digest_hex",
        &hex::encode(taira_bootle_lantern_broker_contract_digest_v1()),
        "broker public export",
    )?;
    let stable_principal_digest = decode_sha256_v1(
        string_field_v1(
            fields,
            "stable_principal_digest_hex",
            "broker public export",
        )?,
        "stable_principal_digest_hex",
    )?;
    let qualification = derive_taira_bootle_lantern_broker_qualification_digest_v1(
        &TairaBootleLanternBrokerQualificationInputsV1 {
            network_id,
            runtime_provider_handle: PROVIDER_HANDLE_V1,
            runtime_provider_revision: PROVIDER_REVISION_V1,
            issuer_id: registration.policy.issuer_id,
            policy_id: registration.policy.policy_id,
            authorization_lifetime_blocks: AUTHORIZATION_LIFETIME_BLOCKS_V1,
            policy: &registration.policy,
            stable_principal_digest,
        },
    )
    .map_err(|source| eyre!("broker provider qualification is invalid: {source}"))?;
    expect_string_v1(
        fields,
        "runtime_provider_policy_digest_hex",
        &hex::encode(qualification),
        "broker public export",
    )?;
    let expected_registration_json = norito::json::to_value(registration)
        .wrap_err("failed to project decoded broker registration to JSON")?;
    if fields.get("registration_instruction") != Some(&expected_registration_json) {
        bail!("broker structured registration differs from its boxed Norito instruction");
    }
    Ok(BrokerPublicMaterialV1 {
        network_id: network_id_text.to_owned(),
        public_export_sha256: hex::encode(sha256(bytes)),
        qualification_policy_digest_hex: string_field_v1(
            fields,
            "runtime_provider_policy_digest_hex",
            "broker public export",
        )?
        .to_owned(),
        issuer_parameter_id_hex,
        issuer_parameter_digest_hex,
        policy_record_digest_hex,
        instruction_norito_sha256: claimed_instruction_sha256.to_owned(),
    })
}
fn render_release_plan_v1(
    bytes: &[u8],
    broker: &BrokerPublicMaterialV1,
) -> color_eyre::Result<Vec<u8>> {
    let mut plan: JsonValue = norito::json::from_slice(bytes)
        .wrap_err("Taira privacy plan template is not strict JSON")?;
    validate_staging_plan_v1(&plan)?;
    expect_canonical_template_bytes_v1(bytes, CANONICAL_PLAN_TEMPLATE_V1, "Taira privacy plan")?;
    let root = object_mut_v1(&mut plan, "privacy plan")?;
    root.insert(
        "network_id".to_owned(),
        JsonValue::String(broker.network_id.clone()),
    );
    let bootle = object_field_mut_v1(root, "bootle_lantern_issuer", "privacy plan")?;
    bootle.insert(
        "public_export_sha256".to_owned(),
        JsonValue::String(broker.public_export_sha256.clone()),
    );
    let provider = object_field_mut_v1(bootle, "runtime_provider", "Bootle/Lantern plan")?;
    provider.insert(
        "qualification_policy_digest_hex".to_owned(),
        JsonValue::String(broker.qualification_policy_digest_hex.clone()),
    );
    let policy = object_field_mut_v1(bootle, "governed_issuer_policy", "Bootle/Lantern plan")?;
    for (field, value) in [
        (
            "instruction_norito_sha256",
            broker.instruction_norito_sha256.as_str(),
        ),
        (
            "issuer_parameter_id_hex",
            broker.issuer_parameter_id_hex.as_str(),
        ),
        (
            "issuer_parameter_digest_hex",
            broker.issuer_parameter_digest_hex.as_str(),
        ),
        (
            "record_digest_hex",
            broker.policy_record_digest_hex.as_str(),
        ),
    ] {
        policy.insert(field.to_owned(), JsonValue::String(value.to_owned()));
    }
    json_pretty_bytes_v1(&plan, "Taira privacy release plan")
}
fn validate_staging_plan_v1(plan: &JsonValue) -> color_eyre::Result<()> {
    let root = object_v1(plan, "privacy plan")?;
    expect_exact_keys_v1(
        root,
        &[
            "bootle_lantern_issuer",
            "chain_discriminant",
            "chain_id",
            "genesis_authority",
            "governance_rollout",
            "governance_permission",
            "network_id",
            "privacy_catalog",
            "schema",
            "schema_version",
        ],
        "privacy plan",
    )?;
    expect_string_v1(
        root,
        "schema",
        "iroha.taira.privacy_bootstrap_plan.v1",
        "privacy plan",
    )?;
    expect_u64_v1(root, "schema_version", 1, "privacy plan")?;
    expect_string_v1(root, "chain_id", CHAIN_ID_V1, "privacy plan")?;
    if !root.get("network_id").is_some_and(JsonValue::is_null) {
        bail!("Taira privacy plan staging network_id must be null");
    }
    expect_u64_v1(
        root,
        "chain_discriminant",
        CHAIN_DISCRIMINANT_V1,
        "privacy plan",
    )?;
    expect_string_v1(
        root,
        "genesis_authority",
        GENESIS_AUTHORITY_V1,
        "privacy plan",
    )?;
    expect_string_v1(
        root,
        "governance_permission",
        "CanEnactGovernance",
        "privacy plan",
    )?;
    let rollout = object_field_v1(root, "governance_rollout", "privacy plan")?;
    expect_exact_keys_v1(
        rollout,
        &[
            "activation_state",
            "controller_observation_required",
            "execution_height",
            "instruction_count",
            "mode",
            "rollout_plan_path",
            "rollout_plan_sha256",
        ],
        "governance rollout",
    )?;
    expect_string_v1(
        rollout,
        "activation_state",
        "not-executed",
        "governance rollout",
    )?;
    expect_string_v1(
        rollout,
        "mode",
        "explicit-register-then-activate",
        "governance rollout",
    )?;
    expect_u64_v1(
        rollout,
        "execution_height",
        super::BOOTSTRAP_EXECUTION_HEIGHT_V1,
        "governance rollout",
    )?;
    expect_u64_v1(
        rollout,
        "instruction_count",
        super::BOOTSTRAP_INSTRUCTION_COUNT_V1 as u64,
        "governance rollout",
    )?;
    expect_string_v1(
        rollout,
        "rollout_plan_path",
        ROLLOUT_PLAN_PATH_V1,
        "governance rollout",
    )?;
    expect_string_v1(
        rollout,
        "rollout_plan_sha256",
        ROLLOUT_PLAN_SHA256_V1,
        "governance rollout",
    )?;
    let actual_rollout_plan_sha256 = hex::encode(sha256(CANONICAL_ROLLOUT_PLAN_V1));
    if actual_rollout_plan_sha256 != ROLLOUT_PLAN_SHA256_V1 {
        bail!(
            "canonical Taira privacy rollout plan SHA-256 differs from its compiled pin: expected {ROLLOUT_PLAN_SHA256_V1}, got {actual_rollout_plan_sha256}"
        );
    }
    validate_rollout_plan_v1(CANONICAL_ROLLOUT_PLAN_V1)?;
    if rollout
        .get("controller_observation_required")
        .and_then(JsonValue::as_bool)
        != Some(true)
    {
        bail!(
            "privacy plan template must require authenticated controller observation after explicit activation"
        );
    }
    validate_catalog_inventory_v1(object_field_v1(root, "privacy_catalog", "privacy plan")?)?;
    let bootle = object_field_v1(root, "bootle_lantern_issuer", "privacy plan")?;
    expect_exact_keys_v1(
        bootle,
        &[
            "authorization_lifetime_blocks",
            "designated_validator",
            "edge_routing",
            "governed_issuer_policy",
            "issuer_id_hex",
            "max_inflight",
            "policy_id_hex",
            "protocol_label",
            "provider_operations",
            "public_export_sha256",
            "runtime_provider",
            "secret_material_permitted",
            "state_authority",
        ],
        "Bootle/Lantern plan",
    )?;
    expect_string_v1(
        bootle,
        "protocol_label",
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1.canonical_label(),
        "Bootle/Lantern plan",
    )?;
    if !bootle
        .get("public_export_sha256")
        .is_some_and(JsonValue::is_null)
    {
        bail!("Bootle/Lantern broker public-export staging digest must be null");
    }
    expect_string_v1(
        bootle,
        "designated_validator",
        "taira-validator-1",
        "Bootle/Lantern plan",
    )?;
    expect_string_v1(
        bootle,
        "edge_routing",
        "designated-validator-only",
        "Bootle/Lantern plan",
    )?;
    expect_string_v1(
        bootle,
        "issuer_id_hex",
        &hex::encode(sha256(ISSUER_ID_DOMAIN_V1)),
        "Bootle/Lantern plan",
    )?;
    expect_string_v1(
        bootle,
        "policy_id_hex",
        &hex::encode(sha256(POLICY_ID_DOMAIN_V1)),
        "Bootle/Lantern plan",
    )?;
    expect_u64_v1(
        bootle,
        "authorization_lifetime_blocks",
        AUTHORIZATION_LIFETIME_BLOCKS_V1,
        "Bootle/Lantern plan",
    )?;
    expect_u64_v1(
        bootle,
        "max_inflight",
        MAX_INFLIGHT_V1,
        "Bootle/Lantern plan",
    )?;
    expect_string_v1(
        bootle,
        "state_authority",
        "torii-local-one-shot-store",
        "Bootle/Lantern plan",
    )?;
    if bootle
        .get("secret_material_permitted")
        .and_then(JsonValue::as_bool)
        != Some(false)
    {
        bail!("Bootle/Lantern release plan must forbid secret material");
    }
    let operations = string_array_field_v1(bootle, "provider_operations", "Bootle/Lantern plan")?;
    if operations
        != [
            "bearer-principal-authentication-v1".to_owned(),
            "falcon512-native-crypto-v1".to_owned(),
        ]
    {
        bail!("Bootle/Lantern provider operation inventory differs from first release");
    }
    let provider = object_field_v1(bootle, "runtime_provider", "Bootle/Lantern plan")?;
    expect_exact_keys_v1(
        provider,
        &[
            "handle",
            "qualification_policy_digest_hex",
            "revision",
            "slot_wire_id",
            "transport",
        ],
        "Bootle/Lantern provider plan",
    )?;
    expect_string_v1(
        provider,
        "transport",
        "stock-local-runtime-provider-broker-v1",
        "Bootle/Lantern provider plan",
    )?;
    expect_u64_v1(provider, "slot_wire_id", 55, "Bootle/Lantern provider plan")?;
    expect_string_v1(
        provider,
        "handle",
        PROVIDER_HANDLE_V1,
        "Bootle/Lantern provider plan",
    )?;
    expect_u64_v1(
        provider,
        "revision",
        PROVIDER_REVISION_V1,
        "Bootle/Lantern provider plan",
    )?;
    if !provider
        .get("qualification_policy_digest_hex")
        .is_some_and(JsonValue::is_null)
    {
        bail!("Bootle/Lantern provider staging digest must be null");
    }
    let policy = object_field_v1(bootle, "governed_issuer_policy", "Bootle/Lantern plan")?;
    expect_exact_keys_v1(
        policy,
        &[
            "instruction_norito_sha256",
            "issuer_parameter_digest_hex",
            "issuer_parameter_id_hex",
            "record_digest_hex",
        ],
        "Bootle/Lantern issuer policy plan",
    )?;
    if policy.values().any(|value| !value.is_null()) {
        bail!("Bootle/Lantern issuer-policy staging fields must all be null");
    }
    Ok(())
}

fn validate_rollout_plan_v1(bytes: &[u8]) -> color_eyre::Result<()> {
    let value: JsonValue = norito::json::from_slice(bytes)
        .wrap_err("failed to decode the canonical Taira privacy rollout plan")?;
    let root = object_v1(&value, "privacy rollout plan")?;
    expect_exact_keys_v1(
        root,
        &[
            "activation_contract",
            "canary_contract",
            "capability_gate",
            "cargo_lock_sha256",
            "chain_id",
            "endpoints",
            "halt_conditions",
            "post_cutover_contract",
            "protocol_matrix_sha256",
            "protocols",
            "publication_contract",
            "resource_ceilings",
            "restart_contract",
            "rollback_contract",
            "schema",
            "schema_version",
            "wire_contract",
        ],
        "privacy rollout plan",
    )?;
    expect_string_v1(
        root,
        "schema",
        "iroha.taira.privacy_rollout_plan.v1",
        "privacy rollout plan",
    )?;
    expect_u64_v1(root, "schema_version", 1, "privacy rollout plan")?;
    expect_string_v1(root, "chain_id", CHAIN_ID_V1, "privacy rollout plan")?;
    expect_string_v1(
        root,
        "cargo_lock_sha256",
        &hex::encode(sha256(CANONICAL_CARGO_LOCK_V1)),
        "privacy rollout plan",
    )?;
    let matrix = privacy_exact12_matrix_bytes_v1()
        .map_err(|source| eyre!("failed to derive the native exact-12 matrix: {source}"))?;
    expect_string_v1(
        root,
        "protocol_matrix_sha256",
        &hex::encode(sha256(&matrix)),
        "privacy rollout plan",
    )?;

    let wire = object_field_v1(root, "wire_contract", "privacy rollout plan")?;
    expect_exact_keys_v1(
        wire,
        &[
            "catalog_commitment_le_hex",
            "catalog_size",
            "proof_envelope_magic_hex",
        ],
        "privacy rollout wire contract",
    )?;
    expect_u64_v1(
        wire,
        "catalog_size",
        PrivacyProtocolIdV1::COUNT as u64,
        "privacy rollout wire contract",
    )?;
    expect_string_v1(
        wire,
        "catalog_commitment_le_hex",
        "e037f13904a0307c00db15d85cfb406bd79772d20144a949def0f3fda78e342e747f65787cbfbffac94f11c369e2bbff",
        "privacy rollout wire contract",
    )?;
    expect_string_v1(
        wire,
        "proof_envelope_magic_hex",
        "4952485a4b31a55a",
        "privacy rollout wire contract",
    )?;

    let gate = object_field_v1(root, "capability_gate", "privacy rollout plan")?;
    expect_exact_keys_v1(
        gate,
        &[
            "all_exact12_rows_required",
            "authenticated_committed_state_required",
            "authoritative_route",
            "caller_asserted_readiness_forbidden",
            "required_readiness",
        ],
        "privacy rollout capability gate",
    )?;
    expect_string_v1(
        gate,
        "authoritative_route",
        "/v1/privacy/capabilities",
        "privacy rollout capability gate",
    )?;
    expect_string_v1(
        gate,
        "required_readiness",
        "production-qualified",
        "privacy rollout capability gate",
    )?;
    for flag in [
        "all_exact12_rows_required",
        "authenticated_committed_state_required",
        "caller_asserted_readiness_forbidden",
    ] {
        if gate.get(flag).and_then(JsonValue::as_bool) != Some(true) {
            bail!("privacy rollout capability gate `{flag}` must be true");
        }
    }

    let protocols = root
        .get("protocols")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("privacy rollout plan `protocols` must be an array"))?;
    if protocols.len() != PrivacyProtocolIdV1::COUNT {
        bail!("privacy rollout plan must contain exactly twelve protocol rows");
    }
    for (index, (value, protocol)) in protocols.iter().zip(PrivacyProtocolIdV1::ALL).enumerate() {
        let row = object_v1(value, "privacy rollout protocol row")?;
        expect_exact_keys_v1(
            row,
            &["index", "label", "security_model"],
            "privacy rollout protocol row",
        )?;
        expect_u64_v1(row, "index", index as u64, "privacy rollout protocol row")?;
        expect_string_v1(
            row,
            "label",
            protocol.canonical_label(),
            "privacy rollout protocol row",
        )?;
        expect_string_v1(
            row,
            "security_model",
            protocol.security_model().canonical_label(),
            "privacy rollout protocol row",
        )?;
    }

    let activation = object_field_v1(root, "activation_contract", "privacy rollout plan")?;
    expect_exact_keys_v1(
        activation,
        &[
            "mode",
            "execution_height",
            "proposed_lifecycle",
            "active_lifecycle",
            "ordered_instruction_count",
            "protocol_count",
            "one_governed_instruction_batch",
        ],
        "privacy activation contract",
    )?;
    expect_string_v1(
        activation,
        "mode",
        "explicit-register-then-activate",
        "privacy activation contract",
    )?;
    expect_string_v1(
        activation,
        "proposed_lifecycle",
        "Proposed",
        "privacy activation contract",
    )?;
    expect_string_v1(
        activation,
        "active_lifecycle",
        "Active",
        "privacy activation contract",
    )?;
    expect_u64_v1(
        activation,
        "execution_height",
        super::BOOTSTRAP_EXECUTION_HEIGHT_V1,
        "privacy activation contract",
    )?;
    expect_u64_v1(
        activation,
        "ordered_instruction_count",
        super::BOOTSTRAP_INSTRUCTION_COUNT_V1 as u64,
        "privacy activation contract",
    )?;
    expect_u64_v1(
        activation,
        "protocol_count",
        PrivacyProtocolIdV1::COUNT as u64,
        "privacy activation contract",
    )?;
    if activation
        .get("one_governed_instruction_batch")
        .and_then(JsonValue::as_bool)
        != Some(true)
    {
        bail!("privacy activation must preserve the complete ordered instruction batch");
    }
    Ok(())
}
fn validate_catalog_inventory_v1(catalog: &JsonMap) -> color_eyre::Result<()> {
    expect_exact_keys_v1(
        catalog,
        &[
            "matrix_file_sha256",
            "matrix_version",
            "protocols",
            "registry_sha256",
        ],
        "privacy catalog",
    )?;
    expect_u64_v1(catalog, "matrix_version", 1, "privacy catalog")?;
    let exact_matrix = privacy_exact12_matrix_bytes_v1()
        .map_err(|source| eyre!("failed to derive the native exact-12 matrix: {source}"))?;
    expect_string_v1(
        catalog,
        "matrix_file_sha256",
        &hex::encode(sha256(&exact_matrix)),
        "privacy catalog",
    )?;
    let mut registry_preimage = Vec::new();
    for protocol in PrivacyProtocolIdV1::ALL {
        registry_preimage.extend_from_slice(protocol.canonical_label().as_bytes());
        registry_preimage.push(b'\n');
    }
    expect_string_v1(
        catalog,
        "registry_sha256",
        &hex::encode(sha256(&registry_preimage)),
        "privacy catalog",
    )?;
    let protocols = catalog
        .get("protocols")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("privacy catalog protocols must be an array"))?;
    if protocols.len() != PrivacyProtocolIdV1::COUNT {
        bail!("privacy catalog must contain exactly twelve protocols");
    }
    for (index, (value, protocol)) in protocols.iter().zip(PrivacyProtocolIdV1::ALL).enumerate() {
        let row = object_v1(value, "privacy catalog row")?;
        expect_exact_keys_v1(
            row,
            &["index", "label", "statement_type"],
            "privacy catalog row",
        )?;
        expect_u64_v1(row, "index", index as u64, "privacy catalog row")?;
        expect_string_v1(
            row,
            "label",
            protocol.canonical_label(),
            "privacy catalog row",
        )?;
        expect_string_v1(
            row,
            "statement_type",
            protocol.canonical_typed_variant_label(),
            "privacy catalog row",
        )?;
    }
    Ok(())
}
fn render_release_config_v1(
    bytes: &[u8],
    broker: &BrokerPublicMaterialV1,
) -> color_eyre::Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).wrap_err("Taira config template is not UTF-8")?;
    let mut config = crate::secret_toml::Value::new(toml::Value::Table(
        crate::secret_toml::parse_table(text, "Taira config template")?,
    ));
    validate_secret_free_config_template_v1(&config)?;
    let root = config
        .as_table_mut()
        .ok_or_else(|| eyre!("Taira config root must be a table"))?;
    if root.get("chain").and_then(toml::Value::as_str) != Some(CHAIN_ID_V1)
        || root
            .get("chain_discriminant")
            .and_then(toml::Value::as_integer)
            != Some(i64::try_from(CHAIN_DISCRIMINANT_V1).expect("fixed discriminant fits i64"))
    {
        bail!("Taira config template targets the wrong chain");
    }
    let torii = root
        .get_mut("torii")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| eyre!("Taira config template has no torii table"))?;
    let issuer = torii
        .get_mut("privacy_bootle_lantern_issuer")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| eyre!("Taira config template has no Bootle/Lantern issuer table"))?;
    let actual_keys = issuer.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_keys = [
        "authorization_lifetime_blocks",
        "enabled",
        "max_inflight",
        "max_records",
        "max_total_bytes",
        "state_dir",
        "terminal_retention_blocks",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if actual_keys != expected_keys
        || issuer.get("enabled").and_then(toml::Value::as_bool) != Some(false)
        || issuer.get("state_dir").and_then(toml::Value::as_str)
            != Some("/var/lib/iroha/taira-validator-1/privacy/bootle-lantern/issuer")
        || issuer.get("max_inflight").and_then(toml::Value::as_integer)
            != Some(i64::try_from(MAX_INFLIGHT_V1).expect("fixed inflight bound fits i64"))
        || issuer
            .get("authorization_lifetime_blocks")
            .and_then(toml::Value::as_integer)
            != Some(300)
        || issuer.get("max_records").and_then(toml::Value::as_integer) != Some(4096)
        || issuer
            .get("max_total_bytes")
            .and_then(toml::Value::as_integer)
            != Some(13_557_760)
        || issuer
            .get("terminal_retention_blocks")
            .and_then(toml::Value::as_integer)
            != Some(4096)
    {
        bail!("Taira Bootle/Lantern config template is not the exact disabled peer-1 contract");
    }
    expect_canonical_template_bytes_v1(bytes, CANONICAL_CONFIG_TEMPLATE_V1, "Taira config")?;
    issuer.insert("enabled".to_owned(), toml::Value::Boolean(true));
    issuer.insert(
        "issuer_id_hex".to_owned(),
        toml::Value::String(hex::encode(sha256(ISSUER_ID_DOMAIN_V1))),
    );
    issuer.insert(
        "policy_id_hex".to_owned(),
        toml::Value::String(hex::encode(sha256(POLICY_ID_DOMAIN_V1))),
    );
    issuer.insert(
        "runtime_provider_registry_handle".to_owned(),
        toml::Value::String(PROVIDER_HANDLE_V1.to_owned()),
    );
    issuer.insert(
        "runtime_provider_registry_revision".to_owned(),
        toml::Value::Integer(
            i64::try_from(PROVIDER_REVISION_V1).expect("fixed provider revision fits i64"),
        ),
    );
    issuer.insert(
        "runtime_provider_registry_policy_digest_hex".to_owned(),
        toml::Value::String(broker.qualification_policy_digest_hex.clone()),
    );
    let mut rendered =
        toml::to_string_pretty(&*config).wrap_err("failed to render release config")?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered.into_bytes())
}
fn validate_secret_free_config_template_v1(config: &toml::Value) -> color_eyre::Result<()> {
    let root = config
        .as_table()
        .ok_or_else(|| eyre!("Taira config root must be a table"))?;
    expect_toml_string_v1(
        root,
        "private_key_file",
        "/run/secrets/iroha/taira-validator-private-key",
        "Taira validator private-key handle",
    )?;
    expect_toml_string_v1(
        root,
        "soranet_transport_public_key",
        "REPLACE_WITH_SORANET_TRANSPORT_PUBLIC_KEY",
        "Taira SoraNet transport public key",
    )?;
    expect_toml_string_v1(
        root,
        "soranet_transport_private_key_file",
        "/run/secrets/iroha/taira-soranet-transport-private-key",
        "Taira SoraNet transport private-key handle",
    )?;
    let torii = toml_table_field_v1(root, "torii", "Taira config")?;
    let onboarding = toml_table_field_v1(torii, "account_onboarding", "Taira torii config")?;
    let onboarding_keys = onboarding
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_onboarding_keys = [
        "additional_permissions",
        "authority",
        "credentials",
        "fee_sponsor_program_id",
        "lease_term_years",
        "private_key_file",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if onboarding_keys != expected_onboarding_keys {
        bail!("Taira onboarding config must have the exact first-release field set");
    }
    expect_toml_string_v1(
        onboarding,
        "authority",
        "REPLACE_WITH_TAIRA_ONBOARDING_AUTHORITY",
        "Taira onboarding authority",
    )?;
    expect_toml_string_v1(
        onboarding,
        "private_key_file",
        "REPLACE_WITH_TAIRA_ONBOARDING_PRIVATE_KEY_FILE",
        "Taira onboarding private-key path",
    )?;
    let expected_fee_sponsor_program_id =
        format!("{GENESIS_AUTHORITY_V1}/{NEVO_FEE_SPONSOR_PROGRAM_NAME_V1}");
    if onboarding
        .get("lease_term_years")
        .and_then(toml::Value::as_integer)
        != Some(1)
        || !onboarding
            .get("additional_permissions")
            .and_then(toml::Value::as_array)
            .is_some_and(Vec::is_empty)
        || onboarding
            .get("fee_sponsor_program_id")
            .and_then(toml::Value::as_str)
            != Some(expected_fee_sponsor_program_id.as_str())
    {
        bail!("Taira onboarding policy differs from the exact first-release contract");
    }
    let credentials = onboarding
        .get("credentials")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| eyre!("Taira onboarding credentials must be an array"))?;
    let expected_credentials = [
        (
            "REPLACE_WITH_TAIRA_BOI_ONBOARDING_CREDENTIAL_ID",
            "is2",
            "REPLACE_WITH_TAIRA_BOI_ONBOARDING_TOKEN_HASH",
        ),
        (
            "REPLACE_WITH_TAIRA_DPN_ONBOARDING_CREDENTIAL_ID",
            "dpn",
            "REPLACE_WITH_TAIRA_DPN_ONBOARDING_TOKEN_HASH",
        ),
        (
            "REPLACE_WITH_TAIRA_CANARY_ONBOARDING_CREDENTIAL_ID",
            "universal",
            "REPLACE_WITH_TAIRA_CANARY_ONBOARDING_TOKEN_HASH",
        ),
    ];
    if credentials.len() != expected_credentials.len() {
        bail!(
            "Taira config template must contain the exact BOI, DPN, and public-reset canary onboarding credentials"
        );
    }
    for (index, (credential, (expected_id, expected_dataspace, expected_token_hash))) in
        credentials.iter().zip(expected_credentials).enumerate()
    {
        let label = format!("Taira onboarding credential {index}");
        let credential = credential
            .as_table()
            .ok_or_else(|| eyre!("{label} must be a table"))?;
        let actual_keys = credential
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_keys = ["id", "scope", "token_hash"]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if actual_keys != expected_keys {
            bail!("{label} must have the exact first-release field set: id, scope, token_hash");
        }
        expect_toml_string_v1(credential, "id", expected_id, &label)?;
        expect_toml_string_v1(credential, "token_hash", expected_token_hash, &label)?;
        let scope = toml_table_field_v1(credential, "scope", &label)?;
        if scope.len() != 1
            || scope.get("dataspace").and_then(toml::Value::as_str) != Some(expected_dataspace)
        {
            bail!(
                "{label} scope differs from the exact first-release dataspace `{expected_dataspace}`"
            );
        }
    }
    expect_toml_string_v1(
        toml_table_field_v1(torii, "faucet", "Taira torii config")?,
        "private_key_file",
        "REPLACE_WITH_TAIRA_FAUCET_PRIVATE_KEY_FILE",
        "Taira faucet private-key path",
    )?;
    expect_toml_string_v1(
        toml_table_field_v1(root, "streaming", "Taira config")?,
        "identity_private_key_file",
        "/run/secrets/iroha/taira-streaming-identity-private-key",
        "Taira streaming private-key handle",
    )?;
    Ok(())
}
fn toml_table_field_v1<'a>(
    fields: &'a toml::Table,
    field: &str,
    label: &str,
) -> color_eyre::Result<&'a toml::Table> {
    fields
        .get(field)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| eyre!("{label} `{field}` must be a table"))
}
fn expect_toml_string_v1(
    fields: &toml::Table,
    field: &str,
    expected: &str,
    label: &str,
) -> color_eyre::Result<()> {
    if fields.get(field).and_then(toml::Value::as_str) != Some(expected) {
        bail!("{label} must remain the exact secret-free staging placeholder");
    }
    Ok(())
}
fn render_release_genesis_v1(
    bytes: &[u8],
    nevo_review: Option<&[u8]>,
) -> color_eyre::Result<Vec<u8>> {
    iroha_genesis::init_instruction_registry();
    validate_genesis_manifest_json(bytes)
        .wrap_err("Taira genesis template exceeds fixed resource bounds")?;
    let genesis: JsonValue =
        norito::json::from_slice(bytes).wrap_err("Taira genesis template is not strict JSON")?;
    let root = object_v1(&genesis, "Taira genesis")?;
    expect_string_v1(root, "chain", CHAIN_ID_V1, "Taira genesis")?;
    expect_u64_v1(
        root,
        "chain_discriminant",
        CHAIN_DISCRIMINANT_V1,
        "Taira genesis",
    )?;
    // Account decoding must use the validated document network, independently
    // of the caller's ambient address context. The guard restores that context
    // on success and every error return.
    let _chain_discriminant =
        ChainDiscriminantGuard::enter(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT);
    let transactions = root
        .get("transactions")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("Taira genesis has no transaction array"))?;
    if transactions.is_empty() {
        bail!("Taira genesis has no transactions");
    }
    for transaction in transactions {
        let instruction_values = transaction
            .get("instructions")
            .ok_or_else(|| eyre!("Taira genesis transaction has no instruction array"))?;
        let decoded = iroha_genesis::genesis_instructions_json::from_value(instruction_values)
            .wrap_err("Taira genesis source template contains an invalid instruction")?;
        for instruction in decoded {
            if instruction
                .as_any()
                .downcast_ref::<RegisterPrivacyProtocolActivationV1>()
                .is_some()
                || instruction
                    .as_any()
                    .downcast_ref::<TransitionPrivacyProtocolLifecycleV1>()
                    .is_some()
                || instruction
                    .as_any()
                    .downcast_ref::<RegisterPrivacyBootleLanternIssuerPolicyV1>()
                    .is_some()
            {
                bail!(
                    "Taira genesis staging template already contains a privacy bootstrap instruction"
                );
            }
        }
    }
    let mut authority_registration_count = 0_usize;
    let mut governance_grant_count = 0_usize;
    let mut authority_registration_index = None;
    let mut governance_grant_index = None;
    let mut global_index = 0_usize;
    for transaction in transactions {
        let instructions = transaction
            .get("instructions")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| eyre!("Taira genesis transaction has no instruction array"))?;
        for instruction in instructions {
            if instruction.is_string() {
                bail!("Taira genesis staging template already contains an encoded instruction");
            }
            if registered_account_id_v1(instruction) == Some(GENESIS_AUTHORITY_V1) {
                authority_registration_count += 1;
                authority_registration_index = Some(global_index);
            }
            if let Some(destination) = governance_grant_destination_v1(instruction)? {
                if destination != GENESIS_AUTHORITY_V1 {
                    bail!("Taira CanEnactGovernance genesis grant targets the wrong authority");
                }
                governance_grant_count += 1;
                governance_grant_index = Some(global_index);
            }
            global_index += 1;
        }
    }
    if authority_registration_count != 1
        || governance_grant_count != 1
        || authority_registration_index >= governance_grant_index
    {
        bail!(
            "Taira genesis does not contain the exact ordered privacy governance authority and grant"
        );
    }
    if let Some(review) = nevo_review {
        validate_nevo_review_v1(bytes, review)?;
    } else {
        expect_canonical_template_bytes_v1(bytes, CANONICAL_GENESIS_TEMPLATE_V1, "Taira genesis")?;
    }
    let final_transaction = transactions
        .last()
        .and_then(JsonValue::as_object)
        .ok_or_else(|| eyre!("Taira genesis final transaction is not an object"))?;
    if final_transaction
        .get("parameters")
        .is_some_and(|value| !value.is_null())
        || final_transaction
            .get("ivm_triggers")
            .and_then(JsonValue::as_array)
            .is_some_and(|values| !values.is_empty())
        || final_transaction
            .get("topology")
            .and_then(JsonValue::as_array)
            .is_some_and(|values| !values.is_empty())
    {
        bail!("Taira genesis final transaction is not instruction-only");
    }
    // Both branches proved the exact source image; no genesis field was edited.
    // Preserve its reviewed digest instead of normalizing incidental JSON formatting.
    Ok(bytes.to_vec())
}
fn registered_account_id_v1(instruction: &JsonValue) -> Option<&str> {
    instruction
        .get("Register")?
        .get("Account")?
        .get("id")?
        .as_str()
}
fn governance_grant_destination_v1(instruction: &JsonValue) -> color_eyre::Result<Option<&str>> {
    let Some(permission) = instruction
        .get("Grant")
        .and_then(|grant| grant.get("Permission"))
    else {
        return Ok(None);
    };
    let Some(object) = permission.get("object").and_then(JsonValue::as_object) else {
        return Ok(None);
    };
    if object.get("name").and_then(JsonValue::as_str) != Some("CanEnactGovernance") {
        return Ok(None);
    }
    if object.len() != 2 || !object.get("payload").is_some_and(JsonValue::is_null) {
        bail!("Taira CanEnactGovernance genesis grant must be unscoped");
    }
    let destination = permission
        .get("destination")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| eyre!("Taira CanEnactGovernance genesis grant has no destination"))?;
    Ok(Some(destination))
}
fn json_pretty_bytes_v1(value: &JsonValue, label: &str) -> color_eyre::Result<Vec<u8>> {
    let mut rendered = norito::json::to_json_pretty(value)
        .wrap_err_with(|| format!("failed to render {label}"))?;
    rendered.push('\n');
    Ok(rendered.into_bytes())
}
fn object_v1<'a>(value: &'a JsonValue, label: &str) -> color_eyre::Result<&'a JsonMap> {
    value
        .as_object()
        .ok_or_else(|| eyre!("{label} must be a JSON object"))
}
fn object_mut_v1<'a>(value: &'a mut JsonValue, label: &str) -> color_eyre::Result<&'a mut JsonMap> {
    value
        .as_object_mut()
        .ok_or_else(|| eyre!("{label} must be a JSON object"))
}
fn object_field_v1<'a>(
    fields: &'a JsonMap,
    field: &str,
    label: &str,
) -> color_eyre::Result<&'a JsonMap> {
    fields
        .get(field)
        .and_then(JsonValue::as_object)
        .ok_or_else(|| eyre!("{label} `{field}` must be an object"))
}
fn object_field_mut_v1<'a>(
    fields: &'a mut JsonMap,
    field: &str,
    label: &str,
) -> color_eyre::Result<&'a mut JsonMap> {
    fields
        .get_mut(field)
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| eyre!("{label} `{field}` must be an object"))
}
fn string_field_v1<'a>(
    fields: &'a JsonMap,
    field: &str,
    label: &str,
) -> color_eyre::Result<&'a str> {
    fields
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| eyre!("{label} `{field}` must be a string"))
}
fn string_array_field_v1(
    fields: &JsonMap,
    field: &str,
    label: &str,
) -> color_eyre::Result<Vec<String>> {
    fields
        .get(field)
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("{label} `{field}` must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| eyre!("{label} `{field}` entry {index} must be a string"))
        })
        .collect()
}
fn expect_string_v1(
    fields: &JsonMap,
    field: &str,
    expected: &str,
    label: &str,
) -> color_eyre::Result<()> {
    if string_field_v1(fields, field, label)? != expected {
        bail!("{label} `{field}` differs from the exact first-release value");
    }
    Ok(())
}
fn expect_u64_v1(
    fields: &JsonMap,
    field: &str,
    expected: u64,
    label: &str,
) -> color_eyre::Result<()> {
    if fields.get(field).and_then(JsonValue::as_u64) != Some(expected) {
        bail!("{label} `{field}` differs from the exact first-release value");
    }
    Ok(())
}
fn expect_exact_keys_v1(
    fields: &JsonMap,
    expected: &[&str],
    label: &str,
) -> color_eyre::Result<()> {
    let actual = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{label} has missing or unknown fields");
    }
    Ok(())
}
fn fixed_nonzero_sha256_v1(value: &str, label: &str) -> color_eyre::Result<()> {
    if value.len() != 64
        || value == "0".repeat(64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be one nonzero lowercase SHA-256 digest");
    }
    Ok(())
}
fn decode_sha256_v1(value: &str, label: &str) -> color_eyre::Result<[u8; 32]> {
    fixed_nonzero_sha256_v1(value, label)?;
    let bytes = hex::decode(value).wrap_err_with(|| format!("failed to decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| eyre!("{label} must decode to exactly 32 bytes"))
}
fn expect_canonical_template_bytes_v1(
    actual: &[u8],
    canonical: &[u8],
    label: &str,
) -> color_eyre::Result<()> {
    if actual != canonical {
        bail!("{label} template differs byte-for-byte from the compiled first-release template");
    }
    Ok(())
}
fn write_new_artifact_set_v1<const N: usize>(
    artifacts: [(&Path, &[u8], &str); N],
) -> color_eyre::Result<()> {
    let unique = artifacts
        .iter()
        .map(|(path, _, _)| resolved_new_output_path_v1(path))
        .collect::<color_eyre::Result<BTreeSet<_>>>()?;
    if unique.len() != N {
        bail!("Taira release output paths must all differ");
    }
    let mut opened = Vec::with_capacity(N);
    for (path, _, description) in &artifacts {
        match create_new_file(path, description) {
            Ok(file) => opened.push(file),
            Err(error) => {
                for ((created_path, _, _), created_file) in artifacts.iter().zip(opened.iter()) {
                    remove_created_file_if_unchanged_v1(created_path, created_file);
                }
                drop(opened);
                return Err(error);
            }
        }
    }
    for index in 0..N {
        let (_, bytes, description) = artifacts[index];
        let result = {
            let file = &mut opened[index];
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .wrap_err_with(|| format!("failed to write and sync {description}"))
        };
        if let Err(error) = result {
            for ((path, _, _), opened_file) in artifacts.iter().zip(opened.iter()) {
                remove_created_file_if_unchanged_v1(path, opened_file);
            }
            drop(opened);
            return Err(error);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_bootstrap::build_taira_privacy_bootstrap_v1;
    use iroha_core_privacy::{
        privacy_engines::bootle_lantern::issuer::{
            BootleLanternIssuerKeyPairV1, BootleLanternIssuerPolicyMetadataV1,
        },
        privacy_profiles::compiled_privacy_profile_v1,
    };
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        account::address::AccountAddress,
        alias_setup::ResolvedAccountAliasV1,
        block::BlockHeader,
        isi::{GrantBox, RegisterBox, UnregisterBox},
        permission::Permission,
        privacy::{
            BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1, BootleLanternAllowedAttributeValuesV1,
            PrivacyIssuerIdV1, PrivacyParameterIdV1, PrivacyPolicyIdV1, PrivacyProposedLifecycleV1,
            PrivacyProtocolLifecycleV1,
        },
    };
    use iroha_executor_data_model::permission::{
        account::{AccountAliasPermissionScope, CanManageAccountAlias},
        smart_contract::CanManageSmartContractCode,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    use std::fs;
    const PLAN_TEMPLATE_V1: &[u8] =
        include_bytes!("../../../../configs/soranexus/taira/privacy_bootstrap_plan.json");
    const CONFIG_TEMPLATE_V1: &[u8] =
        include_bytes!("../../../../configs/soranexus/taira/config.toml");
    const GENESIS_TEMPLATE_V1: &[u8] =
        include_bytes!("../../../../configs/soranexus/taira/genesis.template.json");
    const NEVO_ONBOARDING_ACCOUNT_V1: &str = "testuﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP";
    const NEVO_API_SIGNER_ACCOUNT_V1: &str =
        "testuﾛ1NﾑﾅpﾐTm5Yfﾕ3ｦSヰﾏBｶA5ｻﾔｽｱｼDkDｸkVZBｳﾈyｽﾜヰ9NA1NP";
    const GOLDEN_NEVO_IS2_TOKEN_HASH_V2: &str =
        "blake3:11590239c854c8e1033a98997443be5280c3a883ef97b8999ee45539a8d4197e";
    const GOLDEN_NEVO_DPN_TOKEN_HASH_V2: &str =
        "blake3:1c0a72b28a75a1ef2c09779c7de338ae5afc99e4945ceab869fa72b12bc0efcb";
    fn nevo_fixture_v1() -> (Vec<u8>, Vec<u8>) {
        (
            GOLDEN_NEVO_UNSIGNED_V2.to_vec(),
            GOLDEN_NEVO_REVIEW_V2.to_vec(),
        )
    }
    fn mutate_nevo_review_v1(review: &[u8], mutation: impl FnOnce(&mut JsonMap)) -> Vec<u8> {
        let mut value: JsonValue =
            norito::json::from_slice(review).expect("parse NEVO fixture review");
        mutation(value.as_object_mut().expect("NEVO fixture review object"));
        json_pretty_bytes_v1(&value, "mutated NEVO fixture review")
            .expect("render mutated NEVO fixture review")
    }
    fn policy_registration_fixture_v1() -> RegisterPrivacyBootleLanternIssuerPolicyV1 {
        let issuer = BootleLanternIssuerKeyPairV1::generate_from_secret_seed_v1(
            PrivacyParameterIdV1::new(sha256(b"release-composer-parameter-id")),
            &[0x5a; 32],
        )
        .expect("derive deterministic native issuer fixture");
        let policy = issuer
            .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
                issuer_id: PrivacyIssuerIdV1::new(sha256(ISSUER_ID_DOMAIN_V1)),
                policy_id: PrivacyPolicyIdV1::new(sha256(POLICY_ID_DOMAIN_V1)),
                epoch: 1,
                required_disclosure_bitmap: 0,
                allowed_values: (0..BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
                    .map(|_| BootleLanternAllowedAttributeValuesV1 { values: Vec::new() })
                    .collect(),
            })
            .expect("derive valid governed issuer-policy fixture");
        RegisterPrivacyBootleLanternIssuerPolicyV1::new(policy)
    }
    fn broker_export_fixture_v1() -> Vec<u8> {
        let registration = policy_registration_fixture_v1();
        let instruction = InstructionBox::from(registration.clone());
        let instruction_bytes =
            norito::to_bytes(&instruction).expect("encode boxed policy fixture");
        let stable_principal_digest = sha256(b"iroha.taira.release-composer.stable-principal.v1");
        let network_id =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                Hash::prehashed(sha256(b"iroha.taira.release-composer.genesis.v1")),
            ));
        let qualification = derive_taira_bootle_lantern_broker_qualification_digest_v1(
            &TairaBootleLanternBrokerQualificationInputsV1 {
                network_id,
                runtime_provider_handle: PROVIDER_HANDLE_V1,
                runtime_provider_revision: PROVIDER_REVISION_V1,
                issuer_id: registration.policy.issuer_id,
                policy_id: registration.policy.policy_id,
                authorization_lifetime_blocks: AUTHORIZATION_LIFETIME_BLOCKS_V1,
                policy: &registration.policy,
                stable_principal_digest,
            },
        )
        .expect("derive provider qualification fixture");
        let mut fields = JsonMap::new();
        fields.insert(
            "schema".to_owned(),
            JsonValue::String(BROKER_EXPORT_SCHEMA_V1.to_owned()),
        );
        fields.insert(
            "chain_id".to_owned(),
            JsonValue::String(CHAIN_ID_V1.to_owned()),
        );
        fields.insert(
            "network_id".to_owned(),
            JsonValue::String(network_id.to_string()),
        );
        fields.insert(
            "runtime_provider_handle".to_owned(),
            JsonValue::String(PROVIDER_HANDLE_V1.to_owned()),
        );
        fields.insert(
            "runtime_provider_revision".to_owned(),
            JsonValue::from(PROVIDER_REVISION_V1),
        );
        fields.insert(
            "runtime_provider_policy_digest_hex".to_owned(),
            JsonValue::String(hex::encode(qualification)),
        );
        fields.insert(
            "issuer_id_hex".to_owned(),
            JsonValue::String(hex::encode(sha256(ISSUER_ID_DOMAIN_V1))),
        );
        fields.insert(
            "policy_id_hex".to_owned(),
            JsonValue::String(hex::encode(sha256(POLICY_ID_DOMAIN_V1))),
        );
        fields.insert(
            "authorization_lifetime_blocks".to_owned(),
            JsonValue::from(AUTHORIZATION_LIFETIME_BLOCKS_V1),
        );
        fields.insert(
            "issuer_parameter_id_hex".to_owned(),
            JsonValue::String(hex::encode(
                registration.policy.issuer_parameter_id.as_bytes(),
            )),
        );
        fields.insert(
            "issuer_parameter_digest_hex".to_owned(),
            JsonValue::String(hex::encode(
                registration.policy.issuer_parameter_digest.as_bytes(),
            )),
        );
        fields.insert(
            "policy_record_digest_hex".to_owned(),
            JsonValue::String(hex::encode(registration.policy.record_digest.as_bytes())),
        );
        fields.insert(
            "stable_principal_digest_hex".to_owned(),
            JsonValue::String(hex::encode(stable_principal_digest)),
        );
        fields.insert(
            "issuer_profile_digest_hex".to_owned(),
            JsonValue::String(hex::encode(
                taira_bootle_lantern_issuer_profile_contract_digest_v1(),
            )),
        );
        fields.insert(
            "broker_contract_digest_hex".to_owned(),
            JsonValue::String(hex::encode(taira_bootle_lantern_broker_contract_digest_v1())),
        );
        fields.insert(
            "registration_instruction_norito_hex".to_owned(),
            JsonValue::String(hex::encode(&instruction_bytes)),
        );
        fields.insert(
            "registration_instruction_norito_sha256".to_owned(),
            JsonValue::String(hex::encode(sha256(&instruction_bytes))),
        );
        fields.insert(
            "registration_instruction".to_owned(),
            norito::json::to_value(&registration).expect("project policy fixture"),
        );
        format!(
            "{}\n",
            norito::json::to_json(&JsonValue::Object(fields))
                .expect("encode broker export fixture")
        )
        .into_bytes()
    }
    fn mutate_export_v1(source: &[u8], mutate: impl FnOnce(&mut JsonMap)) -> Vec<u8> {
        let mut value: JsonValue = norito::json::from_slice(source).expect("parse export fixture");
        mutate(value.as_object_mut().expect("export object"));
        format!(
            "{}\n",
            norito::json::to_json(&value).expect("encode mutated export")
        )
        .into_bytes()
    }
    #[test]
    fn complete_release_composition_is_native_deterministic_or_fails_closed_at_source() {
        let export = broker_export_fixture_v1();
        if let Some((protocol_id, source)) =
            PrivacyProtocolIdV1::ALL
                .into_iter()
                .find_map(|protocol_id| {
                    compiled_privacy_profile_v1(protocol_id)
                        .err()
                        .map(|source| (protocol_id, source))
                })
        {
            let error = build_taira_privacy_bootstrap_v1()
                .expect_err("an unavailable compiled profile must prevent partial emission");
            let error = error.to_string();
            assert!(
                error.contains(protocol_id.canonical_label()),
                "closed source gate did not identify `{}`: {error}",
                protocol_id.canonical_label()
            );
            assert!(
                error.contains(&source.to_string()),
                "closed source gate did not retain the native error `{source}`: {error}"
            );
            return;
        }
        let activations = build_taira_privacy_bootstrap_v1()
            .expect("derive the complete exact-12 release-composer source set");
        let first = compose_release_artifacts_v1(
            &activations.instructions_json,
            &activations.report_json,
            &export,
            PLAN_TEMPLATE_V1,
            CONFIG_TEMPLATE_V1,
            GENESIS_TEMPLATE_V1,
            None,
        )
        .expect("compose complete release");
        let second = compose_release_artifacts_v1(
            &activations.instructions_json,
            &activations.report_json,
            &export,
            PLAN_TEMPLATE_V1,
            CONFIG_TEMPLATE_V1,
            GENESIS_TEMPLATE_V1,
            None,
        )
        .expect("recompose complete release");
        assert_eq!(first.plan, second.plan);
        assert_eq!(first.config, second.config);
        assert_eq!(first.genesis, second.genesis);
        assert_eq!(first.broker_public, second.broker_public);
        assert_eq!(first.broker_public, export);
        let plan: JsonValue = norito::json::from_slice(&first.plan).expect("parse release plan");
        let broker_export: JsonValue =
            norito::json::from_slice(&export).expect("parse broker public export");
        assert_eq!(
            plan.get("network_id"),
            broker_export.get("network_id"),
            "rendered plan must bind the authenticated broker NetworkId"
        );
        assert_eq!(
            plan.pointer("/governance_rollout/activation_state")
                .and_then(JsonValue::as_str),
            Some("not-executed")
        );
        assert_eq!(first.genesis, GENESIS_TEMPLATE_V1);
        let expected_export_sha256 = hex::encode(sha256(&export));
        assert_eq!(
            plan.pointer("/bootle_lantern_issuer/public_export_sha256")
                .and_then(JsonValue::as_str),
            Some(expected_export_sha256.as_str())
        );
        let config: toml::Value =
            toml::from_str(std::str::from_utf8(&first.config).expect("release config UTF-8"))
                .expect("parse release config");
        assert_eq!(
            config
                .get("torii")
                .and_then(|value| value.get("privacy_bootle_lantern_issuer"))
                .and_then(|value| value.get("enabled"))
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert!(!String::from_utf8_lossy(&first.plan).contains("issuer_seed"));
        assert!(!String::from_utf8_lossy(&first.config).contains("bearer_token"));
        assert!(!String::from_utf8_lossy(&first.genesis).contains("principal_seed"));
    }
    #[test]
    fn rollout_plan_binds_the_hard_cut_catalog_and_evidence_derived_gate() {
        let bootstrap: JsonValue =
            norito::json::from_slice(PLAN_TEMPLATE_V1).expect("parse staging plan");
        validate_staging_plan_v1(&bootstrap)
            .expect("bootstrap anchor, compiled pin, and rollout bytes must agree");
        validate_rollout_plan_v1(CANONICAL_ROLLOUT_PLAN_V1)
            .expect("canonical rollout plan must satisfy the native hard-cut contract");

        let rollout: JsonValue = norito::json::from_slice(CANONICAL_ROLLOUT_PLAN_V1)
            .expect("parse canonical rollout plan");
        let mut substituted_lock = rollout.clone();
        substituted_lock
            .as_object_mut()
            .expect("rollout plan object")
            .insert(
                "cargo_lock_sha256".to_owned(),
                JsonValue::String("0".repeat(64)),
            );
        let substituted_bytes = json_pretty_bytes_v1(&substituted_lock, "substituted rollout")
            .expect("encode substituted rollout");
        assert!(
            validate_rollout_plan_v1(&substituted_bytes)
                .expect_err("a substituted dependency lock must be rejected")
                .to_string()
                .contains("cargo_lock_sha256")
        );
        let protocols = rollout
            .get("protocols")
            .and_then(JsonValue::as_array)
            .expect("rollout protocol rows");
        assert_eq!(protocols.len(), PrivacyProtocolIdV1::COUNT);
        for (row, protocol) in protocols.iter().zip(PrivacyProtocolIdV1::ALL) {
            assert_eq!(
                row.get("label").and_then(JsonValue::as_str),
                Some(protocol.canonical_label())
            );
            assert_eq!(
                row.get("security_model").and_then(JsonValue::as_str),
                Some(protocol.security_model().canonical_label())
            );
        }
        assert_eq!(
            rollout
                .pointer("/capability_gate/required_readiness")
                .and_then(JsonValue::as_str),
            Some("production-qualified")
        );
        let rollout_text = std::str::from_utf8(CANONICAL_ROLLOUT_PLAN_V1)
            .expect("canonical rollout plan must be UTF-8");
        for removed in [
            "available-experimental",
            "assurance",
            "legacy_policy",
            "missing_evidence",
            "release_status",
            "retired_labels",
        ] {
            assert!(
                !rollout_text.contains(removed),
                "removed rollout field or value `{removed}` must not survive"
            );
        }
    }
    #[test]
    fn release_plan_requires_null_staging_network_and_binds_broker_network() {
        let export = broker_export_fixture_v1();
        let broker = parse_broker_public_export_v1(&export).expect("admit broker fixture");
        let rendered = render_release_plan_v1(PLAN_TEMPLATE_V1, &broker)
            .expect("render release plan from exact staging template");
        let rendered: JsonValue =
            norito::json::from_slice(&rendered).expect("parse rendered release plan");
        assert_eq!(
            rendered.get("network_id").and_then(JsonValue::as_str),
            Some(broker.network_id.as_str())
        );

        let mut populated: JsonValue =
            norito::json::from_slice(PLAN_TEMPLATE_V1).expect("parse staging plan");
        populated
            .as_object_mut()
            .expect("staging plan object")
            .insert(
                "network_id".to_owned(),
                JsonValue::String(broker.network_id.clone()),
            );
        assert!(
            validate_staging_plan_v1(&populated)
                .expect_err("prepopulated staging NetworkId must be rejected")
                .to_string()
                .contains("staging network_id must be null")
        );

        populated
            .as_object_mut()
            .expect("staging plan object")
            .remove("network_id");
        assert!(
            validate_staging_plan_v1(&populated).is_err(),
            "missing staging NetworkId key must be rejected"
        );
    }
    #[test]
    fn bare_trailing_digest_and_secret_field_broker_substitutions_are_rejected() {
        let canonical = broker_export_fixture_v1();
        let registration = policy_registration_fixture_v1();
        let bare = norito::to_bytes(&registration).expect("encode bare policy registration");
        let bare_export = mutate_export_v1(&canonical, |fields| {
            fields.insert(
                "registration_instruction_norito_hex".to_owned(),
                JsonValue::String(hex::encode(&bare)),
            );
            fields.insert(
                "registration_instruction_norito_sha256".to_owned(),
                JsonValue::String(hex::encode(sha256(&bare))),
            );
        });
        assert!(parse_broker_public_export_v1(&bare_export).is_err());
        let trailing = mutate_export_v1(&canonical, |fields| {
            let mut bytes = hex::decode(
                fields
                    .get("registration_instruction_norito_hex")
                    .and_then(JsonValue::as_str)
                    .expect("instruction hex"),
            )
            .expect("decode boxed instruction");
            bytes.push(0);
            fields.insert(
                "registration_instruction_norito_hex".to_owned(),
                JsonValue::String(hex::encode(&bytes)),
            );
            fields.insert(
                "registration_instruction_norito_sha256".to_owned(),
                JsonValue::String(hex::encode(sha256(&bytes))),
            );
        });
        assert!(parse_broker_public_export_v1(&trailing).is_err());
        let digest = mutate_export_v1(&canonical, |fields| {
            fields.insert(
                "registration_instruction_norito_sha256".to_owned(),
                JsonValue::String("33".repeat(32)),
            );
        });
        assert!(parse_broker_public_export_v1(&digest).is_err());
        let secret = mutate_export_v1(&canonical, |fields| {
            fields.insert(
                "issuer_seed".to_owned(),
                JsonValue::String("forbidden".to_owned()),
            );
        });
        assert!(parse_broker_public_export_v1(&secret).is_err());
    }
    #[test]
    fn provider_qualification_profile_contract_and_principal_drift_are_rejected() {
        let canonical = broker_export_fixture_v1();
        for field in [
            "runtime_provider_policy_digest_hex",
            "issuer_profile_digest_hex",
            "broker_contract_digest_hex",
            "stable_principal_digest_hex",
        ] {
            let drifted = mutate_export_v1(&canonical, |fields| {
                fields.insert(field.to_owned(), JsonValue::String("33".repeat(32)));
            });
            assert!(
                parse_broker_public_export_v1(&drifted).is_err(),
                "broker public field {field} must be derived rather than shape-checked"
            );
        }
    }
    #[test]
    fn nevo_golden_extends_the_current_taira_genesis_by_exactly_one_transaction() {
        let base: JsonValue = norito::json::from_slice(CANONICAL_GENESIS_TEMPLATE_V1)
            .expect("decode canonical Taira genesis");
        let mut golden: JsonValue = norito::json::from_slice(GOLDEN_NEVO_UNSIGNED_V2)
            .expect("decode source-pinned NEVO genesis");
        let overlay = golden
            .as_object_mut()
            .and_then(|root| root.get_mut("transactions"))
            .and_then(JsonValue::as_array_mut)
            .expect("NEVO genesis transactions")
            .pop()
            .expect("exactly one NEVO overlay transaction");
        let canonical_overlay: JsonValue = norito::json::from_slice(CANONICAL_NEVO_OVERLAY_V1)
            .expect("decode canonical NEVO overlay");
        assert_eq!(overlay, canonical_overlay);
        assert_eq!(golden, base);
    }
    #[test]
    fn nevo_overlay_grants_current_contract_code_management_authority() {
        iroha_genesis::init_instruction_registry();
        let _chain_discriminant =
            ChainDiscriminantGuard::enter(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT);
        let overlay: JsonValue = norito::json::from_slice(CANONICAL_NEVO_OVERLAY_V1)
            .expect("decode canonical NEVO overlay");
        let instructions = iroha_genesis::genesis_instructions_json::from_value(
            overlay.get("instructions").expect("overlay instructions"),
        )
        .expect("decode canonical NEVO instructions");
        let GrantBox::Permission(grant) = instructions[18]
            .as_any()
            .downcast_ref::<GrantBox>()
            .expect("contract code management grant")
        else {
            panic!("instruction 18 must grant contract code management permission");
        };
        assert_eq!(
            grant.object(),
            &Permission::from(CanManageSmartContractCode)
        );
        assert_eq!(
            grant.destination(),
            &AccountAddress::parse_encoded(GOLDEN_NEVO_API_SIGNER_V2, None)
                .expect("canonical API signer")
                .to_account_id()
                .expect("single-controller API signer")
        );
    }
    #[test]
    fn validate_only_nevo_review_rejects_digest_unbound_identity_mutation() {
        let _caller_network = ChainDiscriminantGuard::enter(42);
        let directory = tempfile::tempdir().expect("create NEVO validation directory");
        let unsigned_genesis_path = directory.path().join("unsigned-genesis.template.json");
        let review_path = directory.path().join("review.json");
        let (genesis, review) = nevo_fixture_v1();
        fs::write(&unsigned_genesis_path, &genesis).expect("write NEVO unsigned genesis");
        fs::write(&review_path, &review).expect("write NEVO review");
        let args = ValidateTairaNevoReviewV1Args {
            unsigned_genesis: unsigned_genesis_path,
            review: review_path.clone(),
        };
        let mut output = std::io::BufWriter::new(Vec::new());
        validate_taira_nevo_review_v1(&args, &mut output)
            .expect("validate exact reviewed NEVO genesis");
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 42);
        let output = String::from_utf8(output.into_inner().expect("flush NEVO validation receipt"))
            .expect("NEVO validation receipt is UTF-8");
        let receipt: JsonValue =
            norito::json::from_str(&output).expect("decode NEVO validation receipt");
        let receipt = receipt.as_object().expect("NEVO validation receipt object");
        assert_eq!(
            receipt.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            [
                "native_recomposition_passed",
                "review_sha256",
                "status",
                "unsigned_genesis_sha256",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            receipt.get("status").and_then(JsonValue::as_str),
            Some("validated")
        );
        assert_eq!(
            receipt
                .get("native_recomposition_passed")
                .and_then(JsonValue::as_bool),
            Some(true)
        );
        let expected_genesis_sha256 = hex::encode(sha256(&genesis));
        let expected_review_sha256 = hex::encode(sha256(&review));
        assert_eq!(
            receipt
                .get("unsigned_genesis_sha256")
                .and_then(JsonValue::as_str),
            Some(expected_genesis_sha256.as_str())
        );
        assert_eq!(
            receipt.get("review_sha256").and_then(JsonValue::as_str),
            Some(expected_review_sha256.as_str())
        );

        let digest_unbound_identity = mutate_nevo_review_v1(&review, |root| {
            root.get_mut("public_identities")
                .and_then(JsonValue::as_object_mut)
                .expect("NEVO public identities")
                .insert(
                    "onboarding_authority_account_id".to_owned(),
                    JsonValue::String(GENESIS_AUTHORITY_V1.to_owned()),
                );
        });
        fs::write(&review_path, digest_unbound_identity).expect("write mutated NEVO review");
        let error = validate_taira_nevo_review_v1(&args, &mut std::io::BufWriter::new(Vec::new()))
            .expect_err("digest-unbound public identity mutation must fail native validation");
        assert!(error.to_string().contains("public_inputs_sha256"));
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 42);
    }
    #[test]
    fn reviewed_nevo_genesis_is_natively_recomposed_and_splices_are_rejected() {
        let (genesis, review) = nevo_fixture_v1();
        assert_eq!(
            render_release_genesis_v1(&genesis, Some(&review))
                .expect("accept exact natively recomposed NEVO genesis"),
            genesis
        );

        let generic_forgery = mutate_nevo_review_v1(&review, |root| {
            root.insert(
                "unsigned_genesis_sha256".to_owned(),
                JsonValue::String(hex::encode(sha256(GENESIS_TEMPLATE_V1))),
            );
        });
        assert!(
            render_release_genesis_v1(GENESIS_TEMPLATE_V1, Some(&generic_forgery))
                .expect_err("generic genesis cannot be review-wrapped as NEVO")
                .to_string()
                .contains("native exact overlay recomposition")
        );

        let identity_splice = mutate_nevo_review_v1(&review, |root| {
            let identities = root
                .get_mut("public_identities")
                .and_then(JsonValue::as_object_mut)
                .expect("NEVO public identities");
            identities.insert(
                "onboarding_authority_account_id".to_owned(),
                JsonValue::String(NEVO_API_SIGNER_ACCOUNT_V1.to_owned()),
            );
            identities.insert(
                "api_signer_account_id".to_owned(),
                JsonValue::String(NEVO_ONBOARDING_ACCOUNT_V1.to_owned()),
            );
            let digest = nevo_public_inputs_sha256_v1(
                NEVO_API_SIGNER_ACCOUNT_V1,
                NEVO_ONBOARDING_ACCOUNT_V1,
                GOLDEN_NEVO_INORI_V2,
                GOLDEN_NEVO_EPR_GUARD_V2,
                GOLDEN_NEVO_IS2_TOKEN_HASH_V2,
                GOLDEN_NEVO_DPN_TOKEN_HASH_V2,
            )
            .expect("derive swapped identity digest");
            root.insert("public_inputs_sha256".to_owned(), JsonValue::String(digest));
        });
        let identity_error = render_release_genesis_v1(&genesis, Some(&identity_splice))
            .expect_err("coherently rehashed identity splice must change the overlay");
        assert!(
            identity_error.to_string().contains("overlay inventory")
                || identity_error
                    .to_string()
                    .contains("native exact overlay recomposition")
        );

        for spliced in [
            mutate_nevo_review_v1(&review, |root| {
                root.insert(
                    "public_inputs_sha256".to_owned(),
                    JsonValue::String("33".repeat(32)),
                );
            }),
            mutate_nevo_review_v1(&review, |root| {
                root.get_mut("credential_hash_bindings")
                    .and_then(JsonValue::as_array_mut)
                    .expect("NEVO credential bindings")[0]
                    .get_mut("token_hash")
                    .map(|value| *value = JsonValue::String(format!("blake3:{}", "44".repeat(32))))
                    .expect("NEVO token hash");
            }),
        ] {
            assert!(
                render_release_genesis_v1(&genesis, Some(&spliced)).is_err(),
                "public-input digest and token-hash splices must fail native admission"
            );
        }
    }
    #[test]
    fn nevo_genesis_render_uses_pinned_address_profile_and_restores_the_caller() {
        let _caller = ChainDiscriminantGuard::enter(753);
        let rendered = render_release_genesis_v1(CANONICAL_GENESIS_TEMPLATE_V1, None)
            .expect("Taira genesis decoding uses its verified profile, not the caller profile");
        assert_eq!(rendered, CANONICAL_GENESIS_TEMPLATE_V1);
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            753
        );
        let mut empty: JsonValue = norito::json::from_slice(CANONICAL_GENESIS_TEMPLATE_V1)
            .expect("parse pinned source for the rejected candidate");
        empty
            .as_object_mut()
            .expect("genesis object")
            .insert("transactions".to_owned(), JsonValue::Array(Vec::new()));
        let empty = json_pretty_bytes_v1(&empty, "empty candidate").expect("encode candidate");
        assert!(
            render_release_genesis_v1(&empty, None)
                .expect_err("empty transaction list must fail after entering its declared profile")
                .to_string()
                .contains("no transactions")
        );
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            753
        );
    }
    #[test]
    fn reviewed_nevo_genesis_carries_exact_ephemeral_alias_authority() {
        let _chain_discriminant =
            ChainDiscriminantGuard::enter(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT);
        let (genesis, _) = nevo_fixture_v1();
        let genesis_json: JsonValue =
            norito::json::from_slice(&genesis).expect("decode reviewed NEVO JSON");
        let instruction_values = genesis_json
            .get("transactions")
            .and_then(JsonValue::as_array)
            .and_then(|transactions| transactions.last())
            .and_then(|transaction| transaction.get("instructions"))
            .expect("reviewed overlay instructions");
        let instructions = iroha_genesis::genesis_instructions_json::from_value(instruction_values)
            .expect("decode reviewed NEVO instructions");
        assert_eq!(instructions.len(), 29);

        let RegisterBox::Role(register) = instructions[8]
            .as_any()
            .downcast_ref::<RegisterBox>()
            .expect("ephemeral role registration")
        else {
            panic!("instruction 8 must register the ephemeral alias role");
        };
        assert_eq!(
            register.object().inner().id.to_string(),
            GENESIS_ALIAS_BOOTSTRAP_ROLE_ID_V1
        );
        assert_eq!(
            register.object().grant_to(),
            &AccountAddress::parse_encoded(GENESIS_ALIAS_BOOTSTRAP_AUTHORITY_V1, None)
                .expect("canonical genesis authority")
                .to_account_id()
                .expect("single-controller genesis authority")
        );
        let exact_alias = |literal: &str| {
            AccountAliasPermissionScope::Alias(ResolvedAccountAliasV1::new(
                literal.parse().expect("canonical NEVO account alias"),
                DataSpaceId::UNIVERSAL,
            ))
        };
        let expected = [
            AccountAliasPermissionScope::Dataspace(DataSpaceId::new(10)),
            AccountAliasPermissionScope::Dataspace(DataSpaceId::new(8_477_022_798_449_861_195)),
            AccountAliasPermissionScope::Domain(
                DomainId::try_new("nevo", "dpn").expect("canonical NEVO domain"),
            ),
            exact_alias("admin@universal"),
            exact_alias("inori@universal"),
            exact_alias("source_guard@universal"),
        ]
        .into_iter()
        .map(|scope| Permission::from(CanManageAccountAlias { scope }))
        .collect::<BTreeSet<_>>();
        assert_eq!(
            register
                .object()
                .inner()
                .permissions()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected
        );

        let UnregisterBox::Role(unregister) = instructions[15]
            .as_any()
            .downcast_ref::<UnregisterBox>()
            .expect("ephemeral role cleanup")
        else {
            panic!("instruction 15 must unregister the ephemeral alias role");
        };
        assert_eq!(
            unregister.object().to_string(),
            GENESIS_ALIAS_BOOTSTRAP_ROLE_ID_V1
        );
        assert!(
            genesis_json
                .get("transactions")
                .and_then(JsonValue::as_array)
                .and_then(|transactions| transactions.last())
                .and_then(|transaction| transaction.get("instructions"))
                .and_then(JsonValue::as_array)
                .expect("reviewed overlay instructions")
                .iter()
                .all(JsonValue::is_object),
            "reviewed genesis must not hide role lifecycle instructions in encoded strings"
        );
    }
    #[test]
    fn coordinated_governance_authority_substitution_is_rejected_natively() {
        let mut plan: JsonValue =
            norito::json::from_slice(PLAN_TEMPLATE_V1).expect("parse staging plan");
        plan.as_object_mut().expect("plan object").insert(
            "genesis_authority".to_owned(),
            JsonValue::String("unreviewed-authority".to_owned()),
        );
        assert!(validate_staging_plan_v1(&plan).is_err());
    }
    #[test]
    fn catalog_digest_type_and_unknown_field_substitutions_are_rejected_natively() {
        for mutation in 0_u8..3 {
            let mut plan: JsonValue =
                norito::json::from_slice(PLAN_TEMPLATE_V1).expect("parse staging plan");
            let catalog = plan
                .pointer_mut("/privacy_catalog")
                .and_then(JsonValue::as_object_mut)
                .expect("catalog object");
            match mutation {
                0 => {
                    catalog.insert(
                        "matrix_file_sha256".to_owned(),
                        JsonValue::String("11".repeat(32)),
                    );
                }
                1 => {
                    catalog
                        .get_mut("protocols")
                        .and_then(JsonValue::as_array_mut)
                        .expect("protocol rows")[0]
                        .as_object_mut()
                        .expect("protocol row")
                        .insert(
                            "statement_type".to_owned(),
                            JsonValue::String("AttackerStatement".to_owned()),
                        );
                }
                _ => {
                    catalog.insert("future_aliases".to_owned(), JsonValue::Array(Vec::new()));
                }
            }
            assert!(
                validate_staging_plan_v1(&plan).is_err(),
                "catalog mutation {mutation} must fail"
            );
        }
    }
    #[test]
    fn config_template_with_materialized_private_key_is_rejected() {
        let text = std::str::from_utf8(CONFIG_TEMPLATE_V1)
            .expect("config fixture UTF-8")
            .replacen(
                "private_key_file = \"/run/secrets/iroha/taira-validator-private-key\"",
                "private_key = \"materialized-private-key\"",
                1,
            );
        let broker = parse_broker_public_export_v1(&broker_export_fixture_v1())
            .expect("parse broker fixture");
        assert!(
            render_release_config_v1(text.as_bytes(), &broker)
                .expect_err("reject materialized private key")
                .to_string()
                .contains("secret-free staging placeholder")
        );
    }
    #[test]
    fn config_template_onboarding_credentials_are_exact_and_secret_free() {
        let broker = parse_broker_public_export_v1(&broker_export_fixture_v1())
            .expect("parse broker fixture");
        for (placeholder, materialized, expected_error) in [
            (
                "REPLACE_WITH_TAIRA_BOI_ONBOARDING_TOKEN_HASH",
                "blake3:1111111111111111111111111111111111111111111111111111111111111111",
                "secret-free staging placeholder",
            ),
            (
                "REPLACE_WITH_TAIRA_DPN_ONBOARDING_CREDENTIAL_ID",
                "materialized-dpn-credential",
                "secret-free staging placeholder",
            ),
            (
                "scope = { dataspace = \"dpn\" }",
                "scope = { dataspace = \"is2\" }",
                "scope differs from the exact first-release dataspace",
            ),
        ] {
            let text = std::str::from_utf8(CONFIG_TEMPLATE_V1)
                .expect("config fixture UTF-8")
                .replacen(placeholder, materialized, 1);
            let error = render_release_config_v1(text.as_bytes(), &broker)
                .expect_err("reject materialized or retargeted onboarding credential");
            assert!(
                error.to_string().contains(expected_error),
                "materializing or retargeting onboarding placeholder {placeholder} returned {error:?}"
            );
        }
    }
    #[test]
    fn config_template_with_materialized_soranet_transport_identity_is_rejected() {
        let broker = parse_broker_public_export_v1(&broker_export_fixture_v1())
            .expect("parse broker fixture");
        for (placeholder, materialized) in [
            (
                "REPLACE_WITH_SORANET_TRANSPORT_PUBLIC_KEY",
                "ed01200000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "soranet_transport_private_key_file = \"/run/secrets/iroha/taira-soranet-transport-private-key\"",
                "soranet_transport_private_key = \"802620000000000000000000000000000000000000000000000000000000000000000000\"",
            ),
        ] {
            let text = std::str::from_utf8(CONFIG_TEMPLATE_V1)
                .expect("config fixture UTF-8")
                .replacen(placeholder, materialized, 1);
            assert!(
                render_release_config_v1(text.as_bytes(), &broker)
                    .expect_err("reject materialized SoraNet transport identity")
                    .to_string()
                    .contains("secret-free staging placeholder"),
                "materializing {placeholder} must fail closed"
            );
        }
    }
    #[test]
    fn semantically_equivalent_template_byte_drift_is_rejected() {
        let broker = parse_broker_public_export_v1(&broker_export_fixture_v1())
            .expect("parse broker fixture");
        let mut plan = b"\n".to_vec();
        plan.extend_from_slice(PLAN_TEMPLATE_V1);
        assert!(
            render_release_plan_v1(&plan, &broker)
                .expect_err("reject whitespace-drifted plan template")
                .to_string()
                .contains("differs byte-for-byte")
        );
        let mut config = CONFIG_TEMPLATE_V1.to_vec();
        config.extend_from_slice(b"\n# unreviewed but semantically inert\n");
        let error = render_release_config_v1(&config, &broker)
            .expect_err("reject comment-drifted config template");
        assert!(
            error.to_string().contains("differs byte-for-byte"),
            "unexpected config-template rejection: {error:?}"
        );
        let mut genesis = b"\n".to_vec();
        genesis.extend_from_slice(GENESIS_TEMPLATE_V1);
        assert!(
            render_release_genesis_v1(&genesis, None)
                .expect_err("reject whitespace-drifted genesis template")
                .to_string()
                .contains("differs byte-for-byte")
        );
    }
    #[test]
    fn decoded_privacy_bootstrap_in_genesis_template_is_rejected() {
        let profile = PrivacyProtocolIdV1::ALL
            .into_iter()
            .find_map(|protocol_id| compiled_privacy_profile_v1(protocol_id).ok())
            .expect("at least one native privacy profile must be governance-available");
        let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Proposed(
            PrivacyProposedLifecycleV1 {
                proposed_at_height: 1,
            },
        ));
        for instruction in [
            InstructionBox::from(RegisterPrivacyProtocolActivationV1::new(activation)),
            InstructionBox::from(TransitionPrivacyProtocolLifecycleV1::new(
                profile.protocol_id,
                super::super::bootstrap_active_lifecycle_v1(),
            )),
        ] {
            let mut genesis: JsonValue =
                norito::json::from_slice(GENESIS_TEMPLATE_V1).expect("parse genesis template");
            let mut one = String::new();
            iroha_genesis::genesis_instructions_json::serialize(&[instruction], &mut one);
            let mut decoded: JsonValue =
                norito::json::from_str(&one).expect("parse decoded activation JSON");
            let injected = decoded
                .as_array_mut()
                .expect("activation array")
                .pop()
                .expect("one activation");
            genesis
                .get_mut("transactions")
                .and_then(JsonValue::as_array_mut)
                .and_then(|transactions| transactions.last_mut())
                .and_then(|transaction| transaction.get_mut("instructions"))
                .and_then(JsonValue::as_array_mut)
                .expect("final instructions")
                .push(injected);
            let tampered =
                json_pretty_bytes_v1(&genesis, "tampered genesis").expect("render tamper");
            assert!(
                render_release_genesis_v1(&tampered, None)
                    .expect_err("reject pre-existing decoded privacy instruction")
                    .to_string()
                    .contains("already contains a privacy bootstrap instruction")
            );
        }
    }
    #[test]
    fn wrong_and_scoped_governance_grants_are_rejected_before_composition() {
        for scoped in [false, true] {
            let mut genesis: JsonValue =
                norito::json::from_slice(GENESIS_TEMPLATE_V1).expect("parse genesis template");
            let transactions = genesis
                .get_mut("transactions")
                .and_then(JsonValue::as_array_mut)
                .expect("transactions");
            let alternative = transactions
                .iter()
                .flat_map(|transaction| {
                    transaction
                        .get("instructions")
                        .and_then(JsonValue::as_array)
                        .into_iter()
                        .flatten()
                })
                .find_map(registered_account_id_v1)
                .filter(|account| *account != GENESIS_AUTHORITY_V1)
                .expect("alternative registered account")
                .to_owned();
            let permission = transactions
                .iter_mut()
                .flat_map(|transaction| {
                    transaction
                        .get_mut("instructions")
                        .and_then(JsonValue::as_array_mut)
                        .into_iter()
                        .flatten()
                })
                .find_map(|instruction| {
                    instruction
                        .get_mut("Grant")?
                        .get_mut("Permission")?
                        .as_object_mut()
                        .filter(|permission| {
                            permission
                                .get("object")
                                .and_then(JsonValue::as_object)
                                .and_then(|object| object.get("name"))
                                .and_then(JsonValue::as_str)
                                == Some("CanEnactGovernance")
                        })
                })
                .expect("governance permission");
            if scoped {
                permission
                    .get_mut("object")
                    .and_then(JsonValue::as_object_mut)
                    .expect("permission object")
                    .insert("payload".to_owned(), norito::json!({"scope": "privacy"}));
            } else {
                permission.insert("destination".to_owned(), JsonValue::String(alternative));
            }
            let tampered =
                json_pretty_bytes_v1(&genesis, "tampered genesis").expect("render tamper");
            let error = render_release_genesis_v1(&tampered, None)
                .expect_err("reject invalid governance grant");
            assert!(
                error.to_string().contains("wrong authority")
                    || error.to_string().contains("must be unscoped")
                    || error.to_string().contains("cannot be decoded natively"),
                "unexpected governance rejection: {error}"
            );
        }
    }
    #[test]
    fn release_output_set_never_overwrites_and_removes_partial_creations() {
        let directory = tempfile::tempdir().expect("temporary release directory");
        let plan = directory.path().join("plan.json");
        let config = directory.path().join("config.toml");
        let genesis = directory.path().join("genesis.template.json");
        fs::write(&config, b"occupied").expect("occupy second path");
        assert!(
            write_new_artifact_set_v1([
                (plan.as_path(), b"plan".as_slice(), "plan"),
                (config.as_path(), b"config".as_slice(), "config"),
                (genesis.as_path(), b"genesis".as_slice(), "genesis"),
            ])
            .is_err()
        );
        assert!(!plan.exists());
        assert_eq!(
            fs::read(&config).expect("read occupied config"),
            b"occupied"
        );
        assert!(!genesis.exists());
    }
}
