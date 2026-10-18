use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use core::num::{NonZeroU16, NonZeroU64};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, Signature};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId, MultisigMember, MultisigPolicy},
    asset::{
        ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, Asset, AssetBalancePolicy, AssetDefinition,
        AssetDefinitionId, AssetId, AssetIssuerUsagePolicyV1, AssetTransferAvailability,
        AssetTransferControlWindow, AssetTransferLimit,
    },
    block::BlockHeader,
    isi::{
        AddSignatory, Burn, SetAssetHoldingLimit, SetAssetTransferAvailability,
        SetAssetTransferBlacklist, SetAssetTransferControl, SetKeyValue, Transfer, Unregister,
        sorafs::{
            CommitSorafsPopCredentialBatch, PublishSorafsPopRevocationList,
            SetSorafsPopIssuerPolicy,
        },
        transfer::{TransferAssetBatch, TransferAssetBatchEntry},
    },
    permission::{Permission, Permissions},
    sorafs::{
        moderation::{
            SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
            SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1,
            SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1, SoraFsModerationBallotCommitV1,
            SoraFsModerationBallotContextV1, SoraFsModerationBallotRevealV1,
        },
        moderation_ledger::{
            MODERATION_APPEAL_INTAKE_VERSION_V1, MODERATION_LEDGER_CASE_VERSION_V1,
            MODERATION_LEDGER_POLICY_VERSION_V1, ModerationAppealIntakeV1, ModerationCaseSpecV1,
            ModerationChallengeDecisionV1, ModerationChallengeKindV1, ModerationLedgerPolicyV1,
            ModerationNoShowKindV1, ModerationOutcomeKindV1,
            sorafs_moderation_panel_roster_hash_v1,
        },
        pop_registry::{
            POP_CREDENTIAL_COMMITMENT_BATCH_VERSION_V1, POP_ISSUER_POLICY_VERSION_V1,
            PopCredentialCommitmentBatchV1, PopCredentialCommitmentV1, PopIssuerPolicyV1,
            pop_credential_payload_commitment_v1, pop_revocation_nonce_commitment_v1,
        },
    },
};
use iroha_executor_data_model::isi::multisig::{
    DEFAULT_MULTISIG_TTL_MS, MultisigInstructionBox, MultisigRegister, MultisigSpec,
};
use iroha_primitives::json::Json;
use sorafs_manifest::pop_credentials::{
    POP_COMMITMENT_ROOT_VERSION_V1, POP_CREDENTIAL_TREE_DEPTH_V1, POP_CREDENTIAL_VERSION_V1,
    POP_REVOCATION_LIST_VERSION_V1, POP_REVOCATION_TREE_DEPTH_V1, PopCommitmentRootV1,
    PopCredentialAttributeV1, PopCredentialMerklePathV1, PopCredentialV1, PopMembershipProofV1,
    PopMembershipWitnessV1, PopRevocationEntryV1, PopRevocationListV1,
    PopRevocationNonMembershipPathV1, PopRevocationReasonV1, PopSignatureAlgorithmV1,
    PopSignatureV1, build_pop_revocation_non_membership_path_v1, derive_pop_holder_commitment_v1,
    pop_commitment_root_signature_digest_v1, pop_credential_leaf_v1,
    pop_credential_root_from_path_v1, pop_credential_signature_digest_v1,
    pop_revocation_list_signature_digest_v1, pop_revocation_root_v1, prove_pop_membership_v1,
    verify_pop_commitment_root_signature_v1, verify_pop_credential_signature_v1,
    verify_pop_revocation_list_signature_v1,
};
use std::collections::BTreeMap;
const OPENED_AT: u64 = 1_000;
const COMMIT_DEADLINE: u64 = 2_000;
const CHALLENGE_SUBMISSION_DEADLINE: u64 = 3_000;
const CHALLENGE_RESOLUTION_DEADLINE: u64 =
    CHALLENGE_SUBMISSION_DEADLINE + MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1;
const REVEAL_DEADLINE: u64 = CHALLENGE_RESOLUTION_DEADLINE + 1_000;
const REVEAL_AT: u64 = CHALLENGE_RESOLUTION_DEADLINE + 500;
const FINALIZE_AT: u64 = REVEAL_DEADLINE + 1;
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::tests::PreCutModerationLedgerPolicyV1"
)]
#[derive(norito::codec::Encode)]
struct PreCutModerationLedgerPolicyV1 {
    version: u16,
    revision: u64,
    predecessor_policy_digest: Option<[u8; 32]>,
    max_panel_size: u16,
    max_candidate_pool_size: u16,
    max_waitlist_size: u16,
    max_exclusions_per_case: u16,
    max_total_window_ms: u64,
    max_challenges_per_case: u16,
    missing_commit_penalty_points: u32,
    unrevealed_commit_penalty_points: u32,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::tests::PreCutModerationLedgerPolicyRecord"
)]
#[derive(norito::codec::Encode)]
struct PreCutModerationLedgerPolicyRecord {
    policy: PreCutModerationLedgerPolicyV1,
    policy_digest: [u8; 32],
    activated_at_unix_ms: u64,
    activated_by: AccountId,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::tests::PreCutModerationCaseSpecV1"
)]
#[derive(norito::codec::Encode)]
struct PreCutModerationCaseSpecV1 {
    version: u16,
    context: SoraFsModerationBallotContextV1,
    round_id: String,
    jurors: Vec<AccountId>,
    quorum: u16,
    commit_deadline_unix_ms: u64,
    challenge_deadline_unix_ms: u64,
    reveal_deadline_unix_ms: u64,
    policy_digest: [u8; 32],
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::tests::PreCutModerationCaseRecordV1"
)]
#[derive(norito::codec::Encode)]
struct PreCutModerationCaseRecordV1 {
    spec: PreCutModerationCaseSpecV1,
    policy: PreCutModerationLedgerPolicyV1,
    status: ModerationCaseStatusV1,
    opened_at_unix_ms: u64,
    opened_by: AccountId,
    commitment_count: u32,
    reveal_count: u32,
    challenge_count: u32,
    challenge_ids: Vec<String>,
    pending_challenge_count: u32,
    accepted_challenge_count: u32,
    expired_challenge_count: u32,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::tests::PreCutModerationAppealRecordV1"
)]
#[derive(norito::codec::Encode)]
struct PreCutModerationAppealRecordV1 {
    intake: ModerationAppealIntakeV1,
    intake_digest: [u8; 32],
    policy: ModerationLedgerPolicyV1,
    pop_snapshot: ModerationPoPRegistrySnapshotV1,
    pop_snapshot_digest: [u8; 32],
    status: ModerationAppealStatusV1,
    submitted_by: AccountId,
    submitted_at_unix_ms: u64,
    eligible_jurors: Vec<AccountId>,
    selection: Option<ModerationPanelSelectionV1>,
    accepted_jurors: Vec<AccountId>,
    replacements: Vec<ModerationJurorReplacementV1>,
    activated_at_unix_ms: Option<u64>,
    finalized_at_unix_ms: Option<u64>,
}
fn keypair(seed: u8) -> KeyPair {
    let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
        .expect("valid deterministic Ed25519 seed");
    KeyPair::from_private_key(private).expect("derive deterministic keypair")
}
fn account(keypair: &KeyPair) -> AccountId {
    AccountId::new(keypair.public_key().clone())
}
fn execute_initial(
    transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: impl Into<iroha_data_model::isi::InstructionBox>,
) -> Result<(), InstructionExecutionError> {
    crate::executor::Executor::Initial
        .execute_instruction(transaction, authority, instruction.into())
        .map_err(|error| match error {
            iroha_data_model::ValidationFail::InstructionFailed(error) => error,
            other => panic!("moderation must reach its exact native handler: {other:?}"),
        })
}
#[test]
fn moderation_manager_permission_requires_exact_direct_and_role_tokens() {
    use crate::role::RoleIdWithOwner;
    use iroha_data_model::role::Role;

    let manager = account(&keypair(0xA1));
    let malformed = Permission::new(MANAGE_PERMISSION.to_owned(), Json::new("forged"));
    let canonical =
        Permission::from(iroha_executor_data_model::permission::sorafs::CanManageSorafsModeration);
    for through_role in [false, true] {
        for (permission, expected) in [(malformed.clone(), false), (canonical.clone(), true)] {
            let mut world = World::with([], [Account::new(manager.clone()).build(&manager)], []);
            if through_role {
                let role_id: iroha_data_model::role::RoleId =
                    "moderation_manager".parse().expect("role id");
                let role = Role::new(role_id.clone(), manager.clone())
                    .add_permission(permission)
                    .build(&manager);
                world.roles.insert(role_id.clone(), role);
                world
                    .account_roles
                    .insert(RoleIdWithOwner::new(manager.clone(), role_id), ());
            } else {
                world
                    .account_permissions
                    .insert(manager.clone(), [permission].into_iter().collect());
            }
            let state = authenticated_moderation_state(world);
            let mut block = state.block(BlockHeader::new(
                NonZeroU64::new(2).expect("non-genesis height"),
                state.view().latest_block_hash(),
                None,
                1_000,
                0,
            ));
            let mut transaction = block.transaction();
            let state_before = transaction
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let result = execute_initial(
                &mut transaction,
                &manager,
                SetSorafsModerationPolicy::new(policy()),
            );
            assert_eq!(result.is_ok(), expected, "role={through_role}: {result:?}");
            assert_eq!(
                read_policy(transaction.world()).unwrap().is_some(),
                expected
            );
            if let Err(error) = result {
                assert!(
                    matches!(error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(ref message)) if message.contains(MANAGE_PERMISSION))
                );
                assert_eq!(
                    transaction
                        .world
                        .smart_contract_state
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>(),
                    state_before,
                    "rejected permission must preserve the complete bootstrap state"
                );
            }
        }
    }
}
fn policy() -> ModerationLedgerPolicyV1 {
    ModerationLedgerPolicyV1 {
        version: MODERATION_LEDGER_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        challenge_voting_asset_id: iroha_config::parameters::defaults::governance::voting_asset_id(
        )
        .parse()
        .expect("default governance voting asset"),
        challenge_bond_amount: Quantity::from(MODERATION_CHALLENGE_BOND_AMOUNT_V1),
        challenge_escrow_account:
            iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
        challenge_slash_receiver_account:
            iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
        challenge_rejected_slash_bps: MODERATION_CHALLENGE_REJECTED_SLASH_BPS_V1,
        challenge_resolution_grace_ms: MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
        max_panel_size: 8,
        max_candidate_pool_size: 32,
        max_waitlist_size: 8,
        max_exclusions_per_case: 16,
        max_total_window_ms: 90_000_000,
        max_challenges_per_case: 2,
        missing_commit_penalty_points: 11,
        unrevealed_commit_penalty_points: 23,
    }
}
fn policy_with_custody(
    challenge_escrow_account: AccountId,
    challenge_slash_receiver_account: AccountId,
) -> ModerationLedgerPolicyV1 {
    let mut policy = policy();
    policy.challenge_escrow_account = challenge_escrow_account;
    policy.challenge_slash_receiver_account = challenge_slash_receiver_account;
    policy
}
fn pre_cut_policy() -> PreCutModerationLedgerPolicyV1 {
    let current = policy();
    PreCutModerationLedgerPolicyV1 {
        version: current.version,
        revision: current.revision,
        predecessor_policy_digest: current.predecessor_policy_digest,
        max_panel_size: current.max_panel_size,
        max_candidate_pool_size: current.max_candidate_pool_size,
        max_waitlist_size: current.max_waitlist_size,
        max_exclusions_per_case: current.max_exclusions_per_case,
        max_total_window_ms: current.max_total_window_ms,
        max_challenges_per_case: current.max_challenges_per_case,
        missing_commit_penalty_points: current.missing_commit_penalty_points,
        unrevealed_commit_penalty_points: current.unrevealed_commit_penalty_points,
    }
}
fn frame_pre_cut_moderation_payload<Owner, Payload>(
    current: &Owner,
    unsupported: &Payload,
) -> Vec<u8>
where
    Owner: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    Payload: norito::SerializePayload,
{
    let (current_payload, current_flags, payload, flags) = {
        let _canonical =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (current_payload, current_flags) = norito::codec::encode_with_header_flags(current);
        let (payload, flags) = norito::codec::encode_with_header_flags(unsupported);
        (current_payload, current_flags, payload, flags)
    };
    let control =
        norito::core::frame_bare_with_header_flags::<Owner>(&current_payload, current_flags)
            .unwrap();
    assert_eq!(
        control,
        encode_state(current, "current layout control").unwrap()
    );
    let decoded: Owner = decode_state_with_current(&control, "current layout control", None)
        .expect("the production state decoder accepts the current layout under this envelope");
    assert_eq!(
        encode_state(&decoded, "decoded current control").unwrap(),
        control
    );
    let frame = norito::core::frame_bare_with_header_flags::<Owner>(&payload, flags).unwrap();
    let view = norito::core::from_bytes_view(&frame)
        .expect("valid unsupported frame header, length and checksum");
    assert_eq!(
        view.schema(),
        norito::schema::identity::frame_hash::<Owner>()
    );
    assert_eq!(view.as_bytes(), payload.as_slice());
    assert!(
        !matches!(
            norito::decode_canonical::<Owner>(&frame),
            Err(norito::Error::SchemaMismatch)
        ),
        "unsupported payload must reach the actual current owner decoder"
    );
    frame
}
fn startup_error(world: World) -> String {
    State::try_new(
        world.sccp_committee_generations.allocation_budget().clone(),
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
    .err()
    .expect("pre-cut moderation state must fail startup")
    .to_string()
}
fn context(jurors: &[AccountId], quorum: u16) -> SoraFsModerationBallotContextV1 {
    SoraFsModerationBallotContextV1 {
        version: SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1,
        case_id: "case-1".to_owned(),
        evidence_bundle_digest: [0x41; 32],
        appeal_finance_config_version: "finance-v1".to_owned(),
        panel_roster_hash: sorafs_moderation_panel_roster_hash_v1(jurors, quorum),
        policy_reference: "policy-v1".to_owned(),
        evidence_uri: Some("ipfs://evidence".to_owned()),
    }
}
fn spec(jurors: Vec<AccountId>, quorum: u16) -> ModerationCaseSpecV1 {
    spec_with_policy(jurors, quorum, &policy())
}
fn spec_with_policy(
    jurors: Vec<AccountId>,
    quorum: u16,
    policy: &ModerationLedgerPolicyV1,
) -> ModerationCaseSpecV1 {
    ModerationCaseSpecV1 {
        version: MODERATION_LEDGER_CASE_VERSION_V1,
        context: context(&jurors, quorum),
        round_id: "round-1".to_owned(),
        jurors,
        quorum,
        commit_deadline_unix_ms: COMMIT_DEADLINE,
        challenge_submission_deadline_unix_ms: CHALLENGE_SUBMISSION_DEADLINE,
        challenge_resolution_deadline_unix_ms: CHALLENGE_RESOLUTION_DEADLINE,
        reveal_deadline_unix_ms: REVEAL_DEADLINE,
        policy_digest: policy.digest().expect("policy digest"),
    }
}
fn startup_registering_appeal(appellant: &KeyPair) -> ModerationAppealRecordV1 {
    let intake = panel_intake(appellant, "startup-appeal", 1, 0, 1, 0x95);
    let intake_digest = intake.digest().expect("startup appeal digest");
    let pop_snapshot = ModerationPoPRegistrySnapshotV1 {
        issuer_policy_digest: [0x81; 32],
        commitment_root: [0x82; 32],
        commitment_tree_version: 1,
        revocation_root: [0x83; 32],
        revocation_list_version: 1,
        registry_audit_sequence: 1,
        registry_audit_head: [0x84; 32],
        captured_at_unix_ms: 1_001_000,
    };
    ModerationAppealRecordV1 {
        intake,
        intake_digest,
        policy: policy(),
        pop_snapshot,
        pop_snapshot_digest: pop_snapshot.digest().expect("startup PoP snapshot digest"),
        status: ModerationAppealStatusV1::RegisteringJurors,
        submitted_by: account(appellant),
        submitted_at_unix_ms: 1_001_000,
        eligible_jurors: Vec::new(),
        sortition_anchor: None,
        selection: None,
        accepted_jurors: Vec::new(),
        replacements: Vec::new(),
        activated_at_unix_ms: None,
        finalized_at_unix_ms: None,
    }
}
fn startup_world_with_policy(manager: &AccountId) -> World {
    let active_policy = ModerationLedgerPolicyRecord {
        policy: policy(),
        policy_digest: policy().digest().expect("current policy digest"),
        activated_at_unix_ms: OPENED_AT,
        activated_by: manager.clone(),
    };
    let mut world = World::new();
    world.smart_contract_state.insert(
        policy_key().clone(),
        encode_state(&active_policy, "current moderation policy").expect("encode current policy"),
    );
    world
}
#[test]
fn startup_rejects_pre_cut_moderation_policy_layout() {
    let manager = account(&keypair(0x11));
    let current = ModerationLedgerPolicyRecord {
        policy: policy(),
        policy_digest: policy().digest().expect("current policy digest"),
        activated_at_unix_ms: OPENED_AT,
        activated_by: manager.clone(),
    };
    let legacy = PreCutModerationLedgerPolicyRecord {
        policy: pre_cut_policy(),
        policy_digest: [0x41; 32],
        activated_at_unix_ms: OPENED_AT,
        activated_by: manager,
    };
    let mut world = World::new();
    world.smart_contract_state.insert(
        policy_key().clone(),
        frame_pre_cut_moderation_payload(&current, &legacy),
    );
    let error = startup_error(world);
    assert!(
        error.contains(
            "incompatible persisted SoraFS moderation V1 policy/appeal/anchor/case state"
        ) && error.contains("moderation policy"),
        "startup must identify the incompatible policy layout: {error}"
    );
}
#[test]
fn startup_rejects_pre_cut_moderation_case_layout() {
    let manager = account(&keypair(0x11));
    let jurors = [account(&keypair(0x21)), account(&keypair(0x22))];
    let current_policy = policy();
    let current_policy_digest = current_policy.digest().expect("current policy digest");
    let active_policy = ModerationLedgerPolicyRecord {
        policy: current_policy,
        policy_digest: current_policy_digest,
        activated_at_unix_ms: OPENED_AT,
        activated_by: manager.clone(),
    };
    let current = ModerationCaseRecordV1 {
        spec: spec_with_policy(jurors.to_vec(), 1, &active_policy.policy),
        policy: active_policy.policy.clone(),
        status: ModerationCaseStatusV1::Open,
        opened_at_unix_ms: OPENED_AT,
        opened_by: manager.clone(),
        commitment_count: 0,
        reveal_count: 0,
        challenge_count: 0,
        challenge_ids: Vec::new(),
        pending_challenge_count: 0,
        accepted_challenge_count: 0,
        expired_challenge_count: 0,
    };
    let legacy = PreCutModerationCaseRecordV1 {
        spec: PreCutModerationCaseSpecV1 {
            version: MODERATION_LEDGER_CASE_VERSION_V1,
            context: context(&jurors, 1),
            round_id: "round-1".to_owned(),
            jurors: jurors.to_vec(),
            quorum: 1,
            commit_deadline_unix_ms: COMMIT_DEADLINE,
            challenge_deadline_unix_ms: CHALLENGE_SUBMISSION_DEADLINE,
            reveal_deadline_unix_ms: REVEAL_DEADLINE,
            policy_digest: [0x42; 32],
        },
        policy: pre_cut_policy(),
        status: ModerationCaseStatusV1::Open,
        opened_at_unix_ms: OPENED_AT,
        opened_by: manager,
        commitment_count: 0,
        reveal_count: 0,
        challenge_count: 0,
        challenge_ids: Vec::new(),
        pending_challenge_count: 0,
        accepted_challenge_count: 0,
        expired_challenge_count: 0,
    };
    let case_id = legacy.spec.context.case_id.clone();
    let round_id = legacy.spec.round_id.clone();
    let mut world = World::new();
    world.smart_contract_state.insert(
        policy_key().clone(),
        encode_state(&active_policy, "current moderation policy").expect("encode current policy"),
    );
    world.smart_contract_state.insert(
        case_key(&case_id, &round_id),
        frame_pre_cut_moderation_payload(&current, &legacy),
    );
    let error = startup_error(world);
    assert!(
        error.contains(
            "incompatible persisted SoraFS moderation V1 policy/appeal/anchor/case state"
        ) && error.contains("moderation case"),
        "startup must identify the incompatible case layout: {error}"
    );
}
#[test]
fn startup_rejects_pre_cut_moderation_appeal_layout() {
    let manager = account(&keypair(0x11));
    let appellant = keypair(0x12);
    let current = startup_registering_appeal(&appellant);
    let case_id = current.intake.case_id.clone();
    let round_id = current.intake.round_id.clone();
    let current_control = current.clone();
    let legacy = PreCutModerationAppealRecordV1 {
        intake: current.intake,
        intake_digest: current.intake_digest,
        policy: current.policy,
        pop_snapshot: current.pop_snapshot,
        pop_snapshot_digest: current.pop_snapshot_digest,
        status: current.status,
        submitted_by: current.submitted_by,
        submitted_at_unix_ms: current.submitted_at_unix_ms,
        eligible_jurors: current.eligible_jurors,
        selection: current.selection,
        accepted_jurors: current.accepted_jurors,
        replacements: current.replacements,
        activated_at_unix_ms: current.activated_at_unix_ms,
        finalized_at_unix_ms: current.finalized_at_unix_ms,
    };
    let mut world = startup_world_with_policy(&manager);
    world.smart_contract_state.insert(
        appeal_key(&case_id, &round_id),
        frame_pre_cut_moderation_payload(&current_control, &legacy),
    );
    let error = startup_error(world);
    assert!(
        error.contains("incompatible persisted SoraFS moderation V1")
            && error.contains("moderation appeal"),
        "startup must identify the incompatible appeal layout: {error}"
    );
}
#[test]
fn startup_rejects_appeal_anchor_schedule_mismatch() {
    let manager = account(&keypair(0x11));
    let appellant = keypair(0x12);
    let appeal = startup_registering_appeal(&appellant);
    let mut world = startup_world_with_policy(&manager);
    world.smart_contract_state.insert(
        appeal_key(&appeal.intake.case_id, &appeal.intake.round_id),
        encode_state(&appeal, "current moderation appeal")
            .expect("encode current moderation appeal"),
    );
    let error = startup_error(world);
    assert!(
        error.contains("incompatible persisted SoraFS moderation V1")
            && error.contains("sortition-anchor schedule does not exactly index"),
        "startup must reject an appeal/schedule mismatch: {error}"
    );
}
fn reveal(
    spec: &ModerationCaseSpecV1,
    juror: &AccountId,
    choice: SoraFsModerationVoteChoice,
    nonce_byte: u8,
) -> SoraFsModerationBallotRevealV1 {
    SoraFsModerationBallotRevealV1 {
        version: SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1,
        context: spec.context.clone(),
        round_id: spec.round_id.clone(),
        juror_id: juror.to_string(),
        choice,
        nonce: vec![nonce_byte; 32],
        revealed_at_unix_ms: 0,
    }
}
fn commit(reveal: &SoraFsModerationBallotRevealV1) -> SoraFsModerationBallotCommitV1 {
    SoraFsModerationBallotCommitV1 {
        version: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
        context: reveal.context.clone(),
        round_id: reveal.round_id.clone(),
        juror_id: reveal.juror_id.clone(),
        commitment_blake2b_256: reveal.compute_commitment(),
        committed_at_unix_ms: 0,
    }
}
fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
    norito::encode_canonical(value).expect("encode canonical fixture")
}
fn parameter_error_message(error: &InstructionExecutionError) -> &str {
    match error {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => message,
        other => panic!("expected typed smart-contract parameter rejection, got {other:?}"),
    }
}
fn encode_alternate_layout<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    norito::to_bytes(value).expect("encode alternate-layout fixture")
}
fn moderation_world(accounts: &[&KeyPair], manager: &AccountId) -> World {
    let voting_asset_id: AssetDefinitionId =
        iroha_config::parameters::defaults::governance::voting_asset_id()
            .parse()
            .expect("default governance voting asset");
    let custody_accounts = [
        iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
        iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
    ];
    let mut account_ids = accounts
        .iter()
        .map(|keypair| account(keypair))
        .collect::<Vec<_>>();
    for custody in custody_accounts {
        if !account_ids.contains(&custody) {
            account_ids.push(custody);
        }
    }
    let account_models = account_ids.into_iter().map(|id| {
        let authority = id.clone();
        Account::new(id).build(&authority)
    });
    let balance = Quantity::from(1_000_u32);
    let assets = accounts.iter().map(|keypair| {
        Asset::new(
            AssetId::new(voting_asset_id.clone(), account(keypair)),
            balance.clone(),
        )
    });
    let mut total = Quantity::zero();
    for _ in accounts {
        total = total
            .checked_add(&balance)
            .expect("moderation fixture voting-asset total remains valid");
    }
    let mut definition = AssetDefinition::numeric(
        voting_asset_id.clone(),
        "moderation challenge bond",
        AssetBalancePolicy::Global,
        None,
    )
    .build(manager);
    definition.total_quantity = total;
    let mut world = World::with_assets([], account_models, [definition], assets, []);
    let mut permissions = Permissions::new();
    for permission in [
        MANAGE_PERMISSION,
        "CanManageSorafsPopRegistry",
        "CanOperateSorafsPopIssuer",
    ] {
        permissions.insert(Permission::new(permission.to_owned(), Json::new(())));
    }
    world
        .account_permissions
        .insert(manager.clone(), permissions);
    world
}
fn state(accounts: &[&KeyPair], manager: &AccountId) -> State {
    let voting_asset_id: AssetDefinitionId =
        iroha_config::parameters::defaults::governance::voting_asset_id()
            .parse()
            .expect("default governance voting asset");
    let state = component_moderation_state(moderation_world(accounts, manager));
    assert_eq!(state.gov.voting_asset_id, voting_asset_id);
    state
}
fn component_moderation_state(world: World) -> State {
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn authenticated_moderation_state(world: World) -> State {
    use crate::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };

    let config = TestChainConfig::new(world, 0);
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let consensus_mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("prepare signed moderation genesis");
    // Consume the original unpublished State before any executor worker starts.
    // Applying its validated signed genesis establishes immutable execution authority.
    let state = std::sync::Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished moderation State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_account,
        consensus_mode.into(),
        None,
    )
    .expect("apply signed moderation genesis");
    state
}
fn voting_asset_balance(state: &State, account: &AccountId) -> Quantity {
    let id = AssetId::new(state.gov.voting_asset_id.clone(), account.clone());
    state
        .world
        .assets
        .view()
        .get(&id)
        .map(|value| value.as_ref().clone())
        .unwrap_or_else(Quantity::zero)
}
fn assert_unique_voting_asset_total(state: &State, accounts: &[AccountId], expected_total: u32) {
    let mut accounts = accounts.to_vec();
    accounts.sort_by_key(ToString::to_string);
    accounts.dedup();
    let total = accounts.iter().fold(Quantity::zero(), |total, account| {
        total
            .checked_add(&voting_asset_balance(state, account))
            .expect("moderation bond custody total remains valid")
    });
    assert_eq!(total, Quantity::from(expected_total));
}
fn assert_bond_custody_distribution(
    state: &State,
    challenger: &AccountId,
    challenger_balance: u32,
    escrow_balance: u32,
    slash_receiver_balance: u32,
) {
    let current_policy = policy();
    assert_eq!(
        voting_asset_balance(state, challenger),
        Quantity::from(challenger_balance)
    );
    assert_eq!(
        voting_asset_balance(state, &current_policy.challenge_escrow_account),
        Quantity::from(escrow_balance)
    );
    assert_eq!(
        voting_asset_balance(state, &current_policy.challenge_slash_receiver_account),
        Quantity::from(slash_receiver_balance)
    );
    let accounts = [
        challenger.clone(),
        current_policy.challenge_escrow_account,
        current_policy.challenge_slash_receiver_account,
    ];
    assert_unique_voting_asset_total(state, &accounts, 1_000);
}
#[test]
fn rejected_challenge_slash_floors_to_voting_asset_precision() {
    let amount = Quantity::from(MODERATION_CHALLENGE_BOND_AMOUNT_V1);
    assert_eq!(
        moderation_challenge_rejected_slash_amount(
            &amount,
            NumericSpec::integer(),
            MODERATION_CHALLENGE_REJECTED_SLASH_BPS_V1,
        )
        .unwrap(),
        Quantity::from(37_u32)
    );
    assert_eq!(
        moderation_challenge_rejected_slash_amount(
            &amount,
            NumericSpec::fractional(1),
            MODERATION_CHALLENGE_REJECTED_SLASH_BPS_V1,
        )
        .unwrap(),
        "37.5".parse::<Quantity>().expect("fractional slash")
    );
}
fn header(height: u64, now: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("nonzero height"),
        None,
        None,
        now,
        0,
    )
}
fn fixture_header(state: &State, height: u64, now: u64) -> BlockHeader {
    let mut result = header(height, now);
    // Raw overlay histories intentionally retain their component-only headers.
    // Native executor fixtures must follow their actual committed genesis parent.
    if crate::state::StateReadOnly::native_execution_tip(&state.view()).is_some() {
        result.prev_block_hash = state.view().latest_block_hash();
    }
    result
}
fn transact(
    state: &mut State,
    height: u64,
    now: u64,
    operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
) -> Result<(), InstructionExecutionError> {
    let call_hash = iroha_crypto::Hash::new([height.to_le_bytes(), now.to_le_bytes()].concat());
    let mut block = state.block(fixture_header(state, height, now));
    let mut transaction = block.transaction_for_fastpq_testing(call_hash);
    operation(&mut transaction)?;
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit test block");
    Ok(())
}
fn scalar(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}
fn pop_nonce(value: u128) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&value.to_le_bytes());
    bytes
}
fn public_key_bytes(keypair: &KeyPair) -> [u8; 32] {
    let (_, bytes) = keypair
        .public_key()
        .try_to_bytes()
        .expect("fixture public key bytes");
    bytes.try_into().expect("Ed25519 public key length")
}
fn empty_pop_signature(keypair: &KeyPair) -> PopSignatureV1 {
    PopSignatureV1 {
        algorithm: PopSignatureAlgorithmV1::Ed25519,
        public_key: public_key_bytes(keypair).to_vec(),
        signature: Vec::new(),
    }
}
fn sign_pop_digest(keypair: &KeyPair, digest: [u8; 32]) -> Vec<u8> {
    Signature::try_new(keypair.private_key(), &digest)
        .expect("sign PoP fixture digest")
        .payload()
        .to_vec()
}
fn sign_pop_credential(mut credential: PopCredentialV1, keypair: &KeyPair) -> PopCredentialV1 {
    credential.issuer_signature = empty_pop_signature(keypair);
    let digest =
        pop_credential_signature_digest_v1(&credential).expect("credential signature digest");
    credential.issuer_signature.signature = sign_pop_digest(keypair, digest);
    verify_pop_credential_signature_v1(&credential).expect("credential signature verifies");
    credential
}
fn sign_pop_root(mut root: PopCommitmentRootV1, keypair: &KeyPair) -> PopCommitmentRootV1 {
    root.publisher_signature = empty_pop_signature(keypair);
    let digest = pop_commitment_root_signature_digest_v1(&root).expect("root signature digest");
    root.publisher_signature.signature = sign_pop_digest(keypair, digest);
    verify_pop_commitment_root_signature_v1(&root).expect("root signature verifies");
    root
}
fn sign_pop_revocations(
    mut revocations: PopRevocationListV1,
    keypair: &KeyPair,
) -> PopRevocationListV1 {
    revocations.publisher_signature = empty_pop_signature(keypair);
    let digest =
        pop_revocation_list_signature_digest_v1(&revocations).expect("revocation signature digest");
    revocations.publisher_signature.signature = sign_pop_digest(keypair, digest);
    verify_pop_revocation_list_signature_v1(&revocations).expect("revocation signature verifies");
    revocations
}
struct PopMaterial {
    credential: PopCredentialV1,
    root: PopCommitmentRootV1,
    revocations: PopRevocationListV1,
    holder_secret: [u8; 32],
    credential_path: PopCredentialMerklePathV1,
    revocation_path: PopRevocationNonMembershipPathV1,
}
impl PopMaterial {
    fn proof(
        &self,
        challenge: [u8; 32],
        verifier_context: &str,
        presentation_binding: [u8; 32],
        now_epoch: u64,
    ) -> PopMembershipProofV1 {
        let witness = PopMembershipWitnessV1 {
            holder_secret: self.holder_secret,
            credential_path: self.credential_path.clone(),
            revocation_path: self.revocation_path.clone(),
        };
        prove_pop_membership_v1(
            &self.credential,
            &self.root,
            &self.revocations,
            &witness,
            sorafs_manifest::pop_credentials::PopMembershipPresentationV1 {
                challenge_digest: challenge,
                verifier_context,
                presentation_binding_digest: presentation_binding,
            },
            now_epoch,
        )
        .expect("create moderation PoP proof")
    }
}
fn pop_material(issuer: &KeyPair) -> PopMaterial {
    let holder_secret = scalar(0x1234_5678);
    let credential_id = scalar(0x8765_4321);
    let holder_commitment =
        derive_pop_holder_commitment_v1(holder_secret, credential_id).expect("holder commitment");
    let nonce = pop_nonce(0xfeed_beef_dead_cafe_1234_5678_9abc_def0);
    let mut credential = PopCredentialV1 {
        version: POP_CREDENTIAL_VERSION_V1,
        credential_id,
        holder_commitment,
        eligibility_class: PopEligibilityClassV1::General,
        attributes: vec![PopCredentialAttributeV1 {
            key: "residency".to_owned(),
            value_commitment: [0x13; 32],
        }],
        issuer_id: "pop-issuer-sora-foundation".to_owned(),
        issued_at_epoch: 900,
        // Eligibility must outlive the mandatory challenge-resolution grace
        // interval and reveal deadline, not only the registration window.
        expires_at_epoch: 900 + 2 * 24 * 60 * 60,
        renewal_at_epoch: 900 + 24 * 60 * 60,
        revocation_nonce: nonce,
        commitment_root: scalar(1),
        commitment_tree_version: 1,
        revocation_list_version: 1,
        issuer_signature: empty_pop_signature(issuer),
    };
    credential = sign_pop_credential(credential, issuer);
    let credential_path = PopCredentialMerklePathV1 {
        siblings: vec![scalar(0); usize::from(POP_CREDENTIAL_TREE_DEPTH_V1)],
        directions: (0..usize::from(POP_CREDENTIAL_TREE_DEPTH_V1))
            .map(|level| level % 3 == 1)
            .collect(),
    };
    let leaf = pop_credential_leaf_v1(&credential).expect("credential leaf");
    let root_digest =
        pop_credential_root_from_path_v1(leaf, &credential_path).expect("credential root");
    credential.commitment_root = root_digest;
    credential = sign_pop_credential(credential, issuer);
    let root = sign_pop_root(
        PopCommitmentRootV1 {
            version: POP_COMMITMENT_ROOT_VERSION_V1,
            root_digest,
            tree_size: 1,
            tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
            tree_version: 1,
            issuer_id: "pop-issuer-sora-foundation".to_owned(),
            published_at_epoch: 999,
            previous_root_digest: None,
            governance_event_digest: [0x17; 32],
            publisher_signature: empty_pop_signature(issuer),
        },
        issuer,
    );
    let entries = Vec::new();
    let revocation_root = pop_revocation_root_v1(&entries).expect("empty revocation root");
    let revocations = sign_pop_revocations(
        PopRevocationListV1 {
            version: POP_REVOCATION_LIST_VERSION_V1,
            list_version: 1,
            commitment_root: root_digest,
            revocation_root,
            revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
            issuer_id: "pop-issuer-sora-foundation".to_owned(),
            published_at_epoch: 999,
            entries,
            publisher_signature: empty_pop_signature(issuer),
        },
        issuer,
    );
    let revocation_path = build_pop_revocation_non_membership_path_v1(
        &revocations.entries,
        credential.revocation_nonce,
    )
    .expect("revocation non-membership path");
    PopMaterial {
        credential,
        root,
        revocations,
        holder_secret,
        credential_path,
        revocation_path,
    }
}
fn shared_pop_material() -> &'static PopMaterial {
    static MATERIAL: std::sync::OnceLock<PopMaterial> = std::sync::OnceLock::new();
    MATERIAL.get_or_init(|| pop_material(&keypair(0x51)))
}
fn proof_for_appeal(appeal: &ModerationAppealRecordV1, juror: &AccountId) -> PopMembershipProofV1 {
    static PROOF: std::sync::OnceLock<PopMembershipProofV1> = std::sync::OnceLock::new();
    let challenge =
        sorafs_moderation_pop_challenge_v1(appeal.intake_digest, appeal.pop_snapshot_digest);
    let context = sorafs_moderation_pop_verifier_context_v1(appeal.intake_digest);
    let binding = sorafs_moderation_pop_presentation_binding_v1(appeal.intake_digest, juror)
        .expect("canonical authenticated juror binding");
    let proof = PROOF.get_or_init(|| {
        shared_pop_material().proof(
            challenge,
            &context,
            binding,
            appeal.submitted_at_unix_ms / 1_000,
        )
    });
    assert_eq!(proof.challenge_digest, challenge);
    assert_eq!(proof.verifier_context, context);
    assert_eq!(proof.presentation_binding_digest, binding);
    proof.clone()
}
fn pop_policy(issuer: &KeyPair) -> PopIssuerPolicyV1 {
    PopIssuerPolicyV1 {
        version: POP_ISSUER_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        issuer_id: "pop-issuer-sora-foundation".to_owned(),
        issuer_account: account(issuer),
        issuer_public_key: public_key_bytes(issuer),
        max_credentials_per_batch: 16,
        max_revocations_per_publication: 16,
        max_credential_lifetime_secs: 2 * 24 * 60 * 60,
        max_future_clock_skew_secs: 5,
        paused: false,
    }
}
fn pop_batch(issuer: &KeyPair, material: &PopMaterial) -> PopCredentialCommitmentBatchV1 {
    let canonical_credential = encode(&material.credential);
    PopCredentialCommitmentBatchV1 {
        version: POP_CREDENTIAL_COMMITMENT_BATCH_VERSION_V1,
        issuer_policy_digest: pop_policy(issuer).digest().expect("PoP policy digest"),
        commitment_root_payload: encode(&material.root),
        revocation_list_payload: encode(&material.revocations),
        commitments: vec![PopCredentialCommitmentV1 {
            credential_commitment: pop_credential_payload_commitment_v1(&canonical_credential),
            revocation_nonce_commitment: pop_revocation_nonce_commitment_v1(
                material.credential.revocation_nonce,
            ),
            commitment_root: material.root.root_digest,
            commitment_tree_version: material.root.tree_version,
            revocation_list_version: material.revocations.list_version,
            issued_at_epoch: material.credential.issued_at_epoch,
            expires_at_epoch: material.credential.expires_at_epoch,
        }],
    }
}
fn setup_panel_foundations(state: &mut State, manager: &KeyPair, material: &PopMaterial) {
    let manager_id = account(manager);
    let height = u64::try_from(state.view().height()).expect("moderation fixture height") + 1;
    transact(state, height, 1_000_000, |transaction| {
        SetSorafsPopIssuerPolicy::new(pop_policy(manager)).execute(&manager_id, transaction)?;
        CommitSorafsPopCredentialBatch::new(encode(&pop_batch(manager, material)))
            .execute(&manager_id, transaction)?;
        SetSorafsModerationPolicy::new(policy()).execute(&manager_id, transaction)
    })
    .expect("activate PoP registry and moderation policy");
    retain_moderation_fixture_header(state, fixture_header(state, height, 1_000_000));
}
fn panel_intake(
    appellant: &KeyPair,
    case_id: &str,
    panel_size: u16,
    waitlist_size: u16,
    quorum: u16,
    deposit_byte: u8,
) -> ModerationAppealIntakeV1 {
    let appellant_id = account(appellant);
    ModerationAppealIntakeV1 {
        version: MODERATION_APPEAL_INTAKE_VERSION_V1,
        case_id: case_id.to_owned(),
        round_id: "round-1".to_owned(),
        appellant: appellant_id.clone(),
        appealed_decision_digest: [0x31; 32],
        proof_token_digest: [0x32; 32],
        evidence_bundle_digest: [0x33; 32],
        appeal_deposit_lock_digest: [deposit_byte; 32],
        appeal_finance_config_version: "finance-v1".to_owned(),
        policy_reference: "policy-v1".to_owned(),
        evidence_uri: Some("ipfs://appeal-evidence".to_owned()),
        panel_size,
        waitlist_size,
        quorum,
        exclusions: vec![appellant_id],
        registration_deadline_unix_ms: 1_003_000,
        acceptance_deadline_unix_ms: 1_005_000,
        commit_deadline_unix_ms: 1_007_000,
        challenge_submission_deadline_unix_ms: 1_009_000,
        challenge_resolution_deadline_unix_ms: 1_009_000
            + MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
        reveal_deadline_unix_ms: 1_011_000 + MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
        policy_digest: policy().digest().expect("moderation policy digest"),
    }
}
struct PanelFixture {
    manager: KeyPair,
    appellant: KeyPair,
    juror: KeyPair,
    outsider: KeyPair,
    state: State,
    next_height: u64,
}
impl PanelFixture {
    fn new() -> Self {
        Self::build(component_moderation_state)
    }
    fn with_authenticated_root() -> Self {
        Self::build(authenticated_moderation_state)
    }
    fn build(make_state: fn(World) -> State) -> Self {
        let manager = keypair(0x51);
        let appellant = keypair(0x52);
        let juror = keypair(0x61);
        let outsider = keypair(0x71);
        let manager_id = account(&manager);
        let appellant_id = account(&appellant);
        let mut world = moderation_world(&[&manager, &appellant, &juror, &outsider], &manager_id);
        let mut appellant_permissions = Permissions::new();
        appellant_permissions.insert(Permission::new(MANAGE_PERMISSION.to_owned(), Json::new(())));
        world
            .account_permissions
            .insert(appellant_id, appellant_permissions);
        let mut state = make_state(world);
        setup_panel_foundations(&mut state, &manager, shared_pop_material());
        let next_height = u64::try_from(state.view().height()).expect("panel fixture height") + 1;
        Self {
            manager,
            appellant,
            juror,
            outsider,
            state,
            next_height,
        }
    }
    fn manager_id(&self) -> AccountId {
        account(&self.manager)
    }
    fn appellant_id(&self) -> AccountId {
        account(&self.appellant)
    }
    fn juror_id(&self) -> AccountId {
        account(&self.juror)
    }
    fn outsider_id(&self) -> AccountId {
        account(&self.outsider)
    }
    fn run(
        &mut self,
        now: u64,
        operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
    ) -> Result<(), InstructionExecutionError> {
        let height = self.next_height;
        let result = transact(&mut self.state, height, now, operation);
        if result.is_ok() {
            let committed_header = fixture_header(&self.state, height, now);
            retain_moderation_fixture_header(&mut self.state, committed_header);
            self.next_height += 1;
        }
        result
    }
    fn submit(&mut self, panel_size: u16, waitlist_size: u16, quorum: u16) {
        let intake = panel_intake(
            &self.appellant,
            "panel-case",
            panel_size,
            waitlist_size,
            quorum,
            0x91,
        );
        let appellant = self.appellant_id();
        self.run(1_001_000, |transaction| {
            SubmitSorafsModerationAppeal::new(intake).execute(&appellant, transaction)
        })
        .expect("submit panel appeal");
    }
    fn appeal(&self) -> ModerationAppealRecordV1 {
        FindSorafsModerationAppeal::new("panel-case".to_owned(), "round-1".to_owned())
            .execute(&self.state.view())
            .expect("panel appeal query")
    }
    fn register_juror(&mut self) {
        let juror = self.juror_id();
        let proof = proof_for_appeal(&self.appeal(), &juror);
        self.run(1_002_000, |transaction| {
            RegisterSorafsModerationJurorEligibility::new(
                "panel-case".to_owned(),
                "round-1".to_owned(),
                encode(&proof),
            )
            .execute(&juror, transaction)
        })
        .expect("register panel juror eligibility");
    }
    fn pin_sortition_anchor(&mut self) -> ModerationSortitionAnchorV1 {
        if self.appeal().sortition_anchor.is_none() {
            self.run(1_004_000, |_| Ok(()))
                .expect("commit first post-registration anchor block");
        }
        self.appeal()
            .sortition_anchor
            .expect("consensus maintenance pinned the sortition anchor")
    }
    fn finalize_single_juror_sortition(&mut self) -> [u8; 32] {
        let manager = self.manager_id();
        let juror = self.juror_id();
        let snapshot_digest = self.appeal().pop_snapshot_digest;
        let randomness_anchor = self.pin_sortition_anchor().block_hash;
        self.run(1_004_001, |transaction| {
            FinalizeSorafsModerationSortition::new(
                "panel-case".to_owned(),
                "round-1".to_owned(),
                snapshot_digest,
                randomness_anchor,
                vec![juror],
                Vec::new(),
            )
            .execute(&manager, transaction)
        })
        .expect("finalize deterministic panel");
        self.appeal()
            .selection
            .expect("selected panel")
            .sortition_digest
    }
}
fn panel_anchor_hash(
    transaction: &StateTransaction<'_, '_>,
) -> Result<[u8; 32], InstructionExecutionError> {
    required_appeal(transaction.world(), "panel-case", "round-1")?
        .sortition_anchor
        .map(|anchor| anchor.block_hash)
        .ok_or_else(|| corrupt_state("panel fixture has no pinned sortition anchor"))
}
#[test]
fn pre_activation_appeal_retains_accounts_and_immutable_policy_asset() {
    let mut fixture = PanelFixture::new();
    let initial_signer = fixture.appellant_id();
    let member = MultisigMember::new(fixture.appellant.public_key().clone(), 1)
        .expect("valid pre-activation appellant member");
    let multisig_appellant = AccountId::new_multisig(
        MultisigPolicy::new(1, vec![member]).expect("valid pre-activation appellant policy"),
    );
    let multisig_spec = MultisigSpec {
        signatories: BTreeMap::from([(initial_signer.clone(), 1)]),
        quorum: NonZeroU16::new(1).expect("nonzero quorum"),
        transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS)
            .expect("nonzero transaction ttl"),
    };
    let registration_seed = account(&keypair(0x53));
    fixture
        .run(1_001_000, |transaction| {
            crate::smartcontracts::isi::multisig::execute_multisig_instruction(
                transaction,
                &initial_signer,
                MultisigInstructionBox::Register(MultisigRegister::with_account(
                    registration_seed,
                    None::<iroha_model_base::domain::DomainId>,
                    multisig_spec,
                )),
            )
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(error.to_string().into())
            })
        })
        .expect("register native multisig appellant");

    let mut intake = panel_intake(&fixture.appellant, "panel-case", 1, 0, 1, 0x91);
    intake.appellant = multisig_appellant.clone();
    intake.exclusions = vec![multisig_appellant.clone()];
    fixture
        .run(1_001_001, |transaction| {
            SubmitSorafsModerationAppeal::new(intake).execute(&multisig_appellant, transaction)
        })
        .expect("submit a registering appeal from the multisig appellant");
    assert_eq!(
        fixture.appeal().status,
        ModerationAppealStatusV1::RegisteringJurors
    );

    let immutable_policy = fixture.appeal().policy;
    let old_custody = immutable_policy.challenge_escrow_account.clone();
    let old_definition = immutable_policy.challenge_voting_asset_id.clone();
    let replacement_definition = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("replacement", "preactivation")
            .expect("replacement moderation domain"),
        "bond".parse().expect("replacement moderation asset name"),
    );
    let manager = fixture.manager_id();
    fixture
        .run(1_001_002, |transaction| {
            seed_moderation_policy_asset_reference_for_test(
                &mut transaction.world,
                replacement_definition,
                manager.clone(),
                manager.clone(),
            )
        })
        .expect("rotate the active policy away from every immutable appeal reference");

    let removal_error = fixture
        .run(1_001_003, |transaction| {
            Unregister::account(multisig_appellant.clone())
                .execute(&multisig_appellant, transaction)
        })
        .expect_err("registering appeal must retain its appellant account");
    assert!(
        removal_error
            .to_string()
            .contains("pre-activation appeal `panel-case`")
            && removal_error.to_string().contains("appellant"),
        "unexpected pre-activation appellant removal error: {removal_error}"
    );
    let added_signatory = fixture.outsider.public_key().clone();
    let rekey_error = fixture
        .run(1_001_003, |transaction| {
            AddSignatory::new(multisig_appellant.clone(), added_signatory)
                .execute(&multisig_appellant, transaction)
        })
        .expect_err("registering appeal appellant must not escape exclusion by rekeying");
    assert!(
        rekey_error
            .to_string()
            .contains("pre-activation appeal `panel-case`")
            && rekey_error.to_string().contains("appellant"),
        "unexpected pre-activation appellant rekey error: {rekey_error}"
    );
    let custody_error = fixture
        .run(1_001_003, |transaction| {
            Unregister::account(old_custody.clone()).execute(&old_custody, transaction)
        })
        .expect_err("registering appeal must retain its immutable policy custody");
    assert!(
        custody_error
            .to_string()
            .contains("pre-activation appeal `panel-case`")
            && custody_error
                .to_string()
                .contains("policy challenge escrow"),
        "unexpected immutable appeal custody removal error: {custody_error}"
    );
    let definition_error = fixture
        .run(1_001_003, |transaction| {
            Unregister::asset_definition(old_definition.clone()).execute(&manager, transaction)
        })
        .expect_err("immutable appeal policy must retain its voting asset definition");
    assert!(
        definition_error
            .to_string()
            .contains("immutable policy challenge voting asset"),
        "unexpected immutable appeal asset removal error: {definition_error}"
    );
    assert!(
        fixture
            .state
            .view()
            .world()
            .account(&multisig_appellant)
            .is_ok()
    );
    assert!(fixture.state.view().world().account(&old_custody).is_ok());
    assert!(
        fixture
            .state
            .view()
            .world()
            .asset_definition(&old_definition)
            .is_ok()
    );
}
#[test]
fn moderation_payload_identity_encoding_ignores_ambient_norito_flags() {
    let juror = account(&keypair(0xA3));
    let case = spec(vec![juror.clone()], 1);
    let reveal = reveal(&case, &juror, SoraFsModerationVoteChoice::Overturn, 0xA4);
    let commit = commit(&reveal);
    let canonical = encode_payload(&commit, "moderation commit").expect("encode canonical commit");
    let alternate = encode_alternate_layout(&commit);
    assert_ne!(alternate, canonical);
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let ambient_encoded = {
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let before = norito::to_bytes(&commit).expect("encode commit under caller ambient flags");
        let encoded = encode_payload(&commit, "moderation commit")
            .expect("canonicalize commit under caller ambient flags");
        let after = norito::to_bytes(&commit).expect("re-encode commit under caller ambient flags");
        assert_eq!(
            before, after,
            "canonical helper must restore the caller's ambient layout"
        );
        encoded
    };
    assert_eq!(ambient_encoded, canonical);
}
#[test]
fn moderation_membership_proof_decoder_rejects_alternate_norito_layout() {
    let mut fixture = PanelFixture::new();
    fixture.submit(1, 0, 1);
    let proof = proof_for_appeal(&fixture.appeal(), &fixture.juror_id());
    let canonical = encode(&proof);
    let alternate = encode_alternate_layout(&proof);
    assert_ne!(
        alternate, canonical,
        "fixture must exercise a distinct advertised Norito layout"
    );
    decode_from_bytes_with_limits::<PopMembershipProofV1>(&alternate, PROOF_LIMITS)
        .expect("ordinary bounded Norito accepts the advertised alternate layout");
    let error = decode_membership_proof(&alternate)
        .expect_err("alternate-layout moderation membership proof must fail");
    assert!(
        parameter_error_message(&error).contains("membership proof is not exact canonical Norito"),
        "unexpected alternate-layout proof rejection: {error:?}"
    );
}
#[test]
fn moderation_juror_registration_rejects_proof_bound_to_another_account() {
    let mut fixture = PanelFixture::with_authenticated_root();
    fixture.submit(1, 0, 1);
    let before = fixture.appeal();
    let proof = proof_for_appeal(&before, &fixture.juror_id());
    let outsider = fixture.outsider_id();
    let error = fixture
        .run(1_002_000, |transaction| {
            execute_initial(
                transaction,
                &outsider,
                RegisterSorafsModerationJurorEligibility::new(
                    "panel-case".to_owned(),
                    "round-1".to_owned(),
                    encode(&proof),
                ),
            )
        })
        .expect_err("copied proof must not let another account steal panel eligibility");
    assert!(
        matches!(error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(ref message)) if message.contains("presentation binding")),
        "unexpected copied-proof rejection: {error:?}"
    );
    assert_eq!(
        fixture.appeal(),
        before,
        "rejected copied proof changed panel eligibility"
    );
    let juror = fixture.juror_id();
    fixture
        .run(1_002_000, |transaction| {
            execute_initial(
                transaction,
                &juror,
                RegisterSorafsModerationJurorEligibility::new(
                    "panel-case".to_owned(),
                    "round-1".to_owned(),
                    encode(&proof),
                ),
            )
        })
        .expect("the exact proof recipient reaches native eligibility through Initial");
    assert_eq!(fixture.appeal().eligible_jurors, vec![fixture.juror_id()]);
}

#[test]
fn moderation_initial_executor_preserves_governance_and_signed_participant_gates() {
    use iroha_data_model::isi::InstructionBox;

    let mut fixture = PanelFixture::with_authenticated_root();
    let outsider = fixture.outsider_id();
    let manager = fixture.manager_id();
    let juror = fixture.juror_id();
    let case = spec(vec![juror.clone()], 1);
    let ballot = reveal(&case, &juror, SoraFsModerationVoteChoice::Uphold, 0xA5);
    let mut probes: Vec<(AccountId, InstructionBox, &str)> = Vec::new();
    for instruction in [
        InstructionBox::from(FinalizeSorafsModerationSortition::new(
            "absent".to_owned(),
            "round-1".to_owned(),
            [1; 32],
            [2; 32],
            vec![juror.clone()],
            vec![],
        )),
        ActivateSorafsModerationCase::new("absent".to_owned(), "round-1".to_owned(), [3; 32])
            .into(),
        ResolveSorafsModerationChallenge::new(
            "absent".to_owned(),
            "round-1".to_owned(),
            "challenge-1".to_owned(),
            ModerationChallengeDecisionV1::Rejected,
        )
        .into(),
        FinalizeSorafsModerationCase::new("absent".to_owned(), "round-1".to_owned()).into(),
    ] {
        probes.push((outsider.clone(), instruction.clone(), MANAGE_PERMISSION));
        probes.push((manager.clone(), instruction, "does not exist"));
    }
    probes.extend([
        (
            outsider.clone(),
            SubmitSorafsModerationCommit::new(encode(&commit(&ballot))).into(),
            "juror must equal the transaction authority",
        ),
        (
            outsider.clone(),
            SubmitSorafsModerationReveal::new(encode(&ballot)).into(),
            "juror must equal the transaction authority",
        ),
        (
            juror.clone(),
            AcceptSorafsModerationJurorAssignment::new(
                "absent".to_owned(),
                "round-1".to_owned(),
                [3; 32],
            )
            .into(),
            "does not exist",
        ),
        (
            outsider.clone(),
            RaiseSorafsModerationChallenge::new(
                "absent".to_owned(),
                "round-1".to_owned(),
                "challenge-1".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [4; 32],
                "evidence-mismatch".to_owned(),
            )
            .into(),
            "does not exist",
        ),
        (
            outsider.clone(),
            ExpireSorafsModerationChallenge {
                case_id: "absent".to_owned(),
                round_id: "round-1".to_owned(),
                challenge_id: "challenge-1".to_owned(),
            }
            .into(),
            "does not exist",
        ),
    ]);
    for (authority, instruction, marker) in probes {
        let before = fixture
            .state
            .view()
            .world()
            .smart_contract_state()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        let error = fixture
            .run(1_001_000, |transaction| {
                execute_initial(transaction, &authority, instruction)
            })
            .expect_err("Initial must preserve native authority and lifecycle rejection");
        assert!(
            matches!(error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(ref message)) if message.contains(marker)),
            "expected native {marker:?}, got {error:?}"
        );
        assert_eq!(
            fixture
                .state
                .view()
                .world()
                .smart_contract_state()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            before
        );
    }
    let intake = panel_intake(&fixture.appellant, "panel-case", 1, 0, 1, 0x91);
    let error = fixture
        .run(1_001_000, |transaction| {
            execute_initial(
                transaction,
                &outsider,
                SubmitSorafsModerationAppeal::new(intake.clone()),
            )
        })
        .expect_err("appellant cannot be substituted");
    assert!(
        matches!(error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(ref message)) if message.contains("appellant must equal the transaction authority"))
    );
    let appellant = fixture.appellant_id();
    fixture
        .run(1_001_000, |transaction| {
            execute_initial(
                transaction,
                &appellant,
                SubmitSorafsModerationAppeal::new(intake),
            )
        })
        .expect("authenticated appellant reaches native intake");
    assert_eq!(fixture.appeal().submitted_by, appellant);
    assert!(fixture.appeal().eligible_jurors.is_empty());
}
fn seed_activated_case(
    transaction: &mut StateTransaction<'_, '_>,
    manager: &AccountId,
    spec: ModerationCaseSpecV1,
    case_policy: ModerationLedgerPolicyV1,
) -> Result<(), InstructionExecutionError> {
    let mut eligible_jurors = spec.jurors.clone();
    eligible_jurors.sort_by_key(ToString::to_string);
    let pop_snapshot = ModerationPoPRegistrySnapshotV1 {
        issuer_policy_digest: [0x81; 32],
        commitment_root: [0x82; 32],
        commitment_tree_version: 1,
        revocation_root: [0x83; 32],
        revocation_list_version: 1,
        registry_audit_sequence: 1,
        registry_audit_head: [0x84; 32],
        captured_at_unix_ms: 700,
    };
    let intake = iroha_data_model::sorafs::moderation_ledger::ModerationAppealIntakeV1 {
        version: iroha_data_model::sorafs::moderation_ledger::MODERATION_APPEAL_INTAKE_VERSION_V1,
        case_id: spec.context.case_id.clone(),
        round_id: spec.round_id.clone(),
        appellant: manager.clone(),
        appealed_decision_digest: [0x31; 32],
        proof_token_digest: [0x32; 32],
        evidence_bundle_digest: spec.context.evidence_bundle_digest,
        appeal_deposit_lock_digest: [0x33; 32],
        appeal_finance_config_version: spec.context.appeal_finance_config_version.clone(),
        policy_reference: spec.context.policy_reference.clone(),
        evidence_uri: spec.context.evidence_uri.clone(),
        panel_size: u16::try_from(spec.jurors.len()).expect("fixture value fits u16"),
        waitlist_size: 0,
        quorum: spec.quorum,
        exclusions: vec![manager.clone()],
        registration_deadline_unix_ms: 800,
        acceptance_deadline_unix_ms: 900,
        commit_deadline_unix_ms: spec.commit_deadline_unix_ms,
        challenge_submission_deadline_unix_ms: spec.challenge_submission_deadline_unix_ms,
        challenge_resolution_deadline_unix_ms: spec.challenge_resolution_deadline_unix_ms,
        reveal_deadline_unix_ms: spec.reveal_deadline_unix_ms,
        policy_digest: spec.policy_digest,
    };
    intake
        .validate()
        .map_err(|error| corrupt_state(format!("fixture appeal invalid: {error}")))?;
    let intake_digest = intake
        .digest()
        .map_err(|error| corrupt_state(format!("fixture appeal digest: {error}")))?;
    let pop_snapshot_digest = pop_snapshot
        .digest()
        .map_err(|error| corrupt_state(format!("fixture snapshot digest: {error}")))?;
    let randomness_anchor = [0x85; 32];
    let seed_digest =
        sorafs_moderation_sortition_seed_v1(intake_digest, pop_snapshot_digest, randomness_anchor);
    let sortition_digest = sorafs_moderation_sortition_digest_v1(
        pop_snapshot_digest,
        seed_digest,
        &spec.jurors,
        &[],
        spec.quorum,
    );
    let appeal = ModerationAppealRecordV1 {
        intake,
        intake_digest,
        policy: case_policy.clone(),
        pop_snapshot,
        pop_snapshot_digest,
        status: ModerationAppealStatusV1::BallotOpen,
        submitted_by: manager.clone(),
        submitted_at_unix_ms: 700,
        eligible_jurors: eligible_jurors.clone(),
        sortition_anchor: Some(ModerationSortitionAnchorV1 {
            block_height: 1,
            block_hash: randomness_anchor,
            block_timestamp_unix_ms: 801,
        }),
        selection: Some(ModerationPanelSelectionV1 {
            randomness_anchor,
            seed_digest,
            jurors: spec.jurors.clone(),
            waitlist: Vec::new(),
            sortition_digest,
            selected_at_unix_ms: 850,
            selected_by: manager.clone(),
        }),
        accepted_jurors: eligible_jurors,
        replacements: Vec::new(),
        activated_at_unix_ms: Some(OPENED_AT),
        finalized_at_unix_ms: None,
    };
    let case = ModerationCaseRecordV1 {
        spec,
        policy: case_policy,
        status: ModerationCaseStatusV1::Open,
        opened_at_unix_ms: OPENED_AT,
        opened_by: manager.clone(),
        commitment_count: 0,
        reveal_count: 0,
        challenge_count: 0,
        challenge_ids: Vec::new(),
        pending_challenge_count: 0,
        accepted_challenge_count: 0,
        expired_challenge_count: 0,
    };
    let mut status = status_for_mutation(transaction.world(), OPENED_AT)?;
    status.appeal_intakes = 1;
    status.eligibility_proofs = case.spec.jurors.len() as u64;
    status.panel_selections = 1;
    status.assignment_acceptances = case.spec.jurors.len() as u64;
    status.open_cases = 1;
    transaction.world.smart_contract_state.insert(
        appeal_key(&case.spec.context.case_id, &case.spec.round_id),
        encode_state(&appeal, "fixture moderation appeal")?,
    );
    transaction.world.smart_contract_state.insert(
        case_key(&case.spec.context.case_id, &case.spec.round_id),
        encode_state(&case, "fixture moderation case")?,
    );
    transaction
        .world
        .smart_contract_state
        .insert(status_key().clone(), encode_status(&status)?);
    Ok(())
}
struct Fixture {
    manager: KeyPair,
    jurors: [KeyPair; 3],
    outsider: KeyPair,
    state: State,
    spec: ModerationCaseSpecV1,
    next_height: u64,
}
impl Fixture {
    fn new(quorum: u16) -> Self {
        Self::new_with_policy(quorum, policy())
    }
    fn new_with_policy(quorum: u16, case_policy: ModerationLedgerPolicyV1) -> Self {
        let manager = keypair(0x11);
        let jurors = [keypair(0x21), keypair(0x22), keypair(0x23)];
        let outsider = keypair(0x31);
        let manager_id = account(&manager);
        let juror_ids = jurors.iter().map(account).collect::<Vec<_>>();
        let spec = spec_with_policy(juror_ids, quorum, &case_policy);
        let mut state = state(
            &[&manager, &jurors[0], &jurors[1], &jurors[2], &outsider],
            &manager_id,
        );
        state.gov.bond_escrow_account = case_policy.challenge_escrow_account.clone();
        state.gov.slash_receiver_account = case_policy.challenge_slash_receiver_account.clone();
        transact(&mut state, 1, OPENED_AT, |transaction| {
            SetSorafsModerationPolicy::new(case_policy.clone())
                .execute(&manager_id, transaction)?;
            seed_activated_case(transaction, &manager_id, spec.clone(), case_policy.clone())
        })
        .expect("activate policy and open case");
        retain_moderation_fixture_header(&mut state, header(1, OPENED_AT));
        Self {
            manager,
            jurors,
            outsider,
            state,
            spec,
            next_height: 2,
        }
    }
    fn manager_id(&self) -> AccountId {
        account(&self.manager)
    }
    fn juror_id(&self, index: usize) -> AccountId {
        account(&self.jurors[index])
    }
    fn run(
        &mut self,
        now: u64,
        operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
    ) -> Result<(), InstructionExecutionError> {
        let height = self.next_height;
        let result = transact(&mut self.state, height, now, operation);
        if result.is_ok() {
            retain_moderation_fixture_header(&mut self.state, header(height, now));
            self.next_height += 1;
        }
        result
    }
}
#[test]
fn persisted_current_moderation_policy_and_case_validate_at_startup() {
    let fixture = Fixture::new(1);
    validate_persisted_moderation_schema_v1(&fixture.state.world.view())
        .expect("current first-release moderation state must validate");
}
#[test]
fn successful_commit_reveal_finalization_persists_queries_and_no_show() {
    let mut fixture = Fixture::new(2);
    let juror0 = fixture.juror_id(0);
    let juror1 = fixture.juror_id(1);
    let juror2 = fixture.juror_id(2);
    let reveal0 = reveal(
        &fixture.spec,
        &juror0,
        SoraFsModerationVoteChoice::Uphold,
        1,
    );
    let reveal1 = reveal(
        &fixture.spec,
        &juror1,
        SoraFsModerationVoteChoice::Uphold,
        2,
    );
    let commit0 = commit(&reveal0);
    let commit1 = commit(&reveal1);
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&commit0)).execute(&juror0, transaction)?;
            SubmitSorafsModerationCommit::new(encode(&commit1)).execute(&juror1, transaction)
        })
        .unwrap();
    fixture
        .run(REVEAL_AT, |transaction| {
            SubmitSorafsModerationReveal::new(encode(&reveal0)).execute(&juror0, transaction)?;
            SubmitSorafsModerationReveal::new(encode(&reveal1)).execute(&juror1, transaction)
        })
        .unwrap();
    let manager = fixture.manager_id();
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .unwrap();
    let case = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(case.status, ModerationCaseStatusV1::Finalized);
    assert_eq!(case.commitment_count, 2);
    assert_eq!(case.reveal_count, 2);
    let outcome = FindSorafsModerationOutcome::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(
        outcome.kind,
        ModerationOutcomeKindV1::Decided(SoraFsModerationVoteChoice::Uphold)
    );
    assert_eq!(outcome.votes_total, 2);
    assert_eq!(outcome.no_show_count, 1);
    let no_show =
        FindSorafsModerationNoShow::new("case-1".to_owned(), "round-1".to_owned(), juror2)
            .execute(&fixture.state.view())
            .unwrap();
    assert_eq!(no_show.kind, ModerationNoShowKindV1::MissingCommit);
    assert_eq!(no_show.penalty_points, 11);
    assert!(
        FindSorafsModerationNoShow::new("case-1".to_owned(), "round-1".to_owned(), juror0,)
            .execute(&fixture.state.view())
            .is_err()
    );
    let status = FindSorafsModerationStatus
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(status.open_cases, 0);
    assert_eq!(status.finalized_cases, 1);
    assert_eq!(status.commitments, 2);
    assert_eq!(status.reveals, 2);
    assert_eq!(status.outcomes, 1);
    assert_eq!(status.no_shows, 1);
}
#[test]
fn duplicate_wrong_authority_phase_and_mismatched_reveal_are_atomic() {
    let mut fixture = Fixture::new(1);
    let juror = fixture.juror_id(0);
    let outsider = account(&fixture.outsider);
    let juror_reveal = reveal(
        &fixture.spec,
        &juror,
        SoraFsModerationVoteChoice::Overturn,
        3,
    );
    let juror_commit = commit(&juror_reveal);
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&juror_commit)).execute(&juror, transaction)
        })
        .unwrap();
    assert!(
        fixture
            .run(1_501, |transaction| {
                SubmitSorafsModerationCommit::new(encode(&juror_commit))
                    .execute(&juror, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(1_501, |transaction| {
                SubmitSorafsModerationCommit::new(encode(&juror_commit))
                    .execute(&outsider, transaction)
            })
            .is_err()
    );
    let other = fixture.juror_id(1);
    let other_reveal = reveal(&fixture.spec, &other, SoraFsModerationVoteChoice::Uphold, 4);
    let other_commit = commit(&other_reveal);
    assert!(
        fixture
            .run(2_001, |transaction| {
                SubmitSorafsModerationCommit::new(encode(&other_commit))
                    .execute(&other, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(2_500, |transaction| {
                SubmitSorafsModerationReveal::new(encode(&juror_reveal))
                    .execute(&juror, transaction)
            })
            .is_err()
    );
    let mut mismatched = juror_reveal.clone();
    mismatched.choice = SoraFsModerationVoteChoice::Modify;
    assert!(
        fixture
            .run(REVEAL_AT, |transaction| {
                SubmitSorafsModerationReveal::new(encode(&mismatched)).execute(&juror, transaction)
            })
            .is_err()
    );
    fixture
        .run(REVEAL_AT, |transaction| {
            SubmitSorafsModerationReveal::new(encode(&juror_reveal)).execute(&juror, transaction)
        })
        .unwrap();
    assert!(
        fixture
            .run(REVEAL_AT + 1, |transaction| {
                SubmitSorafsModerationReveal::new(encode(&juror_reveal))
                    .execute(&juror, transaction)
            })
            .is_err()
    );
    let case = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(case.commitment_count, 1);
    assert_eq!(case.reveal_count, 1);
    let status = FindSorafsModerationStatus
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(status.commitments, 1);
    assert_eq!(status.reveals, 1);
}
#[test]
fn challenge_submission_deadline_is_inclusive_and_one_tick_later_is_atomic() {
    let mut at_deadline = Fixture::new(1);
    let challenger = account(&at_deadline.outsider);
    at_deadline
        .run(CHALLENGE_SUBMISSION_DEADLINE, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-at-deadline".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x61; 32],
                "submitted at the exact deadline".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .expect("the challenge submission deadline is inclusive");
    let challenge = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-at-deadline".to_owned(),
    )
    .execute(&at_deadline.state.view())
    .expect("deadline challenge is retained");
    assert_eq!(challenge.raised_at_unix_ms, CHALLENGE_SUBMISSION_DEADLINE);
    assert_bond_custody_distribution(&at_deadline.state, &challenger, 850, 150, 150);

    let mut after_deadline = Fixture::new(1);
    let late_challenger = account(&after_deadline.outsider);
    let case_before = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&after_deadline.state.view())
        .expect("fixture case");
    let status_before = FindSorafsModerationStatus
        .execute(&after_deadline.state.view())
        .expect("fixture status");
    let error = after_deadline
        .run(CHALLENGE_SUBMISSION_DEADLINE + 1, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-after-deadline".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x62; 32],
                "submitted one tick too late".to_owned(),
            )
            .execute(&late_challenger, transaction)
        })
        .expect_err("one tick after the deadline must reject");
    assert!(
        parameter_error_message(&error).contains("challenge phase is closed"),
        "unexpected deadline error: {error}"
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&after_deadline.state.view())
            .expect("fixture case after rejection"),
        case_before
    );
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&after_deadline.state.view())
            .expect("fixture status after rejection"),
        status_before
    );
    assert!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-after-deadline".to_owned(),
        )
        .execute(&after_deadline.state.view())
        .is_err()
    );
    assert_bond_custody_distribution(&after_deadline.state, &late_challenger, 1_000, 0, 0);
}
#[test]
fn challenge_funding_uses_case_pinned_custody_after_live_governance_rotation() {
    let pinned_escrow = account(&keypair(0x22));
    let pinned_slash_receiver = account(&keypair(0x23));
    let pinned_policy = policy_with_custody(pinned_escrow.clone(), pinned_slash_receiver.clone());
    let mut fixture = Fixture::new_with_policy(1, pinned_policy.clone());
    let challenger = account(&fixture.outsider);
    let rotated_escrow = fixture.juror_id(0);
    let rotated_slash_receiver = fixture.manager_id();
    assert_ne!(pinned_escrow, pinned_slash_receiver);
    assert_ne!(rotated_escrow, rotated_slash_receiver);
    for pinned in [&pinned_escrow, &pinned_slash_receiver] {
        assert_ne!(pinned, &rotated_escrow);
        assert_ne!(pinned, &rotated_slash_receiver);
    }
    fixture.state.gov.bond_escrow_account = rotated_escrow.clone();
    fixture.state.gov.slash_receiver_account = rotated_slash_receiver.clone();

    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-pinned-policy".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x7A; 32],
                "case policy remains authoritative after configuration rotation".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .expect("challenge funding must use the immutable case-policy snapshot");

    let record = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-pinned-policy".to_owned(),
    )
    .execute(&fixture.state.view())
    .expect("query challenge funded under the pinned policy");
    assert_eq!(
        record.bond.asset_definition_id,
        pinned_policy.challenge_voting_asset_id
    );
    assert_eq!(
        record.bond.escrow_account,
        pinned_policy.challenge_escrow_account
    );
    assert_eq!(
        record.bond.slash_receiver_account,
        pinned_policy.challenge_slash_receiver_account
    );
    assert_eq!(record.bond.amount, pinned_policy.challenge_bond_amount);
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(850_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &pinned_escrow),
        Quantity::from(1_150_u32),
        "the old pinned escrow receives the bond"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &pinned_slash_receiver),
        Quantity::from(1_000_u32),
        "funding must not confuse the distinct pinned slash receiver with escrow"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &rotated_escrow),
        Quantity::from(1_000_u32),
        "the distinct replacement escrow must not receive the pinned bond"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &rotated_slash_receiver),
        Quantity::from(1_000_u32),
        "the distinct replacement slash receiver must not receive the pinned bond"
    );

    let manager = fixture.manager_id();
    fixture
        .run(2_600, |transaction| {
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-pinned-policy".to_owned(),
                ModerationChallengeDecisionV1::Rejected,
            )
            .execute(&manager, transaction)
        })
        .expect("rejected settlement must keep using the distinct pinned custody roles");
    let record = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-pinned-policy".to_owned(),
    )
    .execute(&fixture.state.view())
    .expect("query challenge after pinned settlement");
    assert_eq!(
        record.decision,
        Some(ModerationChallengeDecisionV1::Rejected)
    );
    assert_eq!(record.bond.refunded_amount, Quantity::from(113_u32));
    assert_eq!(record.bond.slashed_amount, Quantity::from(37_u32));
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(963_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &pinned_escrow),
        Quantity::from(1_000_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &pinned_slash_receiver),
        Quantity::from(1_037_u32),
        "the slash must reach the old pinned slash receiver"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &rotated_escrow),
        Quantity::from(1_000_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &rotated_slash_receiver),
        Quantity::from(1_000_u32)
    );
    assert_unique_voting_asset_total(
        &fixture.state,
        &[
            challenger,
            pinned_escrow,
            pinned_slash_receiver,
            rotated_escrow,
            rotated_slash_receiver,
        ],
        5_000,
    );
}
#[test]
fn pending_bond_liability_blocks_transfer_and_burn_but_allows_exact_excess() {
    let mut fixture = Fixture::new(1);
    let manager = fixture.manager_id();
    let challenger = account(&fixture.outsider);
    let second_challenger = fixture.juror_id(0);
    let current_policy = policy();
    let escrow = current_policy.challenge_escrow_account.clone();
    assert_ne!(
        manager, escrow,
        "fixture funder must not be the custody account"
    );
    let definition = fixture.state.gov.voting_asset_id.clone();

    fixture
        .run(2_400, |transaction| {
            Transfer::asset_quantity(
                AssetId::new(definition.clone(), manager.clone()),
                10_u32,
                escrow.clone(),
            )
            .execute(&manager, transaction)
        })
        .expect("fund ten units above the pending-bond reserve");
    for (authority, challenge_id, evidence) in [
        (challenger.clone(), "challenge-reserve-a", [0x81; 32]),
        (second_challenger.clone(), "challenge-reserve-b", [0x82; 32]),
    ] {
        fixture
            .run(2_500, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    challenge_id.to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    evidence,
                    "exercise aggregate custody reserve".to_owned(),
                )
                .execute(&authority, transaction)
            })
            .expect("raise a distinct bonded challenge");
    }
    let escrow_asset = AssetId::new(definition, escrow.clone());
    assert_eq!(
        unsettled_moderation_bond_liability(&fixture.state.world.view(), &escrow_asset)
            .expect("sum retained bond liabilities"),
        Quantity::from(300_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &escrow),
        Quantity::from(310_u32)
    );

    let cumulative_batch_error = fixture
        .run(2_501, |transaction| {
            TransferAssetBatch::new(vec![
                TransferAssetBatchEntry::with_leg_id(
                    "reserve-leg-a",
                    escrow.clone(),
                    manager.clone(),
                    escrow_asset.definition().clone(),
                    6_u32,
                ),
                TransferAssetBatchEntry::with_leg_id(
                    "reserve-leg-b",
                    escrow.clone(),
                    challenger.clone(),
                    escrow_asset.definition().clone(),
                    6_u32,
                ),
            ])
            .execute(&escrow, transaction)
        })
        .expect_err("atomic batch aggregate must reject cumulative depletion below bond liability");
    assert!(
        cumulative_batch_error
            .to_string()
            .contains("must retain unsettled bond liability"),
        "unexpected cumulative reserve error: {cumulative_batch_error}"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &escrow),
        Quantity::from(310_u32),
        "rejected cumulative reserve batch must preserve custody"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &manager),
        Quantity::from(990_u32),
        "rejected cumulative reserve batch must roll back its first leg"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(850_u32),
        "rejected cumulative reserve batch must not credit its second leg"
    );

    fixture
        .run(2_501, |transaction| {
            Transfer::asset_quantity(escrow_asset.clone(), 10_u32, manager.clone())
                .execute(&escrow, transaction)
        })
        .expect("the exact balance above aggregate liability remains transferable");
    assert_eq!(
        voting_asset_balance(&fixture.state, &escrow),
        Quantity::from(300_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &manager),
        Quantity::from(1_000_u32)
    );

    let manager_before = voting_asset_balance(&fixture.state, &manager);
    let transfer_error = fixture
        .run(2_502, |transaction| {
            Transfer::asset_quantity(escrow_asset.clone(), 1_u32, manager.clone())
                .execute(&escrow, transaction)
        })
        .expect_err("ordinary transfer cannot consume unsettled bond principal");
    assert!(
        transfer_error
            .to_string()
            .contains("must retain unsettled bond liability"),
        "unexpected custody-transfer error: {transfer_error}"
    );
    let burn_error = fixture
        .run(2_503, |transaction| {
            Burn::asset_quantity(1_u32, escrow_asset.clone()).execute(&escrow, transaction)
        })
        .expect_err("ordinary burn cannot consume unsettled bond principal");
    assert!(
        burn_error
            .to_string()
            .contains("must retain unsettled bond liability"),
        "unexpected custody-burn error: {burn_error}"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &escrow),
        Quantity::from(300_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &manager),
        manager_before
    );

    fixture
        .run(2_900, |transaction| {
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-reserve-a".to_owned(),
                ModerationChallengeDecisionV1::Accepted,
            )
            .execute(&manager, transaction)
        })
        .expect("accepted challenge refunds through its typed settlement path");
    fixture
        .run(2_901, |transaction| {
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-reserve-b".to_owned(),
                ModerationChallengeDecisionV1::Rejected,
            )
            .execute(&manager, transaction)
        })
        .expect("two-leg rejected settlement consumes only its own retained bond");
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .expect("finalize the case before rotating the active policy reference");
    let replacement_definition = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("replacement", "moderation")
            .expect("replacement domain"),
        "bond".parse().expect("replacement asset name"),
    );
    fixture
        .run(FINALIZE_AT + 1, |transaction| {
            seed_moderation_policy_asset_reference_for_test(
                &mut transaction.world,
                replacement_definition,
                manager.clone(),
                manager.clone(),
            )
        })
        .expect("rotate the active policy away from the historical bond definition");
    assert_eq!(
        unsettled_moderation_bond_liability(&fixture.state.world.view(), &escrow_asset)
            .expect("all challenge liabilities are settled"),
        Quantity::zero()
    );
    let historical_reference = retained_moderation_asset_definition_reference(
        &fixture.state.world.view(),
        escrow_asset.definition(),
    )
    .expect("validate retained historical challenge")
    .expect("immutable appeal policy must retain its historical definition");
    assert!(
        historical_reference.contains("immutable policy challenge voting asset"),
        "historical retention must include the immutable appeal policy after rotation: {historical_reference}"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &escrow),
        Quantity::from(37_u32),
        "the default slash receiver is the escrow account, so only the exact slash remains"
    );
}
