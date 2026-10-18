use super::*;
include!("sorafs/permission_token_tests.rs");
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use blake3::hash as blake3_hash;
use core::str::FromStr;
use hex;
use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, Signature, SignatureOf};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            ApplySorafsRepairTaskAction, ApprovePinManifest, BindManifestAlias,
            CompleteReplicationOrder, EstablishSorafsProviderOwnerV1, ExpireReplicationOrder,
            IssueReplicationOrder, RebindSorafsProviderOwnerV1, RecordCapacityTelemetry,
            RegisterCapacityDeclaration, RegisterCapacityDispute, RegisterPinManifest,
            RegisterProviderOwner, RemoveSorafsProviderOwnerV1, RetirePinManifest,
            ReviseReplicationOrderAssignments, RevokeProviderIngestCompletionAuthority,
            SetPricingSchedule, SetProviderIngestCompletionAuthority,
            SorafsProviderGovernanceActionV1, SorafsRepairClaimV1, SorafsRepairCompleteV1,
            SorafsRepairEscalateV1, SorafsRepairFailV1, SorafsRepairRenewV1,
            SorafsRepairTaskActionV1, SubmitSorafsRepairAppeal, SubmitSorafsRepairTask,
            UnregisterProviderOwner, UpsertProviderCredit,
        },
    },
    musubi::{
        ArchiveId, MUSUBI_REGISTRY_VERSION_V1, MusubiArchiveCommitmentV1,
        MusubiArchiveLocationIdV1, MusubiArchiveRecordV1, MusubiContentDigestV1,
        MusubiReplicationOrderLocationLifecycleV1, MusubiSeedIngressReceiptApprovalV1,
        MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptPayloadV1,
        MusubiSeedIngressReceiptV1, MusubiSemanticReleaseDigestV1,
    },
    permission::{Permission as AccountPermission, Permissions},
    prelude::{Account, AccountId, Asset, AssetDefinition, AssetId, Domain},
    query::error::FindError,
    sorafs::{
        capacity::{
            CapacityDisputeEvidence, CapacityDisputeId, CapacityDisputeRecord,
            CapacityDisputeStatus, CapacityFeeLedgerEntry, ProviderId,
        },
        pin_registry::{
            ChunkerProfileHandle, ManifestAliasBinding, ManifestAliasId, ManifestDigest,
            PinManifestRecord, PinPolicy, PinStatus, ProviderIngestCompletionAuthorityV1,
            ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
            ReplicationOrderId, ReplicationOrderStatus, StorageClass,
        },
        pricing::{
            CollateralPolicy, CreditPolicy, PricingScheduleRecord, ProviderCreditRecord,
            SECONDS_PER_BILLING_MONTH, TierRate,
        },
        reputation::{
            REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1, ReputationJournalAuthorityPolicyV1,
        },
    },
};
use iroha_executor_data_model::permission::sorafs::CanOperateSorafsRepair;
use iroha_model_base::{domain::DomainId, metadata::Metadata, name::Name};
use iroha_primitives::{bigint::BigInt, json::Json};
use nonzero_ext::nonzero;
use norito::{json, to_bytes};
use sorafs_manifest::{
    DagCodecId, GovernanceProofs, ManifestBuilder, ManifestV1,
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CAPACITY_DISPUTE_VERSION_V1, CapacityDeclarationV1,
        CapacityDisputeKind, CapacityDisputeV1, CapacityMetadataEntry, ChunkerCommitmentV1,
        REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1,
        ReplicationOrderV1,
    },
    pin_registry::{
        AliasBindingV1, AliasProofBundleV1, alias_merkle_root, alias_proof_signature_digest,
    },
    provider_advert::{CapabilityType, StakePointer},
    repair::{
        REPAIR_EVIDENCE_VERSION_V1, REPAIR_REPORT_VERSION_V1, REPAIR_SLASH_PROPOSAL_VERSION_V1,
        RepairCauseV1, RepairEvidenceV1, RepairManualCauseV1,
    },
};
use std::{collections::BTreeSet, convert::TryInto};
fn canonical_profile(handle: &ChunkerProfileHandle) -> String {
    format!("{}.{}@{}", handle.namespace, handle.name, handle.semver)
}
fn build_envelope(record: &PinManifestRecord, keypair: &KeyPair) -> (Vec<u8>, String) {
    let manifest_hex = hex::encode(record.digest.as_bytes());
    let chunk_hex = hex::encode(record.chunk_digest_sha3_256);
    let profile = canonical_profile(&record.chunker);
    let signature = Signature::try_new(keypair.private_key(), record.digest.as_bytes())
        .expect("council envelope fixture should sign");
    let signature_hex = hex::encode(signature.payload());
    let public_key = keypair.public_key();
    let (_, signer_bytes) = public_key
        .try_to_bytes()
        .expect("fixture public key must be valid");
    let signer_hex = hex::encode(signer_bytes);
    let signer_multihash = public_key.to_string();
    let mut signature_entry = json::Map::new();
    signature_entry.insert("algorithm".into(), json::Value::from("ed25519"));
    signature_entry.insert("signer".into(), json::Value::from(signer_hex));
    signature_entry.insert("signature".into(), json::Value::from(signature_hex.clone()));
    signature_entry.insert(
        "signer_multihash".into(),
        json::Value::from(signer_multihash.clone()),
    );
    let signatures = json::Value::Array(vec![json::Value::Object(signature_entry)]);
    let mut envelope_map = json::Map::new();
    envelope_map.insert("chunk_digest_sha3_256".into(), json::Value::from(chunk_hex));
    envelope_map.insert("manifest_blake3".into(), json::Value::from(manifest_hex));
    envelope_map.insert("profile".into(), json::Value::from(profile));
    envelope_map.insert("signatures".into(), signatures);
    let envelope = json::Value::Object(envelope_map);
    let mut serialized = json::to_vec_pretty(&envelope).expect("serialize council envelope");
    serialized.push(b'\n');
    (serialized, signature_hex)
}
fn council_approval_signer(
    signer_id: &str,
    keypair: &KeyPair,
    valid_from_block_height: u64,
    revoked_at_block_height: Option<u64>,
) -> iroha_config::parameters::actual::SorafsPinApprovalSigner {
    iroha_config::parameters::actual::SorafsPinApprovalSigner {
        signer_id: signer_id.to_owned(),
        public_key: keypair.public_key().clone(),
        valid_from_block_height,
        revoked_at_block_height,
    }
}
fn council_approval_policy(
    quorum: u16,
    mut signers: Vec<iroha_config::parameters::actual::SorafsPinApprovalSigner>,
) -> iroha_config::parameters::actual::SorafsPinPolicyConstraints {
    signers.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    iroha_config::parameters::actual::SorafsPinPolicyConstraints {
        require_council_signatures: true,
        approval_quorum: quorum,
        approval_signers: signers,
        ..Default::default()
    }
}
// Establish trusted approval keys before an execution scope captures its policy.
// Keep automatic registration unchanged for the explicit auto-approval regressions.
fn set_council_approval_signers(
    state: &mut State,
    quorum: u16,
    signers: Vec<iroha_config::parameters::actual::SorafsPinApprovalSigner>,
) {
    let policy = council_approval_policy(quorum, signers);
    state.gov.sorafs_pin_policy.approval_quorum = policy.approval_quorum;
    state.gov.sorafs_pin_policy.approval_signers = policy.approval_signers;
}
fn set_council_approval_policy(
    state: &mut State,
    quorum: u16,
    signers: Vec<iroha_config::parameters::actual::SorafsPinApprovalSigner>,
) {
    set_council_approval_signers(state, quorum, signers);
    state.gov.sorafs_pin_policy.require_council_signatures = true;
}
fn registered_manifest_approval_envelope(
    state_transaction: &mut StateTransaction<'_, '_>,
    council_key: &KeyPair,
) -> (Vec<u8>, String, String) {
    seed_automatic_replication_capacity(state_transaction, default_policy().min_replicas);
    RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), state_transaction)
    .expect("register manifest");
    let stored_record = state_transaction
        .world
        .pin_manifests
        .get(&default_digest())
        .expect("manifest stored")
        .clone();
    let (_, signer_bytes) = council_key
        .public_key()
        .try_to_bytes()
        .expect("council signer key bytes");
    let signer_hex = hex::encode(signer_bytes);
    let (envelope, signature_hex) = build_envelope(&stored_record, council_key);
    (envelope, signature_hex, signer_hex)
}
fn rejected_manifest_approval_message(
    state_transaction: &mut StateTransaction<'_, '_>,
    council_envelope: Vec<u8>,
    council_envelope_digest: Option<[u8; 32]>,
    expectation: &str,
) -> String {
    let error = ApprovePinManifest {
        digest: default_digest(),
        council_envelope: Some(council_envelope),
        council_envelope_digest,
    }
    .execute(&alice(), state_transaction)
    .expect_err(expectation);
    match error {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => message,
        other => panic!("unexpected manifest approval error: {other:?}"),
    }
}
fn council_envelope_error(
    record: &PinManifestRecord,
    envelope: &[u8],
    policy: &iroha_config::parameters::actual::SorafsPinPolicyConstraints,
    executing_block_height: u64,
) -> String {
    match verify_council_envelope(record, envelope, policy, executing_block_height)
        .expect_err("adversarial council envelope must fail")
    {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => message,
        other => panic!("unexpected council envelope error: {other:?}"),
    }
}
const SMALL_ORDER_ED25519_R: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const NONCANONICAL_ED25519_R: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
fn checked_keypair() -> KeyPair {
    KeyPair::try_random().expect("SoraFS fixture key generation should succeed")
}
fn checked_ed25519_keypair() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("SoraFS Ed25519 fixture key generation should succeed")
}
fn xor_quantity_nanos(value: u128) -> Quantity {
    let nanos_per_xor = Quantity::from(1_000_000_000_u64);
    Quantity::from(value)
        .try_div_decimal_exact(nanos_per_xor.as_numeric())
        .expect("u128 nano-XOR test fixture fits Quantity")
}
fn exact_xor_nanos(value: &Quantity) -> u128 {
    let nanos = value
        .try_mul_decimal(&Numeric::from(1_000_000_000_u64))
        .expect("SoraFS XOR quantity scales exactly to nanounits");
    assert_eq!(nanos.scale(), 0, "SoraFS XOR quantity is nano-exact");
    nanos
        .as_numeric()
        .try_mantissa_u128()
        .expect("bounded non-negative XOR nanounits fit u128")
}
fn max_positive_quantity() -> Quantity {
    let mut bytes = [0xff; 64];
    bytes[63] = 0x7f;
    Quantity::from_canonical_numeric(Numeric::new(
        BigInt::from_twos_bytes(&bytes).expect("512-bit positive mantissa fits"),
        0,
    ))
    .expect("maximum positive Numeric is a Quantity")
}
fn provider_credit_nanos(
    provider_id: ProviderId,
    available_credit_nanos: u128,
    bonded_nanos: u128,
) -> ProviderCreditRecord {
    ProviderCreditRecord::new(
        provider_id,
        xor_quantity_nanos(available_credit_nanos),
        xor_quantity_nanos(bonded_nanos),
        Quantity::zero(),
        Quantity::zero(),
        0,
        0,
        Metadata::default(),
    )
}
fn replace_test_tier(schedule: &mut PricingScheduleRecord, replacement: TierRate) {
    let storage_class = replacement.storage_class;
    let tier = schedule
        .tiers
        .iter_mut()
        .find(|tier| tier.storage_class == storage_class)
        .expect("launch schedule contains every storage class");
    *tier = replacement;
}
include!("sorafs/core_ratio_and_repair_tests.rs");
#[test]
fn repair_committed_event_query_returns_anchored_empty_page_for_proven_empty_state() {
    let mut state = make_state();
    let header = repair_block_header(1, 4_000_000);
    let block_hash = iroha_crypto::HashOf::new(&header);
    state.push_block_hash_for_testing(block_hash);
    let page = FindSorafsRepairEvents::new(None, None, 10)
        .execute(&state.view())
        .expect("proven-empty repair state has an anchored empty event page");
    assert_eq!(page.finalized_cursor.height, 1);
    assert_eq!(page.finalized_cursor.block_hash, *block_hash.as_ref());
    assert!(page.events.is_empty());
    assert!(!page.has_more);
    assert!(page.next_after.is_none());
}
fn repair_report(
    ticket_id: &str,
    provider_id: ProviderId,
    manifest_digest: [u8; 32],
    auditor: &AccountId,
    submitted_at_unix: u64,
) -> RepairReportV1 {
    RepairReportV1 {
        version: REPAIR_REPORT_VERSION_V1,
        ticket_id: RepairTicketId(ticket_id.to_owned()),
        auditor_account: auditor.to_string(),
        submitted_at_unix,
        evidence: RepairEvidenceV1 {
            version: REPAIR_EVIDENCE_VERSION_V1,
            manifest_digest,
            provider_id: *provider_id.as_bytes(),
            por_history_id: None,
            cause: RepairCauseV1::Manual(RepairManualCauseV1 {
                reason: "chain-authoritative test".to_owned(),
            }),
            evidence_json: None,
            notes: None,
        },
        notes: None,
    }
}
fn repair_report_payloads_at_ledger_boundary(report: &RepairReportV1) -> (Vec<u8>, Vec<u8>) {
    let encode_with_padding = |padding: usize| {
        let mut candidate = report.clone();
        candidate.evidence.evidence_json = Some(format!("\"{}\"", "x".repeat(padding)));
        candidate
            .validate()
            .expect("boundary repair report remains semantically valid");
        to_bytes(&candidate).expect("encode boundary repair report")
    };
    let mut largest_accepted_padding = 0_usize;
    let mut first_rejected_padding = REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1;
    while encode_with_padding(first_rejected_padding).len()
        <= REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1
    {
        first_rejected_padding = first_rejected_padding
            .checked_mul(2)
            .expect("repair report boundary search remains bounded");
    }
    while largest_accepted_padding + 1 < first_rejected_padding {
        let candidate_padding =
            largest_accepted_padding + (first_rejected_padding - largest_accepted_padding) / 2;
        if encode_with_padding(candidate_padding).len()
            <= REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1
        {
            largest_accepted_padding = candidate_padding;
        } else {
            first_rejected_padding = candidate_padding;
        }
    }
    let largest_accepted = encode_with_padding(largest_accepted_padding);
    let first_rejected = encode_with_padding(first_rejected_padding);
    assert_eq!(
        first_rejected_padding,
        largest_accepted_padding + 1,
        "boundary search finds adjacent valid report payloads"
    );
    assert!(largest_accepted.len() <= REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1);
    assert!(first_rejected.len() > REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1);
    (largest_accepted, first_rejected)
}
fn grant_repair_operator(state: &mut State, account: &AccountId, provider_id: ProviderId) {
    let permission = AccountPermission::from(CanOperateSorafsRepair { provider_id });
    let mut permissions = {
        let view = state.world.account_permissions.view();
        view.get(account)
            .cloned()
            .unwrap_or_else(Permissions::default)
    };
    permissions.insert(permission);
    state
        .world
        .account_permissions
        .insert(account.clone(), permissions);
}
fn revoke_repair_operator(state: &mut State, account: &AccountId, provider_id: ProviderId) {
    let permission = AccountPermission::from(CanOperateSorafsRepair { provider_id });
    let mut permissions = {
        let view = state.world.account_permissions.view();
        view.get(account)
            .cloned()
            .unwrap_or_else(Permissions::default)
    };
    assert!(
        permissions.remove(&permission),
        "repair operator fixture permission must exist before revocation"
    );
    state
        .world
        .account_permissions
        .insert(account.clone(), permissions);
}
pub(super) fn make_state() -> State {
    let kura = Kura::blank_kura_for_testing();
    let handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, handle);
    seed_public_pin_fee_accounts(&mut state);
    seed_sorafs_permissions(&mut state, &alice());
    state.gov.sorafs_telemetry.require_submitter = true;
    state.gov.sorafs_telemetry.submitters = vec![alice()];
    state
}
#[test]
fn sorafs_component_fee_source_requires_a_retained_finite_producer() {
    let state = make_state();
    let mut block = state.block(block_header());
    let mut stx = block.transaction();
    stx.tx_call_hash = Some(Hash::prehashed([0x51; Hash::LENGTH]));
    seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
    let alice_balance_before = pin_fee_balance(&stx, &alice());
    let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
    let instruction = RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    };
    let error = instruction
        .clone()
        .execute(&alice(), &mut stx)
        .expect_err("a copied hash must not substitute for a retained producer invocation");
    assert!(
        matches!(error, InstructionExecutionError::InvariantViolation(message)
        if message.contains("FASTPQ source has no retained producer invocation"))
    );
    assert!(stx.world.pin_manifests.get(&default_digest()).is_none());
    assert_pin_fee_balances_unchanged(
        &stx,
        &alice(),
        alice_balance_before,
        &treasury_account,
        treasury_balance_before,
    );
    drop(stx);
    drop(block);
    let state = make_state();
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
    instruction
        .execute(&alice(), &mut stx)
        .expect("the same exact hash is admitted only with its finite retained producer");
    assert!(stx.world.pin_manifests.get(&default_digest()).is_some());
    assert!(
        crate::executor::root_scope::execution_root_scope(&mut stx).is_err(),
        "component E custody must not create immutable ordinary execution authority"
    );
}

#[test]
fn provider_reverse_index_iteration_is_exact_and_ordered() {
    let state = make_state();
    let mut block = state.block(block_header());
    let mut transaction = block.transaction();
    let provider = ProviderId::new([0xD1; 32]);
    let other_provider = ProviderId::new([0xD2; 32]);
    let first = MusubiArchiveLocationKeyV1::new(
        ArchiveId::new([1; 32]),
        MusubiArchiveLocationIdV1::new([1; 32]),
    );
    let second = MusubiArchiveLocationKeyV1::new(
        ArchiveId::new([2; 32]),
        MusubiArchiveLocationIdV1::new([2; 32]),
    );
    transaction
        .world
        .musubi_locations_by_provider
        .insert(MusubiProviderLocationKeyV1::new(provider, second), ());
    transaction
        .world
        .musubi_locations_by_provider
        .insert(MusubiProviderLocationKeyV1::new(other_provider, first), ());
    transaction
        .world
        .musubi_locations_by_provider
        .insert(MusubiProviderLocationKeyV1::new(provider, first), ());
    assert_eq!(
        next_musubi_location_for_provider(provider, None, &transaction),
        Some(first)
    );
    assert_eq!(
        next_musubi_location_for_provider(provider, Some(first), &transaction),
        Some(second)
    );
    assert_eq!(
        next_musubi_location_for_provider(provider, Some(second), &transaction),
        None
    );
}
fn completion_anchor_hash() -> iroha_crypto::HashOf<iroha_data_model::block::BlockHeader> {
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 42, 0);
    iroha_crypto::HashOf::new(&header)
}
fn completion_anchor() -> ProviderIngestFinalizedAnchorV1 {
    ProviderIngestFinalizedAnchorV1 {
        height: 1,
        block_hash: *completion_anchor_hash().as_ref(),
    }
}
fn make_state_with_completion_anchor() -> State {
    let mut state = make_state();
    state
        .ensure_da_indexes_hydrated()
        .expect("empty test Kura must hydrate before installing a hash-only prefix");
    state.push_block_hash_for_testing(completion_anchor_hash());
    state
}
fn completion_signer_policy(revision: u64) -> ProviderIngestCompletionSignerPolicyV1 {
    let digest_byte = u8::try_from(revision).unwrap_or(0xFE);
    ProviderIngestCompletionSignerPolicyV1 {
        policy_id: [0xA1; 32],
        revision,
        predecessor_digest: (revision > 1).then(|| [digest_byte.saturating_sub(1); 32]),
        policy_digest: [digest_byte; 32],
    }
}
fn completion_authority(owner: &AccountId, revision: u64) -> ProviderIngestCompletionAuthorityV1 {
    ProviderIngestCompletionAuthorityV1::new(
        owner.clone(),
        owner.clone(),
        completion_signer_policy(revision),
    )
}
fn completion_instruction(
    order_id: ReplicationOrderId,
    provider_id: ProviderId,
    completion_epoch: u64,
    owner: &AccountId,
) -> CompleteReplicationOrder {
    CompleteReplicationOrder {
        order_id,
        provider_id,
        completion_epoch,
        expected_authority: completion_authority(owner, 1),
        expected_assignment_revision: 1,
        finalized_anchor: completion_anchor(),
    }
}
fn seed_public_pin_fee_accounts(state: &mut State) {
    let fee_asset_id = state.gov.sorafs_pin_fee_asset_id.clone();
    let domain_id =
        DomainId::try_new("universal", "universal").expect("SoraFS fee fixture owning domain");
    state.world.domains.insert(
        domain_id.clone(),
        Domain::new(domain_id.clone()).build(&alice()),
    );
    let (account_id, account_value) = Account::new(alice()).build(&alice()).into_key_value();
    state.world.accounts.insert(account_id, account_value);
    let (account_id, account_value) = Account::new(bob()).build(&alice()).into_key_value();
    state.world.accounts.insert(account_id, account_value);
    let treasury = state.gov.sorafs_pin_fee_treasury_account.clone();
    let (account_id, account_value) = Account::new(treasury).build(&alice()).into_key_value();
    state.world.accounts.insert(account_id, account_value);
    let definition = AssetDefinition::numeric(
        fee_asset_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id.clone()),
    )
    .build(&alice());
    state
        .world
        .asset_definition_domains
        .insert(fee_asset_id.clone(), domain_id.clone());
    state
        .world
        .domain_asset_definitions
        .insert(domain_id, BTreeSet::from([fee_asset_id.clone()]));
    let owner = definition.owned_by().clone();
    state
        .world
        .asset_definitions_by_owner
        .insert(owner, BTreeSet::from([fee_asset_id.clone()]));
    state
        .world
        .asset_definitions
        .insert(fee_asset_id.clone(), definition);
    seed_pin_fee_balance(state, &alice(), 10_000_000_000_000);
    seed_pin_fee_balance(state, &bob(), 10_000_000_000_000);
    let alice_asset = AssetId::new(fee_asset_id.clone(), alice());
    let bob_asset = AssetId::new(fee_asset_id.clone(), bob());
    state.world.asset_definition_holders.insert(
        fee_asset_id.clone(),
        BTreeSet::from([alice_asset.account().clone(), bob_asset.account().clone()]),
    );
    state.world.asset_definition_assets.insert(
        fee_asset_id.clone(),
        BTreeSet::from([alice_asset, bob_asset]),
    );
    state
        .world
        .asset_definition_nonzero_holders
        .insert(fee_asset_id, BTreeSet::from([alice(), bob()]));
}
fn seed_pin_fee_balance(state: &mut State, account: &AccountId, amount: u128) {
    let fee_asset_id = state.gov.sorafs_pin_fee_asset_id.clone();
    let asset_id = AssetId::new(fee_asset_id, account.clone());
    let (asset_id, asset_value) = Asset::new(asset_id, Quantity::from(amount)).into_key_value();
    state.world.assets.insert(asset_id, asset_value);
}
fn pin_fee_balance(stx: &crate::state::StateTransaction<'_, '_>, account: &AccountId) -> Quantity {
    let asset_id = AssetId::new(stx.gov.sorafs_pin_fee_asset_id.clone(), account.clone());
    stx.world
        .assets
        .get(&asset_id)
        .map(|value| value.as_ref().clone())
        .unwrap_or_else(Quantity::zero)
}
fn assert_pin_fee_balances_unchanged(
    stx: &crate::state::StateTransaction<'_, '_>,
    account: &AccountId,
    account_balance_before: Quantity,
    treasury: &AccountId,
    treasury_balance_before: Quantity,
) {
    assert_eq!(
        pin_fee_balance(stx, account),
        account_balance_before,
        "rejected pin registration must not charge the submitter"
    );
    assert_eq!(
        pin_fee_balance(stx, treasury),
        treasury_balance_before,
        "rejected pin registration must not credit treasury"
    );
}
fn seed_provider_owners(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    providers: &[ProviderId],
    owner: &AccountId,
) {
    for provider in providers {
        stx.world.provider_owners.insert(*provider, owner.clone());
        stx.world.add_account_permission(
            owner,
            iroha_data_model::permission::Permission::from(
                iroha_executor_data_model::permission::sorafs::CanCompleteSorafsReplicationOrder {
                    provider_id: *provider,
                },
            ),
        );
        stx.world
            .provider_ingest_completion_authorities
            .insert(*provider, completion_authority(owner, 1));
    }
}
fn seed_governed_capacity_provider(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    provider: ProviderId,
    owner: &AccountId,
    bonded: Quantity,
) {
    seed_provider_owners(stx, &[provider], owner);
    super::sorafs_reserve::seed_verified_provider_bond_for_test(
        stx,
        provider,
        owner,
        1_000_000,
        bonded.clone(),
    )
    .expect("seed internally consistent native reserve fixture");
    stx.world.provider_credit_ledger.insert(
        provider,
        ProviderCreditRecord::new(
            provider,
            Quantity::zero(),
            bonded,
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        ),
    );
}
fn upsert_provider_credit_with_reserve_fixture(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    authority: &AccountId,
    record: ProviderCreditRecord,
) -> Result<(), InstructionExecutionError> {
    let provider = record.provider_id;
    let owner = stx
        .world
        .provider_owners
        .get(&provider)
        .cloned()
        .ok_or_else(|| invalid_parameter("test credit fixture requires a governed owner"))?;
    let capacity_gib = stx
        .world
        .capacity_declarations
        .get(&provider)
        .map_or(1, |declaration| declaration.committed_capacity_gib);
    super::sorafs_reserve::seed_verified_provider_bond_for_test(
        stx,
        provider,
        &owner,
        capacity_gib,
        record.bonded.clone(),
    )?;
    let expected_current = stx
        .world
        .provider_credit_ledger
        .get(&provider)
        .map(iroha_crypto::HashOf::new);
    UpsertProviderCredit {
        expected_current,
        record,
    }
    .execute(authority, stx)
}
fn register_governed_capacity_declaration(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    authority: &AccountId,
    mut record: CapacityDeclarationRecord,
) -> Result<(), InstructionExecutionError> {
    record.registered_epoch = pin_consensus_epoch(stx);
    seed_governed_capacity_provider(stx, record.provider_id, authority, Quantity::from(1_u32));
    RegisterCapacityDeclaration {
        declaration: record.declaration,
    }
    .execute(authority, stx)
}
fn seed_sorafs_permissions(state: &mut State, authority: &AccountId) {
    let mut perms = Permissions::default();
    for name in [
        "CanBindSorafsAlias",
        "CanDeclareSorafsCapacity",
        "CanSubmitSorafsTelemetry",
        "CanFileSorafsCapacityDispute",
        "CanManageSorafsReputationJournalPolicy",
        "CanRecordSorafsReputationJournal",
        "CanResolveSorafsCapacityDispute",
        "CanIssueSorafsReplicationOrder",
        "CanSetSorafsPricing",
        "CanUpsertSorafsProviderCredit",
    ] {
        perms.insert(AccountPermission::new(name.to_string(), Json::new(())));
    }
    state
        .world
        .account_permissions
        .insert(authority.clone(), perms);
}
fn remove_permission(stx: &mut crate::state::StateTransaction<'_, '_>, name: &str) {
    if let Some(perms) = stx.world.account_permissions.get_mut(&alice()) {
        perms.retain(|perm| perm.name() != name);
    }
}
fn grant_permission(stx: &mut crate::state::StateTransaction<'_, '_>, name: &str) {
    stx.world
        .account_permissions
        .get_mut(&alice())
        .expect("Alice permission set")
        .insert(AccountPermission::new(name.to_owned(), Json::new(())));
}
fn smart_contract_error_message(error: &InstructionExecutionError) -> &str {
    match error {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => message,
        other => panic!("expected smart-contract parameter error, got {other:?}"),
    }
}
fn default_chunker() -> ChunkerProfileHandle {
    ChunkerProfileHandle {
        profile_id: 1,
        namespace: "sorafs".into(),
        name: "sf1".into(),
        semver: "1.0.0".into(),
        multihash_code: 0x1f,
    }
}
pub(super) fn default_digest() -> ManifestDigest {
    manifest_digest_for_seed(0xAA)
}
fn manifest_fixture_with_chunk_digest(seed: u8, chunk_digest_sha3_256: [u8; 32]) -> ManifestV1 {
    let commitment = seed.max(1);
    ManifestBuilder::new()
        .root_cid(sorafs_manifest::canonical_manifest_root_cid(
            [commitment; 32],
        ))
        .dag_codec(DagCodecId(
            sorafs_manifest::chunker_registry::MANIFEST_DAG_CODEC,
        ))
        .chunking_from_registry(sorafs_manifest::chunker_registry::default_descriptor().id)
        .chunk_digest_sha3_256(chunk_digest_sha3_256)
        .por_root([commitment.wrapping_add(2).max(1); 32])
        .content_length(default_content_length())
        .car_digest([commitment.wrapping_add(1).max(1); 32])
        .car_size(
            default_content_length()
                .checked_add(4096)
                .expect("fixture CAR size"),
        )
        .pin_policy(sorafs_manifest::PinPolicy {
            min_replicas: default_policy().min_replicas,
            storage_class: sorafs_manifest::StorageClass::Hot,
            retention_epoch: default_policy().retention_epoch,
        })
        .governance(GovernanceProofs::default())
        .build()
        .expect("fixture manifest")
}
fn chunk_digest_for_seed(seed: u8) -> [u8; 32] {
    [seed.wrapping_add(0x23).max(1); 32]
}
fn manifest_fixture(seed: u8) -> ManifestV1 {
    manifest_fixture_with_chunk_digest(seed, chunk_digest_for_seed(seed))
}
fn manifest_payload_for_seed(seed: u8) -> Vec<u8> {
    manifest_fixture(seed)
        .encode()
        .expect("encode fixture manifest")
}
fn manifest_digest_for_seed(seed: u8) -> ManifestDigest {
    ManifestDigest::from_manifest(&manifest_fixture(seed)).expect("digest fixture manifest")
}
fn fixture_seed_for_digest(digest: ManifestDigest) -> u8 {
    (1..=u8::MAX)
        .find(|seed| manifest_digest_for_seed(*seed) == digest)
        .expect("manifest digest must belong to a test fixture seed")
}
pub(super) fn root_cid_for_manifest(digest: ManifestDigest) -> ManifestRootCid {
    let manifest = manifest_fixture(fixture_seed_for_digest(digest));
    ManifestRootCid::try_from_slice(&manifest.root_cid).expect("canonical root CID")
}
fn por_root_for_manifest(digest: ManifestDigest) -> [u8; 32] {
    manifest_fixture(fixture_seed_for_digest(digest)).por_root
}
pub(super) fn default_root_cid() -> ManifestRootCid {
    root_cid_for_manifest(default_digest())
}
fn default_manifest_payload() -> Vec<u8> {
    manifest_payload_for_seed(0xAA)
}
pub(super) fn default_chunk_digest() -> [u8; 32] {
    chunk_digest_for_seed(0xAA)
}
pub(super) fn default_content_length() -> u64 {
    BYTES_PER_GIB
        .try_into()
        .expect("default GiB byte count fits u64")
}
pub(super) fn default_policy() -> PinPolicy {
    PinPolicy {
        min_replicas: 3,
        storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
        retention_epoch: 100_000,
    }
}
fn musubi_archive_for_pin(pin: &PinManifestRecord, seed: u8) -> MusubiArchiveRecordV1 {
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: pin.root_cid.clone(),
        chunker: pin.chunker.clone(),
        chunk_plan_digest: MusubiContentDigestV1::new(pin.chunk_digest_sha3_256),
        por_root: MusubiContentDigestV1::new(pin.por_root),
        content_length: pin.content_length,
        car_digest: MusubiContentDigestV1::new([seed.wrapping_add(1); 32]),
        car_size: pin
            .content_length
            .checked_add(1)
            .expect("fixture CAR size remains bounded"),
        bundle_digest: MusubiContentDigestV1::new([seed.wrapping_add(2); 32]),
        source_tree_digest: MusubiContentDigestV1::new([seed.wrapping_add(3); 32]),
        descriptor_digest: MusubiContentDigestV1::new([seed.wrapping_add(4); 32]),
        file_count: 1,
        chunk_count: 1,
    };
    let archive_id = commitment.archive_id();
    let broker_keypair = KeyPair::try_from_seed(vec![seed.wrapping_add(5); 32], Algorithm::Ed25519)
        .expect("derive fixture ingress broker");
    let broker = AccountId::new(broker_keypair.public_key().clone());
    let payload = MusubiSeedIngressReceiptPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: MusubiSeedIngressReceiptBindingV1 {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::prehashed([seed.wrapping_add(6); 32]),
            )),
            publisher: alice(),
            ingress_broker: broker,
            seed_provider: ProviderId::new([seed.wrapping_add(7); 32]),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new(
                [seed.wrapping_add(8); 32],
            ),
            archive_id,
            car_body_digest: commitment.car_digest,
            car_body_length: commitment.car_size,
            nonce: [seed.wrapping_add(9); 32],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
    };
    let approval = MusubiSeedIngressReceiptApprovalV1 {
        public_key: broker_keypair.public_key().clone(),
        signature: SignatureOf::try_from_hash(broker_keypair.private_key(), payload.signing_hash())
            .expect("sign fixture ingress receipt"),
    };
    let archive = MusubiArchiveRecordV1 {
        archive_id,
        commitment,
        staging_receipt: MusubiSeedIngressReceiptV1 {
            payload,
            approvals: vec![approval],
        },
        registered_by: alice(),
        registered_at_height: 1,
        location_revision: 1,
        location_ids: Vec::new(),
    };
    archive.validate().expect("valid Musubi archive fixture");
    archive
}
fn registry_grade_musubi_pin() -> PinManifestRecord {
    let mut pin = PinManifestRecord::new(
        default_digest(),
        default_root_cid(),
        default_chunker(),
        default_chunk_digest(),
        por_root_for_manifest(default_digest()),
        1_024,
        default_policy(),
        alice(),
        1,
        None,
        None,
        Metadata::default(),
    );
    pin.approve(1, None);
    pin
}
pub(super) fn second_digest() -> ManifestDigest {
    manifest_digest_for_seed(0xBB)
}
fn third_digest() -> ManifestDigest {
    manifest_digest_for_seed(0xCC)
}
pub(super) fn alias_binding_for(
    digest: ManifestDigest,
    namespace: &str,
    name: &str,
    bound_at: u64,
    expiry_epoch: u64,
) -> ManifestAliasBinding {
    let binding_payload = AliasBindingV1 {
        alias: format!("{namespace}/{name}"),
        manifest_cid: root_cid_for_manifest(digest).as_bytes().to_vec(),
        bound_at,
        expiry_epoch,
    };
    let mut bundle = AliasProofBundleV1 {
        binding: binding_payload,
        registry_root: [0u8; 32],
        registry_height: 1,
        generated_at_unix: bound_at,
        expires_at_unix: bound_at.checked_add(600).expect("alias proof expiry"),
        merkle_path: Vec::new(),
        council_signatures: Vec::new(),
    };
    let root =
        alias_merkle_root(&bundle.binding, &bundle.merkle_path).expect("compute alias proof root");
    bundle.registry_root = root;
    let digest_bytes = alias_proof_signature_digest(&bundle);
    let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[0x22; 32]).expect("seeded key");
    let keypair = KeyPair::from_private_key(private).expect("derive keypair");
    let signature = Signature::try_new(keypair.private_key(), digest_bytes.as_ref())
        .expect("alias proof fixture should sign");
    let (_, signer_bytes) = keypair
        .public_key()
        .try_to_bytes()
        .expect("fixture public key must be valid");
    let signer: [u8; 32] = signer_bytes
        .try_into()
        .expect("ed25519 public key must be 32 bytes");
    bundle
        .council_signatures
        .push(sorafs_manifest::CouncilSignature {
            signer,
            signature: signature.payload().to_vec(),
        });
    let proof = to_bytes(&bundle).expect("encode alias proof bundle");
    ManifestAliasBinding {
        name: name.to_owned(),
        namespace: namespace.to_owned(),
        proof,
    }
}
fn sample_alias_binding() -> ManifestAliasBinding {
    alias_binding_for(default_digest(), "sora", "docs", 8, 16)
}
#[test]
fn register_pin_manifest_allows_public_submission() {
    let mut state = make_initial_sorafs_state();
    seed_sorafs_permissions(&mut state, &bob());
    let mut block = state.block(initial_sorafs_block_header(&state));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
    if let Some(perms) = stx.world.account_permissions.get_mut(&alice()) {
        perms.clear();
    }
    let alice_balance_before = pin_fee_balance(&stx, &alice());
    let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
    let register = RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    };
    let expected_amount = stx
        .world
        .sorafs_pricing
        .get()
        .public_pin_fee(
            default_policy().storage_class,
            default_content_length(),
            default_policy().min_replicas,
            pin_consensus_epoch(&stx),
            default_policy().retention_epoch,
        )
        .expect("default public pin fee");
    register
        .execute_initial(&alice(), &mut stx)
        .expect("public register must succeed");
    let record = stx
        .world
        .pin_manifests
        .get(&default_digest())
        .expect("manifest stored");
    assert_eq!(record.submitted_by, alice());
    assert_eq!(record.status, PinStatus::Approved(5));
    assert_eq!(record.content_length, default_content_length());
    assert_eq!(record.digest, default_digest());
    assert_eq!(record.root_cid, default_root_cid());
    assert_eq!(record.chunker, default_chunker());
    assert_eq!(record.por_root, por_root_for_manifest(default_digest()));
    assert_eq!(record.policy, default_policy());
    let payment = record
        .pin_fee_payment
        .as_ref()
        .expect("fee payment recorded");
    assert_eq!(payment.paid_by, alice());
    assert_eq!(payment.fee_asset_id, stx.gov.sorafs_pin_fee_asset_id);
    assert_eq!(
        payment.treasury_account_id,
        stx.gov.sorafs_pin_fee_treasury_account
    );
    assert_eq!(payment.amount, expected_amount);
    assert_eq!(
        pin_fee_balance(&stx, &alice()),
        alice_balance_before
            .checked_sub(&expected_amount)
            .expect("alice has enough fee balance")
    );
    assert_eq!(
        pin_fee_balance(&stx, &treasury_account),
        treasury_balance_before
            .checked_add(&expected_amount)
            .expect("treasury balance remains representable")
    );
    let expected_usage = PinResourceUsage {
        manifest_count: 1,
        content_bytes: default_content_length(),
    };
    assert_eq!(
        read_pin_usage(stx.world(), pin_global_usage_key(), "global usage")
            .expect("valid global usage"),
        Some(expected_usage)
    );
    assert_eq!(
        read_pin_usage(
            stx.world(),
            &pin_authority_usage_key(&alice()).expect("authority usage key"),
            "authority usage",
        )
        .expect("valid authority usage"),
        Some(expected_usage)
    );
    assert_eq!(
        read_pin_lineage(stx.world(), &default_digest()).expect("valid lineage"),
        Some(PinLineageSummaryV1::root())
    );
    assert!(
        stx.world
            .smart_contract_state
            .get(&pin_expiry_key(
                default_policy().retention_epoch,
                &default_digest()
            ))
            .is_some(),
        "registration must install its deterministic expiry index"
    );
    assert!(
        stx.world
            .smart_contract_state
            .get(&pin_status_index_key(&record.status, &default_digest()))
            .is_some_and(Vec::is_empty),
        "registration must install the exact lifecycle index marker"
    );
}
#[test]
fn public_pin_resource_ceilings_reject_before_fee_or_state_mutation() {
    let mut state = make_state();
    state.gov.sorafs_pin_policy.max_global_manifests = 1;
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
    RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), &mut stx)
    .expect("first pin remains within the configured ceiling");
    let alice_balance_before = pin_fee_balance(&stx, &alice());
    let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
    let error = RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xBB),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), &mut stx)
    .expect_err("the second pin must exceed the global manifest ceiling");
    assert!(smart_contract_error_message(&error).contains("global SoraFS pin ceiling"));
    assert!(stx.world.pin_manifests.get(&second_digest()).is_none());
    assert_pin_fee_balances_unchanged(
        &stx,
        &alice(),
        alice_balance_before,
        &treasury_account,
        treasury_balance_before,
    );
    assert_eq!(
        read_pin_usage(stx.world(), pin_global_usage_key(), "global usage")
            .expect("valid global usage"),
        Some(PinResourceUsage {
            manifest_count: 1,
            content_bytes: default_content_length(),
        })
    );
}
#[test]
fn retired_pin_history_cannot_recycle_count_ceilings() {
    for authority_scoped in [false, true] {
        let mut state = make_state();
        if authority_scoped {
            state.gov.sorafs_pin_policy.max_manifests_per_authority = 1;
        } else {
            state.gov.sorafs_pin_policy.max_global_manifests = 1;
        }
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("first pin remains within the retained-record ceiling");
        RetirePinManifest {
            digest: default_digest(),
            reason: Some("release replica capacity".to_owned()),
        }
        .execute(&alice(), &mut stx)
        .expect("the authenticated submitter may retire its pin");
        let expected_usage = PinResourceUsage {
            manifest_count: 1,
            content_bytes: 0,
        };
        assert_eq!(
            read_pin_usage(stx.world(), pin_global_usage_key(), "global usage")
                .expect("valid global usage"),
            Some(expected_usage)
        );
        assert_eq!(
            read_pin_usage(
                stx.world(),
                &pin_authority_usage_key(&alice()).expect("authority usage key"),
                "authority usage",
            )
            .expect("valid authority usage"),
            Some(expected_usage)
        );
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let error = RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xBB),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("retirement must not reopen a retained-record quota slot");
        let expected_error = if authority_scoped {
            "SoraFS pin ceiling for authority"
        } else {
            "global SoraFS pin ceiling"
        };
        assert!(smart_contract_error_message(&error).contains(expected_error));
        assert!(stx.world.pin_manifests.get(&second_digest()).is_none());
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
}
#[test]
fn public_pin_global_and_authority_byte_ceilings_reject_before_fee_or_state() {
    for authority_scoped in [false, true] {
        let mut state = make_state();
        if authority_scoped {
            state.gov.sorafs_pin_policy.max_bytes_per_authority = default_content_length();
        } else {
            state.gov.sorafs_pin_policy.max_global_bytes = default_content_length();
        }
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("first pin remains within the content-byte ceiling");
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let error = RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xBB),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("the second pin must exceed the content-byte ceiling");
        let expected_error = if authority_scoped {
            "SoraFS pin ceiling for authority"
        } else {
            "global SoraFS pin ceiling"
        };
        assert!(smart_contract_error_message(&error).contains(expected_error));
        assert!(stx.world.pin_manifests.get(&second_digest()).is_none());
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
}
#[test]
fn pin_expiry_uses_consensus_time_and_releases_live_content_atomically() {
    let state = make_state();
    {
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("register paid pin fixture");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit registered pin fixture");
    }
    let previous = state
        .view()
        .latest_block()
        .expect("canonical history read completes")
        .map(|block| block.hash());
    {
        let header = iroha_data_model::block::BlockHeader::new(
            nonzero!(2_u64),
            previous.clone(),
            None,
            default_policy().retention_epoch * 1_000 - 1,
            0,
        );
        let mut block = state.block(header);
        assert_eq!(
            expire_pin_manifests_at_consensus_time(&mut block)
                .expect("pre-expiry maintenance succeeds"),
            0,
            "retention epoch is inclusive until its consensus second"
        );
        assert!(matches!(
            block
                .world
                .pin_manifests
                .get(&default_digest())
                .expect("live pin record")
                .status,
            PinStatus::Approved(5)
        ));
    }
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        previous,
        None,
        default_policy().retention_epoch * 1_000,
        0,
    );
    let mut block = state.block(header);
    assert_eq!(
        expire_pin_manifests_at_consensus_time(&mut block)
            .expect("due expiry maintenance succeeds"),
        1
    );
    let stored = block
        .world
        .pin_manifests
        .get(&default_digest())
        .expect("retired pin remains queryable");
    assert_eq!(
        stored.status,
        PinStatus::Retired(default_policy().retention_epoch)
    );
    assert_eq!(
        stored.retirement_reason.as_deref(),
        Some("consensus retention expired")
    );
    assert_eq!(
        read_pin_usage(&block.world, pin_global_usage_key(), "global usage")
            .expect("valid global usage"),
        Some(PinResourceUsage {
            manifest_count: 1,
            content_bytes: 0,
        }),
        "expiry must retain the record charge while releasing live content bytes"
    );
    assert!(
        block
            .world
            .smart_contract_state
            .get(&pin_expiry_key(
                default_policy().retention_epoch,
                &default_digest()
            ))
            .is_none()
    );
}
#[test]
fn pin_expiry_rejects_malformed_index_without_partial_retirement() {
    let state = make_state();
    {
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("register paid pin fixture");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit registered pin fixture");
    }
    let previous = state
        .view()
        .latest_block()
        .expect("canonical history read completes")
        .map(|block| block.hash());
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        previous,
        None,
        default_policy().retention_epoch * 1_000,
        0,
    );
    let mut block = state.block(header);
    let malformed_key = StatePath::from_str(&format!(
        "{PIN_EXPIRY_STATE_KEY_PREFIX_V1}not-an-epoch/{}",
        manifest_hex(&second_digest())
    ))
    .expect("malformed expiry fixture is still a valid state path");
    block
        .world
        .smart_contract_state
        .insert(malformed_key, Vec::new());
    let error = expire_pin_manifests_at_consensus_time(&mut block)
        .expect_err("malformed authenticated expiry state must reject the complete effect");
    assert!(matches!(
        error,
        PinExpiryMaintenanceError::Instruction(InstructionExecutionError::InvariantViolation(message))
            if message.contains("non-canonical expiry key")
    ));
    assert!(matches!(
        block
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains live")
            .status,
        PinStatus::Approved(5)
    ));
    assert!(
        block
            .world
            .smart_contract_state
            .get(&pin_expiry_key(
                default_policy().retention_epoch,
                &default_digest()
            ))
            .is_some(),
        "the due canonical marker must remain when any index entry is corrupt"
    );
    assert_eq!(
        read_pin_usage(&block.world, pin_global_usage_key(), "global usage")
            .expect("valid global usage"),
        Some(PinResourceUsage {
            manifest_count: 1,
            content_bytes: default_content_length(),
        })
    );
}
#[test]
fn public_pin_cannot_reserve_alias_without_alias_permission() {
    let mut state = make_initial_sorafs_state();
    seed_sorafs_permissions(&mut state, &bob());
    let mut block = state.block(initial_sorafs_block_header(&state));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    remove_permission(&mut stx, "CanBindSorafsAlias");
    let alice_balance_before = pin_fee_balance(&stx, &alice());
    let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
    let alias = default_alias_binding();
    let error = RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: Some(alias.clone()),
        successor_of: None,
    }
    .execute_initial(&alice(), &mut stx)
    .expect_err("permissionless public pins must not reserve governed aliases");
    assert!(matches!(
        error,
        InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(message)
        ) if message.contains("CanBindSorafsAlias")
    ));
    assert!(stx.world.pin_manifests.get(&default_digest()).is_none());
    assert!(
        stx.world
            .manifest_aliases
            .get(&ManifestAliasId::from(&alias))
            .is_none()
    );
    assert_pin_fee_balances_unchanged(
        &stx,
        &alice(),
        alice_balance_before,
        &treasury_account,
        treasury_balance_before,
    );
}
#[test]
fn register_pin_manifest_rejects_unfunded_public_submission_without_side_effects() {
    let mut state = make_initial_sorafs_state();
    seed_sorafs_permissions(&mut state, &bob());
    let mut block = state.block(initial_sorafs_block_header(&state));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    if let Some(perms) = stx.world.account_permissions.get_mut(&alice()) {
        perms.clear();
    }
    let alice_fee_asset = AssetId::new(stx.gov.sorafs_pin_fee_asset_id.clone(), alice());
    stx.world.assets.remove(alice_fee_asset);
    let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
    let register = RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    };
    register
        .execute_initial(&alice(), &mut stx)
        .expect_err("unfunded public pin registration must fail");
    assert!(
        stx.world.pin_manifests.get(&default_digest()).is_none(),
        "failed paid registration must not leave a manifest record"
    );
    assert_eq!(pin_fee_balance(&stx, &alice()), Quantity::zero());
    assert_eq!(
        pin_fee_balance(&stx, &treasury_account),
        treasury_balance_before,
        "failed paid registration must not credit treasury"
    );
}
#[test]
fn register_pin_manifest_rejects_insufficient_public_fee_without_side_effects() {
    let mut state = make_state();
    seed_sorafs_permissions(&mut state, &bob());
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    if let Some(perms) = stx.world.account_permissions.get_mut(&alice()) {
        perms.clear();
    }
    let alice_fee_asset = AssetId::new(stx.gov.sorafs_pin_fee_asset_id.clone(), alice());
    let low_balance: Quantity = "0.000000001".parse().expect("non-negative low balance");
    let (asset_id, asset_value) = Asset::new(alice_fee_asset, low_balance.clone()).into_key_value();
    stx.world.assets.insert(asset_id, asset_value);
    let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
    let register = RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    };
    register
        .execute(&alice(), &mut stx)
        .expect_err("underfunded public pin registration must fail");
    assert!(
        stx.world.pin_manifests.get(&default_digest()).is_none(),
        "failed paid registration must not leave a manifest record"
    );
    assert_pin_fee_balances_unchanged(
        &stx,
        &alice(),
        low_balance,
        &treasury_account,
        treasury_balance_before,
    );
}
#[test]
fn threshold_approval_may_be_relayed_without_broad_permission() {
    let mut state = make_initial_sorafs_state();
    seed_sorafs_permissions(&mut state, &bob());
    let signer = checked_ed25519_keypair();
    set_council_approval_signers(
        &mut state,
        1,
        vec![council_approval_signer("council-a", &signer, 0, None)],
    );
    let mut block = state.block(initial_sorafs_block_header(&state));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
    insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
    let record = stx
        .world
        .pin_manifests
        .get(&default_digest())
        .expect("pending manifest fixture")
        .clone();
    let (council_envelope, _) = build_envelope(&record, &signer);
    let approve = ApprovePinManifest {
        digest: default_digest(),
        council_envelope: Some(council_envelope),
        council_envelope_digest: None,
    };
    approve
        .execute_initial(&bob(), &mut stx)
        .expect("any authenticated account may relay a valid governed approval");
    assert!(matches!(
        stx.world
            .pin_manifests
            .get(&default_digest())
            .expect("approved manifest")
            .status,
        PinStatus::Approved(5)
    ));
}
#[test]
fn retire_pin_manifest_requires_exact_authenticated_submitter() {
    let mut state = make_initial_sorafs_state();
    seed_sorafs_permissions(&mut state, &bob());
    let mut block = state.block(initial_sorafs_block_header(&state));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
    RegisterPinManifest {
        manifest_payload: default_manifest_payload(),
        alias: None,
        successor_of: None,
    }
    .execute_initial(&alice(), &mut stx)
    .expect("public submitter registers its paid pin");
    let retire = RetirePinManifest {
        digest: default_digest(),
        reason: None,
    };
    let error = retire
        .clone()
        .execute_initial(&bob(), &mut stx)
        .expect_err("an unrelated account must not retire another account's pin");
    assert!(smart_contract_error_message(&error).contains("authenticated submitter"));
    retire
        .execute_initial(&alice(), &mut stx)
        .expect("the exact submitter may retire without a broad permission token");
}
#[test]
fn bind_manifest_alias_requires_permission() {
    let mut state = make_initial_sorafs_state();
    seed_sorafs_permissions(&mut state, &bob());
    let mut block = state.block(initial_sorafs_block_header(&state));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
    remove_permission(&mut stx, "CanBindSorafsAlias");
    let bind = BindManifestAlias {
        digest: default_digest(),
        binding: sample_alias_binding(),
        bound_epoch: 8,
        expiry_epoch: 12,
    };
    let error = bind
        .execute_initial(&alice(), &mut stx)
        .expect_err("permissionless bind must fail");
    assert!(matches!(
        error,
        InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(message)
        ) if message.contains("CanBindSorafsAlias")
    ));
}
pub(super) fn register_and_approve_manifest(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    digest: ManifestDigest,
    chunk_digest: [u8; 32],
    council_key: &KeyPair,
) {
    seed_automatic_replication_capacity(stx, default_policy().min_replicas);
    let seed = fixture_seed_for_digest(digest);
    let manifest = manifest_fixture_with_chunk_digest(seed, chunk_digest);
    assert_eq!(
        ManifestDigest::from_manifest(&manifest).expect("digest registration fixture"),
        digest,
        "registration helper chunk digest must match the fixture digest"
    );
    let register = RegisterPinManifest {
        manifest_payload: manifest.encode().expect("encode registration fixture"),
        alias: None,
        successor_of: None,
    };
    register.execute(&alice(), stx).expect("register manifest");
    let stored_record = stx
        .world
        .pin_manifests
        .get(&digest)
        .expect("manifest stored")
        .clone();
    let (envelope, _) = build_envelope(&stored_record, council_key);
    let approve = ApprovePinManifest {
        digest,
        council_envelope: Some(envelope),
        council_envelope_digest: None,
    };
    approve.execute(&alice(), stx).expect("approve manifest");
}
fn seed_automatic_replication_capacity(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    replicas: u16,
) {
    let consensus_epoch = pin_consensus_epoch(stx);
    seed_eligible_auto_replication_providers_for_test(
        stx,
        &alice(),
        replicas,
        StorageClass::Hot,
        &default_chunker(),
        consensus_epoch,
        u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1),
        1_024,
    )
    .expect("seed canonical automatic replication providers");
}
