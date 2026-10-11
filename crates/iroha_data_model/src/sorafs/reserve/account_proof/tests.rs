//! Genuine quorum signatures over explicitly synthetic World preimages, not native execution.
//!
//! These model controls test codec and evidence semantics only. Core must separately produce
//! originals through real Set/Register transactions and the native same-cut projection.

use super::*;
use crate::{
    IntoKeyValue, Registrable,
    account::Account,
    asset::{AssetBalancePolicy, AssetDefinition},
    block::consensus::SumeragiRootScope,
    sorafs::{
        pin_registry::StorageClass,
        reserve::{
            RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveDuration, ReserveLifecycleStage,
            ReservePolicyV1, ReserveProviderTermsV1, ReserveTier,
            history::{reserve_state_key, validate_provider_record},
        },
    },
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, test_fixtures::NativeFinalityFixture,
        world_state_value_hash_v1,
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::{state_path::StatePath, topology::DataSpaceId};
use iroha_primitives::numeric::NumericSpec;
use sorafs_manifest::deal::XorQuantity;

const CHAIN: &str = "reserve-account-synthetic-world";
fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn provider() -> ProviderId {
    ProviderId::new([0x41; 32])
}
fn schema() -> Hash {
    Hash::new(b"independently qualified reserve account schema specimen")
}
fn policy() -> ReserveAuthorityPolicyV1 {
    ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
        custody_account: account(2),
        treasury_account: account(3),
        operations_authority: account(4),
        decision_authority: account(5),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).unwrap(),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    }
}
fn singleton(policy: &ReserveAuthorityPolicyV1) -> ReserveStateV1 {
    ReserveStateV1 {
        policy: ReserveAuthorityPolicyRecordV1 {
            policy: policy.clone(),
            policy_digest: policy.digest().unwrap(),
            activated_by: account(1),
            activated_at_unix: 1,
        },
        journal_head: ReserveEventJournalHeadV1 {
            last_sequence: 1,
            last_target_block_height: 2,
            last_event_index: 0,
        },
    }
}
fn partition(policy: &ReserveAuthorityPolicyV1) -> ReserveProviderAccountV1 {
    ReserveProviderAccountV1 {
        terms: ReserveProviderTermsV1 {
            provider_id: provider(),
            // Native semantics permit an owner distinct from the policy operator.
            provider_account: account(6),
            tier: ReserveTier::TierB,
            storage_class: StorageClass::Hot,
            duration: ReserveDuration::Monthly,
            capacity_gib: 64,
        },
        policy_digest: policy.digest().unwrap(),
        revision: 1,
        reserve_balance: XorQuantity::zero(),
        debt_principal: XorQuantity::zero(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::try_from_micro(10).unwrap(),
        lifecycle_stage: ReserveLifecycleStage::Warning,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    }
}
fn row<K: norito::codec::Encode, V: norito::codec::Encode>(
    field: &str,
    key: &K,
    value: &V,
) -> WorldStateSnapshotEntryV1 {
    WorldStateSnapshotEntryV1 {
        field_id: field.into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(key).unwrap()),
        value_hash: world_state_value_hash_v1(value).unwrap(),
    }
}
fn sort(proof: &mut ReserveAccountProofV1) {
    proof
        .world
        .entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
}
fn rebuild(proof: &mut ReserveAccountProofV1, policy: &ReserveAuthorityPolicyV1) {
    let mut entries = Vec::new();
    let owner = account(6);
    for id in std::collections::BTreeSet::from([
        account(1),
        owner.clone(),
        policy.custody_account.clone(),
        policy.treasury_account.clone(),
        policy.operations_authority.clone(),
        policy.decision_authority.clone(),
    ]) {
        let (_, value) = Account::new(id.clone()).build(&owner).into_key_value();
        entries.push(row("world.accounts", &id, &value));
    }
    let asset = AssetDefinition::new(
        policy.asset_definition.clone(),
        "Reserve XOR",
        NumericSpec::fractional(6),
        AssetBalancePolicy::Global,
        None,
    )
    .build(&owner);
    entries.push(row(
        "world.asset_definitions",
        &policy.asset_definition,
        &asset,
    ));
    entries.push(row("world.provider_owners", &provider(), &proof.owner));
    entries.push(row(
        "world.smart_contract_state",
        reserve_state_key(),
        &proof.policy,
    ));
    if let Some(bytes) = &proof.current {
        entries.push(row(
            "world.smart_contract_state",
            &reserve_provider_key(provider()),
            bytes,
        ));
    }
    if let Some(bytes) = &proof.credit {
        let credit: ProviderCreditRecord = norito::decode_canonical(bytes).unwrap();
        entries.push(row("world.provider_credit_ledger", &provider(), &credit));
    }
    if let Some(bytes) = &proof.capacity {
        let capacity: CapacityDeclarationRecord = norito::decode_canonical(bytes).unwrap();
        entries.push(row("world.capacity_declarations", &provider(), &capacity));
    }
    let pricing: PricingScheduleRecord = norito::decode_canonical(&proof.pricing).unwrap();
    entries.push(WorldStateSnapshotEntryV1 {
        field_id: "world.sorafs_pricing".into(),
        kind: WorldStateElementKindV1::Cell,
        key_hash: None,
        value_hash: world_state_value_hash_v1(&pricing).unwrap(),
    });
    proof.world.entries = entries;
    sort(proof);
}
fn certify(
    native: &mut NativeFinalityFixture,
    proof: &ReserveAccountProofV1,
) -> VerifiedSumeragiBlock {
    let mut header = native.next_header();
    header.creation_time_ms = header.creation_time_ms.max(2_000);
    let block = native.block_with_submitted_work(header);
    let certificate = native.certify_with_world_root(block, proof.world.root().unwrap());
    native
        .verifier()
        .verify_retained_decision(&certificate)
        .unwrap()
}
fn fixture(
    present: bool,
) -> (
    NativeFinalityFixture,
    ReserveAccountProofV1,
    ReserveAuthorityPolicyV1,
    VerifiedSumeragiBlock,
) {
    let mut native = NativeFinalityFixture::start(CHAIN);
    let policy = policy();
    let mut proof = ReserveAccountProofV1 {
        world: WorldStateSnapshotV1 {
            schema_hash: schema(),
            entries: Vec::new(),
        },
        owner: account(6),
        policy: norito::encode_canonical(&singleton(&policy)).unwrap(),
        current: present.then(|| norito::encode_canonical(&partition(&policy)).unwrap()),
        credit: None,
        capacity: None,
        pricing: norito::encode_canonical(&PricingScheduleRecord::launch_default()).unwrap(),
    };
    rebuild(&mut proof, &policy);
    let block = certify(&mut native, &proof);
    (native, proof, policy, block)
}
fn verify(
    proof: &ReserveAccountProofV1,
    policy: &ReserveAuthorityPolicyV1,
    block: &VerifiedSumeragiBlock,
) -> Result<VerifiedReserveAccountStateV1, FinalityError> {
    proof.verify(
        &ReserveAccountProofExpectedV1 {
            chain: CHAIN,
            network_id: block.commitment().schedule.current.network_id,
            operator: &policy.operations_authority,
            provider_id: provider(),
            owner: &account(6),
            policy,
            schema: schema(),
        },
        block,
    )
}

#[test]
fn exact_partition_and_absence_share_one_cut_and_the_borrowed_wire() {
    for present in [false, true] {
        let (_, proof, policy, block) = fixture(present);
        let result = verify(&proof, &policy, &block).unwrap();
        assert_eq!(
            result.network_id(),
            block.commitment().schedule.current.network_id
        );
        assert_eq!(result.operator(), &account(4));
        assert_eq!(result.owner(), &account(6));
        assert_eq!(result.provider_id(), provider());
        assert_eq!(result.height(), block.height());
        assert_eq!(result.context_id(), block.context_id());
        assert_eq!(result.block_time_ms(), block.header().creation_time_ms);
        assert_eq!(result.policy(), &singleton(&policy).policy);
        assert_eq!(result.journal_head(), &singleton(&policy).journal_head);
        assert_eq!(
            result.current(),
            present.then(|| partition(&policy)).as_ref()
        );
        let borrowed = ReserveAccountProofRefV1::new(
            &proof.world,
            &proof.owner,
            &proof.policy,
            proof.current.as_ref(),
            proof.credit.as_ref(),
            proof.capacity.as_ref(),
            &proof.pricing,
        );
        let bytes = norito::encode_canonical(&proof).unwrap();
        assert_eq!(norito::encode_canonical(&borrowed).unwrap(), bytes);
        assert_eq!(
            norito::json::to_vec(&borrowed).unwrap(),
            norito::json::to_vec(&proof).unwrap()
        );
        assert_eq!(ReserveAccountProofV1::decode_frame(&bytes).unwrap(), proof);
    }
}

#[test]
fn every_independent_selection_refuses_substitution() {
    let (_, proof, policy, block) = fixture(true);
    let operator = account(4);
    let owner = account(6);
    let other = account(9);
    // Network identity follows signed genesis, not the human-readable chain label.
    let foreign = NativeFinalityFixture::start_with_mode(
        "other-reserve-account-network",
        crate::parameter::system::SumeragiConsensusMode::Npos,
    );
    assert_ne!(
        foreign.network_id(),
        block.commitment().schedule.current.network_id
    );
    let expected = || ReserveAccountProofExpectedV1 {
        chain: CHAIN,
        network_id: block.commitment().schedule.current.network_id,
        operator: &operator,
        provider_id: provider(),
        owner: &owner,
        policy: &policy,
        schema: schema(),
    };
    assert!(
        proof
            .verify(
                &ReserveAccountProofExpectedV1 {
                    chain: "other-chain",
                    ..expected()
                },
                &block
            )
            .is_err()
    );
    assert!(
        proof
            .verify(
                &ReserveAccountProofExpectedV1 {
                    network_id: foreign.network_id(),
                    ..expected()
                },
                &block
            )
            .is_err()
    );
    assert!(
        proof
            .verify(
                &ReserveAccountProofExpectedV1 {
                    operator: &other,
                    ..expected()
                },
                &block
            )
            .is_err()
    );
    assert!(
        proof
            .verify(
                &ReserveAccountProofExpectedV1 {
                    owner: &other,
                    ..expected()
                },
                &block
            )
            .is_err()
    );
    for provider_id in [ProviderId::new([0; 32]), ProviderId::new([0x42; 32])] {
        assert!(
            proof
                .verify(
                    &ReserveAccountProofExpectedV1 {
                        provider_id,
                        ..expected()
                    },
                    &block
                )
                .is_err()
        );
    }
    assert!(
        proof
            .verify(
                &ReserveAccountProofExpectedV1 {
                    schema: Hash::new(b"other schema"),
                    ..expected()
                },
                &block
            )
            .is_err()
    );
    for changed in [
        ReserveAuthorityPolicyV1 {
            operations_authority: other.clone(),
            ..policy.clone()
        },
        ReserveAuthorityPolicyV1 {
            decision_authority: other.clone(),
            ..policy.clone()
        },
        ReserveAuthorityPolicyV1 {
            custody_account: other.clone(),
            ..policy.clone()
        },
        ReserveAuthorityPolicyV1 {
            treasury_account: other,
            ..policy.clone()
        },
        ReserveAuthorityPolicyV1 {
            grace_period_days: policy.grace_period_days + 1,
            ..policy.clone()
        },
        ReserveAuthorityPolicyV1 {
            revision: 2,
            predecessor_policy_digest: Some(policy.digest().unwrap()),
            ..policy.clone()
        },
    ] {
        assert!(verify(&proof, &changed, &block).is_err());
    }
}

#[test]
fn private_root_and_another_certified_cut_do_not_prove_current_partition() {
    let (mut native, proof, policy, block) = fixture(true);
    let mut changed = proof.clone();
    changed.current = None;
    rebuild(&mut changed, &policy);
    let next = certify(&mut native, &changed);
    assert!(verify(&proof, &policy, &next).is_err());
    assert!(verify(&changed, &policy, &block).is_err());
    let mut private = NativeFinalityFixture::start_with_scope(
        CHAIN,
        SumeragiRootScope::Dataspace {
            parent_network_id: native.network_id(),
            dataspace_id: DataSpaceId::new(7),
        },
    );
    let private_block = certify(&mut private, &proof);
    assert!(verify(&proof, &policy, &private_block).is_err());
}

#[test]
fn concealment_owner_substitution_and_wrong_physical_key_refuse() {
    let (mut native, proof, policy, block) = fixture(true);
    let mut hidden = proof.clone();
    hidden.current = None;
    assert!(verify(&hidden, &policy, &block).is_err());
    let mut owner = proof.clone();
    owner.owner = account(9);
    assert!(verify(&owner, &policy, &block).is_err());
    // Even an independently signed synthetic World must contain the exact selected key.
    let mut wrong_key = proof.clone();
    let original_key = world_state_value_hash_v1(&reserve_provider_key(provider())).unwrap();
    wrong_key
        .world
        .entries
        .iter_mut()
        .find(|entry| {
            entry.field_id == "world.smart_contract_state" && entry.key_hash == Some(original_key)
        })
        .unwrap()
        .key_hash = Some(
        world_state_value_hash_v1(&reserve_provider_key(ProviderId::new([0x42; 32]))).unwrap(),
    );
    sort(&mut wrong_key);
    let block = certify(&mut native, &wrong_key);
    assert!(verify(&wrong_key, &policy, &block).is_err());
}

#[test]
fn selected_owner_operator_policy_accounts_asset_and_singleton_must_exist() {
    let (mut native, proof, policy, _) = fixture(false);
    let selected = [
        &account(6),
        &policy.operations_authority,
        &policy.custody_account,
        &policy.treasury_account,
        &policy.decision_authority,
    ]
    .into_iter()
    .map(|id| ("world.accounts", world_state_value_hash_v1(id).unwrap()))
    .chain([
        (
            "world.asset_definitions",
            world_state_value_hash_v1(&policy.asset_definition).unwrap(),
        ),
        (
            "world.provider_owners",
            world_state_value_hash_v1(&provider()).unwrap(),
        ),
        (
            "world.smart_contract_state",
            world_state_value_hash_v1(reserve_state_key()).unwrap(),
        ),
    ])
    .collect::<Vec<_>>();
    for (field, key) in selected {
        let mut missing = proof.clone();
        missing
            .world
            .entries
            .retain(|entry| !(entry.field_id == field && entry.key_hash == Some(key)));
        let block = certify(&mut native, &missing);
        assert!(
            verify(&missing, &policy, &block).is_err(),
            "missing {field}"
        );
    }
}

#[test]
fn active_policy_may_advance_without_rewriting_original_partition() {
    let (mut native, mut proof, old, _) = fixture(true);
    let original = proof.current.clone();
    let next = ReserveAuthorityPolicyV1 {
        revision: 2,
        predecessor_policy_digest: Some(old.digest().unwrap()),
        grace_period_days: old.grace_period_days + 1,
        ..old.clone()
    };
    proof.policy = norito::encode_canonical(&singleton(&next)).unwrap();
    rebuild(&mut proof, &next);
    let block = certify(&mut native, &proof);
    let verified = verify(&proof, &next, &block).unwrap();
    assert_eq!(verified.policy().policy_digest, next.digest().unwrap());
    assert_eq!(
        verified.current().unwrap().policy_digest,
        old.digest().unwrap()
    );
    assert_eq!(verified.current().unwrap(), &partition(&old));
    assert_eq!(
        proof.current, original,
        "proof never normalizes native original data"
    );
    assert!(verify(&proof, &old, &block).is_err());
}

#[test]
fn canonical_partition_structure_is_shared_without_extra_consensus_rules() {
    let original = partition(&policy());
    let mut invalid = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut row = original.clone();
            row.$field = $value;
            invalid.push(row);
        }};
    }
    let mut row = original.clone();
    row.terms.capacity_gib = 0;
    invalid.push(row);
    let mut row = original.clone();
    row.terms.provider_id = ProviderId::new([0x42; 32]);
    invalid.push(row);
    changed!(policy_digest, [0; 32]);
    changed!(revision, 0);
    changed!(debt_principal, XorQuantity::try_from_micro(11).unwrap());
    changed!(pending_movements, 257);
    changed!(open_appeals, 17);
    changed!(rent_charged_through_unix, 0);
    changed!(interest_accrued_at_unix, 0);
    changed!(updated_at_unix, 0);
    changed!(rent_charged_through_unix, 2);
    changed!(interest_accrued_at_unix, 2);
    for row in invalid {
        assert!(validate_provider_record(&row, provider()).is_err());
        let bytes = norito::encode_canonical(&row).unwrap();
        assert!(decode_reserve_provider_frame(&bytes, provider()).is_err());
    }
    // Existing native structure accepts any nonzero last-projected digest and <= hard ceilings.
    let mut bounded = original.clone();
    bounded.policy_digest = [0x77; 32];
    bounded.pending_movements = 256;
    bounded.open_appeals = 16;
    validate_provider_record(&bounded, provider()).unwrap();
    assert_eq!(
        reserve_provider_key(provider()).to_string(),
        format!("sorafs_reserve_provider_v1_{}", "41".repeat(32))
    );
    assert_eq!(
        decode_reserve_provider_frame(&norito::encode_canonical(&original).unwrap(), provider())
            .unwrap(),
        original
    );
}

#[test]
fn committed_owner_future_time_and_noncanonical_originals_still_refuse() {
    let (mut native, proof, policy, _) = fixture(true);
    for current in [
        ReserveProviderAccountV1 {
            terms: ReserveProviderTermsV1 {
                provider_account: account(9),
                ..partition(&policy).terms
            },
            ..partition(&policy)
        },
        ReserveProviderAccountV1 {
            updated_at_unix: u64::MAX,
            ..partition(&policy)
        },
    ] {
        let mut changed = proof.clone();
        changed.current = Some(norito::encode_canonical(&current).unwrap());
        rebuild(&mut changed, &policy);
        let block = certify(&mut native, &changed);
        assert!(verify(&changed, &policy, &block).is_err());
    }
    for policy_bytes in [
        {
            let mut state = singleton(&policy);
            state.policy.policy_digest[0] ^= 1;
            norito::encode_canonical(&state).unwrap()
        },
        {
            let mut state = singleton(&policy);
            state.policy.activated_at_unix = u64::MAX;
            norito::encode_canonical(&state).unwrap()
        },
        {
            let mut state = singleton(&policy);
            state.journal_head.last_target_block_height = u64::MAX;
            norito::encode_canonical(&state).unwrap()
        },
    ] {
        let mut changed = proof.clone();
        changed.policy = policy_bytes;
        rebuild(&mut changed, &policy);
        let block = certify(&mut native, &changed);
        assert!(verify(&changed, &policy, &block).is_err());
    }
    let mut trailing = proof;
    trailing.current.as_mut().unwrap().push(0);
    rebuild(&mut trailing, &policy);
    let block = certify(&mut native, &trailing);
    assert!(verify(&trailing, &policy, &block).is_err());
}

#[test]
fn absence_is_only_this_partition_not_empty_namespace_or_readiness() {
    let (mut native, mut proof, policy, _) = fixture(false);
    let unrelated: StatePath = "sorafs_reserve_unrelated_v1".parse().unwrap();
    proof
        .world
        .entries
        .push(row("world.smart_contract_state", &unrelated, &vec![9_u8]));
    sort(&mut proof);
    let block = certify(&mut native, &proof);
    assert!(verify(&proof, &policy, &block).unwrap().current().is_none());
}

#[test]
fn canonical_component_and_cumulative_decode_budgets_are_finite() {
    let (_, proof, policy, block) = fixture_with_credit();
    let bytes = norito::encode_canonical(&proof).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ReserveAccountProofV1::decode_frame(&trailing).is_err());
    assert!(ReserveAccountProofV1::decode_frame(&[]).is_err());
    assert!(
        ReserveAccountProofV1::decode_frame(&vec![0; MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1 + 1])
            .is_err()
    );
    assert!(decode_reserve_provider_frame(&vec![0; STATE_MAX_BYTES + 1], provider()).is_err());
    let tight = norito::DecodeLimits::new(
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        0,
        64,
    );
    assert!(
        norito::core::with_decode_limits_scope(tight, || ReserveAccountProofV1::decode_frame(
            &bytes
        ))
        .unwrap_err()
        .is_decode_resource_limit()
    );
    let (decoded, decode_usage) =
        norito::core::with_decode_limits_measured(RESERVE_ACCOUNT_PROOF_LIMITS_V1, || {
            ReserveAccountProofV1::decode_frame(&bytes)
        });
    assert_eq!(decoded.unwrap(), proof);
    let decode_and_verify = || {
        let decoded = ReserveAccountProofV1::decode_frame(&bytes).map_err(map_invalid)?;
        verify(&decoded, &policy, &block)
    };
    let (outcome, usage) =
        norito::core::with_decode_limits_measured(RESERVE_ACCOUNT_PROOF_LIMITS_V1, || {
            decode_and_verify()
        });
    outcome.unwrap();
    assert!(usage.total_allocated_bytes() > decode_usage.total_allocated_bytes());
    let just_short = norito::DecodeLimits::new(
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        usage.total_allocated_bytes() - 1,
        64,
    );
    assert!(norito::core::with_decode_limits_scope(just_short, decode_and_verify).is_err());
    norito::core::with_decode_limits_scope(RESERVE_ACCOUNT_PROOF_LIMITS_V1, decode_and_verify)
        .unwrap();
    let mut too_large = proof;
    too_large.current = Some(vec![0; STATE_MAX_BYTES + 1]);
    assert!(verify(&too_large, &policy, &block).is_err());
}

fn credit() -> ProviderCreditRecord {
    // These intentionally differ from partition reserve/cap and use future epoch values.
    // A signed synthetic World checks exact projection evidence, not native Upsert validity.
    let mut record = ProviderCreditRecord::new(
        provider(),
        19_u32.into(),
        23_u32.into(),
        29_u32.into(),
        31_u32.into(),
        u64::MAX - 1,
        u64::MAX - 2,
        iroha_model_base::metadata::Metadata::default(),
    );
    record.low_balance_since_epoch = Some(u64::MAX - 3);
    record.slashed = 37_u32.into();
    record.under_delivery_strikes = 5;
    record.last_penalty_epoch = Some(u64::MAX - 4);
    record.metadata.insert(
        "source".parse().unwrap(),
        iroha_primitives::json::Json::new("original"),
    );
    record
}

fn fixture_with_credit() -> (
    NativeFinalityFixture,
    ReserveAccountProofV1,
    ReserveAuthorityPolicyV1,
    VerifiedSumeragiBlock,
) {
    let (mut native, mut proof, policy, _) = fixture(true);
    proof.credit = Some(norito::encode_canonical(&credit()).unwrap());
    rebuild(&mut proof, &policy);
    let block = certify(&mut native, &proof);
    (native, proof, policy, block)
}

#[test]
fn exact_credit_projection_and_explicit_absence_share_owned_and_borrowed_layout() {
    let (_, proof, policy, block) = fixture_with_credit();
    let verified = verify(&proof, &policy, &block).unwrap();
    assert_eq!(verified.credit(), Some(&credit()));
    assert_eq!(verified.current(), Some(&partition(&policy)));
    let borrowed = ReserveAccountProofRefV1::new(
        &proof.world,
        &proof.owner,
        &proof.policy,
        proof.current.as_ref(),
        proof.credit.as_ref(),
        proof.capacity.as_ref(),
        &proof.pricing,
    );
    let bytes = norito::encode_canonical(&proof).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), bytes);
    assert_eq!(ReserveAccountProofV1::decode_frame(&bytes).unwrap(), proof);
    let json = norito::json::to_vec(&proof).unwrap();
    assert_eq!(norito::json::to_vec(&borrowed).unwrap(), json);
    assert_eq!(
        norito::json::from_slice::<ReserveAccountProofV1>(&json).unwrap(),
        proof
    );
    for partition_present in [false, true] {
        let (_, absent, policy, block) = fixture(partition_present);
        let verified = verify(&absent, &policy, &block).unwrap();
        assert!(verified.credit().is_none());
        assert_eq!(verified.current().is_some(), partition_present);
        let mut value = norito::json::to_value(&absent).unwrap();
        let fields = value.as_object_mut().unwrap();
        assert_eq!(fields.remove("credit"), Some(norito::json::Value::Null));
        let missing = norito::json::to_vec(&value).unwrap();
        assert!(norito::json::from_slice::<ReserveAccountProofV1>(&missing).is_err());
    }
}

#[test]
fn credit_concealment_insertion_and_every_typed_original_change_refuse() {
    let (_, proof, policy, block) = fixture_with_credit();
    let mut hidden = proof.clone();
    hidden.credit = None;
    assert!(verify(&hidden, &policy, &block).is_err());
    let (_, mut absent, absent_policy, absent_block) = fixture(true);
    absent.credit = proof.credit.clone();
    assert!(verify(&absent, &absent_policy, &absent_block).is_err());
    let original = credit();
    let mut changes = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut value = original.clone();
            value.$field = $value;
            changes.push(value);
        }};
    }
    changed!(provider_id, ProviderId::new([0x42; 32]));
    changed!(available_credit, 101_u32.into());
    changed!(bonded, 102_u32.into());
    changed!(required_bond, 103_u32.into());
    changed!(expected_settlement, 104_u32.into());
    changed!(onboarding_epoch, 105);
    changed!(last_settlement_epoch, 106);
    changed!(low_balance_since_epoch, None);
    changed!(slashed, 107_u32.into());
    changed!(under_delivery_strikes, 108);
    changed!(last_penalty_epoch, None);
    changed!(metadata, iroha_model_base::metadata::Metadata::default());
    for record in changes {
        let mut altered = proof.clone();
        altered.credit = Some(norito::encode_canonical(&record).unwrap());
        assert!(verify(&altered, &policy, &block).is_err());
    }
}

#[test]
fn credit_key_field_kind_and_typed_hash_are_exact() {
    let (mut native, proof, policy, _) = fixture_with_credit();
    for variant in 0..4 {
        let mut altered = proof.clone();
        let entry = altered
            .world
            .entries
            .iter_mut()
            .find(|entry| entry.field_id == "world.provider_credit_ledger")
            .unwrap();
        match variant {
            0 => entry.field_id = "world.provider_credit_other".into(),
            1 => entry.kind = WorldStateElementKindV1::Cell,
            2 => {
                entry.key_hash =
                    Some(world_state_value_hash_v1(&ProviderId::new([0x42; 32])).unwrap())
            }
            // The response bytes are not the native typed table value.
            _ => {
                entry.value_hash =
                    world_state_value_hash_v1(proof.credit.as_ref().unwrap()).unwrap()
            }
        }
        if entry.kind == WorldStateElementKindV1::Cell {
            entry.key_hash = None;
        }
        sort(&mut altered);
        let block = certify(&mut native, &altered);
        assert!(verify(&altered, &policy, &block).is_err());
        if variant == 1 {
            altered.credit = None;
            assert!(verify(&altered, &policy, &block).is_err());
        }
    }
    let mut mismatched = proof.clone();
    let mut wrong_provider = credit();
    wrong_provider.provider_id = ProviderId::new([0x42; 32]);
    mismatched.credit = Some(norito::encode_canonical(&wrong_provider).unwrap());
    rebuild(&mut mismatched, &policy);
    let block = certify(&mut native, &mismatched);
    assert!(verify(&mismatched, &policy, &block).is_err());
    let (_, mut absent, absent_policy, _) = fixture(false);
    let mut other = credit();
    other.provider_id = ProviderId::new([0x42; 32]);
    absent.world.entries.push(row(
        "world.provider_credit_ledger",
        &other.provider_id,
        &other,
    ));
    sort(&mut absent);
    let block = certify(&mut native, &absent);
    assert!(
        verify(&absent, &absent_policy, &block)
            .unwrap()
            .credit()
            .is_none()
    );
}

#[test]
fn credit_original_codec_bounds_and_inherited_refusal_are_not_absence() {
    let (_, proof, policy, block) = fixture_with_credit();
    let mut trailing = proof.credit.clone().unwrap();
    trailing.push(0);
    for bytes in [
        Vec::new(),
        vec![0],
        trailing,
        vec![0; MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1 + 1],
    ] {
        let mut altered = proof.clone();
        altered.credit = Some(bytes);
        assert!(verify(&altered, &policy, &block).is_err());
    }
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    assert!(
        norito::core::with_decode_limits_scope(zero, || verify(&proof, &policy, &block)).is_err()
    );
    // The same original proof succeeds outside the expired local refusal scope; no new
    // certificate, absent DTO, policy or record was synthesized for retry.
    assert_eq!(
        verify(&proof, &policy, &block).unwrap().credit(),
        Some(&credit())
    );
}

#[test]
fn former_four_field_payload_cannot_omit_credit_absence_evidence() {
    // Deliberately incomplete test specimen under the sole current frame identity. A retired
    // identity is already rejected by canonical decoding; missing the fifth payload field must
    // also fail rather than being defaulted to authenticated absence.
    #[derive(norito::derive::NoritoSerialize)]
    struct Incomplete<'a> {
        world: borrowed::Value<'a, WorldStateSnapshotV1>,
        owner: borrowed::Value<'a, AccountId>,
        policy: borrowed::Vec<'a, u8>,
        current: Option<borrowed::Vec<'a, u8>>,
    }
    impl norito::NoritoSchema for Incomplete<'_> {
        fn nominal_name() -> String {
            <ReserveAccountProofV1 as norito::NoritoSchema>::nominal_name()
        }
        fn frame_name() -> String {
            <ReserveAccountProofV1 as norito::NoritoSchema>::frame_name()
        }
    }
    let (_, proof, _, _) = fixture(false);
    let incomplete = Incomplete {
        world: borrowed::Value(&proof.world),
        owner: borrowed::Value(&proof.owner),
        policy: borrowed::Vec(&proof.policy),
        current: proof.current.as_ref().map(borrowed::Vec),
    };
    assert!(
        ReserveAccountProofV1::decode_frame(&norito::encode_canonical(&incomplete).unwrap())
            .is_err()
    );
}

#[path = "capacity_pricing_tests.rs"]
mod capacity_pricing_tests;
