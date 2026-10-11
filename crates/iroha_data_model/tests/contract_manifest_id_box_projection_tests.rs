//! Public identity-box allocation controls through the nested manifest signing boundary.

use super::{FAIL_SIZE, measured, populated_manifest};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    IdBox, ValidationFail,
    account::AccountId,
    asset::id::{AssetDefinitionId, AssetId},
    events::{
        EventFilterBox,
        pipeline::{PipelineEventFilterBox, TransactionEventFilter, TransactionStatus},
    },
    isi::{
        InstructionType,
        error::{InstructionExecutionError, RepetitionError},
    },
    parameter::{CustomParameterId, system::TransactionParameters},
    permission::Permission,
    smart_contract::manifest::{
        ContractManifest, ManifestSigningError, TriggerCallback, TriggerDescriptor,
    },
    transaction::error::TransactionRejectionReason,
    trigger::action::Repeats,
};
use iroha_model_base::{domain::DomainId, name::Name, peer::PeerId, topology::LaneId};
use iroha_primitives::json::Json;
use norito::core::{BoundedEncodeError, DecodeBudgetContext, DecodeFlagsGuard, DecodeLimits};
use std::io;

fn id_cases() -> Vec<IdBox> {
    let name = "original_identity_"
        .repeat(7)
        .parse::<Name>()
        .expect("long checked name");
    let domain = DomainId::try_new("originaldomainlabel".repeat(2).as_str(), "universal")
        .expect("checked domain");
    let key = KeyPair::try_from_seed(vec![0x39; 32], Algorithm::Ed25519)
        .expect("deterministic identity key");
    let account = AccountId::new(key.public_key().clone());
    let definition = AssetDefinitionId::derive_from_components(domain.clone(), name.clone());
    vec![
        IdBox::DomainId(domain.clone()),
        IdBox::AccountId(account.clone()),
        IdBox::AssetDefinitionId(definition.clone()),
        IdBox::AssetId(AssetId::of(definition, account)),
        IdBox::NftId(iroha_data_model::nft::NftId::new(
            domain.clone(),
            name.clone(),
        )),
        IdBox::RwaId(iroha_data_model::rwa::RwaId::new(
            domain,
            Hash::prehashed([0x17; 32]),
        )),
        IdBox::PeerId(PeerId::new(key.public_key().clone())),
        IdBox::LaneId(LaneId::new(7)),
        IdBox::TriggerId(name.as_ref().parse().expect("trigger")),
        IdBox::RoleId(name.as_ref().parse().expect("role")),
        IdBox::Permission(Permission::new(
            "CanObserveOriginalRetainedIdentity".repeat(4),
            Json::from_raw_json(format!("{{\"detail\":\"{}\"}}", "original".repeat(128)))
                .expect("canonical retained JSON"),
        )),
        IdBox::CustomParameterId(CustomParameterId::new(name.clone())),
        IdBox::RepoAgreementId(iroha_data_model::repo::RepoAgreementId::new(name)),
    ]
}

fn funded_context(
    allocated: usize,
) -> (AllocationBudget, AllocationReservation, DecodeBudgetContext) {
    let cap = usize::try_from(TransactionParameters::default().max_tx_bytes().get())
        .expect("native transaction ceiling");
    let pool = AllocationBudget::new(
        allocated
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .expect("finite counter and output allowance"),
    );
    let mut grant = pool
        .try_reserve_bytes(pool.limit_bytes())
        .expect("original complete grant");
    let context = DecodeBudgetContext::from_reservation(
        DecodeLimits::new(
            cap,
            cap,
            cap,
            allocated,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        &mut grant,
    )
    .expect("counter from original grant");
    (pool, grant, context)
}

fn rejected_manifest(id: IdBox) -> ContractManifest {
    let mut manifest = populated_manifest();
    let reason = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::Repetition(RepetitionError::new(InstructionType::Register, id)),
    ));
    let filter =
        TransactionEventFilter::new().for_status(TransactionStatus::Rejected(Box::new(reason)));
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        "original_metadata".parse().expect("metadata name"),
        Json::from_raw_json(format!("{{\"detail\":\"{}\"}}", "canonical".repeat(128)))
            .expect("retained canonical metadata"),
    );
    manifest
        .entrypoints
        .as_mut()
        .expect("populated entrypoints")[0]
        .triggers = vec![TriggerDescriptor {
        id: "original_rejection".parse().expect("trigger id"),
        repeats: Repeats::Exactly(1),
        filter: EventFilterBox::Pipeline(PipelineEventFilterBox::Transaction(filter)),
        authority: None,
        metadata,
        callback: TriggerCallback {
            namespace: None,
            entrypoint: "pay".into(),
        },
    }];
    manifest
}

#[test]
fn public_id_box_counts_and_streams_every_variant_without_heap_scratch() {
    for id in id_cases() {
        let expected = norito::encode_canonical(&id).expect("original canonical identity");
        let (pool, grant, context) = funded_context(0);
        let (counted, allocations) = measured(|| context.with(|| norito::canonical_frame_len(&id)));
        assert_eq!(counted.expect("bounded count"), expected.len());
        assert_eq!(
            allocations, 0,
            "public identity count cloned retained backing"
        );
        assert_eq!(context.consumed_allocated_bytes(), 0);
        let mut actual = vec![0; expected.len()];
        let mut writer = io::Cursor::new(actual.as_mut_slice());
        let (result, allocations) =
            measured(|| context.with(|| norito::core::write_canonical_to_writer(&id, &mut writer)));
        result.expect("bounded streaming write");
        assert_eq!(
            allocations, 0,
            "public identity write cloned retained backing"
        );
        assert_eq!(usize::try_from(writer.position()).unwrap(), expected.len());
        assert_eq!(actual, expected);
        assert_eq!(context.consumed_allocated_bytes(), 0);
        drop(context);
        drop(grant);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn public_id_box_bounded_output_has_only_its_exact_allocation_and_no_renewal() {
    for id in id_cases() {
        let expected = norito::encode_canonical(&id).expect("original canonical identity");
        let (pool, mut grant, context) = funded_context(expected.len());
        let frame = grant
            .try_partition_bytes(expected.len())
            .expect("original exact frame");
        let _layout = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (output, allocations) =
            measured(|| context.with(|| norito::core::to_bytes_bounded(&id, expected.len())));
        let output = output.expect("one exact original output");
        assert_eq!(output, expected);
        assert_eq!(output.capacity(), expected.len());
        assert_eq!(allocations, 1);
        assert_eq!(context.consumed_allocated_bytes(), expected.len() as u64);
        drop(output);
        drop(frame);
        let physical_retry = pool
            .try_reserve_bytes(expected.len())
            .expect("actual physical bytes refunded after output");
        let clone = context.clone();
        let (second, allocations) =
            measured(|| clone.with(|| norito::core::to_bytes_bounded(&id, expected.len())));
        assert!(
            matches!(second, Err(BoundedEncodeError::Serialization(ref e)) if e.is_decode_resource_limit())
        );
        assert_eq!(allocations, 0);
        assert_eq!(context.consumed_allocated_bytes(), expected.len() as u64);
        drop(clone);
        drop(physical_retry);
        drop(context);
        drop(grant);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn public_id_box_preserves_frame_and_actual_allocator_refusals() {
    for id in id_cases() {
        let exact = norito::canonical_frame_len(&id).expect("identity count");
        let (_pool, mut grant, context) = funded_context(exact);
        let _frame = grant.try_partition_bytes(exact).expect("original frame");
        let _layout = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (short, allocations) =
            measured(|| context.with(|| norito::core::to_bytes_bounded(&id, exact - 1)));
        assert!(
            matches!(short, Err(BoundedEncodeError::FrameTooLarge { encoded_bytes, max_bytes })
            if encoded_bytes == exact && max_bytes == exact - 1)
        );
        assert_eq!(allocations, 0);
        assert_eq!(context.consumed_allocated_bytes(), 0);
        FAIL_SIZE.with(|size| size.set(Some(exact)));
        let (refused, allocations) =
            measured(|| context.with(|| norito::core::to_bytes_bounded(&id, exact)));
        assert!(
            matches!(refused, Err(BoundedEncodeError::AllocationFailed { bytes }) if bytes == exact)
        );
        assert_eq!(
            allocations, 1,
            "the refused original output was the sole allocator request"
        );
        assert_eq!(context.consumed_allocated_bytes(), exact as u64);
    }
}

#[test]
fn rejected_event_manifest_count_and_write_need_only_the_original_counter() {
    for id in id_cases() {
        let manifest = rejected_manifest(id);
        let expected = norito::encode_canonical(&manifest.signature_payload())
            .expect("canonical rejected-status manifest");
        let (_pool, _grant, context) = funded_context(0);
        let (count, allocations) = measured(|| {
            context.with(|| norito::canonical_frame_len(&manifest.signature_payload()))
        });
        assert_eq!(count.expect("exact nested count"), expected.len());
        assert_eq!(
            allocations, 0,
            "nested rejection identity caused unowned scratch"
        );
        assert_eq!(context.consumed_allocated_bytes(), 0);
        let mut actual = vec![0; expected.len()];
        let mut writer = io::Cursor::new(actual.as_mut_slice());
        let (result, allocations) = measured(|| {
            manifest
                .signature_payload()
                .write_canonical(&context, expected.len(), &mut writer)
        });
        result.expect("original borrowed nested write");
        assert_eq!(allocations, 0);
        assert_eq!(actual, expected);
        assert_eq!(context.consumed_allocated_bytes(), 0);
    }
}

#[test]
fn rejected_event_manifest_exact_output_preserves_cumulative_and_allocator_refusals() {
    let manifest = rejected_manifest(id_cases().remove(0));
    let exact = norito::canonical_frame_len(&manifest.signature_payload()).expect("manifest count");
    let (_pool, mut grant, context) = funded_context(exact);
    let frame = grant.try_partition_bytes(exact).expect("original frame");
    let (short, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact - 1));
    assert!(matches!(
        short,
        Err(BoundedEncodeError::FrameTooLarge { .. })
    ));
    assert_eq!(allocations, 0);
    assert_eq!(context.consumed_allocated_bytes(), 0);
    let (output, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact));
    let output = output.expect("exact nested output");
    assert_eq!(output.len(), exact);
    assert_eq!(output.capacity(), exact);
    assert_eq!(allocations, 1);
    assert_eq!(context.consumed_allocated_bytes(), exact as u64);
    drop(output);
    drop(frame);
    let (second, allocations) =
        measured(|| manifest.signature_payload_bytes(&context.clone(), exact));
    assert!(
        matches!(second, Err(BoundedEncodeError::Serialization(ref e)) if e.is_decode_resource_limit())
    );
    assert_eq!(allocations, 0);

    let (_pool, mut grant, context) = funded_context(exact);
    let _frame = grant
        .try_partition_bytes(exact)
        .expect("second original fixture frame");
    FAIL_SIZE.with(|size| size.set(Some(exact)));
    let (refused, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact));
    assert!(
        matches!(refused, Err(BoundedEncodeError::AllocationFailed { bytes }) if bytes == exact)
    );
    assert_eq!(allocations, 1);
    assert_eq!(context.consumed_allocated_bytes(), exact as u64);
}

#[test]
fn rejected_event_manifest_signer_and_verification_share_one_finite_original_owner() {
    let key = KeyPair::try_from_seed(vec![0x47; 32], Algorithm::Ed25519)
        .expect("deterministic provenance key");
    let manifest = rejected_manifest(id_cases().remove(10));
    let exact = norito::canonical_frame_len(&manifest.signature_payload()).expect("nested count");
    let key_bytes = key.public_key().retained_allocation_layout().size();
    let cumulative = exact
        .checked_mul(2)
        .and_then(|n| n.checked_add(key_bytes))
        .expect("two finite frames and one exact compact signer");
    let (pool, mut grant, context) = funded_context(cumulative);
    let signer_credit = grant
        .try_partition_bytes(key_bytes)
        .expect("retained original signer grant");
    let frame = grant
        .try_partition_bytes(exact)
        .expect("original signing frame");
    let authenticated = manifest
        .try_signed(&context, exact, &key)
        .expect("bounded provenance");
    assert_eq!(
        context.consumed_allocated_bytes(),
        (exact + key_bytes) as u64
    );
    drop(frame); // try_signed already consumed and freed its payload.
    let verify_frame = grant
        .try_partition_bytes(exact)
        .expect("same original verification frame");
    let (payload, allocations) =
        measured(|| authenticated.signature_payload_bytes(&context, exact));
    let payload = payload.expect("same cumulative owner verification output");
    assert_eq!(allocations, 1);
    let provenance = authenticated.provenance.as_ref().expect("signed manifest");
    assert_eq!(provenance.signer, *key.public_key());
    provenance
        .signature
        .verify(&provenance.signer, &payload)
        .expect("genuine signature");
    assert_eq!(context.consumed_allocated_bytes(), cumulative as u64);
    drop(payload);
    drop(verify_frame);
    drop(authenticated);
    drop(signer_credit);
    drop(context);
    drop(grant);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn rejected_event_manifest_short_signer_allowance_refuses_without_new_credit() {
    let key = KeyPair::try_from_seed(vec![0x47; 32], Algorithm::Ed25519)
        .expect("deterministic provenance key");
    let manifest = rejected_manifest(id_cases().remove(0));
    let exact = norito::canonical_frame_len(&manifest.signature_payload()).expect("nested count");
    let key_bytes = key.public_key().retained_allocation_layout().size();
    let (pool, grant, context) = funded_context(exact + key_bytes - 1);
    let before = pool.reserved_bytes();
    let error = manifest
        .try_signed(&context, exact, &key)
        .expect_err("short original signer allowance");
    assert!(matches!(error,
        ManifestSigningError::Encoding(BoundedEncodeError::Serialization(ref e))
        if e.is_decode_resource_limit()));
    assert_eq!(context.consumed_allocated_bytes(), exact as u64);
    assert_eq!(pool.reserved_bytes(), before);
    drop(context);
    drop(grant);
    assert_eq!(pool.reserved_bytes(), 0);
}
