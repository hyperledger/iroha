//! Exact graph parity and retained-prefix refusal controls for every closed effect variant.

use super::*;
use crate::account::{MultisigMember, MultisigPolicy};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{Algorithm, KeyPair};
use norito::core::{PreparedDecodeError, PreparedDecodeWorkspace};

fn account(seed: u8) -> AccountId {
    AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(
                    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                    1,
                )
                .unwrap(),
                MultisigMember::new(
                    KeyPair::from_seed(vec![seed + 1; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                    2,
                )
                .unwrap(),
            ],
        )
        .unwrap(),
    )
}
fn fixture() -> FastpqExecutionEffectsV1 {
    let mut tape = super::super::tests::effects();
    let FastpqExecutionEffectKindV1::Mint(mut mint) = tape.effects[0].kind.clone() else {
        panic!("canonical fixture")
    };
    mint.balance.account = account(11);
    let mut destination = mint.balance.clone();
    destination.account = account(31);
    let transfer = FastpqExecutionTransferV1 {
        source: mint.balance.clone(),
        destination,
        amount: Quantity::from(2u32),
        source_before: Quantity::from(9u32),
        source_after: Quantity::from(7u32),
        destination_before: Quantity::from(1u32),
        destination_after: Quantity::from(3u32),
    };
    let mut burn = mint.clone();
    burn.balance.account = account(51);
    let kinds = [
        FastpqExecutionEffectKindV1::Transfer(transfer),
        FastpqExecutionEffectKindV1::Mint(mint.clone()),
        FastpqExecutionEffectKindV1::Burn(burn),
        FastpqExecutionEffectKindV1::Retire(mint.balance.asset),
    ];
    tape.effects = kinds
        .into_iter()
        .enumerate()
        .map(|(i, kind)| FastpqExecutionEffectV1 {
            ordinal: u32::try_from(i).expect("fixture ordinal fits u32"),
            authority_digest: Hash::new([u8::try_from(i).expect("fixture index fits u8")]),
            authorization_context: Hash::new([u8::try_from(i).expect("fixture index fits u8"), 1]),
            kind,
        })
        .collect();
    tape
}
fn workspace(pool: &AllocationBudget) -> PreparedDecodeWorkspace {
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    PreparedDecodeWorkspace::from_reservation(pool, &mut reservation).unwrap()
}
fn decode(
    workspace: &mut PreparedDecodeWorkspace,
    bytes: &[u8],
    pending: &mut PendingFastpqEffectsDecodeV1,
) -> Result<(), PreparedDecodeError<Error>> {
    workspace.decode_canonical_into::<FastpqExecutionEffectsV1, _>(
        bytes,
        norito::canonical_decode_limits(bytes.len()),
        pending,
    )
}
fn finish(mut pending: PendingFastpqEffectsDecodeV1) -> AllocatedFastpqEffectsV1 {
    pending
        .finish()
        .unwrap_or_else(|_| panic!("canonical complete tape was not consumable"))
}
#[test]
fn every_closed_effect_variant_keeps_exact_original_graph_and_physical_custody() {
    let original = fixture();
    let bytes = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(8 * 1024 * 1024);
    let mut workspace = workspace(&pool);
    let controls = pool.reserved_bytes();
    let mut pending = PendingFastpqEffectsDecodeV1::new(&pool, original.effects.len());
    decode(&mut workspace, &bytes, &mut pending).unwrap();
    assert!(pending.belongs_to(&pool));
    let complete = finish(pending);
    assert_eq!(complete.canonical(), &original);
    assert_eq!(
        execution_effects_digest_v1(complete.canonical()).unwrap(),
        execution_effects_digest_v1(&original).unwrap()
    );
    assert_eq!(
        pool.reserved_bytes(),
        controls + complete.allocation_bytes().unwrap()
    );
    assert!(complete.belongs_to(&pool));
    assert!(!complete.belongs_to(&AllocationBudget::new(8 * 1024 * 1024)));
    drop(complete);
    assert_eq!(pool.reserved_bytes(), controls);
    drop(workspace);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn last_effect_allocation_refusal_preserves_completed_multisig_prefix_and_retries_same_source() {
    let original = fixture();
    let bytes = norito::encode_canonical(&original).unwrap();
    let probe = AllocationBudget::new(8 * 1024 * 1024);
    let mut controls = workspace(&probe);
    let mut full = PendingFastpqEffectsDecodeV1::new(&probe, 8);
    decode(&mut controls, &bytes, &mut full).unwrap();
    let demand = probe.reserved_bytes();
    drop(full);
    drop(controls);
    assert_eq!(probe.reserved_bytes(), 0);
    let pool = AllocationBudget::new(demand);
    let blocker = pool.try_reserve_bytes(1).unwrap();
    let mut controls = workspace(&pool);
    let mut pending = PendingFastpqEffectsDecodeV1::new(&pool, 8);
    let error = decode(&mut controls, &bytes, &mut pending).unwrap_err();
    assert!(matches!(
        error,
        PreparedDecodeError::Destination(Error::Allocation(ChargedBufferError::Admission(
            AllocationRefusal::Capacity { .. }
        )))
    ));
    let values = pending
        .effects
        .as_ref()
        .expect("original concrete effect backing");
    assert!(
        !values.as_slice().is_empty(),
        "late refusal must retain a real decoded prefix"
    );
    let pointer = values.as_slice().as_ptr();
    let count = values.as_slice().len();
    assert!(pending.belongs_to(&pool));
    let retained = pool.reserved_bytes();
    let owner_address = std::ptr::from_ref(&pending);
    let source = pending.source;
    let context_source = pending.context_source;
    let ledger_pointer = pending.ledger.as_ref().unwrap().as_slice().as_ptr();
    assert!(matches!(
        pending.finish(),
        Err(Error::Invariant("unfinished tape destination"))
    ));
    assert_eq!(std::ptr::from_ref(&pending), owner_address);
    assert_eq!(pending.source, source);
    assert_eq!(pending.context_source, context_source);
    assert_eq!(
        pending.effects.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    assert_eq!(pending.effects.as_ref().unwrap().as_slice().len(), count);
    assert_eq!(
        pending.ledger.as_ref().unwrap().as_slice().as_ptr(),
        ledger_pointer
    );
    assert_eq!(pool.reserved_bytes(), retained);
    assert!(!pending.is_complete());
    assert!(pending.belongs_to(&pool));
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), retained - 1);
    decode(&mut controls, &bytes, &mut pending).unwrap();
    assert_eq!(
        pending.effects.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    assert!(pending.effects.as_ref().unwrap().as_slice().len() > count);
    let complete = finish(pending);
    assert_eq!(complete.canonical(), &original);
    drop(complete);
    drop(controls);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn original_context_cannot_be_substituted_after_a_complete_tape_is_retained() {
    let original = fixture();
    let bytes = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(8 * 1024 * 1024);
    let mut controls = workspace(&pool);
    let mut pending = PendingFastpqEffectsDecodeV1::new(&pool, 8);
    decode(&mut controls, &bytes, &mut pending).unwrap();
    let retained = pool.reserved_bytes();
    let mut changed = original;
    changed.context.source.height += 1;
    let changed = norito::encode_canonical(&changed).unwrap();
    let error = decode(&mut controls, &changed, &mut pending).unwrap_err();
    assert!(matches!(
        error,
        PreparedDecodeError::Destination(Error::Invariant("original tape context changed"))
    ));
    assert_eq!(pool.reserved_bytes(), retained);
    assert!(pending.belongs_to(&pool));
    decode(&mut controls, &bytes, &mut pending).unwrap();
    drop(finish(pending));
    drop(controls);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn fixed_manifest_uses_the_original_workspace_and_exact_canonical_frame() {
    let tape = fixture();
    let entries = [tape.context.entry];
    let manifest = crate::fastpq::build_fastpq_ordinary_source_statement_manifest_v1(
        tape.context.source,
        &entries,
        &[],
        1,
        0,
    )
    .unwrap();
    let bytes = norito::encode_canonical(&manifest).unwrap();
    let pool = AllocationBudget::new(4096);
    let mut controls = workspace(&pool);
    let original = pool.reserved_bytes();
    assert_eq!(
        decode_fastpq_source_manifest_frame_v1(&bytes, &mut controls).unwrap(),
        manifest
    );
    assert_eq!(
        pool.reserved_bytes(),
        original,
        "fixed fields must not materialize hidden DTO backing"
    );
    let mut altered = bytes.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert!(decode_fastpq_source_manifest_frame_v1(&altered, &mut controls).is_err());
    assert_eq!(pool.reserved_bytes(), original);
    assert_eq!(
        decode_fastpq_source_manifest_frame_v1(&bytes, &mut controls).unwrap(),
        manifest
    );
    drop(controls);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn effect_count_cap_refuses_before_any_effect_or_member_backing() {
    let original = fixture();
    let bytes = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(8 * 1024 * 1024);
    let mut controls = workspace(&pool);
    let used = pool.reserved_bytes();
    let mut pending = PendingFastpqEffectsDecodeV1::new(&pool, original.effects.len() - 1);
    assert!(matches!(
        decode(&mut controls, &bytes, &mut pending),
        Err(PreparedDecodeError::Destination(Error::EffectLimit {
            actual: 4,
            maximum: 3
        }))
    ));
    assert!(!pending.is_complete());
    assert!(pending.effects.is_none());
    assert!(pending.ledger.is_none());
    assert_eq!(pool.reserved_bytes(), used);
    drop(pending);
    drop(controls);
    assert_eq!(pool.reserved_bytes(), 0);
}

fn source_leaf() -> crate::fastpq::FastpqOrdinarySourceStatementLeafV1 {
    let tape = fixture();
    crate::fastpq::FastpqOrdinarySourceStatementLeafV1 {
        source: tape.context.source,
        statement_index: 0,
        entry_index: 0,
        effect_count: u32::try_from(tape.effects.len()).unwrap(),
        entry_hash: tape.context.entry.entry_hash,
        execution_kind: tape.context.entry.execution_kind,
        route: tape.context.entry.route,
        dataspace_id: tape.context.entry.dataspace_id,
        effects_digest: execution_effects_digest_v1(&tape).unwrap().into(),
        slot: 123_456,
        perm_root: [0x23; 32],
        tx_set_hash: [0x45; 32],
    }
}

// Enter the same canonical element-field boundary used by the funded source
// destination, without introducing a context around any raw array child.
fn source_leaf_field(
    payload: &[u8],
) -> Result<crate::fastpq::FastpqOrdinarySourceStatementLeafV1, Error> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut framed = Vec::new();
    ncore::write_len_with_flags(
        &mut framed,
        u64::try_from(payload.len()).unwrap(),
        ncore::default_encode_flags(),
    )
    .unwrap();
    framed.extend_from_slice(payload);
    let _context = ncore::PayloadCtxGuard::enter(&framed);
    let mut offset = 0;
    let field = ncore::framed_field::<crate::fastpq::FastpqOrdinarySourceStatementLeafV1>(
        &framed,
        &mut offset,
    )?;
    let result = field
        .with_payload(|bytes| decode_fastpq_source_leaf_payload_v1(bytes).map_err(destination));
    assert_eq!(offset, framed.len());
    result.map_err(Error::from)
}

#[test]
fn source_leaf_raw_arrays_preserve_following_fields_under_canonical_boundary() {
    let original = source_leaf();
    let frame = norito::encode_canonical(&original).unwrap();
    assert_eq!(
        norito::decode_canonical::<crate::fastpq::FastpqOrdinarySourceStatementLeafV1>(&frame)
            .unwrap(),
        original,
    );
    let view = ncore::from_bytes_view(&frame).unwrap();
    let decoded = source_leaf_field(view.as_bytes()).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
    assert_eq!(decoded.slot, 123_456);
    assert_eq!(decoded.perm_root, [0x23; 32]);
    assert_eq!(decoded.tx_set_hash, [0x45; 32]);
}

#[test]
fn source_leaf_raw_arrays_keep_exact_width_and_complete_record_checks() {
    let frame = norito::encode_canonical(&source_leaf()).unwrap();
    let view = ncore::from_bytes_view(&frame).unwrap();
    let payload = view.as_bytes();
    let mut offset = 0;
    for _ in 0..8 {
        let (length, prefix) =
            ncore::read_len_from_slice_with_flags(&payload[offset..], view.flags()).unwrap();
        offset += prefix + length;
    }
    let (length, prefix) =
        ncore::read_len_from_slice_with_flags(&payload[offset..], view.flags()).unwrap();
    assert_eq!(length, 32, "the actual nonterminal effects_digest field");
    for width in [31, 33] {
        let mut malformed = payload[..offset].to_vec();
        ncore::write_len_with_flags(&mut malformed, width, view.flags()).unwrap();
        malformed.extend_from_slice(&payload[offset + prefix..]);
        assert!(matches!(
            source_leaf_field(&malformed),
            Err(Error::Codec(norito::Error::LengthMismatch))
        ));
    }
    assert!(source_leaf_field(&payload[..payload.len() - 1]).is_err());
    let mut trailing = payload.to_vec();
    trailing.push(0);
    assert!(matches!(
        source_leaf_field(&trailing),
        Err(Error::Codec(norito::Error::LengthMismatch))
    ));
    assert_eq!(source_leaf_field(payload).unwrap(), source_leaf());
}

#[test]
fn completed_tape_take_rejects_prepared_replay_without_reminting_custody() {
    let original = fixture();
    let bytes = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(8 * 1024 * 1024);
    let mut workspace = workspace(&pool);
    let controls = pool.reserved_bytes();
    let mut pending = PendingFastpqEffectsDecodeV1::new(&pool, original.effects.len());
    decode(&mut workspace, &bytes, &mut pending).unwrap();
    let pointer = pending.effects.as_ref().unwrap().as_slice().as_ptr();
    let complete = pending.finish().unwrap();
    assert_eq!(complete.canonical(), &original);
    assert_eq!(complete.canonical().effects.as_ptr(), pointer);
    assert!(complete.belongs_to(&pool));
    let retained = controls + complete.allocation_bytes().unwrap();
    assert_eq!(pool.reserved_bytes(), retained);
    assert!(!pending.is_complete());
    assert!(matches!(
        pending.finish(),
        Err(Error::Invariant("completed tape was already taken"))
    ));
    assert!(matches!(
        pending.decode_payload(&[]),
        Err(Error::Invariant("completed tape was already taken"))
    ));
    // The public prepared decoder resets a destination before traversal; reset must
    // never revive this consumed original or allocate another copy of its tape.
    assert!(
        matches!(
            decode(&mut workspace, &bytes, &mut pending),
            Err(PreparedDecodeError::Destination(Error::Invariant(
                "completed tape was already taken"
            )))
        ),
        "completed FASTPQ tape must refuse prepared replay without minting another graph"
    );
    assert_eq!(pool.reserved_bytes(), retained);
    assert!(!pending.is_complete());
    assert_eq!(complete.canonical(), &original);
    drop(pending);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(complete);
    assert_eq!(pool.reserved_bytes(), controls);
    drop(workspace);
    assert_eq!(pool.reserved_bytes(), 0);
}
