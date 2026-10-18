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
            ordinal: i as u32,
            authority_digest: Hash::new([i as u8]),
            authorization_context: Hash::new([i as u8, 1]),
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
fn finish(pending: PendingFastpqEffectsDecodeV1) -> AllocatedFastpqEffectsV1 {
    match pending.finish() {
        Ok(owner) => owner,
        Err(_) => panic!("canonical complete tape was not consumable"),
    }
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
