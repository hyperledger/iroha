//! Original native registry fixtures; no verifier admission is claimed.

use crate::state::World;
use iroha_data_model::{
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};

/// Stable source key used by the relation controls.
pub(crate) fn id() -> VerifyingKeyId {
    VerifyingKeyId::new("stark/fri", "key")
}
/// Minimal record; the inverse does not enforce the separate verifier admission policy.
pub(crate) fn record() -> VerifyingKeyRecord {
    VerifyingKeyRecord::new(
        1,
        "circuit",
        BackendTag::Stark,
        "goldilocks",
        [1; 32],
        [2; 32],
    )
}
/// Identical current and predecessor images with one exact inverse.
pub(crate) fn world() -> World {
    let mut world = World::default();
    let value = record();
    world
        .verifying_keys_by_circuit
        .insert((value.circuit_id.clone(), value.version), id());
    world.verifying_keys.insert(id(), value);
    world
}
/// Restore a correct current inverse while retaining the previous corrupted pair.
pub(crate) fn repair_current(world: &World, previous_index_keys: &[(String, u32)]) {
    let mut index = world.verifying_keys_by_circuit.block();
    for key in previous_index_keys {
        index.remove(key.clone());
    }
    index.insert((record().circuit_id, record().version), id());
    index.commit();
}
