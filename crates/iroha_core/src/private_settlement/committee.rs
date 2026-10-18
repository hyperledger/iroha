//! Committee-side verification and durable Prepare staging.
//!
//! This boundary joins one consistent committed WSV snapshot with one
//! immutable restricted sidecar. It never returns proof bytes, encrypted audit
//! capsules, approvals, or auditor material: successful callers receive only
//! the exact purpose-separated Prepare body that their consensus key may sign.

use super::{
    protocol::{
        private_settlement_phase_body_v1, private_settlement_reserved_prepared_bundle_digest_v1,
    },
    sidecar_store::{
        PrivateSettlementCommitteeValidationMaterialV1, PrivateSettlementFileSidecarStoreV1,
    },
    state::{
        PrivateSettlementStateErrorV1, ValidatedPrivateSettlementLegV1,
        validate_private_settlement_leg_v1,
    },
};
use crate::private_settlement::global_state::PrivateSettlementPoolKeyExtV1 as _;
#[cfg(test)]
use crate::private_settlement::state::{
    PrivateSettlementPoolGovernanceExtV1 as _, PrivateSettlementPoolStateExtV1 as _,
};
use crate::state::{StateView, WorldView};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::nexus::PrivateSettlementNullifierKeyV1;
use iroha_data_model::nexus::{
    PrivateSettlementPoolGovernanceProjectionV1, PrivateSettlementPoolKeyV1,
    PrivateSettlementPoolStateV1,
};
use iroha_data_model::{
    nexus::{PrivateSettlementPhaseBodyV1, PrivateSettlementPhaseV1},
    privacy::{PrivacyCommitmentV1, PrivacyNullifierV1},
};
use iroha_model_base::peer::PeerId;
use mv::storage::StorageReadOnly as _;
use std::collections::BTreeSet;
use thiserror::Error;

struct PrivateSettlementCommitteeValidationInputsV1 {
    material: PrivateSettlementCommitteeValidationMaterialV1,
    pool_state: PrivateSettlementPoolStateV1,
    pool_governance: PrivateSettlementPoolGovernanceProjectionV1,
    existing_nullifiers: BTreeSet<PrivacyNullifierV1>,
    existing_commitments: BTreeSet<PrivacyCommitmentV1>,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
}

impl PrivateSettlementCommitteeValidationInputsV1 {
    fn validate(&self) -> Result<ValidatedPrivateSettlementLegV1, PrivateSettlementStateErrorV1> {
        validate_private_settlement_leg_v1(
            &self.material.manifest,
            &self.material.payload,
            &self.material.policy,
            &self.material.audit_approvals,
            &self.material.availability,
            &self.pool_state,
            &self.pool_governance,
            &self.existing_nullifiers,
            &self.existing_commitments,
            self.canonical_genesis_hash,
            self.current_height,
        )
    }
}

/// Verify and durably reserve one private-settlement leg before a Prepare vote.
///
/// `state` must be one consistent committed snapshot. The exact committee peer
/// is authenticated again by the restricted store, and every failure maps to
/// one public-safe error without revealing whether material was missing,
/// unauthorized, stale, replayed, or cryptographically invalid.
///
/// # Errors
///
/// Returns a uniformly redacted rejection without returning restricted bytes.
pub(crate) fn prepare_private_settlement_leg_v1(
    state: &StateView<'_>,
    store: &PrivateSettlementFileSidecarStoreV1,
    payload_digest: Hash,
    committee_validator: &PeerId,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
) -> Result<PrivateSettlementPhaseBodyV1, PrivateSettlementCommitteeErrorV1> {
    if state.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(PrivateSettlementCommitteeErrorV1);
    }
    prepare_private_settlement_leg_from_world_v1(
        state.world(),
        store,
        payload_digest,
        committee_validator,
        canonical_genesis_hash,
        current_height,
        PrivateSettlementCommitteeValidationInputsV1::validate,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_private_settlement_leg_from_world_v1<F>(
    world: &WorldView<'_>,
    store: &PrivateSettlementFileSidecarStoreV1,
    payload_digest: Hash,
    committee_validator: &PeerId,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    validate: F,
) -> Result<PrivateSettlementPhaseBodyV1, PrivateSettlementCommitteeErrorV1>
where
    F: FnOnce(
        &PrivateSettlementCommitteeValidationInputsV1,
    ) -> Result<ValidatedPrivateSettlementLegV1, PrivateSettlementStateErrorV1>,
{
    let material = store
        .fetch_for_committee_validation(payload_digest, committee_validator, current_height)
        .map_err(|_| PrivateSettlementCommitteeErrorV1)?;
    let pool_key = PrivateSettlementPoolKeyV1::new(
        material.payload.statement.route,
        material.payload.statement.pool_id,
    )
    .map_err(|_| PrivateSettlementCommitteeErrorV1)?;
    let pool_state = world
        .private_settlement_pools
        .get(&pool_key)
        .cloned()
        .ok_or(PrivateSettlementCommitteeErrorV1)?;
    let pool_governance = world
        .private_settlement_governance
        .get(&pool_key)
        .cloned()
        .ok_or(PrivateSettlementCommitteeErrorV1)?;
    if material
        .payload
        .delta
        .encrypted_outputs
        .iter()
        .any(|output| {
            world
                .private_settlement_recipient_index
                .get(&output.recipient)
                .is_some()
        })
    {
        return Err(PrivateSettlementCommitteeErrorV1);
    }
    let existing_nullifiers = world
        .private_settlement_nullifiers
        .iter()
        .filter_map(|(key, _)| (key.pool == pool_key).then_some(key.nullifier))
        .collect::<BTreeSet<_>>();
    let existing_commitments = world
        .private_settlement_outputs
        .iter()
        .filter_map(|(key, _)| (key.pool == pool_key).then_some(key.commitment))
        .collect::<BTreeSet<_>>();
    let inputs = PrivateSettlementCommitteeValidationInputsV1 {
        material,
        pool_state,
        pool_governance,
        existing_nullifiers,
        existing_commitments,
        canonical_genesis_hash,
        current_height,
    };
    let verified = validate(&inputs).map_err(|_| PrivateSettlementCommitteeErrorV1)?;
    let prepare_body = private_settlement_phase_body_v1(
        &inputs.material.manifest,
        verified.delta(),
        &inputs.material.authority,
        PrivateSettlementPhaseV1::Prepare,
        private_settlement_reserved_prepared_bundle_digest_v1(),
    )
    .map_err(|_| PrivateSettlementCommitteeErrorV1)?;
    store
        .stage_verified(payload_digest, verified, current_height)
        .map_err(|_| PrivateSettlementCommitteeErrorV1)?;
    Ok(prepare_body)
}

/// Uniform public-safe committee preparation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("private-settlement committee preparation failed")]
pub(crate) struct PrivateSettlementCommitteeErrorV1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        private_settlement::{
            global_state::PrivateSettlementFinalizationReferenceV1,
            sidecar_store::{
                PrivateSettlementSidecarLifecycleV1, PrivateSettlementSidecarStoreConfigV1,
                tests::{
                    SidecarFixtureV1, audit_approval, sidecar_fixture,
                    sidecar_fixture_with_threshold,
                },
            },
            state::validate_private_settlement_leg_without_proof_for_test_v1,
        },
        state::World,
    };
    use iroha_crypto::{Algorithm, KeyPair, Signature};
    use iroha_data_model::privacy::PrivacyCommitmentV1;
    use iroha_model_base::peer::PeerId;

    struct CommitteeFixtureV1 {
        restricted: SidecarFixtureV1,
        pool: PrivateSettlementPoolStateV1,
        governance: PrivateSettlementPoolGovernanceProjectionV1,
    }

    fn align_fixture_with_governed_pool(mut restricted: SidecarFixtureV1) -> CommitteeFixtureV1 {
        let initial_commitments = restricted
            .plaintext
            .inputs
            .iter()
            .map(|input| input.commitment)
            .collect::<Vec<_>>();
        let governance = PrivateSettlementPoolGovernanceProjectionV1::from_restricted(
            &restricted.pool_governance,
        )
        .expect("fixture governance projection");
        let pool = PrivateSettlementPoolStateV1::bootstrap(
            restricted.sidecar.payload.statement.route,
            restricted.sidecar.payload.statement.pool_id,
            governance.governance_digest,
            &initial_commitments,
        )
        .expect("fixture pool frontier");
        let successor = pool
            .successor(&restricted.sidecar.payload.statement.output_commitments)
            .expect("fixture successor frontier");

        restricted.sidecar.payload.statement.old_epoch = pool.epoch();
        restricted.sidecar.payload.statement.old_root = pool.root();
        restricted.sidecar.payload.statement.new_epoch = successor.epoch;
        restricted.sidecar.payload.statement.new_root = successor.root;
        restricted.sidecar.payload.delta.old_epoch = pool.epoch();
        restricted.sidecar.payload.delta.old_root = pool.root();
        restricted.sidecar.payload.delta.new_epoch = successor.epoch;
        restricted.sidecar.payload.delta.new_root = successor.root;
        restricted.sidecar.payload.delta.statement_digest = restricted
            .sidecar
            .payload
            .statement
            .digest()
            .expect("aligned statement digest");
        restricted.sidecar.payload.delta.proof_digest = restricted.sidecar.payload.proof_digest();
        restricted.sidecar.manifest.legs[0].delta_digest = restricted
            .sidecar
            .payload
            .delta
            .digest()
            .expect("aligned delta digest");
        let payload_digest = restricted
            .sidecar
            .payload
            .payload_digest()
            .expect("aligned payload digest");
        restricted.sidecar.manifest.legs[0].payload_digest = payload_digest;
        restricted.sidecar.payload.availability.body.payload_digest = payload_digest;
        restricted.sidecar.payload.availability.body.payload_bytes = u32::try_from(
            restricted
                .sidecar
                .payload
                .sidecar_material_bytes_len()
                .expect("aligned sidecar bytes"),
        )
        .expect("fixture sidecar byte bound");
        let availability_preimage = restricted
            .sidecar
            .payload
            .availability
            .signature_preimage()
            .expect("availability preimage");
        let signatures = restricted.validator_keys[..3]
            .iter()
            .map(|key| {
                Signature::try_new(key.private_key(), &availability_preimage)
                    .expect("availability signature")
                    .payload()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let signature_refs = signatures.iter().map(Vec::as_slice).collect::<Vec<_>>();
        restricted.sidecar.payload.availability.aggregate_signature =
            iroha_crypto::bls_normal_aggregate_signatures(&signature_refs)
                .expect("availability aggregate");
        restricted.sidecar.manifest.legs[0].availability_certificate_digest = restricted
            .sidecar
            .payload
            .availability
            .digest()
            .expect("availability digest");
        restricted
            .sidecar
            .validate()
            .expect("WSV-aligned restricted sidecar");
        CommitteeFixtureV1 {
            restricted,
            pool,
            governance,
        }
    }

    fn world_with_pool(fixture: &CommitteeFixtureV1, pool: PrivateSettlementPoolStateV1) -> World {
        let mut world = World::default();
        let key = PrivateSettlementPoolKeyV1::new(pool.route(), pool.pool_id())
            .expect("fixture pool key");
        world
            .private_settlement_governance
            .insert(key, fixture.governance.clone());
        world.private_settlement_pools.insert(key, pool);
        world
    }

    fn validate_without_proof(
        inputs: &PrivateSettlementCommitteeValidationInputsV1,
    ) -> Result<ValidatedPrivateSettlementLegV1, PrivateSettlementStateErrorV1> {
        validate_private_settlement_leg_without_proof_for_test_v1(
            &inputs.material.manifest,
            &inputs.material.payload,
            &inputs.material.policy,
            &inputs.material.audit_approvals,
            &inputs.material.availability,
            &inputs.pool_state,
            &inputs.pool_governance,
            &inputs.existing_nullifiers,
            &inputs.existing_commitments,
            inputs.current_height,
        )
    }

    fn open_and_audit(
        fixture: &CommitteeFixtureV1,
        root: &std::path::Path,
    ) -> (PrivateSettlementFileSidecarStoreV1, Hash) {
        let store = PrivateSettlementFileSidecarStoreV1::open(
            root.join("restricted-sidecars"),
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open committee store");
        store
            .store(fixture.restricted.sidecar.clone())
            .expect("store restricted sidecar");
        let digest = fixture.restricted.sidecar.payload_digest();
        let approval = audit_approval(&store, &fixture.restricted, digest, 12);
        store
            .record_audited(digest, vec![approval], 12)
            .expect("threshold approval is durable");
        (store, digest)
    }

    fn prepare_from_world(
        fixture: &CommitteeFixtureV1,
        world: &World,
        store: &PrivateSettlementFileSidecarStoreV1,
        digest: Hash,
        validator: &PeerId,
        current_height: u64,
    ) -> Result<PrivateSettlementPhaseBodyV1, PrivateSettlementCommitteeErrorV1> {
        prepare_private_settlement_leg_from_world_v1(
            &world.view(),
            store,
            digest,
            validator,
            *fixture.restricted.sidecar.manifest.network_id.as_bytes(),
            current_height,
            validate_without_proof,
        )
    }

    #[test]
    fn audited_committee_leg_is_staged_before_prepare_candidate_is_returned() {
        let fixture = align_fixture_with_governed_pool(sidecar_fixture());
        let world = world_with_pool(&fixture, fixture.pool.clone());
        let temp = tempfile::tempdir().expect("tempdir");
        let (store, digest) = open_and_audit(&fixture, temp.path());

        let candidate = prepare_from_world(
            &fixture,
            &world,
            &store,
            digest,
            &fixture.restricted.validator,
            12,
        )
        .expect("committee Prepare candidate");
        assert_eq!(candidate.phase, PrivateSettlementPhaseV1::Prepare);
        assert_eq!(
            candidate.prepared_bundle_digest,
            private_settlement_reserved_prepared_bundle_digest_v1()
        );
        assert_eq!(
            candidate.delta_digest,
            fixture.restricted.sidecar.manifest.legs[0].delta_digest
        );
        assert_eq!(
            store
                .fetch_for_committee(digest, &fixture.restricted.validator, 12)
                .expect("prepared committee view")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::Prepared
        );
    }

    #[test]
    fn exact_prepare_retry_is_idempotent_across_store_restart() {
        let fixture = align_fixture_with_governed_pool(sidecar_fixture());
        let world = world_with_pool(&fixture, fixture.pool.clone());
        let temp = tempfile::tempdir().expect("tempdir");
        let (store, digest) = open_and_audit(&fixture, temp.path());
        let first = prepare_from_world(
            &fixture,
            &world,
            &store,
            digest,
            &fixture.restricted.validator,
            12,
        )
        .expect("first Prepare candidate");
        drop(store);

        let reopened = PrivateSettlementFileSidecarStoreV1::open(
            temp.path().join("restricted-sidecars"),
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("reopen staged committee store");
        let replay = prepare_from_world(
            &fixture,
            &world,
            &reopened,
            digest,
            &fixture.restricted.validator,
            13,
        )
        .expect("idempotent Prepare candidate after restart");
        assert_eq!(first, replay);
    }

    #[test]
    fn unauthorized_committee_fetch_is_uniformly_rejected() {
        let fixture = align_fixture_with_governed_pool(sidecar_fixture());
        let world = world_with_pool(&fixture, fixture.pool.clone());
        let temp = tempfile::tempdir().expect("tempdir");
        let (store, digest) = open_and_audit(&fixture, temp.path());
        let outsider = PeerId::from(
            KeyPair::from_seed(vec![0xFA; 32], Algorithm::BlsNormal)
                .public_key()
                .clone(),
        );

        assert_eq!(
            prepare_from_world(&fixture, &world, &store, digest, &outsider, 12),
            Err(PrivateSettlementCommitteeErrorV1)
        );
    }

    #[test]
    fn stale_pool_head_and_wsv_replays_are_uniformly_rejected() {
        let fixture = align_fixture_with_governed_pool(sidecar_fixture());
        let temp = tempfile::tempdir().expect("tempdir");
        let (store, digest) = open_and_audit(&fixture, temp.path());
        let stale_pool = PrivateSettlementPoolStateV1::bootstrap(
            fixture.pool.route(),
            fixture.pool.pool_id(),
            fixture.governance.governance_digest,
            &[PrivacyCommitmentV1::new([0xEE; 32])],
        )
        .expect("different authoritative pool head");
        let stale_world = world_with_pool(&fixture, stale_pool);
        assert_eq!(
            prepare_from_world(
                &fixture,
                &stale_world,
                &store,
                digest,
                &fixture.restricted.validator,
                12,
            ),
            Err(PrivateSettlementCommitteeErrorV1)
        );

        let mut replay_world = world_with_pool(&fixture, fixture.pool.clone());
        let pool_key =
            PrivateSettlementPoolKeyV1::new(fixture.pool.route(), fixture.pool.pool_id())
                .expect("fixture pool key");
        replay_world.private_settlement_nullifiers.insert(
            PrivateSettlementNullifierKeyV1 {
                pool: pool_key,
                nullifier: fixture.restricted.sidecar.payload.delta.nullifiers[0],
            },
            PrivateSettlementFinalizationReferenceV1 {
                bundle_id: Hash::new(b"prior bundle"),
                receipt_digest: Hash::new(b"prior receipt"),
                leg_ordinal: 0,
                finalized_height: 11,
            },
        );
        assert_eq!(
            prepare_from_world(
                &fixture,
                &replay_world,
                &store,
                digest,
                &fixture.restricted.validator,
                12,
            ),
            Err(PrivateSettlementCommitteeErrorV1)
        );

        let mut recipient_replay_world = world_with_pool(&fixture, fixture.pool.clone());
        recipient_replay_world
            .private_settlement_recipient_index
            .insert(
                fixture.restricted.sidecar.payload.delta.encrypted_outputs[0].recipient,
                PrivateSettlementFinalizationReferenceV1 {
                    bundle_id: Hash::new(b"prior recipient bundle"),
                    receipt_digest: Hash::new(b"prior recipient receipt"),
                    leg_ordinal: 0,
                    finalized_height: 11,
                },
            );
        assert_eq!(
            prepare_from_world(
                &fixture,
                &recipient_replay_world,
                &store,
                digest,
                &fixture.restricted.validator,
                12,
            ),
            Err(PrivateSettlementCommitteeErrorV1)
        );
    }

    #[test]
    fn insufficient_auditor_threshold_never_reaches_validation_or_staging() {
        let fixture = align_fixture_with_governed_pool(sidecar_fixture_with_threshold(2));
        let world = world_with_pool(&fixture, fixture.pool.clone());
        let temp = tempfile::tempdir().expect("tempdir");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            temp.path().join("restricted-sidecars"),
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open threshold store");
        store
            .store(fixture.restricted.sidecar.clone())
            .expect("store threshold sidecar");
        let digest = fixture.restricted.sidecar.payload_digest();
        let first = audit_approval(&store, &fixture.restricted, digest, 12);
        let outcome = store
            .record_audit_approval(digest, first, 12)
            .expect("first approval is durable");
        assert!(!outcome.audited);

        assert_eq!(
            prepare_from_world(
                &fixture,
                &world,
                &store,
                digest,
                &fixture.restricted.validator,
                12,
            ),
            Err(PrivateSettlementCommitteeErrorV1)
        );
    }
}
