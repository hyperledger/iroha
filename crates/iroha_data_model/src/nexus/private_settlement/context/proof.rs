//! Selected-cut authentication of exact public pool originals; not wallet/prover authority.

use super::*;
use crate::{
    NetworkId,
    block::consensus::SumeragiRootScope,
    sorafs::stream_token_custody::proof::borrowed,
    sumeragi_finality::{
        FinalityError, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
        VerifiedSumeragiBlock, VerifiedWorldStateSnapshotV1, WorldStateSnapshotV1,
    },
};

fn invalid(reason: &str) -> FinalityError {
    FinalityError(reason.into())
}

/// Data-only complete World proof and exact canonical public pool originals.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementPoolCutProofV1")]
pub struct PrivateSettlementPoolCutProofV1 {
    /// Complete hash preimages of the selected original World cut.
    pub world: WorldStateSnapshotV1,
    /// Original canonical public governance row.
    pub governance: PrivateSettlementPoolGovernanceProjectionV1,
    /// Original canonical compact pool frontier row.
    pub pool: PrivateSettlementPoolStateV1,
}

/// Encoder for the sole proof layout, borrowing original funded native values.
#[derive(norito::derive::NoritoSerialize, norito::derive::JsonSerialize)]
pub struct PrivateSettlementPoolCutProofRefV1<'a> {
    world: borrowed::Value<'a, WorldStateSnapshotV1>,
    governance: borrowed::Value<'a, PrivateSettlementPoolGovernanceProjectionV1>,
    pool: borrowed::Value<'a, PrivateSettlementPoolStateV1>,
}
impl norito::NoritoSchema for PrivateSettlementPoolCutProofRefV1<'_> {
    fn nominal_name() -> String {
        <PrivateSettlementPoolCutProofV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <PrivateSettlementPoolCutProofV1 as norito::NoritoSchema>::frame_name()
    }
}
impl<'a> PrivateSettlementPoolCutProofRefV1<'a> {
    /// Borrow exact originals without cloning the World or manufacturing authority.
    #[must_use]
    pub fn new(
        world: &'a WorldStateSnapshotV1,
        governance: &'a PrivateSettlementPoolGovernanceProjectionV1,
        pool: &'a PrivateSettlementPoolStateV1,
    ) -> Self {
        Self {
            world: borrowed::Value(world),
            governance: borrowed::Value(governance),
            pool: borrowed::Value(pool),
        }
    }
}

/// Opaque facts at one independently selected certified Global World cut.
///
/// This is not an execution capability or a complete proving context. Assignment/lifecycle
/// of committee keys, restricted policy openings, and native compact-frontier mathematics
/// must be independently joined before proof generation. Current execution rechecks conflicts.
///
/// Decoding a data-only response cannot construct this token.
/// ```compile_fail
/// use iroha_data_model::nexus::VerifiedPrivateSettlementPoolCutV1;
/// let untrusted = norito::decode_canonical::<VerifiedPrivateSettlementPoolCutV1<'_>>(&[]);
/// ```
#[derive(Debug)]
pub struct VerifiedPrivateSettlementPoolCutV1<'a> {
    network: NetworkId,
    key: PrivateSettlementPoolKeyV1,
    world: VerifiedWorldStateSnapshotV1,
    governance: &'a PrivateSettlementPoolGovernanceProjectionV1,
    pool: &'a PrivateSettlementPoolStateV1,
}
impl PrivateSettlementPoolCutProofV1 {
    /// Decode one canonical bounded proof. Decoding alone grants no verified state.
    /// # Errors
    /// Oversized, noncanonical, malformed or locally unaffordable input.
    pub fn decode_frame(bytes: &[u8]) -> Result<Self, norito::Error> {
        if bytes.is_empty() || bytes.len() > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1 {
            return Err(norito::Error::Message(
                "private pool proof exceeds complete World bound".into(),
            ));
        }
        norito::decode_canonical_with_limits(
            bytes,
            norito::DecodeLimits::new(
                MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
                MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                128 * 1024 * 1024,
                64,
            ),
        )
    }
    /// Authenticate exact selected pool rows under independently selected schema and finality.
    ///
    /// Callers select the network, schema, pool and certified block independently of this reply.
    /// Selecting a sufficiently fresh block is a separate caller policy; historical evidence
    /// never asserts that these facts are still current.
    /// # Errors
    /// Foreign root/network/schema/pool, genesis-only trust, malformed cut, changed typed
    /// preimages, or finite bound refusal.
    pub fn verify<'a>(
        &'a self,
        network: NetworkId,
        schema: Hash,
        key: PrivateSettlementPoolKeyV1,
        block: &VerifiedSumeragiBlock,
    ) -> Result<VerifiedPrivateSettlementPoolCutV1<'a>, FinalityError> {
        if block.height() < 2
            || block.root_scope() != SumeragiRootScope::Global
            || block.commitment().schedule.current.network_id != network
            || self.world.schema_hash != schema
            || key.pool_id.is_zero()
            || key.route.lane_incarnation == Hash::prehashed([0; Hash::LENGTH])
            || key.route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
            || self.governance.route != key.route
            || self.governance.pool_id != key.pool_id
            || self.pool.route != key.route
            || self.pool.pool_id != key.pool_id
            || self.pool.restricted_pool_policy_digest != self.governance.governance_digest
            || norito::canonical_frame_len(self).map_err(|e| FinalityError(e.to_string()))?
                > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
        {
            return Err(invalid(
                "private pool proof differs from selected Global cut or typed scope",
            ));
        }
        let world = self.world.authenticate(block)?;
        world.verify_table_value(
            "world.private_settlement_governance",
            &key,
            &self.governance,
        )?;
        world.verify_table_value("world.private_settlement_pools", &key, &self.pool)?;
        Ok(VerifiedPrivateSettlementPoolCutV1 {
            network,
            key,
            world,
            governance: &self.governance,
            pool: &self.pool,
        })
    }
}
impl VerifiedPrivateSettlementPoolCutV1<'_> {
    /// Independently pinned genesis-derived network of this cut.
    #[must_use]
    pub fn network(&self) -> NetworkId {
        self.network
    }

    pub(super) fn verified_world(&self) -> &VerifiedWorldStateSnapshotV1 {
        &self.world
    }

    /// Exact independently selected route-scoped pool.
    #[must_use]
    pub fn key(&self) -> PrivateSettlementPoolKeyV1 {
        self.key
    }
    /// Original canonical public governance facts, not a restricted policy opening.
    #[must_use]
    pub fn governance(&self) -> &PrivateSettlementPoolGovernanceProjectionV1 {
        self.governance
    }
    /// Original canonical frontier facts; caller reuses native frontier math before proving.
    #[must_use]
    pub fn pool(&self) -> &PrivateSettlementPoolStateV1 {
        self.pool
    }
    /// Selected certified height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.world.height()
    }
    /// Exact selected certified decision.
    #[must_use]
    pub fn context_id(&self) -> Hash {
        self.world.context_id()
    }
    /// Ledger timestamp of that decision, without a wall-clock freshness assertion.
    #[must_use]
    pub fn block_time_ms(&self) -> u64 {
        self.world.block_time_ms()
    }
    /// Prove one exact spent-note marker absent from the canonical table at this same cut.
    /// # Errors
    /// Zero marker, existing key, invalid canonical key or incompatible native field.
    pub fn verify_nullifier_absent(
        &self,
        nullifier: PrivacyNullifierV1,
    ) -> Result<(), FinalityError> {
        if nullifier.is_zero() {
            return Err(invalid("private nullifier is zero"));
        }
        self.world
            .verify_private_settlement_nullifier_absent(&PrivateSettlementNullifierKeyV1 {
                pool: self.key,
                nullifier,
            })
    }
    /// Prove one exact output commitment absent at this same cut; no recipient index is read.
    /// # Errors
    /// Zero commitment, existing key, invalid canonical key or incompatible native field.
    pub fn verify_output_absent(
        &self,
        commitment: PrivacyCommitmentV1,
    ) -> Result<(), FinalityError> {
        if commitment.is_zero() {
            return Err(invalid("private output commitment is zero"));
        }
        self.world
            .verify_private_settlement_output_absent(&PrivateSettlementOutputKeyV1 {
                pool: self.key,
                commitment,
            })
    }
}

#[cfg(test)]
#[path = "proof_tests.rs"]
pub mod tests;
