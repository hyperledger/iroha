//! Same-cut native assignment and restricted-opening joins, without wallet authority.
use super::*;
use crate::asset::AssetDefinitionId;
use crate::{
    NetworkId,
    consensus::{ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole},
    nexus::{
        PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementCommitteeAuthorityV1, PrivateSettlementPoolGovernanceV1,
    },
    sorafs::stream_token_custody::proof::borrowed,
    sumeragi_finality::{FinalityError, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, VerifiedSumeragiBlock},
    sumeragi_lanes::SumeragiLaneState,
};
use iroha_crypto::HashOf;

/// Maximum canonical request: at most the protocol's 255 fixed-width pool selectors.
/// This read bound neither increases a transaction nor a complete-World response limit.
pub const PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1: usize = 64 * 1024;

/// Exact ordered selected pools requested together from one retained World cut.
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
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementContextRequestV1")]
pub struct PrivateSettlementContextRequestV1 {
    /// Unique selectors in the caller's exact intent order; no implicit latest selection.
    pub pools: Vec<PrivateSettlementPoolKeyV1>,
}
impl PrivateSettlementContextRequestV1 {
    /// Validate finite shape without asserting any state authority.
    /// # Errors
    /// Empty/oversized, duplicate or malformed private scope.
    pub fn validate(&self) -> Result<(), FinalityError> {
        if self.pools.is_empty()
            || self.pools.len() > super::super::ATOMIC_PRIVATE_SETTLEMENT_MAX_LEGS_V1
            || self.pools.iter().enumerate().any(|(i, key)| {
                key.pool_id.is_zero()
                    || key.route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
                    || key.route.lane_incarnation == Hash::prehashed([0; 32])
                    || self.pools[..i].contains(key)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// One bounded response for every selected leg from one physical retained World.
/// Complete proofs repeat the same canonical World/lane preimages; the aggregate frame,
/// including all repetitions, remains within the existing 32 MiB complete-World cap.
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
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementContextsProofV1")]
pub struct PrivateSettlementContextsProofV1 {
    /// Exact requested order. No extra values or duplicate selectors are authorized.
    pub contexts: Vec<PrivateSettlementContextProofV1>,
}
/// Encoder borrowing every selected value from the same original funded World.
#[derive(norito::derive::NoritoSerialize, norito::derive::JsonSerialize)]
pub struct PrivateSettlementContextsProofRefV1<'a> {
    contexts: Vec<PrivateSettlementContextProofRefV1<'a>>,
}
impl norito::NoritoSchema for PrivateSettlementContextsProofRefV1<'_> {
    fn nominal_name() -> String {
        PrivateSettlementContextsProofV1::nominal_name()
    }
    fn frame_name() -> String {
        PrivateSettlementContextsProofV1::frame_name()
    }
}
impl<'a> PrivateSettlementContextsProofRefV1<'a> {
    /// Borrow one exact original source; caller funds the finite vector of references.
    pub fn new(contexts: Vec<PrivateSettlementContextProofRefV1<'a>>) -> Self {
        Self { contexts }
    }
}
impl PrivateSettlementContextsProofV1 {
    /// Decode only the bounded canonical data; independent verification remains mandatory.
    /// # Errors
    /// Malformed, noncanonical, oversized or locally unaffordable response.
    pub fn decode_frame(bytes: &[u8]) -> Result<Self, norito::Error> {
        if bytes.is_empty() || bytes.len() > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1 {
            return Err(norito::Error::Message(
                "private contexts exceed complete World bound".into(),
            ));
        }
        norito::decode_canonical_with_limits(
            bytes,
            norito::DecodeLimits::new(
                crate::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
                crate::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                128 * 1024 * 1024,
                64,
            ),
        )
    }
    /// Verify every selector and same-cut preimage before any wallet reservation.
    /// # Errors
    /// Missing/extra/reordered originals or any finality, scope, row or key mismatch.
    pub fn verify(
        &self,
        network: NetworkId,
        schema: Hash,
        request: &PrivateSettlementContextRequestV1,
        block: &VerifiedSumeragiBlock,
    ) -> Result<(), FinalityError> {
        request.validate()?;
        if self.contexts.len() != request.pools.len()
            || norito::canonical_frame_len(self).map_err(|_| invalid())?
                > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
        {
            return Err(invalid());
        }
        let first = &self.contexts[0];
        for (proof, key) in self.contexts.iter().zip(&request.pools) {
            if proof.pool.world != first.pool.world || proof.lanes != first.lanes {
                return Err(invalid());
            }
            proof.verify(network, schema, *key, block)?;
        }
        Ok(())
    }
}

fn invalid() -> FinalityError {
    FinalityError(
        "private context differs from exact committed assignment or restricted opening".into(),
    )
}

/// Original public-key index and one exact live Committee-role record.
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
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementCommitteeKeyProofV1")]
pub struct PrivateSettlementCommitteeKeyProofV1 {
    /// Complete canonical index row, including its registration order.
    pub index: Vec<ConsensusKeyId>,
    /// One original live record whose exact identifier belongs to that index.
    pub record: ConsensusKeyRecord,
}

/// Encoder borrowing both original registry values.
#[derive(norito::derive::NoritoSerialize, norito::derive::JsonSerialize)]
pub struct PrivateSettlementCommitteeKeyProofRefV1<'a> {
    index: borrowed::Value<'a, Vec<ConsensusKeyId>>,
    record: borrowed::Value<'a, ConsensusKeyRecord>,
}
impl norito::NoritoSchema for PrivateSettlementCommitteeKeyProofRefV1<'_> {
    fn nominal_name() -> String {
        PrivateSettlementCommitteeKeyProofV1::nominal_name()
    }
    fn frame_name() -> String {
        PrivateSettlementCommitteeKeyProofV1::frame_name()
    }
}
impl<'a> PrivateSettlementCommitteeKeyProofRefV1<'a> {
    /// Borrow exact funded originals; this constructor grants no authentication.
    #[must_use]
    pub fn new(index: &'a Vec<ConsensusKeyId>, record: &'a ConsensusKeyRecord) -> Self {
        Self {
            index: borrowed::Value(index),
            record: borrowed::Value(record),
        }
    }
}

/// Complete selected World cut plus the public lane/key originals needed for preparation.
///
/// Restricted openings and plaintext witness material are never part of this response.
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
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementContextProofV1")]
pub struct PrivateSettlementContextProofV1 {
    /// Sole complete World proof and selected public governance/frontier rows.
    pub pool: PrivateSettlementPoolCutProofV1,
    /// Exact original canonical native lane cell from that same cut.
    pub lanes: SumeragiLaneState,
    /// Registry originals in the selected lane's exact four-member order.
    #[norito(json = "committee_keys_json")]
    pub committee_keys:
        [PrivateSettlementCommitteeKeyProofV1; PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1],
}

/// Single canonical response encoder borrowing all original native authority.
#[derive(norito::derive::NoritoSerialize, norito::derive::JsonSerialize)]
pub struct PrivateSettlementContextProofRefV1<'a> {
    pool: PrivateSettlementPoolCutProofRefV1<'a>,
    lanes: borrowed::Value<'a, SumeragiLaneState>,
    #[norito(json = "committee_keys_json")]
    committee_keys:
        [PrivateSettlementCommitteeKeyProofRefV1<'a>; PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1],
}
impl norito::NoritoSchema for PrivateSettlementContextProofRefV1<'_> {
    fn nominal_name() -> String {
        PrivateSettlementContextProofV1::nominal_name()
    }
    fn frame_name() -> String {
        PrivateSettlementContextProofV1::frame_name()
    }
}
impl<'a> PrivateSettlementContextProofRefV1<'a> {
    /// Borrow one same-cut response without cloning the retained World graph.
    #[must_use]
    pub fn new(
        pool: PrivateSettlementPoolCutProofRefV1<'a>,
        lanes: &'a SumeragiLaneState,
        committee_keys: [PrivateSettlementCommitteeKeyProofRefV1<'a>;
            PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1],
    ) -> Self {
        Self {
            pool,
            lanes: borrowed::Value(lanes),
            committee_keys,
        }
    }
}

// JSON alone adapts the exact four-element array. The binary field remains the
// canonical fixed array, and both writers visit the original borrowed values.
mod committee_keys_json {
    use super::{PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1, PrivateSettlementCommitteeKeyProofV1};
    use norito::json::{BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser};

    pub(super) fn serialize<T: JsonSerialize>(
        values: &[T; PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1],
        out: &mut String,
    ) {
        out.push('[');
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            value.json_serialize(out);
        }
        out.push(']');
    }
    pub(super) fn serialize_bounded<T: JsonSerialize>(
        values: &[T; PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                value.json_serialize_to(out)?;
            }
            out.push(']')
        })();
        out.end_container();
        result
    }
    pub(super) fn deserialize(
        parser: &mut Parser<'_>,
    ) -> Result<
        [PrivateSettlementCommitteeKeyProofV1; PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1],
        norito::json::Error,
    > {
        // Preflight preserves the original inherited JSON sequence/depth limits
        // and refuses wrong counts before constructing any owned registry row.
        if parser.preflight_array_entries()? != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1 {
            return Err(norito::json::Error::Message(
                "private context requires exactly four committee key proofs".into(),
            ));
        }
        parser.expect(b'[')?;
        let first = PrivateSettlementCommitteeKeyProofV1::json_deserialize(parser)?;
        parser.expect(b',')?;
        let second = PrivateSettlementCommitteeKeyProofV1::json_deserialize(parser)?;
        parser.expect(b',')?;
        let third = PrivateSettlementCommitteeKeyProofV1::json_deserialize(parser)?;
        parser.expect(b',')?;
        let fourth = PrivateSettlementCommitteeKeyProofV1::json_deserialize(parser)?;
        parser.expect(b']')?;
        Ok([first, second, third, fourth])
    }
}

/// Verified historical public context; it grants neither note ownership nor future freshness.
///
/// The native prover must still validate frontier math and original secret membership witnesses.
/// ```compile_fail
/// use iroha_data_model::nexus::VerifiedPrivateSettlementContextV1;
/// let untrusted = norito::decode_canonical::<VerifiedPrivateSettlementContextV1<'_>>(&[]);
/// ```
#[derive(Debug)]
pub struct VerifiedPrivateSettlementContextV1<'a> {
    pool: VerifiedPrivateSettlementPoolCutV1<'a>,
    authority: PrivateSettlementCommitteeAuthorityV1,
}
impl PrivateSettlementContextProofV1 {
    /// Decode under the existing complete-World response and allocation limits.
    /// # Errors
    /// Noncanonical, malformed, oversized or locally unaffordable input.
    pub fn decode_frame(bytes: &[u8]) -> Result<Self, norito::Error> {
        if bytes.is_empty() || bytes.len() > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1 {
            return Err(norito::Error::Message(
                "private context exceeds complete World bound".into(),
            ));
        }
        norito::decode_canonical_with_limits(
            bytes,
            norito::DecodeLimits::new(
                crate::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
                crate::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                128 * 1024 * 1024,
                64,
            ),
        )
    }
    /// Authenticate every original under independently selected root, schema, pool and decision.
    /// # Errors
    /// Any row/cell substitution, invalid assignment, disabled/future/expired registry key,
    /// wrong role or malformed public governance lineage.
    pub fn verify(
        &self,
        network: NetworkId,
        schema: Hash,
        key: PrivateSettlementPoolKeyV1,
        block: &VerifiedSumeragiBlock,
    ) -> Result<VerifiedPrivateSettlementContextV1<'_>, FinalityError> {
        if norito::canonical_frame_len(self).map_err(|_| invalid())?
            > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
        {
            return Err(invalid());
        }
        let pool = self.pool.verify(network, schema, key, block)?;
        let world = pool.verified_world();
        world.verify_cell_value("world.sumeragi_lanes", &self.lanes)?;
        let record = private_settlement_native_route_v1(&self.lanes, key.route, block.height())
            .map_err(|_| invalid())?;
        if record.committee.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1 {
            return Err(invalid());
        }
        let validators: Vec<_> = record
            .committee
            .iter()
            .map(|member| member.peer.clone())
            .collect();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: key.route,
            validator_set_hash: HashOf::new(&validators),
            validators,
            validator_pops: record
                .committee
                .iter()
                .map(|member| member.pop.clone())
                .collect(),
        };
        validate_private_settlement_committee_assignment_v1(
            &self.lanes,
            &authority,
            block.height(),
        )
        .map_err(|_| invalid())?;
        for (member, original) in record.committee.iter().zip(&self.committee_keys) {
            let key = member.peer.public_key().to_string();
            world.verify_table_value("world.consensus_keys_by_pk", &key, &original.index)?;
            world.verify_table_value(
                "world.consensus_keys",
                &original.record.id,
                &original.record,
            )?;
            if original.record.id.role != ConsensusKeyRole::Committee
                || !original.index.contains(&original.record.id)
                || !original.record.is_live_at(block.height(), 0, 0)
                || &original.record.public_key != member.peer.public_key()
            {
                return Err(invalid());
            }
        }
        pool.governance()
            .validate_public_lineage()
            .map_err(|_| invalid())?;
        Ok(VerifiedPrivateSettlementContextV1 { pool, authority })
    }
}
impl<'a> VerifiedPrivateSettlementContextV1<'a> {
    /// Authenticated selected pool and exact replay-table absence checks.
    #[must_use]
    pub fn pool_cut(&self) -> &VerifiedPrivateSettlementPoolCutV1<'a> {
        &self.pool
    }
    /// Complete ordered native participant authority from the same cut.
    #[must_use]
    pub fn authority(&self) -> &PrivateSettlementCommitteeAuthorityV1 {
        &self.authority
    }
    /// Join all public intent fields to this authenticated selected cut before wallet effects.
    ///
    /// This check needs no restricted opening or witness. Callers preparing several legs must
    /// complete it for every selected leg before reserving any of their notes.
    /// # Errors
    /// Malformed intent or a different network, original height, pool, asset or audit policy.
    pub fn verify_intent(
        &self,
        intent: &super::super::PrivateSettlementProofIntentV1,
        ordinal: u8,
    ) -> Result<(), FinalityError> {
        intent.validate().map_err(|_| invalid())?;
        let leg = intent.legs.get(usize::from(ordinal)).ok_or_else(invalid)?;
        let public = self.pool.governance();
        if intent.network_id != self.pool.network()
            || intent.authority_context_height != self.pool.height()
            || intent.expiry_height < self.pool.height()
            || leg.route != self.pool.key().route
            || leg.pool_id != self.pool.key().pool_id
            || leg.asset_binding_commitment != public.asset_binding_commitment
            || leg.audit_policy_digest != public.audit_policy_digest
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Check exact configured restricted openings before consuming any wallet witness.
    ///
    /// Current revision is required, matching native new-Prepare admission. Historical
    /// superseded policy read authorization does not authorize a new payment.
    /// # Errors
    /// Wrong digest, asset/salt, policy/epoch or lifecycle at the selected cut or expiry.
    pub fn verify_openings<'b>(
        &'b self,
        governance: &'b PrivateSettlementPoolGovernanceV1,
        policy: &'b PrivateSettlementAuditPolicyV1,
        asset: &AssetDefinitionId,
        salt: [u8; 32],
        expiry_height: u64,
    ) -> Result<VerifiedPrivateSettlementOpeningsV1<'b, 'a>, FinalityError> {
        let public = self.pool.governance();
        if expiry_height < self.pool.height() {
            return Err(invalid());
        }
        governance
            .validate_asset_opening(self.pool.key().route, self.pool.key().pool_id, asset, salt)
            .map_err(|_| invalid())?;
        governance
            .validate_against_policy_at(policy, self.pool.height())
            .map_err(|_| invalid())?;
        governance
            .validate_against_policy_at(policy, expiry_height)
            .map_err(|_| invalid())?;
        let body = &governance.body;
        if public.version != body.version
            || public.route != body.route
            || public.pool_id != body.pool_id
            || public.asset_binding_commitment != body.asset_binding_commitment
            || public.audit_policy_digest != body.audit_policy_digest
            || public.audit_key_epoch != body.audit_key_epoch
            || public.lifecycle != body.lifecycle
            || public.governance_digest != governance.governance_digest
        {
            return Err(invalid());
        }
        Ok(VerifiedPrivateSettlementOpeningsV1 {
            context: self,
            governance,
            policy,
            expiry_height,
        })
    }
}

/// Borrowed exact configured openings matched to an independently authenticated public cut.
/// No codec or constructor may synthesize this value; secret owners retain their zeroizing Drop.
pub struct VerifiedPrivateSettlementOpeningsV1<'a, 'cut> {
    context: &'a VerifiedPrivateSettlementContextV1<'cut>,
    governance: &'a PrivateSettlementPoolGovernanceV1,
    policy: &'a PrivateSettlementAuditPolicyV1,
    expiry_height: u64,
}
impl std::fmt::Debug for VerifiedPrivateSettlementOpeningsV1<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedPrivateSettlementOpeningsV1(<restricted>)")
    }
}
impl<'a, 'cut> VerifiedPrivateSettlementOpeningsV1<'a, 'cut> {
    /// Same-cut public authority checked before witness consumption.
    #[must_use]
    pub fn context(&self) -> &'a VerifiedPrivateSettlementContextV1<'cut> {
        self.context
    }
    /// Exact configured restricted mapping; do not serialize into workflow journals.
    #[must_use]
    pub fn governance(&self) -> &'a PrivateSettlementPoolGovernanceV1 {
        self.governance
    }
    /// Exact active audit policy, including its authorized auditor keys.
    #[must_use]
    pub fn policy(&self) -> &'a PrivateSettlementAuditPolicyV1 {
        self.policy
    }
    /// Caller-authorized expiry within both restricted lifecycles.
    #[must_use]
    pub fn expiry_height(&self) -> u64 {
        self.expiry_height
    }
}

#[cfg(test)]
#[path = "selected_tests.rs"]
mod tests;
