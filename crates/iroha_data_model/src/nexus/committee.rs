//! Frozen validator elections and per-seat preparation evidence.
//!
//! A preparation selects an immutable committee two scheduling epochs ahead.
//! Its terminal disposition is authenticated by incumbent boundary finality.

use crate::{
    NetworkId,
    asset::{AssetBalanceScope, AssetDefinitionId},
    block::BlockHeader,
    consensus::GlobalThresholdBeaconPartialSignatureV1,
    parameter::{CustomParameter, CustomParameterId, system::SumeragiNposParameters},
    sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, MAX_VALIDATORS,
        ValidatorCommitteeMemberV1, ValidatorEpochAuthorizationV1, ValidatorEpochDecisionV1,
        ValidatorGenerationV1, validate_committee,
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_model_base::peer::PeerId;
use iroha_primitives::{
    json::Json,
    numeric::{Quantity, XOR_QUANTITY_SCALE},
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Signed eligibility policy frozen with one immutable committee selection.
///
/// The selecting execution authenticates the XOR identity against the network's installed
/// parameters. Activation uses these exact floors and bounds even if later parameters change.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorElectionPolicyV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorElectionPolicyV1 {
    /// Exact canonical XOR definition authenticated by this network's signed parameters.
    pub xor_asset_definition_id: AssetDefinitionId,
    /// The single global custody bucket; dataspace-scoped stake is not eligible.
    pub asset_scope: AssetBalanceScope,
    /// Canonical XOR precision, exactly nine decimal places.
    pub asset_scale: u32,
    /// Positive minimum self-bond, exactly representable at the frozen asset scale.
    pub min_self_bond: Quantity,
    /// Positive minimum nomination, exactly representable at the frozen asset scale.
    pub min_nomination_bond: Quantity,
    /// Exact bounded `3f + 1` selection ceiling, in 4 through 31.
    pub max_validators: u32,
    /// Complete target epoch length; at least three heights are required for the real pulse.
    pub epoch_length_blocks: u64,
}

impl ValidatorElectionPolicyV1 {
    /// Snapshot the exact eligibility fields of authenticated network parameters.
    ///
    /// This does not authenticate an arbitrary parameter body. The selecting execution must
    /// obtain it from its original committed prestate and check the actual XOR definition.
    ///
    /// # Errors
    /// Rejects invalid signed parameters or noncanonical frozen eligibility bounds.
    pub fn from_npos_parameters(parameters: &SumeragiNposParameters) -> Result<Self, String> {
        parameters.validate().map_err(str::to_owned)?;
        let policy = Self {
            xor_asset_definition_id: parameters.xor_asset_definition_id.clone(),
            asset_scope: AssetBalanceScope::Global,
            asset_scale: XOR_QUANTITY_SCALE,
            min_self_bond: parameters.min_self_bond.clone(),
            min_nomination_bond: parameters.min_nomination_bond.clone(),
            max_validators: parameters.max_validators,
            epoch_length_blocks: parameters.epoch_length_blocks.get(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the signed eligibility fields without constructing an owned snapshot.
    ///
    /// This borrows the original parameters and supplies the same Global XOR precision
    /// as [`Self::from_npos_parameters`]. It grants no network or execution authority.
    ///
    /// # Errors
    /// Preserves signed-parameter validation before the frozen eligibility bounds.
    pub(crate) fn validate_npos_parameters(
        parameters: &SumeragiNposParameters,
    ) -> Result<(), String> {
        parameters.validate().map_err(str::to_owned)?;
        validate_election_policy_fields(
            &parameters.xor_asset_definition_id,
            AssetBalanceScope::Global,
            XOR_QUANTITY_SCALE,
            &parameters.min_self_bond,
            &parameters.min_nomination_bond,
            parameters.max_validators,
            parameters.epoch_length_blocks.get(),
        )
    }

    /// Validate the exact first-release monetary and scheduling bounds.
    ///
    /// The network-specific XOR identity is authenticated by the selecting execution and
    /// frozen in this body; its name alone cannot establish network authority.
    ///
    /// # Errors
    /// Rejects synthetic stake, scoped custody, wrong precision, fractional dust, or bad bounds.
    pub fn validate(&self) -> Result<(), String> {
        validate_election_policy_fields(
            &self.xor_asset_definition_id,
            self.asset_scope,
            self.asset_scale,
            &self.min_self_bond,
            &self.min_nomination_bond,
            self.max_validators,
            self.epoch_length_blocks,
        )
    }
}

// One predicate serves the owned snapshot and the original borrowed signed policy.
// The fixed identity comparison and later complete epoch validation remain unchanged.
fn validate_election_policy_fields(
    xor_asset_definition_id: &AssetDefinitionId,
    asset_scope: AssetBalanceScope,
    asset_scale: u32,
    min_self_bond: &Quantity,
    min_nomination_bond: &Quantity,
    max_validators: u32,
    epoch_length_blocks: u64,
) -> Result<(), String> {
    // DM17 restores only fixed synthetic-identity reconstruction.
    #[cfg(not(all(test, sumeragi_model_mutation = "DM17")))]
    let synthetic_bytes = SumeragiNposParameters::REJECTED_SYNTHETIC_XOR_ASSET_BYTES;
    #[cfg(all(test, sumeragi_model_mutation = "DM17"))]
    let synthetic_bytes = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("nexus.universal")
            .expect("fixed synthetic domain"),
        "xor".parse().expect("fixed synthetic asset name"),
    )
    .aid_bytes();
    if xor_asset_definition_id.aid_bytes() == synthetic_bytes
        || asset_scope != AssetBalanceScope::Global
        || asset_scale != XOR_QUANTITY_SCALE
        || min_self_bond.is_zero()
        || min_nomination_bond.is_zero()
        || min_self_bond.scale() > asset_scale
        || min_nomination_bond.scale() > asset_scale
        || !(4..=31).contains(&max_validators)
        || !(max_validators - 1).is_multiple_of(3)
        || epoch_length_blocks < 3
    {
        return Err("invalid frozen validator election policy".to_owned());
    }
    Ok(())
}

/// Immutable result of the election at the end of epoch E for epoch E+2.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteePreparationV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteePreparationV1 {
    /// Sole first-release layout version.
    pub version: u16,
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Epoch whose final pre-state supplied the election inputs.
    pub selection_epoch: u64,
    /// Boundary height whose exact current quorum freezes this election.
    pub selection_height: u64,
    /// Last committed block before the selecting boundary, never that boundary's own hash.
    pub selection_anchor: HashOf<BlockHeader>,
    /// Scheduling epoch after the complete preparation epoch.
    pub target_epoch: u64,
    /// Inclusive activation height.
    pub first_height: u64,
    /// Inclusive end of the initial target scheduling epoch.
    pub last_height: u64,
    /// Successor generation relative to the authority governing preparation.
    pub authority_generation: u64,
    /// Exact E+1 authorization, whose current quorum will decide this attempt.
    pub preparing_authorization_id: [u8; 32],
    /// Independently domain-separated election randomness from the authenticated boundary pulse.
    pub election_seed: [u8; 32],
    /// Exact signed eligibility policy at the selecting boundary's prestate.
    pub eligibility: ValidatorElectionPolicyV1,
    /// Complete ordered equal-vote target committee and original BLS possession proofs.
    /// This committee cannot be shrunk or rerolled within the attempt.
    pub committee: Vec<ValidatorCommitteeMemberV1>,
}

impl ValidatorCommitteePreparationV1 {
    /// Validate scheduling arithmetic and the canonical complete committee.
    ///
    /// # Errors
    /// Rejects malformed bounds or any invalid BLS proof. Election-input authentication and
    /// current custody readiness are checked against the original execution prestate.
    pub fn validate(&self) -> Result<(), String> {
        let invalid = || "invalid frozen validator committee preparation".to_owned();
        self.eligibility.validate()?;
        validate_committee(&self.committee)?;
        if self.version != 1
            || self.network_id.as_bytes() == &[0; 32]
            || self.selection_anchor.as_ref() == &[0; 32]
            || self.selection_height == 0
            || self.authority_generation == 0
            || self.selection_epoch.checked_add(2) != Some(self.target_epoch)
            || self.last_height < self.first_height
            || self
                .selection_height
                .checked_add(1)
                .is_none_or(|preparing_first| self.first_height <= preparing_first)
            || self.preparing_authorization_id == [0; 32]
            || self.election_seed == [0; 32]
            || self.committee.len() > self.eligibility.max_validators as usize
            || self
                .last_height
                .checked_sub(self.first_height)
                .and_then(|distance| distance.checked_add(1))
                != Some(self.eligibility.epoch_length_blocks)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Check the complete epoch reserved for preparation against its authenticated authorization.
    ///
    /// # Errors
    /// Rejects epoch/height gaps, changed generation, or a different predecessor authorization.
    pub fn validate_against_preparing_authorization(
        &self,
        preparing: &ValidatorEpochAuthorizationV1,
    ) -> Result<(), String> {
        self.validate()?;
        preparing.validate().map_err(|error| error.to_string())?;
        if self.network_id != preparing.network_id
            || self.selection_epoch.checked_add(1) != Some(preparing.epoch)
            || self.selection_height.checked_add(1) != Some(preparing.first_height)
            || preparing.last_height.checked_add(1) != Some(self.first_height)
            || preparing.authority_generation.checked_add(1) != Some(self.authority_generation)
            || preparing
                .authorization_id()
                .map_err(|error| error.to_string())?
                != self.preparing_authorization_id
        {
            return Err(
                "frozen preparation differs from its exact preparing authorization".to_owned(),
            );
        }
        Ok(())
    }

    /// Commit to every frozen input, without a certificate or a self-referential context hash.
    ///
    /// # Errors
    /// Returns an error when the preparation is not canonical.
    pub fn transition_id(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let mut bytes = b"iroha:validator-committee-preparation:v1".to_vec();
        bytes.extend(self.encode());
        Ok(Hash::new(bytes).into())
    }

    /// Unique DKG session for this immutable preparation attempt.
    ///
    /// # Errors
    /// Rejects a malformed preparation before deriving its separate session domain.
    pub fn beacon_session_id(&self) -> Result<[u8; 32], String> {
        Ok(Hash::new_from_chunks(&[
            b"iroha:validator-committee-beacon-session:v1",
            &self.transition_id()?,
        ])
        .into())
    }

    /// Project the immutable target roster into its successor validator generation.
    ///
    /// An activation authorization must select exactly this generation's identity.
    #[must_use]
    pub fn generation(&self) -> ValidatorGenerationV1 {
        ValidatorGenerationV1::from_committee(
            self.network_id,
            self.authority_generation,
            &self.committee,
        )
    }
}

/// Complete public credentials prepared for the immutable target committee.
///
/// The target generation is the frozen preparation roster itself; only the finalized target
/// threshold-beacon transcript is installed separately.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteeCredentialsV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeCredentialsV1 {
    /// Exact finalized target DKG transcript, retained separately from the incumbent session.
    pub beacon: InstalledBeaconEpochBindingV1,
}

/// Actual threshold-share possession evidence for one target seat.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteeSeatReadinessV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeSeatReadinessV1 {
    /// Zero-based index in the immutable ordered target roster.
    pub validator_index: u32,
    /// Adaptive threshold proof of the exact beacon share under a separate readiness domain.
    pub beacon: GlobalThresholdBeaconPartialSignatureV1,
}

/// Exact preparation attempt and target interval acknowledged by one prospective seat.
///
/// The incumbent certificate must additionally authenticate the frozen transition, and the
/// seat's adaptive beacon proof over [`Self::signing_digest`] establishes possession of that
/// seat's exact threshold share. The context grants no activation authority by itself.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorSeatReadinessContextV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorSeatReadinessContextV1 {
    /// Sole first-release layout version.
    pub version: u16,
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Unique frozen preparation attempt, including its finalized election context.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub transition_id: [u8; 32],
    /// Scheduling epoch in which the prepared generation may first activate.
    pub target_epoch: u64,
    /// Successor validator generation whose seat this readiness acknowledges.
    pub authority_generation: u64,
    /// Exact [`ValidatorGenerationV1`] identity of the ordered target roster.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub authority_id: [u8; 32],
    /// First target height, inclusive.
    pub first_height: u64,
    /// Last target height, inclusive.
    pub last_height: u64,
    /// Exact zero-based position in the target generation.
    pub validator_index: u32,
    /// Exact installed target beacon session and complete transcript.
    pub beacon: InstalledBeaconEpochBindingV1,
}

impl ValidatorSeatReadinessContextV1 {
    /// Validate a complete prospective-seat challenge without granting activation authority.
    ///
    /// # Errors
    /// Rejects empty identities, invalid intervals, or an index outside the committee bound.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.network_id.as_bytes() == &[0; 32]
            || self.transition_id == [0; 32]
            || self.authority_id == [0; 32]
            || self.target_epoch == 0
            || self.first_height <= 1
            || self.last_height < self.first_height
            || usize::try_from(self.validator_index)
                .ok()
                .is_none_or(|index| index >= MAX_VALIDATORS)
            || self.beacon.session_id == [0; 32]
            || self.beacon.transcript_hash == [0; 32]
        {
            return Err("invalid validator seat readiness context".to_owned());
        }
        Ok(())
    }

    /// Derive the domain-separated readiness digest for the exact seat occupant.
    ///
    /// # Errors
    /// Rejects a malformed context or a non-canonical peer identity. The caller verifies that
    /// `validator` occupies [`Self::validator_index`] in the authenticated target roster.
    pub fn signing_digest(&self, validator: &PeerId) -> Result<[u8; 32], String> {
        self.validate()?;
        let identity = norito::encode_canonical(validator).map_err(|error| error.to_string())?;
        Ok(Hash::new_from_chunks(&[
            b"iroha:validator-seat-readiness:v1",
            &[0],
            &self.version.to_le_bytes(),
            self.network_id.as_bytes(),
            &self.transition_id,
            &self.target_epoch.to_le_bytes(),
            &self.authority_generation.to_le_bytes(),
            &self.authority_id,
            &self.first_height.to_le_bytes(),
            &self.last_height.to_le_bytes(),
            &self.validator_index.to_le_bytes(),
            &self.beacon.session_id,
            &self.beacon.transcript_hash,
            &u64::try_from(identity.len())
                .map_err(|error| error.to_string())?
                .to_le_bytes(),
            &identity,
        ])
        .into())
    }
}

/// Retained preparation progress and its incumbent-certified terminal disposition.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteeTransitionV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeTransitionV1 {
    /// Immutable authenticated election; no update may change this value.
    pub preparation: ValidatorCommitteePreparationV1,
    /// Once installed, the exact credentials cannot be replaced within this attempt.
    pub credentials: Option<ValidatorCommitteeCredentialsV1>,
    /// Strictly ordered evidence for distinct target seats; activation requires every seat.
    pub readiness: Vec<ValidatorCommitteeSeatReadinessV1>,
    /// Authorization body whose boundary certificate activated or cancelled this attempt.
    /// This body alone is never accepted as proof of finality.
    pub outcome: Option<ValidatorEpochAuthorizationV1>,
}

/// Install one complete public credential set for an already frozen attempt.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct PrepareValidatorCommitteeCredentialsV1 {
    /// Exact immutable attempt; a cancelled attempt cannot be reused.
    pub transition_id: [u8; 32],
    /// Target scheduling epoch identifying the retained preparation.
    pub target_epoch: u64,
    /// Finalized target beacon transcript.
    pub credentials: ValidatorCommitteeCredentialsV1,
}

/// Admit one target seat's possession evidence under its frozen attempt.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct AdmitValidatorCommitteeSeatV1 {
    /// Exact immutable attempt, including its authenticated selecting boundary.
    pub transition_id: [u8; 32],
    /// Target scheduling epoch identifying the retained preparation.
    pub target_epoch: u64,
    /// Exact seat and adaptive beacon-share possession.
    pub readiness: ValidatorCommitteeSeatReadinessV1,
}

/// Owner-authorized preparation commands accepted through `SetParameter`.
///
/// These commands never activate a committee. Only the incumbent's boundary finality
/// certifies activation or cancellation. Execution consumes the command into the dedicated
/// World stores; the command is not persisted as a mutable network parameter.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteeOperationV1")]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    variant_size_differences,
    reason = "boxing a variant would change the reviewed Norito operation layout"
)]
pub enum ValidatorCommitteeOperationV1 {
    /// Bind the immutable target roster to its finalized target DKG transcript.
    PrepareCredentials(PrepareValidatorCommitteeCredentialsV1),
    /// Record actual possession for one exact target seat.
    AdmitSeat(AdmitValidatorCommitteeSeatV1),
}

impl ValidatorCommitteeOperationV1 {
    /// Reserved first-release operation envelope identifier.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        "validator_committee_operation_v1"
            .parse()
            .expect("static committee operation identifier")
    }

    /// Produce the exact command envelope to inspect and sign.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(Self::parameter_id(), Json::new(self))
    }

    /// Decode only the canonical reserved operation envelope.
    ///
    /// # Errors
    /// Rejects malformed matching payloads and unknown variants or fields.
    pub fn from_custom_parameter(
        parameter: &CustomParameter,
    ) -> Result<Option<Self>, norito::json::Error> {
        if parameter.id() != &Self::parameter_id() {
            return Ok(None);
        }
        norito::json::from_str(parameter.payload().get()).map(Some)
    }
}

impl ValidatorCommitteeTransitionV1 {
    fn validated_credentials(&self) -> Result<&ValidatorCommitteeCredentialsV1, String> {
        self.preparation.validate()?;
        let credentials = self
            .credentials
            .as_ref()
            .ok_or("committee credentials are not prepared")?;
        if credentials.beacon.session_id != self.preparation.beacon_session_id()?
            || credentials.beacon.transcript_hash == [0; 32]
        {
            return Err("prepared credentials differ from the immutable target".to_owned());
        }
        Ok(credentials)
    }

    /// Derive the complete, replay-bound possession challenge for one target seat.
    ///
    /// # Errors
    /// Rejects missing credentials, malformed preparation or an out-of-range seat.
    pub fn readiness_context(
        &self,
        validator_index: u32,
    ) -> Result<ValidatorSeatReadinessContextV1, String> {
        let credentials = self.validated_credentials()?;
        if usize::try_from(validator_index)
            .ok()
            .is_none_or(|index| index >= self.preparation.committee.len())
        {
            return Err("target validator seat is out of range".to_owned());
        }
        let context = ValidatorSeatReadinessContextV1 {
            version: 1,
            network_id: self.preparation.network_id,
            transition_id: self.preparation.transition_id()?,
            target_epoch: self.preparation.target_epoch,
            authority_generation: self.preparation.authority_generation,
            authority_id: {
                #[cfg(not(all(test, sumeragi_model_mutation = "DM18")))]
                let identity = ValidatorGenerationV1::generation_id_from_committee(
                    self.preparation.network_id,
                    self.preparation.authority_generation,
                    &self.preparation.committee,
                );
                #[cfg(all(test, sumeragi_model_mutation = "DM18"))]
                let identity = self.preparation.generation().generation_id();
                identity.map_err(|error| error.to_string())?
            },
            first_height: self.preparation.first_height,
            last_height: self.preparation.last_height,
            validator_index,
            beacon: credentials.beacon,
        };
        context.validate()?;
        Ok(context)
    }

    /// Validate structural consistency before cryptographic and finality verification.
    ///
    /// # Errors
    /// Rejects replaced credentials, repeated seats, inconsistent terminal decisions or incomplete activation.
    #[expect(
        clippy::suspicious_operation_groupings,
        reason = "the outcome epoch intentionally binds the preparation target epoch"
    )]
    pub fn validate(&self) -> Result<(), String> {
        self.preparation.validate()?;
        let invalid = || "invalid validator committee transition progress".to_owned();
        let preparation = &self.preparation;
        if self.readiness.len() > preparation.committee.len()
            || self
                .readiness
                .windows(2)
                .any(|pair| pair[0].validator_index >= pair[1].validator_index)
        {
            return Err(invalid());
        }
        if self.credentials.is_some() {
            let credentials = self.validated_credentials()?;
            for ready in &self.readiness {
                self.readiness_context(ready.validator_index)?;
                if ready.beacon.session_id != credentials.beacon.session_id
                    || u32::from(ready.beacon.signer_index) != ready.validator_index + 1
                {
                    return Err(invalid());
                }
            }
        } else if !self.readiness.is_empty() {
            return Err(invalid());
        }
        if let Some(outcome) = &self.outcome {
            outcome.validate().map_err(|_| invalid())?;
            if outcome.network_id != preparation.network_id
                || outcome.epoch != preparation.target_epoch
                || outcome.first_height != preparation.first_height
                || outcome.last_height != preparation.last_height
                || outcome.previous_authorization_id != preparation.preparing_authorization_id
                || outcome.transition_id != preparation.transition_id()?
            {
                return Err(invalid());
            }
            match outcome.decision {
                ValidatorEpochDecisionV1::Activate => {
                    let credentials = self.credentials.as_ref().ok_or_else(invalid)?;
                    if self.readiness.len() != preparation.committee.len()
                        || outcome.beacon != BeaconEpochBindingV1::Installed(credentials.beacon)
                        || {
                            #[cfg(not(all(test, sumeragi_model_mutation = "DM19")))]
                            let relation = outcome.validate_against_committee(
                                preparation.network_id,
                                preparation.authority_generation,
                                &preparation.committee,
                            );
                            #[cfg(all(test, sumeragi_model_mutation = "DM19"))]
                            let relation =
                                outcome.validate_against_generation(&preparation.generation());
                            relation.is_err()
                        }
                    {
                        return Err(invalid());
                    }
                }
                ValidatorEpochDecisionV1::RetainAndCancel => {
                    if outcome.authority_generation.checked_add(1)
                        != Some(preparation.authority_generation)
                    {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::GlobalThresholdBeaconPartialSignatureProofV1;
    use iroha_crypto::{Algorithm, KeyPair};

    fn network() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"committee-model-test",
        )))
    }

    fn members(seeds: std::ops::RangeInclusive<u8>) -> Vec<ValidatorCommitteeMemberV1> {
        let mut members = seeds
            .map(|seed| {
                let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
                ValidatorCommitteeMemberV1 {
                    validator: PeerId::new(pair.public_key().clone()),
                    proof_of_possession: iroha_crypto::bls_normal_pop_prove(pair.private_key())
                        .unwrap(),
                }
            })
            .collect::<Vec<_>>();
        members.sort_by(|a, b| a.validator.cmp(&b.validator));
        members
    }

    fn preparing() -> ValidatorEpochAuthorizationV1 {
        let incumbent = ValidatorGenerationV1::from_committee(network(), 0, &members(5..=8));
        ValidatorEpochAuthorizationV1 {
            version: 1,
            network_id: incumbent.network_id,
            epoch: 1,
            first_height: 11,
            last_height: 20,
            authority_generation: 0,
            authority_id: incumbent.generation_id().unwrap(),
            beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                session_id: [7; 32],
                transcript_hash: [8; 32],
            }),
            previous_authorization_id: [9; 32],
            transition_id: [0; 32],
            decision: ValidatorEpochDecisionV1::Retain,
        }
    }

    fn preparation() -> ValidatorCommitteePreparationV1 {
        let authorization = preparing();
        ValidatorCommitteePreparationV1 {
            version: 1,
            network_id: authorization.network_id,
            selection_epoch: 0,
            selection_height: 10,
            selection_anchor: HashOf::from_untyped_unchecked(Hash::new(b"height-nine")),
            target_epoch: 2,
            first_height: 21,
            last_height: 30,
            authority_generation: 1,
            preparing_authorization_id: authorization.authorization_id().unwrap(),
            election_seed: [4; 32],
            eligibility:
                ValidatorElectionPolicyV1 {
                    epoch_length_blocks: 10,
                    ..ValidatorElectionPolicyV1::from_npos_parameters(
                        &SumeragiNposParameters::default(),
                    )
                    .unwrap()
                },
            committee: members(1..=4),
        }
    }

    fn transition() -> ValidatorCommitteeTransitionV1 {
        let credentials = ValidatorCommitteeCredentialsV1 {
            beacon: InstalledBeaconEpochBindingV1 {
                session_id: preparation().beacon_session_id().unwrap(),
                transcript_hash: [6; 32],
            },
        };
        ValidatorCommitteeTransitionV1 {
            preparation: preparation(),
            readiness: (0..4)
                .map(|index| ValidatorCommitteeSeatReadinessV1 {
                    validator_index: index,
                    beacon: GlobalThresholdBeaconPartialSignatureV1 {
                        session_id: credentials.beacon.session_id,
                        signer_index: u16::try_from(index).unwrap() + 1,
                        signature_share: [1; 48],
                        proof: GlobalThresholdBeaconPartialSignatureProofV1 {
                            x: [1; 96],
                            y: [2; 48],
                            z_s: [3; 32],
                            z_r: [4; 32],
                            z_u: [5; 32],
                        },
                    },
                })
                .collect(),
            credentials: Some(credentials),
            outcome: None,
        }
    }

    #[test]
    fn frozen_policy_validation_borrows_fixed_synthetic_identity_without_allocation() {
        use crate::amx_prepare_streaming_allocations::PhysicalObservation;

        let mut policy =
            ValidatorElectionPolicyV1::from_npos_parameters(&SumeragiNposParameters::default())
                .unwrap();
        let observation = PhysicalObservation::start();
        let result = policy.validate();
        let requests = observation.snapshot().requests();
        drop(observation);
        assert_eq!(requests, [0; 3]);
        assert_eq!(result, Ok(()));

        policy.xor_asset_definition_id = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::parse_fully_qualified("nexus.universal").unwrap(),
            "xor".parse().unwrap(),
        );
        assert_eq!(
            policy.validate().unwrap_err(),
            "invalid frozen validator election policy"
        );
    }

    #[test]
    fn frozen_policy_snapshots_signed_fields_and_rejects_non_xor_precision() {
        let mut parameters = SumeragiNposParameters {
            min_self_bond: "1000.000000001".parse().unwrap(),
            ..SumeragiNposParameters::default()
        };
        let frozen = ValidatorElectionPolicyV1::from_npos_parameters(&parameters).unwrap();
        assert_eq!(
            frozen.xor_asset_definition_id,
            parameters.xor_asset_definition_id
        );
        assert_eq!(frozen.min_self_bond, parameters.min_self_bond);
        assert_eq!(frozen.min_nomination_bond, parameters.min_nomination_bond);
        assert_eq!(frozen.max_validators, parameters.max_validators);
        assert_eq!(
            frozen.epoch_length_blocks,
            parameters.epoch_length_blocks.get()
        );
        assert_eq!(frozen.asset_scope, AssetBalanceScope::Global);
        assert_eq!(frozen.asset_scale, 9);
        parameters.min_self_bond = Quantity::one();
        assert_ne!(frozen.min_self_bond, parameters.min_self_bond);
        for mutation in 0..10 {
            let mut invalid = frozen.clone();
            match mutation {
                0 => {
                    invalid.asset_scope =
                        AssetBalanceScope::Dataspace(crate::nexus::DataSpaceId::new(1))
                }
                1 => invalid.asset_scale = 8,
                2 => invalid.min_self_bond = Quantity::zero(),
                3 => invalid.min_nomination_bond = Quantity::zero(),
                4 => invalid.min_self_bond = "0.0000000001".parse().unwrap(),
                5 => invalid.min_nomination_bond = "0.0000000001".parse().unwrap(),
                6 => invalid.max_validators = 5,
                7 => invalid.max_validators = 34,
                8 => invalid.epoch_length_blocks = 2,
                _ => {
                    invalid.xor_asset_definition_id = AssetDefinitionId::derive_from_components(
                        iroha_model_base::domain::DomainId::try_new("nexus", "universal").unwrap(),
                        "xor".parse().unwrap(),
                    )
                }
            }
            assert!(invalid.validate().is_err(), "mutation {mutation}");
        }
        parameters.min_nomination_bond = "0.0000000001".parse().unwrap();
        assert!(ValidatorElectionPolicyV1::from_npos_parameters(&parameters).is_err());
        let wire = norito::encode_canonical(&frozen).unwrap();
        assert_eq!(
            frozen,
            norito::decode_canonical::<ValidatorElectionPolicyV1>(&wire).unwrap()
        );
    }

    #[test]
    fn borrowed_npos_policy_matches_owned_validation_order_and_exact_bounds() {
        for mutation in 0..9 {
            let mut parameters = SumeragiNposParameters::default();
            let expected = match mutation {
                0 => None,
                1 => {
                    parameters.min_self_bond = "0.0000000001".parse().unwrap();
                    Some("invalid frozen validator election policy")
                }
                2 => {
                    parameters.min_nomination_bond = "0.0000000001".parse().unwrap();
                    Some("invalid frozen validator election policy")
                }
                3 => {
                    parameters.epoch_length_blocks = std::num::NonZeroU64::new(2).unwrap();
                    parameters.evidence_horizon_blocks = 1;
                    parameters.slashing_delay_blocks = 1;
                    parameters.validate().unwrap();
                    Some("invalid frozen validator election policy")
                }
                4 => {
                    parameters.xor_asset_definition_id = AssetDefinitionId::derive_from_components(
                        iroha_model_base::domain::DomainId::parse_fully_qualified(
                            "nexus.universal",
                        )
                        .unwrap(),
                        "xor".parse().unwrap(),
                    );
                    parameters.epoch_seed = [0; 32];
                    parameters.min_self_bond = "0.0000000001".parse().unwrap();
                    Some(
                        "NPoS must use the network's canonical XOR asset, not synthetic nexus.universal/xor",
                    )
                }
                5 => {
                    parameters.epoch_seed = [0; 32];
                    parameters.min_self_bond = "0.0000000001".parse().unwrap();
                    Some("epoch_seed must not be all zero")
                }
                6 => {
                    parameters.max_validators = 5;
                    parameters.min_self_bond = "0.0000000001".parse().unwrap();
                    Some("max_validators must be a bounded 3f + 1 committee size (4..=31)")
                }
                7 => {
                    parameters.min_self_bond = Quantity::zero();
                    parameters.min_nomination_bond = "0.0000000001".parse().unwrap();
                    Some("NPoS minimum bond values must be greater than zero")
                }
                _ => {
                    parameters.finality_margin_blocks = 0;
                    parameters.min_self_bond = "0.0000000001".parse().unwrap();
                    Some("NPoS finality and reconfiguration bounds must be greater than zero")
                }
            };
            let original = parameters.clone();
            let owned = ValidatorElectionPolicyV1::from_npos_parameters(&parameters).map(|_| ());
            let borrowed = ValidatorElectionPolicyV1::validate_npos_parameters(&parameters);
            assert_eq!(borrowed, owned, "mutation {mutation}");
            assert_eq!(
                borrowed,
                expected.map_or(Ok(()), |error| Err(error.to_owned())),
                "mutation {mutation}"
            );
            assert_eq!(parameters, original);
        }
    }

    #[test]
    fn frozen_preparation_binds_policy_and_verifies_every_real_pop() {
        let preparation = preparation();
        let original_id = preparation.transition_id().unwrap();
        for mutation in 0..3 {
            let mut changed = preparation.clone();
            match mutation {
                0 => changed.eligibility.min_self_bond = "2000".parse().unwrap(),
                1 => changed.eligibility.min_nomination_bond = "2".parse().unwrap(),
                _ => changed.eligibility.max_validators = 7,
            }
            changed.validate().unwrap();
            assert_ne!(original_id, changed.transition_id().unwrap());
            assert_ne!(
                preparation.beacon_session_id().unwrap(),
                changed.beacon_session_id().unwrap()
            );
        }
        for index in 0..preparation.committee.len() {
            let mut invalid = preparation.clone();
            invalid.committee[index].proof_of_possession[0] ^= 1;
            assert!(invalid.validate().is_err(), "invalid proof at seat {index}");
        }
        let mut swapped = preparation.clone();
        let first_proof = swapped.committee[0].proof_of_possession.clone();
        swapped.committee[0].proof_of_possession = swapped.committee[1].proof_of_possession.clone();
        swapped.committee[1].proof_of_possession = first_proof;
        assert!(
            swapped.validate().is_err(),
            "correct proofs for different peers are invalid"
        );
        let wire = norito::encode_canonical(&preparation).unwrap();
        assert_eq!(
            preparation,
            norito::decode_canonical::<ValidatorCommitteePreparationV1>(&wire).unwrap()
        );
    }

    #[test]
    fn committee_preparation_reserves_a_complete_epoch_and_exact_parent() {
        let preparation = preparation();
        preparation
            .validate_against_preparing_authorization(&preparing())
            .unwrap();
        for mutation in 0..5 {
            let mut wrong = preparation.clone();
            match mutation {
                0 => wrong.target_epoch -= 1,
                1 => wrong.first_height -= 1,
                2 => wrong.authority_generation += 1,
                3 => wrong.preparing_authorization_id[0] ^= 1,
                _ => wrong.selection_height += 1,
            }
            assert!(
                wrong
                    .validate_against_preparing_authorization(&preparing())
                    .is_err()
            );
        }
        let mut another_attempt = preparation.clone();
        another_attempt.selection_anchor =
            HashOf::from_untyped_unchecked(Hash::new(b"another-anchor"));
        assert_ne!(
            preparation.transition_id().unwrap(),
            another_attempt.transition_id().unwrap()
        );
        let mut partial = preparation;
        partial.committee.pop();
        assert!(partial.validate().is_err());
    }

    #[test]
    fn committee_preparation_binds_unequal_preparing_and_target_intervals() {
        let preparing = preparing();
        let mut target = preparation();
        target.last_height = 45;
        target.eligibility.epoch_length_blocks = 25;
        target
            .validate_against_preparing_authorization(&preparing)
            .unwrap();
        let id = target.transition_id().unwrap();
        let mut changed = target.clone();
        changed.last_height += 1;
        assert!(
            changed.validate().is_err(),
            "target bounds cannot change without the frozen policy"
        );
        changed.eligibility.epoch_length_blocks += 1;
        assert_ne!(id, changed.transition_id().unwrap());
        target.first_height += 1;
        assert!(
            target
                .validate_against_preparing_authorization(&preparing)
                .is_err()
        );
        target.first_height = target.selection_height + 1;
        assert!(
            target.validate().is_err(),
            "preparation must reserve a complete nonempty epoch"
        );
    }

    #[test]
    fn committee_activation_requires_every_distinct_target_seat() {
        let mut transition = transition();
        let credentials = transition.credentials.as_ref().unwrap();
        transition.outcome = Some(ValidatorEpochAuthorizationV1 {
            epoch: 2,
            first_height: 21,
            last_height: 30,
            authority_generation: 1,
            authority_id: transition.preparation.generation().generation_id().unwrap(),
            beacon: BeaconEpochBindingV1::Installed(credentials.beacon),
            previous_authorization_id: preparing().authorization_id().unwrap(),
            transition_id: transition.preparation.transition_id().unwrap(),
            decision: ValidatorEpochDecisionV1::Activate,
            ..preparing()
        });
        transition.validate().unwrap();
        transition
            .outcome
            .as_ref()
            .unwrap()
            .validate_successor(&preparing())
            .unwrap();
        let mut missing = transition.clone();
        missing.readiness.pop();
        assert!(
            missing.validate().is_err(),
            "an exact quorum of target seats is insufficient"
        );
        let mut duplicate = transition.clone();
        duplicate.readiness[3] = duplicate.readiness[2].clone();
        assert!(duplicate.validate().is_err());
        let mut wrong_session = transition;
        wrong_session.readiness[0].beacon.session_id[0] ^= 1;
        assert!(wrong_session.validate().is_err());
    }

    #[test]
    fn committee_cancellation_retains_the_current_generation_without_new_keys() {
        let mut transition = ValidatorCommitteeTransitionV1 {
            preparation: preparation(),
            credentials: None,
            readiness: Vec::new(),
            outcome: None,
        };
        let current = preparing();
        transition.outcome = Some(ValidatorEpochAuthorizationV1 {
            epoch: 2,
            first_height: 21,
            last_height: 30,
            previous_authorization_id: current.authorization_id().unwrap(),
            transition_id: transition.preparation.transition_id().unwrap(),
            decision: ValidatorEpochDecisionV1::RetainAndCancel,
            ..current
        });
        transition.validate().unwrap();
        transition
            .outcome
            .as_ref()
            .unwrap()
            .validate_successor(&current)
            .unwrap();
        transition.outcome.as_mut().unwrap().transition_id[0] ^= 1;
        assert!(transition.validate().is_err());
    }

    #[test]
    fn committee_readiness_context_binds_attempt_seat_and_credentials() {
        let transition = transition();
        let first = transition.readiness_context(0).unwrap();
        assert_ne!(first, transition.readiness_context(1).unwrap());
        assert!(transition.readiness_context(4).is_err());
        assert_eq!(
            first.authority_id,
            transition.preparation.generation().generation_id().unwrap()
        );
        let seat = &transition.preparation.committee[0].validator;
        let other = &transition.preparation.committee[1].validator;
        let digest = first.signing_digest(seat).unwrap();
        assert_ne!(digest, first.signing_digest(other).unwrap());
        for coordinate in 0..7 {
            let mut changed = first;
            match coordinate {
                0 => changed.transition_id[0] ^= 1,
                1 => changed.target_epoch += 1,
                2 => changed.authority_generation += 1,
                3 => changed.authority_id[0] ^= 1,
                4 => changed.first_height += 1,
                5 => changed.validator_index = 1,
                _ => changed.beacon.transcript_hash[0] ^= 1,
            }
            assert_ne!(
                changed.signing_digest(seat).unwrap(),
                digest,
                "coordinate {coordinate}"
            );
        }
        let mut empty = first;
        empty.beacon.transcript_hash = [0; 32];
        assert!(empty.signing_digest(seat).is_err());
        let mut changed = transition.clone();
        changed.preparation.election_seed[0] ^= 1;
        assert!(changed.readiness_context(0).is_err());
        changed = transition;
        changed.credentials.as_mut().unwrap().beacon.transcript_hash = [0; 32];
        assert!(changed.readiness_context(0).is_err());
    }

    #[test]
    fn committee_transition_and_operations_roundtrip_canonical_codecs() {
        let transition = transition();
        transition.validate().unwrap();
        assert_eq!(
            transition,
            ValidatorCommitteeTransitionV1::decode(&mut transition.encode().as_slice()).unwrap()
        );
        let json = norito::json::to_json(&transition).unwrap();
        assert_eq!(transition, norito::json::from_json(&json).unwrap());
        let context = transition.readiness_context(2).unwrap();
        assert_eq!(
            context,
            ValidatorSeatReadinessContextV1::decode(&mut context.encode().as_slice()).unwrap()
        );
        for operation in [
            ValidatorCommitteeOperationV1::PrepareCredentials(
                PrepareValidatorCommitteeCredentialsV1 {
                    transition_id: transition.preparation.transition_id().unwrap(),
                    target_epoch: transition.preparation.target_epoch,
                    credentials: transition.credentials.unwrap(),
                },
            ),
            ValidatorCommitteeOperationV1::AdmitSeat(AdmitValidatorCommitteeSeatV1 {
                transition_id: transition.preparation.transition_id().unwrap(),
                target_epoch: transition.preparation.target_epoch,
                readiness: transition.readiness[0].clone(),
            }),
        ] {
            let parameter = operation.clone().into_custom_parameter();
            assert_eq!(
                Some(operation),
                ValidatorCommitteeOperationV1::from_custom_parameter(&parameter).unwrap()
            );
        }
    }

    fn original_committee_storage(
        committee: &[ValidatorCommitteeMemberV1],
    ) -> [(*const u8, usize, *const u8, usize); 4] {
        assert_eq!(committee.len(), 4);
        std::array::from_fn(|index| {
            let member = &committee[index];
            let (algorithm, key) = member.validator.public_key().try_to_bytes().unwrap();
            assert_eq!(algorithm, Algorithm::BlsNormal);
            (
                key.as_ptr(),
                key.len(),
                member.proof_of_possession.as_ptr(),
                member.proof_of_possession.len(),
            )
        })
    }

    fn activated_original_transition() -> ValidatorCommitteeTransitionV1 {
        let mut original = transition();
        let credentials = original.credentials.as_ref().unwrap();
        original.outcome = Some(ValidatorEpochAuthorizationV1 {
            epoch: original.preparation.target_epoch,
            first_height: original.preparation.first_height,
            last_height: original.preparation.last_height,
            authority_generation: original.preparation.authority_generation,
            authority_id: original.preparation.generation().generation_id().unwrap(),
            beacon: BeaconEpochBindingV1::Installed(credentials.beacon),
            previous_authorization_id: original.preparation.preparing_authorization_id,
            transition_id: original.preparation.transition_id().unwrap(),
            decision: ValidatorEpochDecisionV1::Activate,
            ..preparing()
        });
        original
    }

    #[test]
    fn public_readiness_borrows_original_roster_with_only_canonical_transcript_work() {
        use crate::amx_prepare_streaming_allocations::measured;

        let original = transition();
        let original_wire = original.encode();
        let original_storage = original_committee_storage(&original.preparation.committee);
        let original_generation = original.preparation.generation();
        let expected_authority = original_generation.generation_id().unwrap();
        let expected_transition = original.preparation.transition_id().unwrap();
        let credentials = original.credentials.as_ref().unwrap();
        let expected = ValidatorSeatReadinessContextV1 {
            version: 1,
            network_id: original.preparation.network_id,
            transition_id: expected_transition,
            target_epoch: original.preparation.target_epoch,
            authority_generation: original.preparation.authority_generation,
            authority_id: expected_authority,
            first_height: original.preparation.first_height,
            last_height: original.preparation.last_height,
            validator_index: 0,
            beacon: credentials.beacon,
        };
        expected.validate().unwrap();
        let seat_digest = expected
            .signing_digest(&original.preparation.committee[0].validator)
            .unwrap();
        // Measure only the two existing public canonical transcript operations required
        // by this challenge. Their real wire scratch is permitted, without guessed counts.
        let (transcripts, required_requests) = measured(|| {
            (
                original.preparation.beacon_session_id(),
                original.preparation.transition_id(),
            )
        });
        assert_eq!(transcripts.0.unwrap(), credentials.beacon.session_id);
        assert_eq!(transcripts.1.unwrap(), expected_transition);
        assert!(required_requests.iter().any(|count| *count != 0));
        let (actual, actual_requests) = measured(|| original.readiness_context(0));
        let actual = actual.unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .signing_digest(&original.preparation.committee[0].validator)
                .unwrap(),
            seat_digest
        );
        assert_eq!(original.encode(), original_wire);
        assert_eq!(
            original_committee_storage(&original.preparation.committee),
            original_storage
        );
        assert_eq!(
            actual_requests, required_requests,
            "public readiness must borrow the original roster beyond its independently measured canonical transcript work"
        );
    }

    #[test]
    fn public_activation_borrows_original_generation_beyond_existing_readiness_work() {
        use crate::amx_prepare_streaming_allocations::measured;

        let original = activated_original_transition();
        let original_wire = original.encode();
        let original_storage = original_committee_storage(&original.preparation.committee);
        let generation = original.preparation.generation();
        let outcome = original.outcome.as_ref().unwrap();
        outcome.validate_against_generation(&generation).unwrap();
        outcome.validate_successor(&preparing()).unwrap();
        let mut without_outcome = original.clone();
        without_outcome.outcome = None;
        // The genuine public readiness path and one extra canonical transition transcript
        // remain mandatory. Compare the actual same-shape calls; no implementation estimate.
        let (readiness, readiness_requests) = measured(|| without_outcome.validate());
        readiness.unwrap();
        let (transcript, transcript_requests) = measured(|| original.preparation.transition_id());
        assert_eq!(transcript.unwrap(), outcome.transition_id);
        let required_requests: [usize; 3] = std::array::from_fn(|route| {
            readiness_requests[route]
                .checked_add(transcript_requests[route])
                .unwrap()
        });
        let (actual, actual_requests) = measured(|| original.validate());
        actual.unwrap();
        assert_eq!(original.encode(), original_wire);
        assert_eq!(
            original_committee_storage(&original.preparation.committee),
            original_storage
        );
        assert_eq!(
            original.outcome.as_ref().unwrap().authority_id,
            generation.generation_id().unwrap()
        );
        assert_eq!(
            actual_requests, required_requests,
            "public activation must borrow the original target generation beyond existing readiness and canonical transcript work"
        );
    }

    #[test]
    fn borrowed_readiness_and_activation_preserve_original_error_order_and_identity() {
        let original = activated_original_transition();
        let expected_id = original.preparation.generation().generation_id().unwrap();
        for seat in 0..4 {
            let context = original.readiness_context(seat).unwrap();
            assert_eq!(context.authority_id, expected_id);
            assert_eq!(context.validator_index, seat);
        }
        assert_eq!(original.validate(), Ok(()));
        let mut changed = original.clone();
        changed.preparation.eligibility.asset_scale = 10;
        changed.preparation.committee[0].proof_of_possession.clear();
        changed.credentials = None;
        assert_eq!(
            changed.readiness_context(4).unwrap_err(),
            "invalid frozen validator election policy"
        );
        assert_eq!(
            changed.validate().unwrap_err(),
            "invalid frozen validator election policy"
        );
        changed = original.clone();
        changed.preparation.committee[0].proof_of_possession.clear();
        changed.preparation.version = 0;
        changed.credentials = None;
        assert_eq!(
            changed.readiness_context(4).unwrap_err(),
            "native committee key order or proof shape is invalid"
        );
        changed = original.clone();
        changed.preparation.version = 0;
        changed.credentials = None;
        assert_eq!(
            changed.readiness_context(4).unwrap_err(),
            "invalid frozen validator committee preparation"
        );
        changed = original.clone();
        changed.credentials = None;
        assert_eq!(
            changed.readiness_context(4).unwrap_err(),
            "committee credentials are not prepared"
        );
        changed = original.clone();
        changed.credentials.as_mut().unwrap().beacon.session_id[0] ^= 1;
        assert_eq!(
            changed.readiness_context(4).unwrap_err(),
            "prepared credentials differ from the immutable target"
        );
        assert_eq!(
            original.readiness_context(4).unwrap_err(),
            "target validator seat is out of range"
        );
        for coordinate in 0..5 {
            let mut changed = original.clone();
            match coordinate {
                0 => {
                    changed.outcome.as_mut().unwrap().network_id =
                        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                            Hash::new(b"foreign preparation network"),
                        ))
                }
                1 => changed.outcome.as_mut().unwrap().authority_generation += 1,
                2 => changed.outcome.as_mut().unwrap().authority_id[0] ^= 1,
                3 => {
                    changed.outcome.as_mut().unwrap().beacon =
                        BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                            session_id: [7; 32],
                            transcript_hash: [8; 32],
                        })
                }
                _ => changed.readiness.pop().map(|_| ()).unwrap(),
            }
            assert_eq!(
                changed.validate().unwrap_err(),
                "invalid validator committee transition progress",
                "coordinate {coordinate}"
            );
        }
    }
}
