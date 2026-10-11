//! Incumbent-certified scheduling authorizations for native validator epochs.
//!
//! An authorization names one scheduling epoch, its inclusive height bounds, the validator
//! generation it selects, its threshold-beacon binding and its predecessor. The body carries no
//! certificate: the incumbent boundary quorum authenticates it separately, so its identity is
//! independent of the signer subset.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};

use super::{
    ValidatorCommitteeMemberV1, ValidatorGenerationV1, generation::generation_id_from_roster,
};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId};
use iroha_model_base::peer::PeerId;

/// Sole first-release scheduling authorization layout version.
const AUTHORIZATION_VERSION_V1: u16 = 1;
const AUTHORIZATION_DOMAIN_V1: &[u8] = b"iroha:validator-epoch-authorization:v1";

/// Exact authority of an installed threshold-beacon transcript.
///
/// Norito encodes `session_id` before `transcript_hash`. The installed enum
/// variant owns one length-delimited instance of this body.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct InstalledBeaconEpochBindingV1 {
    /// Non-zero session identifier.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub session_id: [u8; 32],
    /// Recomputed complete transcript commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub transcript_hash: [u8; 32],
}

/// Exact beacon authority bound to one scheduling epoch.
///
/// JSON uses a closed `kind`/`value` envelope with `bootstrap` and `installed`
/// tags; only `bootstrap` has a null value.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum BeaconEpochBindingV1 {
    /// Generation-zero genesis before the authenticated initial ceremony is installed.
    Bootstrap,
    /// Complete binding to an authenticated installed threshold-beacon transcript.
    Installed(InstalledBeaconEpochBindingV1),
}

/// Decision certified by the incumbent boundary quorum for the next scheduling epoch.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[repr(u8)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ValidatorEpochDecisionV1 {
    /// Signed genesis establishes the initial authorization.
    Genesis = 0,
    /// Activate one complete prepared successor generation.
    Activate = 1,
    /// Retain the exact incumbent generation and installed beacon authority.
    Retain = 2,
    /// Retain the incumbent and certify cancellation of the named frozen attempt.
    RetainAndCancel = 3,
}

/// Complete scheduling authority certified by the incumbent boundary quorum.
///
/// This body excludes its certificate, so its identity is independent of signer subset and
/// cannot recursively depend on the context or certificate which authenticates it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi::epoch::ValidatorEpochAuthorizationV1")]
pub struct ValidatorEpochAuthorizationV1 {
    /// Sole first-release layout version.
    pub version: u16,
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Monotonic scheduling epoch, advanced even when the incumbent is retained.
    pub epoch: u64,
    /// First governed height, inclusive.
    pub first_height: u64,
    /// Last governed height, inclusive.
    pub last_height: u64,
    /// Validator generation whose ordered BLS roster is authorized.
    pub authority_generation: u64,
    /// Exact [`ValidatorGenerationV1`] identity of that network, generation and roster.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub authority_id: [u8; 32],
    /// Exact installed beacon authority, or the explicit genesis bootstrap state.
    pub beacon: BeaconEpochBindingV1,
    /// Previous authorization identity; zero only for genesis.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub previous_authorization_id: [u8; 32],
    /// Frozen attempt identity for activation or certified cancellation; otherwise zero.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub transition_id: [u8; 32],
    /// Incumbent-certified disposition of the next scheduling epoch.
    pub decision: ValidatorEpochDecisionV1,
}

impl ValidatorEpochAuthorizationV1 {
    /// Construct the initial scheduling authorization from the signed genesis roster.
    ///
    /// The network and complete roster commitment come from the validated generation-zero
    /// roster. This constructs the body; callers still authenticate the signed genesis.
    ///
    /// # Errors
    /// Rejects invalid rosters, nonzero generations, and an empty height interval.
    pub fn genesis(
        generation: &ValidatorGenerationV1,
        last_height: u64,
    ) -> Result<Self, ValidatorEpochAuthorizationErrorV1> {
        Self::genesis_from_roster(
            generation.network_id,
            generation.generation,
            generation.validators.iter(),
            last_height,
        )
    }

    /// Construct the same generation-zero authorization from the original committee.
    /// No roster graph is copied; this shape relation confers no authentication.
    ///
    /// # Errors
    /// Preserves the original roster-before-authorization refusal order.
    pub(crate) fn genesis_from_committee(
        network_id: NetworkId,
        committee: &[ValidatorCommitteeMemberV1],
        last_height: u64,
    ) -> Result<Self, ValidatorEpochAuthorizationErrorV1> {
        Self::genesis_from_roster(
            network_id,
            0,
            committee.iter().map(|member| &member.validator),
            last_height,
        )
    }

    fn genesis_from_roster<'a, I>(
        network_id: NetworkId,
        generation: u64,
        validators: I,
        last_height: u64,
    ) -> Result<Self, ValidatorEpochAuthorizationErrorV1>
    where
        I: ExactSizeIterator<Item = &'a PeerId> + Clone,
    {
        let authorization = Self {
            version: AUTHORIZATION_VERSION_V1,
            network_id,
            epoch: 0,
            first_height: 1,
            last_height,
            authority_generation: generation,
            authority_id: generation_id_from_roster(network_id, generation, validators.clone())?,
            beacon: BeaconEpochBindingV1::Bootstrap,
            previous_authorization_id: [0; 32],
            transition_id: [0; 32],
            decision: ValidatorEpochDecisionV1::Genesis,
        };
        authorization.validate_against_roster(network_id, generation, validators)?;
        Ok(authorization)
    }

    /// Validate canonical shape without treating this body as a certificate.
    ///
    /// # Errors
    /// Rejects invalid versions, empty identities or intervals, and contradictory decisions.
    pub fn validate(&self) -> Result<(), ValidatorEpochAuthorizationErrorV1> {
        if self.version != AUTHORIZATION_VERSION_V1 {
            return Err(ValidatorEpochAuthorizationErrorV1::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.network_id.as_bytes() == &[0; 32]
            || self.authority_id == [0; 32]
            || self.first_height == 0
            || self.last_height < self.first_height
        {
            return Err(invalid("epoch_authorization"));
        }
        match self.beacon {
            BeaconEpochBindingV1::Bootstrap => {
                if self.decision != ValidatorEpochDecisionV1::Genesis {
                    return Err(invalid("epoch_authorization.beacon"));
                }
            }
            BeaconEpochBindingV1::Installed(binding) => {
                if binding.session_id == [0; 32] || binding.transcript_hash == [0; 32] {
                    return Err(invalid("epoch_authorization.beacon"));
                }
            }
        }
        match self.decision {
            ValidatorEpochDecisionV1::Genesis => {
                if self.epoch != 0
                    || self.authority_generation != 0
                    || self.first_height != 1
                    || self.previous_authorization_id != [0; 32]
                    || self.transition_id != [0; 32]
                    || self.beacon != BeaconEpochBindingV1::Bootstrap
                {
                    return Err(invalid("epoch_authorization.genesis"));
                }
            }
            decision => {
                if self.epoch == 0
                    || self.first_height == 1
                    || self.previous_authorization_id == [0; 32]
                    || matches!(self.beacon, BeaconEpochBindingV1::Bootstrap)
                    || ((decision == ValidatorEpochDecisionV1::Retain)
                        != (self.transition_id == [0; 32]))
                {
                    return Err(invalid("epoch_authorization.decision"));
                }
            }
        }
        Ok(())
    }

    /// Validate the exact validator generation selected by this authorization.
    ///
    /// # Errors
    /// Rejects any mismatch in network, generation number, or complete roster commitment.
    pub fn validate_against_generation(
        &self,
        generation: &ValidatorGenerationV1,
    ) -> Result<(), ValidatorEpochAuthorizationErrorV1> {
        self.validate_against_roster(
            generation.network_id,
            generation.generation,
            generation.validators.iter(),
        )
    }

    /// Check the same authorization relation against the original committee peers.
    /// No separately copied generation graph participates in the comparison.
    ///
    /// # Errors
    /// Preserves authorization-first validation and network/generation short circuits.
    pub(crate) fn validate_against_committee(
        &self,
        network_id: NetworkId,
        generation: u64,
        committee: &[ValidatorCommitteeMemberV1],
    ) -> Result<(), ValidatorEpochAuthorizationErrorV1> {
        self.validate_against_roster(
            network_id,
            generation,
            committee.iter().map(|member| &member.validator),
        )
    }

    fn validate_against_roster<'a, I>(
        &self,
        network_id: NetworkId,
        generation: u64,
        validators: I,
    ) -> Result<(), ValidatorEpochAuthorizationErrorV1>
    where
        I: ExactSizeIterator<Item = &'a PeerId> + Clone,
    {
        self.validate()?;
        if self.network_id != network_id
            || self.authority_generation != generation
            || self.authority_id != generation_id_from_roster(network_id, generation, validators)?
        {
            return Err(invalid("epoch_authorization.generation"));
        }
        Ok(())
    }

    /// Validate one contiguous scheduling transition from an authenticated predecessor.
    ///
    /// The caller must separately verify the incumbent boundary certificate and, for activation,
    /// the complete prepared target and all-seat custody readiness. A genesis-to-retain transition
    /// binds the initial ceremony from authenticated state; later retention preserves its binding.
    ///
    /// # Errors
    /// Rejects epoch or height gaps, stale parent identity, generation relabeling, or changed
    /// incumbent authority on retention.
    pub fn validate_successor(
        &self,
        previous: &Self,
    ) -> Result<(), ValidatorEpochAuthorizationErrorV1> {
        self.validate()?;
        previous.validate()?;
        if self.network_id != previous.network_id
            || previous.epoch.checked_add(1) != Some(self.epoch)
            || previous.last_height.checked_add(1) != Some(self.first_height)
            || self.previous_authorization_id != previous.authorization_id()?
        {
            return Err(invalid("epoch_authorization.predecessor"));
        }
        match self.decision {
            ValidatorEpochDecisionV1::Genesis => {
                return Err(invalid("epoch_authorization.successor"));
            }
            ValidatorEpochDecisionV1::Activate => {
                if previous.authority_generation.checked_add(1) != Some(self.authority_generation)
                    || self.authority_id == previous.authority_id
                {
                    return Err(invalid("epoch_authorization.activation"));
                }
            }
            ValidatorEpochDecisionV1::Retain | ValidatorEpochDecisionV1::RetainAndCancel => {
                if self.authority_generation != previous.authority_generation
                    || self.authority_id != previous.authority_id
                    || (previous.beacon != BeaconEpochBindingV1::Bootstrap
                        && self.beacon != previous.beacon)
                {
                    return Err(invalid("epoch_authorization.retention"));
                }
            }
        }
        Ok(())
    }

    /// Compute the fixed-width identity certified by the incumbent boundary quorum.
    ///
    /// # Errors
    /// Returns an error unless the authorization has a canonical shape.
    pub fn authorization_id(&self) -> Result<[u8; 32], ValidatorEpochAuthorizationErrorV1> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(AUTHORIZATION_DOMAIN_V1);
        hasher.update([0]);
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.network_id.as_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.first_height.to_le_bytes());
        hasher.update(self.last_height.to_le_bytes());
        hasher.update(self.authority_generation.to_le_bytes());
        hasher.update(self.authority_id);
        match self.beacon {
            BeaconEpochBindingV1::Bootstrap => {
                hasher.update([0]);
                hasher.update([0; 64]);
            }
            BeaconEpochBindingV1::Installed(binding) => {
                hasher.update([1]);
                hasher.update(binding.session_id);
                hasher.update(binding.transcript_hash);
            }
        }
        hasher.update(self.previous_authorization_id);
        hasher.update(self.transition_id);
        hasher.update([self.decision as u8]);
        Ok(hasher.finalize().into())
    }
}

/// Structural failure of a scheduling authorization body or its selected validator generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidatorEpochAuthorizationErrorV1 {
    /// The body used a version other than the sole first-release layout.
    #[error("unsupported validator epoch authorization version {actual}")]
    UnsupportedVersion {
        /// Encountered version.
        actual: u16,
    },
    /// A required field was zero, inconsistent, or non-canonical.
    #[error("invalid validator epoch authorization field `{field}`")]
    InvalidField {
        /// Stable field label.
        field: &'static str,
    },
}

fn invalid(field: &'static str) -> ValidatorEpochAuthorizationErrorV1 {
    ValidatorEpochAuthorizationErrorV1::InvalidField { field }
}

#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
