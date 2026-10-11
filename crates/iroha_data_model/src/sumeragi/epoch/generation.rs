//! Neutral validator signing generations.
//!
//! A generation is one network's exact ordered equal-vote BLS roster under a monotonic
//! generation number. Scheduling authorizations, committee preparations, threshold-beacon
//! DKG sessions and prepared-seat readiness bind its fixed-width identity. Scheduling epochs
//! may retain one generation; only an incumbent-certified activation advances it.

use iroha_crypto::Algorithm;
use iroha_model_base::peer::PeerId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};

use super::{MAX_VALIDATORS, ValidatorCommitteeMemberV1, ValidatorEpochAuthorizationErrorV1};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId};

/// Sole first-release generation transcript version.
const GENERATION_VERSION_V1: u16 = 1;
const GENERATION_DOMAIN_V1: &[u8] = b"iroha:validator-generation:v1";
/// Exact BLS-normal public key width bound by the generation transcript.
const BLS_PUBLIC_KEY_BYTES: usize = 48;

/// One network's ordered validator roster under one monotonic signing generation.
///
/// This value carries no certificate and is never authority by itself: callers derive it from
/// an authenticated epoch context or frozen committee preparation and compare its identity
/// with the incumbent-certified [`super::ValidatorEpochAuthorizationV1`].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sumeragi::epoch::ValidatorGenerationV1")]
pub struct ValidatorGenerationV1 {
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Monotonic generation; genesis uses zero and each activation adds one.
    pub generation: u64,
    /// Exact `3f + 1` BLS-normal roster in strictly ascending public-key order.
    pub validators: Vec<PeerId>,
}

impl ValidatorGenerationV1 {
    /// Project the ordered roster of an authenticated committee into one generation.
    #[must_use]
    pub fn from_committee(
        network_id: NetworkId,
        generation: u64,
        committee: &[ValidatorCommitteeMemberV1],
    ) -> Self {
        Self {
            network_id,
            generation,
            validators: committee
                .iter()
                .map(|member| member.validator.clone())
                .collect(),
        }
    }

    /// Validate the network, exact committee geometry and canonical BLS roster order.
    ///
    /// Proofs of possession are checked by the committee owner; this checks only the roster.
    ///
    /// # Errors
    /// Rejects a zero network, a non-`3f + 1` roster, non-BLS keys and unordered or repeated keys.
    pub fn validate(&self) -> Result<(), ValidatorEpochAuthorizationErrorV1> {
        validate_roster(self.network_id, self.validators.iter())
    }

    /// Hash the network, generation and exact ordered roster with a fixed-width transcript.
    ///
    /// # Errors
    /// Rejects an invalid generation.
    pub fn generation_id(&self) -> Result<[u8; 32], ValidatorEpochAuthorizationErrorV1> {
        generation_id_from_roster(self.network_id, self.generation, self.validators.iter())
    }

    /// Hash the same generation transcript from the original complete committee peers.
    /// This validates only roster geometry and grants no source or signing authority.
    ///
    /// # Errors
    /// Preserves network, key shape and ordering refusal before the canonical hash.
    pub(crate) fn generation_id_from_committee(
        network_id: NetworkId,
        generation: u64,
        committee: &[ValidatorCommitteeMemberV1],
    ) -> Result<[u8; 32], ValidatorEpochAuthorizationErrorV1> {
        generation_id_from_roster(
            network_id,
            generation,
            committee.iter().map(|member| &member.validator),
        )
    }
}

// Pure borrowed projection of the original roster. It carries no certificate,
// source grant or retained graph; callers establish those independently.
fn validate_roster<'a, I>(
    network_id: NetworkId,
    validators: I,
) -> Result<(), ValidatorEpochAuthorizationErrorV1>
where
    I: ExactSizeIterator<Item = &'a PeerId>,
{
    let n = validators.len();
    if network_id.as_bytes() == &[0; 32]
        || !(4..=MAX_VALIDATORS).contains(&n)
        || !(n - 1).is_multiple_of(3)
    {
        return Err(invalid());
    }
    let mut previous: Option<&[u8]> = None;
    for validator in validators {
        let key = bls_key(validator)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(invalid());
        }
        previous = Some(key);
    }
    Ok(())
}

/// Derive the canonical generation transcript from exact borrowed original peers.
/// This pure relation retains no graph and grants no signing or source authority.
///
/// # Errors
/// Preserves network, geometry, key shape and ordering validation before hashing.
pub(super) fn generation_id_from_roster<'a, I>(
    network_id: NetworkId,
    generation: u64,
    validators: I,
) -> Result<[u8; 32], ValidatorEpochAuthorizationErrorV1>
where
    I: ExactSizeIterator<Item = &'a PeerId> + Clone,
{
    validate_roster(network_id, validators.clone())?;
    let count = u32::try_from(validators.len()).map_err(|_| invalid())?;
    let mut hasher = Sha256::new();
    hasher.update(GENERATION_DOMAIN_V1);
    hasher.update([0]);
    hasher.update(GENERATION_VERSION_V1.to_le_bytes());
    hasher.update(network_id.as_bytes());
    hasher.update(generation.to_le_bytes());
    hasher.update(count.to_le_bytes());
    for validator in validators {
        hasher.update(bls_key(validator)?);
    }
    Ok(hasher.finalize().into())
}

fn bls_key(validator: &PeerId) -> Result<&[u8], ValidatorEpochAuthorizationErrorV1> {
    let (algorithm, key) = validator
        .public_key()
        .try_to_bytes()
        .map_err(|_| invalid())?;
    if algorithm != Algorithm::BlsNormal || key.len() != BLS_PUBLIC_KEY_BYTES {
        return Err(invalid());
    }
    Ok(key)
}

fn invalid() -> ValidatorEpochAuthorizationErrorV1 {
    ValidatorEpochAuthorizationErrorV1::InvalidField {
        field: "validator_generation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use iroha_crypto::{Hash, HashOf, KeyPair};

    fn network() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"validator generation fixture",
        )))
    }

    fn roster(count: u8) -> Vec<PeerId> {
        let mut peers = (1..=count)
            .map(|seed| {
                PeerId::new(
                    KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                        .unwrap()
                        .public_key()
                        .clone(),
                )
            })
            .collect::<Vec<_>>();
        peers.sort();
        peers
    }

    fn generation(number: u64) -> ValidatorGenerationV1 {
        ValidatorGenerationV1 {
            network_id: network(),
            generation: number,
            validators: roster(4),
        }
    }

    #[test]
    fn generation_identity_is_an_independent_fixed_width_transcript() {
        let value = generation(3);
        let mut expected = Sha256::new();
        expected.update(b"iroha:validator-generation:v1");
        expected.update([0]);
        expected.update(1_u16.to_le_bytes());
        expected.update(network().as_bytes());
        expected.update(3_u64.to_le_bytes());
        expected.update(4_u32.to_le_bytes());
        for peer in &value.validators {
            let (_, key) = peer.public_key().to_bytes();
            assert_eq!(key.len(), 48);
            expected.update(key);
        }
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(value.generation_id().unwrap(), expected);
    }

    #[test]
    fn generation_identity_binds_network_number_and_exact_roster() {
        let base = generation(0);
        let id = base.generation_id().unwrap();
        let mut other = base.clone();
        other.generation = 1;
        assert_ne!(other.generation_id().unwrap(), id);
        let mut other = base.clone();
        other.network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"other network")),
        );
        assert_ne!(other.generation_id().unwrap(), id);
        let mut other = base.clone();
        other.validators = roster(7);
        assert_ne!(other.generation_id().unwrap(), id);
    }

    #[test]
    fn generation_roundtrips_canonical_norito_and_json() {
        let value = generation(2);
        let bytes = norito::encode_canonical(&value).unwrap();
        assert_eq!(
            norito::decode_canonical::<ValidatorGenerationV1>(&bytes).unwrap(),
            value
        );
        let json = norito::json::to_json(&value).unwrap();
        assert_eq!(
            norito::json::from_str::<ValidatorGenerationV1>(&json).unwrap(),
            value
        );
    }

    #[test]
    fn generation_rejects_geometry_order_and_key_algorithm() {
        let base = generation(0);
        for mutation in 0..4 {
            let mut bad = base.clone();
            match mutation {
                0 => {
                    bad.validators.pop();
                }
                1 => bad.validators.swap(0, 1),
                2 => bad.validators[1] = bad.validators[0].clone(),
                _ => {
                    bad.validators[0] = PeerId::new(
                        KeyPair::from_seed(vec![9; 32], Algorithm::Ed25519)
                            .public_key()
                            .clone(),
                    );
                }
            }
            assert!(bad.validate().is_err(), "mutation {mutation}");
            assert!(bad.generation_id().is_err(), "mutation {mutation}");
        }
        let mut seven = base;
        seven.validators = roster(7);
        seven.validate().unwrap();
    }
}
