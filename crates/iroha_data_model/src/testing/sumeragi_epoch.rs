//! Deterministic, non-shipping validator-generation and epoch-authorization fixtures.
//!
//! These builders construct canonical bodies for tests. They carry no certificate: a consumer
//! still authenticates signed genesis or an incumbent boundary before treating them as authority.

use crate::{
    NetworkId,
    block::consensus::{SumeragiGenesisContextParameters, ValidatorPower},
    sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochAuthorizationV1,
        ValidatorEpochDecisionV1, ValidatorGenerationV1,
    },
};

/// Build the signed-genesis Sumeragi context used by consensus fixtures.
#[must_use]
pub fn genesis_context_parameters() -> SumeragiGenesisContextParameters {
    SumeragiGenesisContextParameters::recommended()
}

/// Project an ordered BLS fixture roster into one validator generation.
///
/// # Panics
/// Panics unless `roster` is an exact ordered `3f + 1` BLS-normal roster.
#[must_use]
pub fn validator_generation(
    network_id: NetworkId,
    generation: u64,
    roster: &[ValidatorPower],
) -> ValidatorGenerationV1 {
    let generation = ValidatorGenerationV1 {
        network_id,
        generation,
        validators: roster
            .iter()
            .map(|validator| validator.validator.clone())
            .collect(),
    };
    generation
        .validate()
        .expect("fixture roster is an ordered BLS 3f+1 generation");
    generation
}

/// Build generation zero and its explicit genesis authorization.
///
/// # Panics
/// Panics for an invalid roster or an empty height interval.
#[must_use]
pub fn genesis_authorization(
    network_id: NetworkId,
    last_height: u64,
    roster: &[ValidatorPower],
) -> (ValidatorEpochAuthorizationV1, ValidatorGenerationV1) {
    let generation = validator_generation(network_id, 0, roster);
    let authorization = ValidatorEpochAuthorizationV1::genesis(&generation, last_height)
        .expect("generation-zero genesis authorization");
    (authorization, generation)
}

/// Build one explicit contiguous successor and check its predecessor and generation binding.
///
/// # Panics
/// Panics unless the successor is a valid contiguous authorization for `generation`.
#[must_use]
pub fn successor_authorization(
    previous: &ValidatorEpochAuthorizationV1,
    generation: &ValidatorGenerationV1,
    last_height: u64,
    beacon: BeaconEpochBindingV1,
    decision: ValidatorEpochDecisionV1,
    transition_id: [u8; 32],
) -> ValidatorEpochAuthorizationV1 {
    let authorization = ValidatorEpochAuthorizationV1 {
        version: 1,
        network_id: generation.network_id,
        epoch: previous
            .epoch
            .checked_add(1)
            .expect("fixture epoch successor"),
        first_height: previous
            .last_height
            .checked_add(1)
            .expect("fixture height successor"),
        last_height,
        authority_generation: generation.generation,
        authority_id: generation
            .generation_id()
            .expect("fixture generation identity"),
        beacon,
        previous_authorization_id: previous
            .authorization_id()
            .expect("fixture previous authorization identity"),
        transition_id,
        decision,
    };
    authorization
        .validate_against_generation(generation)
        .expect("successor generation binding");
    authorization
        .validate_successor(previous)
        .expect("contiguous fixture epoch authorization");
    authorization
}

/// Return the explicit installed-beacon binding used by non-shipping authorization histories.
#[must_use]
pub fn fixture_installed_beacon() -> BeaconEpochBindingV1 {
    BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
        session_id: [0x71; 32],
        transcript_hash: [0x72; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::peer::PeerId;

    fn roster() -> Vec<ValidatorPower> {
        let mut roster = (1_u8..=4)
            .map(|seed| ValidatorPower {
                validator: PeerId::new(
                    KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                        .unwrap()
                        .public_key()
                        .clone(),
                ),
                power: 1,
            })
            .collect::<Vec<_>>();
        roster.sort_by(|left, right| left.validator.cmp(&right.validator));
        roster
    }

    #[test]
    fn retained_history_keeps_generation_zero_and_links_each_successor() {
        let network_id =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"fixture retained authorization history",
            )));
        let (genesis, generation) = genesis_authorization(network_id, 1, &roster());
        assert_eq!(generation.generation, 0);
        let first = successor_authorization(
            &genesis,
            &generation,
            10,
            fixture_installed_beacon(),
            ValidatorEpochDecisionV1::Retain,
            [0; 32],
        );
        let second = successor_authorization(
            &first,
            &generation,
            20,
            fixture_installed_beacon(),
            ValidatorEpochDecisionV1::Retain,
            [0; 32],
        );
        assert_eq!((second.epoch, second.first_height), (2, 11));
        assert_eq!(second.authority_id, genesis.authority_id);
        second.validate_successor(&first).unwrap();
        assert!(second.validate_successor(&genesis).is_err());
        let successor = validator_generation(network_id, 1, &roster());
        let activated = successor_authorization(
            &second,
            &successor,
            30,
            fixture_installed_beacon(),
            ValidatorEpochDecisionV1::Activate,
            [0xA1; 32],
        );
        assert_eq!(activated.authority_generation, 1);
        assert_ne!(activated.authority_id, genesis.authority_id);
        assert!(genesis_context_parameters().validate().is_ok());
    }
}
