//! Cryptographic custody evidence for an exact prepared beacon seat.

use iroha_crypto::Hash;
use iroha_data_model::{
    consensus::GlobalThresholdBeaconPartialSignatureV1, nexus::ValidatorSeatReadinessContextV1,
    sumeragi::epoch::ValidatorGenerationV1,
};
use thiserror::Error;

use super::{
    GlobalThresholdBeaconPartialSignerV1, ValidatedGlobalThresholdBeaconSessionV1,
    adaptive_partial_signature_from_dto_v1, authenticated_global_threshold_beacon_roster_hash_v1,
};

const READINESS_DOMAIN: &[u8] = b"iroha.global-threshold-beacon.prepared-seat-readiness.v1\0";

/// Closed errors for proof-bearing prepared-seat custody checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GlobalThresholdBeaconSeatReadinessErrorV1 {
    /// The generation, preparation context, session or exact seat is inconsistent.
    #[error("prepared beacon seat readiness binding is invalid")]
    InvalidBinding,
    /// The exact live share is unavailable or its owner cannot produce a proof.
    #[error("prepared beacon seat custody is unavailable")]
    CustodyUnavailable,
    /// The adaptive proof does not establish possession of the exact public share.
    #[error("prepared beacon seat custody proof is invalid")]
    InvalidProof,
}

/// Derive the separate challenge after checking every exact prepared-seat binding.
///
/// The challenge grants no activation authority; authenticated transition state supplies that.
///
/// # Errors
/// Rejects malformed contexts and mismatched network, committee, session, transcript or seat.
pub fn global_threshold_beacon_seat_readiness_challenge_v1(
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    generation: &ValidatorGenerationV1,
    context: &ValidatorSeatReadinessContextV1,
) -> Result<(Hash, u16), GlobalThresholdBeaconSeatReadinessErrorV1> {
    use GlobalThresholdBeaconSeatReadinessErrorV1::InvalidBinding;
    context.validate().map_err(|_| InvalidBinding)?;
    if context.network_id != generation.network_id
        || context.authority_generation != generation.generation
        || context.authority_id != generation.generation_id().map_err(|_| InvalidBinding)?
        || session.record().network_id != context.network_id
        || context.beacon.session_id != session.record().session_id
        || context.beacon.transcript_hash != session.record().transcript_hash
    {
        return Err(InvalidBinding);
    }
    authenticated_global_threshold_beacon_roster_hash_v1(session.record(), &generation.validators)
        .map_err(|_| InvalidBinding)?;
    let validator = generation
        .validators
        .get(usize::try_from(context.validator_index).map_err(|_| InvalidBinding)?)
        .ok_or(InvalidBinding)?;
    let signer_index = u16::try_from(context.validator_index)
        .ok()
        .and_then(|index| index.checked_add(1))
        .ok_or(InvalidBinding)?;
    let context_digest = context
        .signing_digest(validator)
        .map_err(|_| InvalidBinding)?;
    let challenge = Hash::new_from_chunks(&[READINESS_DOMAIN, &context_digest]);
    Ok((challenge, signer_index))
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Prove actual threshold-share custody for one exact target seat and frozen attempt.
///
/// The challenge is disjoint from pulse payloads and binds the full scheduling/readiness context,
/// the seat occupant and the exact ordered DKG roster. This proof neither activates a session
/// nor authorizes a pulse. The incumbent transition certificate must authenticate its context.
///
/// # Errors
/// Rejects inconsistent bindings, unavailable custody, or a provider returning another share.
pub fn prove_global_threshold_beacon_seat_readiness_v1(
    provider: &dyn GlobalThresholdBeaconPartialSignerV1,
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    generation: &ValidatorGenerationV1,
    context: &ValidatorSeatReadinessContextV1,
) -> Result<GlobalThresholdBeaconPartialSignatureV1, GlobalThresholdBeaconSeatReadinessErrorV1> {
    global_threshold_beacon_seat_readiness_challenge_v1(session, generation, context)?;
    let proof = provider.prove_seat_readiness(session, generation, context)?;
    verify_global_threshold_beacon_seat_readiness_v1(session, generation, context, &proof)?;
    Ok(proof)
}

pub(super) fn prove_with_partial_signer<P: GlobalThresholdBeaconPartialSignerV1 + ?Sized>(
    provider: &P,
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    generation: &ValidatorGenerationV1,
    context: &ValidatorSeatReadinessContextV1,
) -> Result<GlobalThresholdBeaconPartialSignatureV1, GlobalThresholdBeaconSeatReadinessErrorV1> {
    use GlobalThresholdBeaconSeatReadinessErrorV1::CustodyUnavailable;
    let (challenge, index) =
        global_threshold_beacon_seat_readiness_challenge_v1(session, generation, context)?;
    let capability = provider
        .attest_partial_signing_capability(session, index)
        .map_err(|_| CustodyUnavailable)?;
    if !capability.matches(session, index) {
        return Err(CustodyUnavailable);
    }
    let proof = provider
        .sign_partial(session, challenge.as_ref())
        .map_err(|_| CustodyUnavailable)?;
    verify_global_threshold_beacon_seat_readiness_v1(session, generation, context, &proof)?;
    Ok(proof)
}

/// Verify actual share possession against the complete authenticated DKG public transcript.
///
/// Both adaptive representation equations must verify for this seat and readiness challenge.
/// A peer signature, public transcript membership or threshold aggregate is insufficient.
///
/// # Errors
/// Rejects wrong contexts, sessions, rosters, seats and malformed or replayed custody proofs.
pub fn verify_global_threshold_beacon_seat_readiness_v1(
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    generation: &ValidatorGenerationV1,
    context: &ValidatorSeatReadinessContextV1,
    proof: &GlobalThresholdBeaconPartialSignatureV1,
) -> Result<(), GlobalThresholdBeaconSeatReadinessErrorV1> {
    use GlobalThresholdBeaconSeatReadinessErrorV1::InvalidProof;
    let (challenge, index) =
        global_threshold_beacon_seat_readiness_challenge_v1(session, generation, context)?;
    if proof.session_id != session.record().session_id || proof.signer_index != index {
        return Err(InvalidProof);
    }
    let partial = adaptive_partial_signature_from_dto_v1(proof).map_err(|_| InvalidProof)?;
    session
        .transcript()
        .verify_partial_signature(challenge.as_ref(), &partial)
        .map_err(|_| InvalidProof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::{
        AdaptiveThresholdBlsSecretShare, InMemoryGlobalThresholdBeaconPartialSignerV1,
        RuntimeGlobalThresholdBeaconShareCustodyV1,
        fixtures::{adaptive_beacon_fixture_for_session_and_keys, adaptive_dkg_session_fixture},
        global_threshold_beacon_roster_hash_v1,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1;
    use iroha_data_model::{
        block::consensus::ValidatorPower, testing::sumeragi_epoch::validator_generation,
    };
    use iroha_model_base::peer::PeerId;

    #[test]
    fn prepared_beacon_seat_readiness_requires_actual_share_and_exact_context() {
        let mut keys = (1..=4_u8)
            .map(|seed| {
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).expect("BLS peer")
            })
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
        let peers = keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let mut dkg = adaptive_dkg_session_fixture();
        dkg.roster_hash = global_threshold_beacon_roster_hash_v1(&peers);
        let fixture = adaptive_beacon_fixture_for_session_and_keys(
            dkg,
            &keys,
            &crate::beacon::fixtures::fixture_budget(),
        );
        let roster = peers
            .into_iter()
            .map(|validator| ValidatorPower {
                validator,
                power: 1,
            })
            .collect::<Vec<_>>();
        let authority = validator_generation(dkg.network_id, 1, &roster);
        let context = ValidatorSeatReadinessContextV1 {
            version: 1,
            network_id: dkg.network_id,
            transition_id: [0xA1; 32],
            target_epoch: 2,
            authority_generation: 1,
            authority_id: authority.generation_id().unwrap(),
            first_height: 201,
            last_height: 300,
            validator_index: 0,
            beacon: InstalledBeaconEpochBindingV1 {
                session_id: fixture.session.record().session_id,
                transcript_hash: fixture.session.record().transcript_hash,
            },
        };
        let custody = RuntimeGlobalThresholdBeaconShareCustodyV1::new();
        assert_eq!(
            prove_global_threshold_beacon_seat_readiness_v1(
                &custody,
                &fixture.session,
                &authority,
                &context
            ),
            Err(GlobalThresholdBeaconSeatReadinessErrorV1::CustodyUnavailable)
        );
        let private_shares = fixture
            .dealer_secrets
            .iter()
            .zip(&fixture.dealer_commitments)
            .map(|(secret, dealer)| {
                secret
                    .private_share(&fixture.parameters, dealer, 1)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
            fixture.session.transcript(),
            &private_shares,
        )
        .unwrap();
        custody
            .insert_validated_share(
                InMemoryGlobalThresholdBeaconPartialSignerV1::from_validated_share(
                    fixture.session.clone(),
                    share,
                )
                .unwrap(),
            )
            .unwrap();
        let proof = prove_global_threshold_beacon_seat_readiness_v1(
            &custody,
            &fixture.session,
            &authority,
            &context,
        )
        .unwrap();
        verify_global_threshold_beacon_seat_readiness_v1(
            &fixture.session,
            &authority,
            &context,
            &proof,
        )
        .unwrap();
        for coordinate in 0..8 {
            let mut changed = context;
            match coordinate {
                0 => changed.transition_id[0] ^= 1,
                1 => changed.target_epoch += 1,
                2 => changed.first_height += 1,
                3 => changed.last_height += 1,
                4 => changed.authority_generation += 1,
                5 => changed.authority_id[0] ^= 1,
                6 => changed.validator_index = 1,
                _ => changed.beacon.transcript_hash = [0xA2; 32],
            }
            assert!(
                verify_global_threshold_beacon_seat_readiness_v1(
                    &fixture.session,
                    &authority,
                    &changed,
                    &proof
                )
                .is_err(),
                "coordinate {coordinate}"
            );
        }
        let mut malformed = proof.clone();
        malformed.proof.z_s[0] ^= 1;
        assert!(
            verify_global_threshold_beacon_seat_readiness_v1(
                &fixture.session,
                &authority,
                &context,
                &malformed
            )
            .is_err()
        );
        let unrelated = custody
            .sign_partial(&fixture.session, b"unrelated pulse-domain payload")
            .unwrap();
        assert!(
            verify_global_threshold_beacon_seat_readiness_v1(
                &fixture.session,
                &authority,
                &context,
                &unrelated
            )
            .is_err()
        );
        let mut other_authority = authority.clone();
        other_authority.generation += 1;
        assert!(
            verify_global_threshold_beacon_seat_readiness_v1(
                &fixture.session,
                &other_authority,
                &context,
                &proof
            )
            .is_err()
        );
        // The same mathematical share evidence is not accepted as a pulse or another payload.
        let partial = adaptive_partial_signature_from_dto_v1(&proof).unwrap();
        assert!(
            fixture
                .session
                .transcript()
                .verify_partial_signature(b"unrelated pulse-domain payload", &partial)
                .is_err()
        );
    }
}
