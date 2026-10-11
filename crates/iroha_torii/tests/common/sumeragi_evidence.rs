//! Original native signed evidence for endpoint transport tests.
//!
//! Attribution is fixture-only; these helpers do not establish historical authority or finality.
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::block::consensus::{Evidence, EvidenceAttribution, EvidenceOffender};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    message::{Evidence as NativeEvidence, Vote, VoteKind},
    types::{EpochId, Hash32, SIGNATURE_LEN, Signature as NativeSignature},
};

fn keys(seed: u8) -> Vec<KeyPair> {
    let mut keys = (0..4_u8)
        .map(|index| {
            KeyPair::try_from_seed(vec![seed, index], Algorithm::BlsNormal)
                .expect("fixture BLS key")
        })
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    keys
}
/// Build two original conflicting Prepare votes signed by the same native committee key.
pub(super) fn make_phase_vote_evidence(height: u64, seed: u8) -> Evidence {
    assert!(height > 0);
    let keys = keys(seed);
    let vote = |subject: u8| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance: Hash32([seed; 32]),
            epoch: EpochId {
                epoch: 0,
                context: Hash32([seed.wrapping_add(1); 32]),
            },
            height,
            view: 0,
            block_hash: Hash32([subject; 32]),
            result: Hash32([seed.wrapping_add(3); 32]),
            signer: 0,
            sig: NativeSignature([0; SIGNATURE_LEN]),
        };
        vote.sig = NativeSignature(
            Signature::new(keys[0].private_key(), &vote.preimage())
                .payload()
                .try_into()
                .expect("native BLS signature width"),
        );
        vote
    };
    Evidence::from_native(&NativeEvidence::VoteEquivocation(
        vote(seed),
        vote(seed.wrapping_add(1)),
    ))
    .expect("canonical native pair")
}
/// Matching explicit fixture attribution; only Core history verification may produce admitted records.
pub(super) fn make_phase_vote_attribution(height: u64, seed: u8) -> EvidenceAttribution {
    EvidenceAttribution {
        scope: iroha_data_model::block::consensus::EvidenceScope::Root,
        instance: [seed; 32],
        height,
        epoch: 0,
        context_id: [seed.wrapping_add(1); 32],
        authority_generation: [seed.wrapping_add(2); 32],
        offenders: vec![EvidenceOffender {
            lane_stake: None,
            signer: 0,
            peer_id: PeerId::new(keys(seed)[0].public_key().clone()),
        }],
        safety_violation: false,
    }
}
#[test]
fn evidence_fixture_authenticates_and_rejects_modified_signed_bytes() {
    for height in [1, 2, 30] {
        let evidence = make_phase_vote_evidence(height, 0xA1);
        let NativeEvidence::VoteEquivocation(first, mut second) = evidence.decode_native().unwrap()
        else {
            panic!("native vote pair")
        };
        let keys = keys(0xA1);
        assert_eq!(keys.len(), 4);
        let attribution = make_phase_vote_attribution(height, 0xA1);
        assert_eq!(
            attribution.offenders[0].peer_id.public_key(),
            keys[0].public_key()
        );
        assert_eq!(first.height, second.height);
        assert_eq!(first.epoch, second.epoch);
        assert_eq!(first.signer, second.signer);
        assert_ne!(first.block_hash, second.block_hash);
        for vote in [&first, &second] {
            Signature::from_bytes(&vote.sig.0)
                .verify(keys[0].public_key(), &vote.preimage())
                .expect("original native signature");
        }
        second.block_hash = Hash32([0xCC; 32]);
        assert!(
            Signature::from_bytes(&second.sig.0)
                .verify(keys[0].public_key(), &second.preimage())
                .is_err()
        );
    }
}
