//! Signed native genesis authority tests; no result-only field grants signing authority.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::{SignedBlock, consensus::SumeragiGenesisContextParameters},
    isi::{InstructionBox, RegisterPeerWithPop, SetParameter},
    parameter::{
        CustomParameter, Parameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            SumeragiNposParameters, consensus_metadata,
        },
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::json::Json;
use std::num::NonZeroU64;

pub(crate) fn genesis_fixture(
    mode: SumeragiConsensusMode,
    length: u64,
    duplicate_npos: bool,
) -> SignedBlock {
    let mut voters = (1_u8..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    voters.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let metadata = ConsensusHandshakeMetadata {
        mode,
        block_cadence_ms: NonZeroU64::new(1000).unwrap(),
        wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0x71; 32]),
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
    };
    let mut instructions = voters
        .iter()
        .map(|pair| {
            InstructionBox::from(RegisterPeerWithPop::new(
                PeerId::new(pair.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
            ))
        })
        .collect::<Vec<_>>();
    instructions.push(
        SetParameter::new(Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            Json::new(metadata),
        )))
        .into(),
    );
    if mode == SumeragiConsensusMode::Npos {
        let parameters = SumeragiNposParameters {
            epoch_length_blocks: NonZeroU64::new(length).unwrap(),
            epoch_seed: [0x31; 32],
            evidence_horizon_blocks: 1,
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter();
        instructions.push(SetParameter::new(Parameter::Custom(parameters.clone())).into());
        if duplicate_npos {
            instructions.push(SetParameter::new(Parameter::Custom(parameters)).into());
        }
    }
    let signer = KeyPair::from_seed(
        b"native genesis authority fixture".to_vec(),
        Algorithm::Ed25519,
    );
    let transaction = TransactionBuilder::new_genesis(
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(signer.private_key());
    SignedBlock::genesis(vec![transaction], signer.private_key(), None, None)
}

#[test]
fn signed_genesis_fixes_complete_generation_epoch_seed_and_proofs() {
    for mode in [
        SumeragiConsensusMode::Permissioned,
        SumeragiConsensusMode::Npos,
    ] {
        let genesis = genesis_fixture(mode, 10, false);
        let context = authenticated_genesis(&genesis)
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        assert_eq!(
            context.network_id,
            NetworkId::from_genesis_hash(genesis.hash())
        );
        assert_eq!(context.authorization.authority_generation, 0);
        assert_eq!(context.authorization.epoch, 0);
        assert_eq!(context.committee.len(), 4);
        assert_eq!(context.authorization.first_height, 1);
        if mode == SumeragiConsensusMode::Npos {
            assert_eq!(context.authorization.last_height, 10);
            assert_eq!(context.leader_seed, [0x31; 32]);
        } else {
            assert_eq!(context.authorization.last_height, u64::MAX);
        }
        context.validate().unwrap();
    }
}

#[test]
fn signed_genesis_rejects_short_or_repeated_epoch_authority() {
    for length in [1, 2] {
        assert!(
            authenticated_genesis(&genesis_fixture(SumeragiConsensusMode::Npos, length, false))
                .map(|genesis| genesis.into_parts().0)
                .is_err()
        );
    }
    assert!(
        authenticated_genesis(&genesis_fixture(SumeragiConsensusMode::Npos, 10, true))
            .map(|genesis| genesis.into_parts().0)
            .is_err()
    );
    let first = authenticated_genesis(&genesis_fixture(SumeragiConsensusMode::Npos, 10, false))
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let changed = authenticated_genesis(&genesis_fixture(SumeragiConsensusMode::Npos, 11, false))
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    assert_ne!(first.context_id().unwrap(), changed.context_id().unwrap());
    assert_ne!(first.network_id, changed.network_id);
}
