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
    genesis_fixture_with_scope(
        mode,
        length,
        duplicate_npos,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
    )
}

pub(crate) fn genesis_fixture_with_scope(
    mode: SumeragiConsensusMode,
    length: u64,
    duplicate_npos: bool,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
) -> SignedBlock {
    let parameters = (mode == SumeragiConsensusMode::Npos).then(|| SumeragiNposParameters {
        epoch_length_blocks: NonZeroU64::new(length).unwrap(),
        epoch_seed: [0x31; 32],
        evidence_horizon_blocks: 1,
        slashing_delay_blocks: 1,
        ..SumeragiNposParameters::default()
    });
    genesis_fixture_with_policy(mode, parameters, duplicate_npos, root_scope)
}

/// Sign exactly the requested policy presence, including the malformed absence fixture.
fn genesis_fixture_with_policy(
    mode: SumeragiConsensusMode,
    parameters: Option<SumeragiNposParameters>,
    duplicate_npos: bool,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
) -> SignedBlock {
    let mut voters = (1_u8..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    voters.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let mut context = SumeragiGenesisContextParameters::recommended();
    context.root_scope = root_scope;
    let metadata = ConsensusHandshakeMetadata {
        mode,
        block_cadence_ms: NonZeroU64::new(1000).unwrap(),
        wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0x71; 32]),
        sumeragi_context: context,
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
    if let Some(parameters) = parameters {
        let parameters = parameters.into_custom_parameter();
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

#[test]
fn permissioned_epoch_is_zero_without_npos_parameters_at_all_boundaries() {
    use crate::sumeragi::schedule::{ChainParamsRecord, ScheduleError, ScheduledConfig};
    let genesis = genesis_fixture(SumeragiConsensusMode::Permissioned, 7, false);
    let (original, _) = authenticated_genesis(&genesis).unwrap().into_parts();
    assert_eq!(original.authorization.epoch, 0);
    assert_eq!(original.authorization.first_height, 1);
    assert_eq!(original.authorization.last_height, u64::MAX);
    for height in [0, 1, 3_600, 3_601, u64::MAX] {
        let scheduled = ScheduledConfig {
            height,
            epoch: original.clone(),
            params: ChainParamsRecord::from_core(&iroha_sumeragi::types::ChainParams::default()),
        }
        .height_config();
        if height == 0 {
            assert!(matches!(scheduled, Err(ScheduleError::Epoch(reason))
                if reason == "scheduled height is outside its authenticated epoch"));
        } else {
            assert_eq!(
                scheduled
                    .expect("signed Permissioned authority needs no NPoS policy")
                    .epoch
                    .id
                    .epoch,
                0
            );
        }
    }
}

#[test]
fn npos_epoch_rejects_missing_committed_parameters() {
    // Omit the policy before signing. The actual signed-genesis reader must
    // refuse missing authority, without relying on a mutable World default.
    let genesis = genesis_fixture_with_policy(
        SumeragiConsensusMode::Npos,
        None,
        false,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
    );
    assert_eq!(
        iroha_genesis::signed_genesis_consensus_metadata(&genesis)
            .unwrap()
            .mode,
        SumeragiConsensusMode::Npos,
    );
    assert!(matches!(
        authenticated_genesis(&genesis),
        Err(iroha_data_model::sumeragi_finality::GenesisReadError::Invalid(reason))
            if reason == "NPoS genesis omits its signed epoch length and seed"
    ));
}
