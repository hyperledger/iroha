//! Startup of the Sumeragi driver (`specs/sumeragi.md` §7.4, §10, §12.1).
//!
//! Genesis (iroha height 1, the core's genesis height `g`) is applied locally, without a
//! consensus round: every node executes the same signed genesis block to the same state. Its
//! result `R_g` (the core's `tip.result` at `g`) is kept durably in the genesis frame as a
//! result-only certificate (no core header, no CommitQC), so a restart reads it back instead of
//! recomputing it. On restart genesis is re-executed from Kura and must reproduce that result;
//! later blocks are replayed through the executor, each checked against its certified result.

use iroha_data_model::{
    account::AccountId,
    block::{CommitCertificate, SignedBlock},
    parameter::system::ConsensusMode,
    sumeragi::epoch::ValidatorEpochContextV1,
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::time::TimeSource;
use iroha_sumeragi::types::Hash32;

use super::{
    commitment::{encode_result_preimage, execution_result, result_of_preimage},
    network_topology::Topology,
    schedule,
};
use crate::{
    block::ValidBlock,
    state::{State, StateBlock},
};

/// The genesis height: iroha's genesis block is height 1.
pub const GENESIS_HEIGHT: u64 = 1;
const _: () = assert!(
    iroha_sumeragi::message::PROTOCOL_VERSION == iroha_data_model::sumeragi::PROTOCOL_VERSION
);

/// Why startup failed.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// Original signed policy could not be decoded with local resources.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// The genesis block is invalid.
    #[error("genesis is invalid: {0}")]
    InvalidGenesis(#[source] Box<crate::block::BlockValidationError>),
    /// The executed genesis lane transition did not complete correctly.
    #[error("genesis lane transition is invalid: {0}")]
    LaneStep(#[source] super::lanes::step::LaneStepError),
    /// The original executed genesis and witness cannot form their commitment.
    #[error("genesis execution commitment is invalid: {0}")]
    ExecutionCommitment(#[source] iroha_data_model::sumeragi_finality::CommitmentError),
    /// The genesis committee or schedule is invalid.
    #[error("genesis schedule is invalid: {0}")]
    Schedule(String),
    /// Genesis re-executed to a different result than the stored one.
    #[error("genesis re-execution diverges from the stored result")]
    GenesisDiverged,
    /// A local failure (storage, state publication).
    #[error("local failure: {0}")]
    Local(String),
}

/// The core's view of the applied genesis: its block hash and result (`Init.tip` at `g`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisTip {
    /// Core hash of genesis: the bytes of iroha's genesis block hash.
    pub block_hash: Hash32,
    /// `R_g`.
    pub result: Hash32,
}

/// Origin proof produced only after this module executes the independently signed genesis.
pub(crate) struct GenesisExecutionAuthorization {
    state: usize,
    tip: crate::state::native_execution_tip::NativeExecutionTipRecord,
    telemetry_origin: super::executor::CommitTelemetryOrigin,
}
impl GenesisExecutionAuthorization {
    pub(super) fn into_parts(
        self,
    ) -> (
        usize,
        crate::state::native_execution_tip::NativeExecutionTipRecord,
        super::executor::CommitTelemetryOrigin,
    ) {
        (self.state, self.tip, self.telemetry_origin)
    }
}

/// The core hash of an iroha block: the bytes of its header hash.
#[must_use]
pub fn core_hash_of(block: &SignedBlock) -> Hash32 {
    let hash: iroha_crypto::Hash = block.hash().into();
    Hash32(*hash.as_ref())
}

/// Execute and apply `genesis` to the empty `state`.
///
/// `stored` is `None` for a fresh chain (the genesis frame is then written to Kura with its
/// result-only certificate) and the genesis frame read back from Kura on a restart (its
/// certificate must reproduce).
///
/// # Errors
/// Invalid genesis, an invalid genesis schedule, a divergent re-execution, or a local
/// failure.
pub fn apply_genesis(
    state: &State,
    genesis: SignedBlock,
    genesis_account: &AccountId,
    consensus_mode: ConsensusMode,
    stored: Option<&CommitCertificate>,
) -> Result<GenesisTip, StartupError> {
    let signed_epoch = super::epoch::authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .map_err(|error| {
            match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                StartupError::Schedule(error.to_string())
            }) {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    StartupError::Deferred(reason)
                }
            }
        })?;
    let committee = genesis_committee_peers(&genesis)?;
    let topology = Topology::new(committee.clone());
    let block_hash = core_hash_of(&genesis);
    let (valid, overlay) = ValidBlock::validate_signed_genesis(
        genesis,
        &topology,
        genesis_account,
        &TimeSource::new_system(),
        state,
        consensus_mode,
    )
    .unpack(|_| {})
    .map_err(|(_, error)| StartupError::InvalidGenesis(error))?;
    finish_genesis(
        state,
        committee,
        valid,
        overlay,
        &signed_epoch,
        block_hash,
        stored,
    )
}

/// Retire validation before reserving the late result, certificate and publication frame.
/// The same existing boxed overlay and valid block move once; the caller retains its signed
/// epoch and topology until this original publication finishes. No owner is recreated.
#[inline(never)]
fn finish_genesis(
    state: &State,
    committee: Vec<PeerId>,
    valid: ValidBlock,
    mut overlay: Box<StateBlock<'_>>,
    signed_epoch: &ValidatorEpochContextV1,
    block_hash: Hash32,
    stored: Option<&CommitCertificate>,
) -> Result<GenesisTip, StartupError> {
    let inputs = overlay
        .take_sumeragi_execution_inputs()
        .map_err(|error| StartupError::Schedule(error.to_string()))?;
    if inputs.get().schedule.current != *signed_epoch
        || inputs.get().beacon.is_some()
        || inputs.get().schedule.boundary.is_some()
    {
        return Err(StartupError::Schedule(
            "executed genesis differs from its independently signed epoch authority".into(),
        ));
    }
    overlay
        .take_sumeragi_lanes()
        .map_err(StartupError::LaneStep)?;
    let mut witness = overlay
        .take_exec_witness()
        .ok_or_else(|| StartupError::Local("genesis witness was not captured".into()))?;
    let budget = state.ivm_execution_budget();
    let native_lanes =
        iroha_data_model::sumeragi_finality::NativeLaneStateProof::from_witness(&witness, &budget)
            .map_err(|error| StartupError::Local(error.to_string()))?;
    // Genesis starts from the empty World and absorbs everything it holds (§4.1, E51).
    let transition = overlay
        .world_state_transition()
        .map_err(StartupError::Local)?;
    let retained_result = execution_result(
        &mut witness,
        valid.as_ref(),
        &transition,
        inputs,
        native_lanes,
    )
    .map_err(StartupError::ExecutionCommitment)?;
    let preimage = encode_result_preimage(&retained_result, &budget)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    let result = result_of_preimage(preimage.as_slice());
    let empty_header = iroha_allocation::ChargedBuffer::new(0, &budget)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    let empty_qc = iroha_allocation::ChargedBuffer::new(0, &budget)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    let empty_availability = iroha_allocation::ChargedBuffer::new(0, &budget)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    let certificate = CommitCertificate::from_charged_parts(
        empty_header,
        empty_qc,
        preimage,
        empty_availability,
        &budget,
    )
    .map_err(|(_original_parts, error)| StartupError::Local(error.to_string()))?;
    // Freeze H1 complete context values from the same original overlay and R used by
    // every successor. A separately reconstructed current-head projection is not a source.
    let archive = crate::query::native_context_archive::NativeContextArchive::open(
        state.kura(),
        budget.clone(),
        state.kura().native_context_archive_max_bytes(),
    )
    .map_err(|error| StartupError::Local(error.to_string()))?;
    let native_contexts = archive
        .prepare(&overlay, valid.as_ref(), &retained_result, &witness)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    let shell = iroha_data_model::block::SharedSignedBlock::reserve(&budget)
        .map_err(|error| StartupError::Deferred(error.into()))?;
    let committed = valid
        .with_commit_certificate(certificate.clone())
        .commit_unchecked(shell)
        .unpack(|_| {});
    match stored {
        Some(stored) => {
            if stored != &certificate {
                return Err(StartupError::GenesisDiverged);
            }
        }
        None => {
            state
                .kura()
                .store_block(committed.shared().clone())
                .map_err(|error| StartupError::Local(error.to_string()))?;
        }
    }
    // The canonical executed frame is durable (or matched exactly on replay) before
    // the original projection is published. Refusal occurs before State visibility;
    // restart re-executes the same signed genesis and must reproduce both exact values.
    archive
        .publish(&native_contexts)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    overlay
        .authorize_sumeragi_output_publication(
            &committed,
            &witness,
            &certificate,
            super::executor::NativeExecutionAuthorization::from_genesis(
                GenesisExecutionAuthorization {
                    telemetry_origin: match stored {
                        Some(_) => super::executor::CommitTelemetryOrigin::HistoricalReplay,
                        None => super::executor::CommitTelemetryOrigin::Forward,
                    },
                    state: std::ptr::from_ref(state) as usize,
                    tip: crate::state::native_execution_tip::NativeExecutionTipRecord {
                        height: GENESIS_HEIGHT,
                        creation_time_ms: u64::try_from(
                            committed.as_ref().header().creation_time().as_millis(),
                        )
                        .expect("block creation time fits u64"),
                        iroha_hash: committed.as_ref().hash(),
                        core_hash: block_hash.0,
                        result: result.0,
                    },
                },
            ),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
                StartupError::Local(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                StartupError::Deferred(reason)
            }
        })?;
    overlay
        .apply_without_execution_with_sumeragi_commit(&committed, &certificate, committee)
        .map_err(|error| StartupError::Local(error.to_string()))?;
    overlay
        .commit()
        .map_err(|error| StartupError::Local(error.to_string()))?;
    // Keep the original canonical graph and its same-pool ledger alive until publication
    // completes; the certificate separately owns the exact original encoded allocation.
    drop(retained_result);
    Ok(GenesisTip { block_hash, result })
}

/// The genesis tip recorded in Kura, if genesis is stored with its result certificate.
///
/// # Errors
/// The stored frame cannot project to a valid original proposal.
pub fn stored_genesis(
    state: &State,
) -> Result<Option<(SignedBlock, CommitCertificate, GenesisTip)>, StartupError> {
    let Some(block) = state
        .kura()
        .get_block(
            core::num::NonZeroUsize::new(1).expect("non-zero"),
            &state.ivm_execution_budget(),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                StartupError::Deferred(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                StartupError::Local(error.to_string())
            }
        })?
    else {
        return Ok(None);
    };
    let Some(certificate) = block.commit_certificate().cloned() else {
        return Ok(None);
    };
    let tip = GenesisTip {
        block_hash: core_hash_of(&block),
        result: result_of_preimage(certificate.result_preimage()),
    };
    let proposal = block
        .canonical_resultless_proposal()
        .map_err(|error| StartupError::Local(format!("stored genesis proposal: {error}")))?;
    Ok(Some((proposal, certificate, tip)))
}

/// The validators of a signed genesis, in canonical order (`C_g`).
///
/// # Errors
/// The genesis does not register a valid committee.
pub fn genesis_committee_peers(genesis: &SignedBlock) -> Result<Vec<PeerId>, StartupError> {
    let genesis = iroha_genesis::GenesisBlock(genesis.clone());
    let validators = schedule::genesis_validators(&genesis)
        .map_err(|error| StartupError::Schedule(error.to_string()))?;
    let committee = schedule::genesis_committee(&genesis)
        .map_err(|error| StartupError::Schedule(error.to_string()))?;
    let mut peers = validators.into_keys().collect::<Vec<_>>();
    peers.sort_by_key(|peer| {
        schedule::consensus_key(peer)
            .ok()
            .and_then(|key| committee.index_of(&key))
    });
    Ok(peers)
}

/// The height the state has applied.
#[must_use]
pub fn applied_height(state: &State) -> u64 {
    state.view().height() as u64
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        isi::{
            InstructionBox, RegisterBox,
            register::{RegisterCommitteePeerWithPop, RegisterPeerWithPop},
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_genesis::GenesisBlock;

    use super::*;

    fn bls(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).expect("BLS fixture key")
    }

    fn peer(pair: &KeyPair) -> PeerId {
        PeerId::new(pair.public_key().clone())
    }

    fn pop(pair: &KeyPair) -> Vec<u8> {
        iroha_crypto::bls_normal_pop_prove(pair.private_key()).expect("PoP fixture")
    }

    fn genesis_with(instructions: Vec<InstructionBox>) -> SignedBlock {
        let genesis_key = KeyPair::random();
        let account = AccountId::new(genesis_key.public_key().clone());
        let transaction =
            TransactionBuilder::new_genesis(account, FeePaymentIntent::authority(Vec::new(), None))
                .with_instructions(instructions)
                .sign(genesis_key.private_key());
        SignedBlock::genesis(vec![transaction], genesis_key.private_key(), None, None)
    }

    /// Every caller of the removed `signed_genesis_voting_peers` (kagami, irohad, the test
    /// network, the beacon tools) now reads `schedule::genesis_validators` or
    /// `genesis_committee_peers`; both must yield the exact order it did: the signed validators in
    /// canonical `PeerId` order, independent of registration order, without committee-only peers.
    #[test]
    fn genesis_roster_order_is_canonical_and_identical_for_every_reader() {
        let validators = [7_u8, 3, 5, 1, 6, 2, 4].map(bls);
        let committee_only = bls(9);
        let mut instructions: Vec<InstructionBox> = validators
            .iter()
            .map(|pair| {
                InstructionBox::from(RegisterBox::Peer(RegisterPeerWithPop::new(
                    peer(pair),
                    pop(pair),
                )))
            })
            .collect();
        instructions.push(InstructionBox::from(RegisterCommitteePeerWithPop::new(
            peer(&committee_only),
            pop(&committee_only),
        )));
        let genesis = genesis_with(instructions);

        let mut expected = validators.iter().map(peer).collect::<Vec<_>>();
        expected.sort();
        let signed = schedule::genesis_validators(&GenesisBlock(genesis.clone()))
            .expect("signed validators")
            .into_keys()
            .collect::<Vec<_>>();
        assert_eq!(
            signed, expected,
            "signed validators in canonical PeerId order"
        );
        assert!(!signed.contains(&peer(&committee_only)));

        let committee_peers = genesis_committee_peers(&genesis).expect("genesis committee");
        assert_eq!(
            committee_peers, signed,
            "the node's committee order equals the signed-genesis roster order"
        );
        let committee =
            schedule::genesis_committee(&GenesisBlock(genesis)).expect("core committee");
        for (position, member) in committee_peers.iter().enumerate() {
            let key = schedule::consensus_key(member).expect("BLS consensus key");
            assert_eq!(
                committee.index_of(&key).map(|index| index as usize),
                Some(position),
                "the core committee indexes the roster in the same order"
            );
        }
    }

    #[test]
    fn genesis_committee_peers_reject_a_genesis_without_validators() {
        let genesis = genesis_with(Vec::new());
        assert!(matches!(
            genesis_committee_peers(&genesis),
            Err(StartupError::Schedule(_))
        ));
    }
}
