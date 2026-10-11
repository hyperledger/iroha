//! The execution result `R` of a block (`specs/sumeragi.md` §4.1; option R1 of the integration
//! plan): `R = H("iroha/sumeragi/result/v1" ‖ norito(ExecutionResultCommitment))`, where `H` is
//! the chain hash (`iroha_crypto::Hash`) and `norito(·)` the canonical Norito frame.
//!
//! [`ExecutionResultCommitment`] binds:
//! - the [`ExecutionCommitment`]: the complete World state roots before and after the block's
//!   execution and the Merkle commitment of the events it emitted ([`WorldStateTransition`]),
//!   the witnessed pre- and post-state roots, the ordinary-write root, the exact result-bearing
//!   block wire (length and hash; it carries every
//!   transaction result and trigger output) and the network-input and typed-output Merkle
//!   commitments;
//! - the exact current native epoch and complete successor schedule, retaining every ordered
//!   BLS key, original PoP, validator generation and epoch authorization;
//! - the mandatory complete lane-context set proof against the exact ordinary-write root;
//! - the finalized beacon pulse consumed by execution and the atomic epoch-boundary decision.
//!   Chain parameters retain lag two; authority beyond a boundary stays unavailable until that
//!   boundary is certified and applied (§10.1, [`super::schedule`]).
//!
//! The canonical preimage is stored as `CommitCertificate.result_preimage` next to the block, so a
//! proof (§11) can disclose it and anyone can re-hash it
//! ([`result_of_preimage`]).
//!
//! The World state roots are roots of the complete World state accumulator
//! (`crate::state::world_projection::WorldStateAccumulator`, Appendix E, E51): a homomorphic
//! multiset hash over every canonical World entry, updated from the block's complete change set,
//! so divergence in any World state (roles, permissions, peers, parameters, triggers, ...)
//! changes `R` at the block that causes it. The witnessed roots stay: the ordinary-write root
//! carries the per-key sparse-Merkle proofs of a block's writes (§11).
//!
//! Every function here is pure and deterministic: the inputs are the execution witness, the
//! executed block, the World state transition and the scheduled configuration; no clock, no
//! node configuration and no hash-map iteration order enter `R`. Each sparse Merkle tree is
//! built once per block.
//! The shared result codec and complete epoch graph are owned by
//! [`iroha_data_model::sumeragi_finality`]; this module produces those canonical values from
//! Core's execution witnesses and retained schedule without defining a parallel wire layout.

use iroha_crypto::{Hash, HashOf, MerkleTree, MerkleTreeCommitment};
use iroha_data_model::{
    block::{SignedBlock, consensus::ExecWitness},
    events::EventBox,
    sumeragi_finality::MAX_EXECUTED_BLOCK_WIRE_BYTES,
};
#[cfg(test)]
use iroha_data_model::{
    consensus::FinalizedGlobalThresholdBeaconPulseV1, parameter::system::ConsensusMode,
};
#[cfg(test)]
use iroha_sumeragi::types::Hash32;
#[cfg(test)]
use norito::NoritoDeserialize;
use norito::NoritoSerialize;
use thiserror::Error;

use super::schedule::NativeExecutionInputs;
#[cfg(test)]
use super::schedule::ScheduleOutcome;
use crate::exec_witness::{
    roots::{parent_state_from_witness, witness_pairs},
    smt::compute_post_state_root,
};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError, RetainedPayload};
use iroha_data_model::sumeragi_finality::NativeLaneStateProof;

pub use iroha_data_model::sumeragi_finality::{
    CommitmentError, ExecutionCommitment, ExecutionResultCommitment, MAX_RESULT_PREIMAGE_BYTES,
    RESULT_TAG, chain_hash, result_of_preimage,
};

/// The complete-World part of one block's execution (`specs/sumeragi.md` §4.1, Appendix E,
/// E51), produced by the State that executed the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldStateTransition {
    /// Complete World state root the block executed on (the empty World for genesis).
    pub parent_world_state_root: Hash,
    /// Complete World state root after the block's execution.
    pub world_state_root: Hash,
    /// Merkle root and count of the events the execution emitted, in emission order.
    pub event_commitment: Option<MerkleTreeCommitment<EventBox>>,
}

/// The event commitment of a block's emitted events, in emission order: the Merkle root over
/// the hashes of their canonical Norito encodings and their count; `None` without events.
///
/// # Errors
/// The event count exceeds `u64` or the Merkle frontier cannot represent it.
pub fn event_commitment(
    events: &[EventBox],
) -> Result<Option<MerkleTreeCommitment<EventBox>>, CommitmentError> {
    let count = u64::try_from(events.len())
        .map_err(|_| CommitmentError::Encoding("event count exceeds u64".into()))?;
    let Some(count) = core::num::NonZeroU64::new(count) else {
        return Ok(None);
    };
    let root = MerkleTree::<EventBox>::root_from_typed_leaves(events.iter().map(HashOf::new))
        .ok_or_else(|| CommitmentError::Encoding("event Merkle root overflow".into()))?;
    Ok(Some(MerkleTreeCommitment::new(root, count)))
}

/// The execution commitment of `executed` (the result-bearing block, without a certificate)
/// whose execution produced `witness` and the World state `transition`.
///
/// # Errors
/// See [`CommitmentError`].
pub fn execution_commitment(
    witness: &ExecWitness,
    executed: &SignedBlock,
    transition: &WorldStateTransition,
) -> Result<ExecutionCommitment, CommitmentError> {
    if !executed.has_results() {
        return Err(CommitmentError::MissingResult);
    }
    if executed.commit_certificate().is_some() {
        return Err(CommitmentError::CertifiedBlock);
    }
    executed
        .validate_output_merkle_cache()
        .map_err(|error| CommitmentError::InvalidOutputs(error.to_string()))?;
    // The certificate was refused above, so this complete stored-frame identity is exactly
    // the result-bearing wire R authenticates. Stream its original graph instead of creating
    // uncharged payload and frame buffers solely to count and hash their bytes.
    let (executed_block_wire_len, executed_block_wire_hash) = executed
        .canonical_wire_identity()
        .map_err(|error| CommitmentError::Encoding(error.to_string()))?;
    if executed_block_wire_len == 0 || executed_block_wire_len > MAX_EXECUTED_BLOCK_WIRE_BYTES {
        return Err(CommitmentError::WireLength(executed_block_wire_len));
    }
    // One tree per root: the witnessed writes (or, for a read-only block, reads) and the
    // pre-values of the written keys.
    let (reads, writes) = witness_pairs(witness);
    let witnessed_root = compute_post_state_root(&reads, &writes);
    let ordinary_writes_root = if writes.is_empty() {
        compute_post_state_root(&[], &[])
    } else {
        witnessed_root
    };
    let parent_state_root = parent_state_from_witness(witness);
    Ok(ExecutionCommitment {
        parent_state_root,
        post_state_root: witnessed_root,
        ordinary_writes_root,
        parent_world_state_root: transition.parent_world_state_root,
        world_state_root: transition.world_state_root,
        event_commitment: transition.event_commitment,
        executed_block_wire_len,
        executed_block_wire_hash,
        transaction_input_commitment: executed.network_input_merkle_commitment(),
        transaction_output_commitment: executed.output_merkle_commitment(),
    })
}

/// `R` of an executed block bound to its complete native schedule and finalized pulse.
/// The returned owner retains the original execution inputs. Encode only after storing this
/// owner beside the original overlay, so resource refusal retries encoding without execution.
///
/// # Errors
/// See [`CommitmentError`].
#[allow(unsafe_code)]
pub(crate) fn execution_result(
    witness: &mut crate::state::CapturedExecWitness,
    executed: &SignedBlock,
    transition: &WorldStateTransition,
    inputs: RetainedPayload<NativeExecutionInputs>,
    native_lanes: NativeLaneStateProof,
) -> Result<RetainedPayload<ExecutionResultCommitment>, CommitmentError> {
    let height = executed.header().height().get();
    let execution = witness.prepare_native_execution(executed, transition)?;
    // SAFETY: only the two original canonical fields move, without clone, growth, sharing or
    // extraction. The new height, slim execution commitment and fixed context proof contain
    // no owned allocations.
    // The original allocation ledger follows the whole R owner through publication and drop.
    let commitment = unsafe {
        inputs.map_payload(|inputs| ExecutionResultCommitment {
            height,
            execution,
            schedule: inputs.schedule,
            beacon: inputs.beacon,
            native_lanes,
        })
    };
    commitment.get().validate()?;
    if commitment.get().beacon.as_ref().is_some_and(|pulse| {
        Some(pulse.finalized_chain_anchor.block_hash) != executed.header().prev_block_hash()
    }) {
        return Err(CommitmentError::Beacon(
            "pulse anchor differs from executed parent".into(),
        ));
    }
    Ok(commitment)
}

/// A result preimage could not be encoded; resource refusal is local and preserves the result.
/// Callers must never turn a finite-pool refusal into a deterministic invalid-block verdict.
#[derive(Debug, Error)]
pub enum ResultPreimageError {
    /// Encoding was offered a different pool than the retained original result allocations.
    #[error("result preimage budget differs from original execution source")]
    ForeignBudget,
    /// The canonical preimage exceeds the fixed protocol bound.
    #[error("result preimage exceeds its byte bound: {0}")]
    PreimageLength(usize),
    /// Original-pool admission or allocator refusal; retains its exact typed release hint.
    #[error("result preimage allocation: {0}")]
    Allocation(#[from] ChargedBufferError),
    /// A canonical serializer or bounded writer failed; no partial output is returned.
    #[error("result preimage encoding: {0}")]
    Encoding(#[from] norito::Error),
}

impl ResultPreimageError {
    /// Whether retrying this same immutable result after local capacity/allocator recovery is safe.
    /// Source, protocol-size and serializer errors require correction instead of an encoding loop.
    #[must_use]
    pub const fn is_local_refusal(&self) -> bool {
        matches!(self, Self::Allocation(_))
    }
}

/// Encode into one exactly admitted original-pool allocation while borrowing the retained R.
/// Both success and refusal leave the original R and its ledger with the caller. The returned
/// buffer must stay owned until the actual final certificate bytes are destroyed; copying or
/// extracting it into an uncharged certificate does not transfer that custody.
///
/// The canonical nonpacked layout streams this fixed record graph, its byte/element sequences,
/// public keys and borrowed bounded numeric fields. The root schema identity is a static literal.
/// No output-sized staging Vec or copied epoch graph is constructed.
///
/// # Errors
/// Returns a source mismatch, protocol bound, exact original-pool refusal or codec failure.
/// The caller must retain its original executed block and overlay when retrying allocation.
pub(crate) fn encode_result_preimage(
    commitment: &RetainedPayload<ExecutionResultCommitment>,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<u8>, ResultPreimageError> {
    if !commitment.belongs_to(budget) {
        return Err(ResultPreimageError::ForeignBudget);
    }
    encode_canonical_part(commitment.get(), budget, MAX_RESULT_PREIMAGE_BYTES)
}

/// An immutable consensus artifact whose canonical frame is carried by a certificate.
/// This selects a writer only: no alternate layout, decoder or storage tag is introduced.
pub(crate) enum CertificatePart<'a> {
    /// Complete context-bound block header.
    Header(&'a iroha_sumeragi::message::BlockHeader),
    /// Complete context-bound exact-quorum receipt.
    Qc(&'a iroha_sumeragi::message::Qc),
    /// Complete original signed-availability frame; never re-signed at publication.
    Availability(&'a iroha_sumeragi::availability::AvailabilityFrame),
}

/// Count and encode a certificate header, QC or original availability frame into exact original-pool backing.
/// The supplied protocol bound is checked before any output allocation. The caller retains
/// earlier successfully encoded parts across a later refusal; no result preimage is copied.
///
/// # Errors
/// Returns a protocol-size, original-pool admission/allocator or canonical encoding failure.
pub(crate) fn encode_certificate_part(
    part: CertificatePart<'_>,
    budget: &AllocationBudget,
    max_bytes: usize,
) -> Result<ChargedBuffer<u8>, ResultPreimageError> {
    match part {
        CertificatePart::Header(value) => {
            encode_canonical_part(&HeaderFrame(value), budget, max_bytes)
        }
        CertificatePart::Qc(value) => encode_canonical_part(&QcFrame(value), budget, max_bytes),
        CertificatePart::Availability(value) => encode_canonical_part(value, budget, max_bytes),
    }
}

// These writer-only borrows preserve the declared canonical frame identities while avoiding
// allocating schema-name Strings. All payload serialization remains owned by the core types.
struct HeaderFrame<'a>(&'a iroha_sumeragi::message::BlockHeader);
struct QcFrame<'a>(&'a iroha_sumeragi::message::Qc);
macro_rules! borrowed_certificate_frame {
    ($name:ident, $identity:literal) => {
        impl norito::core::SerializePayload for $name<'_> {
            fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
                norito::core::SerializePayload::serialize(self.0, out)
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                norito::core::SerializePayload::encoded_len_hint(self.0)
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                norito::core::SerializePayload::encoded_len_exact(self.0)
            }
        }
        impl norito::NoritoSchema for $name<'_> {
            fn nominal_name() -> String {
                $identity.to_owned()
            }
            fn static_frame_name() -> Option<&'static str> {
                Some($identity)
            }
        }
    };
}
borrowed_certificate_frame!(HeaderFrame, "iroha_sumeragi::BlockHeader");
borrowed_certificate_frame!(QcFrame, "iroha_sumeragi::Qc");

fn encode_canonical_part<T: NoritoSerialize>(
    value: &T,
    budget: &AllocationBudget,
    max_bytes: usize,
) -> Result<ChargedBuffer<u8>, ResultPreimageError> {
    let length = norito::canonical_frame_len(value)?;
    if length > max_bytes {
        return Err(ResultPreimageError::PreimageLength(length));
    }
    let mut buffer = ChargedBuffer::new(length, budget)?;
    norito::core::write_canonical_to_writer(value, &mut ResultPreimageWriter(&mut buffer))?;
    if buffer.as_slice().len() != length {
        return Err(ResultPreimageError::Encoding(norito::Error::LengthMismatch));
    }
    Ok(buffer)
}

/// Fixed-capacity destination which cannot replace or grow its charged allocation.
struct ResultPreimageWriter<'a>(&'a mut ChargedBuffer<u8>);
impl std::io::Write for ResultPreimageWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::ValidBlock,
        sumeragi::{
            crypto::{BlsCrypto, core_key},
            schedule::{ChainParamsRecord, ScheduledConfig, ScheduledSlot},
        },
    };
    use iroha_crypto::{Algorithm, KeyPair, PublicKey, bls_normal_pop_prove};
    use iroha_data_model::{
        NetworkId,
        block::{BlockHeader, consensus::ExecKv},
        sumeragi::epoch::{ValidatorCommitteeMemberV1, ValidatorEpochContextV1},
        sumeragi::epoch::{ValidatorEpochAuthorizationV1, ValidatorGenerationV1},
    };
    use iroha_model_base::peer::PeerId;
    use iroha_sumeragi::types::ChainParams;
    fn kv(key: &str, value: &str) -> ExecKv {
        ExecKv {
            key: key.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    fn transition() -> WorldStateTransition {
        WorldStateTransition {
            parent_world_state_root: Hash::new(b"parent world"),
            world_state_root: Hash::new(b"world"),
            event_commitment: None,
        }
    }

    fn witness(reads: Vec<ExecKv>, writes: Vec<ExecKv>) -> ExecWitness {
        ExecWitness {
            reads,
            writes,
            fastpq_transcripts: Vec::new(),
            fastpq_batches: Vec::new(),
        }
    }

    fn sample_witness() -> ExecWitness {
        witness(
            vec![kv("balance/alice", "10"), kv("balance/bob", "3")],
            vec![kv("balance/alice", "7"), kv("balance/bob", "6")],
        )
    }

    fn executed(key: &KeyPair) -> SignedBlock {
        ValidBlock::new_dummy(key.private_key()).into()
    }

    fn with_context_write(
        mut witness: ExecWitness,
        network: NetworkId,
        height: u64,
    ) -> ExecWitness {
        let contexts = iroha_data_model::sumeragi_lanes::SumeragiLaneState::default();
        let commitment =
            iroha_data_model::sumeragi_finality::SumeragiLaneStateCommitment::from_state(
                network, height, &contexts,
            )
            .unwrap();
        witness.writes.push(ExecKv {
            key: iroha_data_model::sumeragi_finality::SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
            value: norito::encode_canonical(&commitment).unwrap(),
        });
        witness
    }

    fn context_proof(witness: &ExecWitness) -> NativeLaneStateProof {
        let budget = AllocationBudget::new(1024 * 1024);
        NativeLaneStateProof::from_witness(witness, &budget).unwrap()
    }

    fn result_for_test(
        witness: &ExecWitness,
        executed: &SignedBlock,
        schedule: ScheduleOutcome,
        beacon: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    ) -> Result<(ExecutionResultCommitment, Vec<u8>, Hash32), CommitmentError> {
        let height = executed.header().height().get();
        let witness = with_context_write(witness.clone(), schedule.current.network_id, height);
        let native_lanes = context_proof(&witness);
        let commitment = ExecutionResultCommitment::new(
            height,
            execution_commitment(&witness, executed, &transition())?,
            schedule,
            beacon,
            native_lanes,
        )?;
        let preimage = commitment.preimage()?;
        let result = result_of_preimage(&preimage);
        Ok((commitment, preimage, result))
    }

    fn members(bytes: &[u8]) -> Vec<(PublicKey, Vec<u8>)> {
        let mut members = bytes
            .iter()
            .map(|byte| {
                let key = KeyPair::from_seed(vec![*byte; 32], Algorithm::BlsNormal);
                (
                    key.public_key().clone(),
                    bls_normal_pop_prove(key.private_key()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|(key, _)| core_key(key).unwrap());
        members
    }

    fn epoch(bytes: &[u8]) -> ValidatorEpochContextV1 {
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"commitment fixture",
            )),
        );
        let committee = members(bytes)
            .into_iter()
            .map(|(key, pop)| ValidatorCommitteeMemberV1 {
                validator: PeerId::new(key),
                proof_of_possession: pop,
            })
            .collect::<Vec<_>>();
        let generation = ValidatorGenerationV1::from_committee(network_id, 0, &committee);
        let authorization = ValidatorEpochAuthorizationV1::genesis(&generation, u64::MAX).unwrap();
        ValidatorEpochContextV1 {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            version: 1,
            network_id,
            mode: ConsensusMode::Permissioned,
            authorization,
            committee,
            leader_seed: [0x31; 32],
        }
    }

    fn outcome(current: ValidatorEpochContextV1) -> ScheduleOutcome {
        let params = ChainParamsRecord::from_core(&ChainParams::default());
        ScheduleOutcome {
            height: 2,
            current: current.clone(),
            boundary: None,
            next: ScheduledSlot::Ready(ScheduledConfig {
                height: 3,
                epoch: current.clone(),
                params,
            }),
            after_next: ScheduledSlot::Ready(ScheduledConfig {
                height: 4,
                epoch: current,
                params,
            }),
        }
    }
    fn next() -> ScheduleOutcome {
        outcome(epoch(&[1, 2, 3, 4]))
    }

    #[test]
    fn result_is_deterministic_across_independent_computations() {
        let block = executed(&KeyPair::random());
        let (first, preimage, result) =
            result_for_test(&sample_witness(), &block.clone(), next(), None).unwrap();
        let (second, second_preimage, second_result) =
            result_for_test(&sample_witness(), &block, next(), None).unwrap();
        assert_eq!(first, second);
        assert_eq!(preimage, second_preimage);
        assert_eq!(result, second_result);
        assert_eq!(result_of_preimage(&preimage), result);
        assert_eq!(first.result().unwrap(), result);
        assert_eq!(ExecutionResultCommitment::decode(&preimage).unwrap(), first);
        assert!(ExecutionResultCommitment::decode(&preimage[1..]).is_err());
        assert_eq!(result.0[31] & 1, 1);
    }

    #[test]
    fn witness_order_and_incidental_reads_do_not_change_r() {
        let block = executed(&KeyPair::random());
        let reordered = witness(
            vec![kv("balance/bob", "3"), kv("balance/alice", "10")],
            vec![kv("balance/bob", "6"), kv("balance/alice", "7")],
        );
        let incidental = witness(
            vec![
                kv("balance/alice", "10"),
                kv("balance/bob", "3"),
                kv("permission-cache", "hit"),
            ],
            sample_witness().writes,
        );
        let base = result_for_test(&sample_witness(), &block, next(), None)
            .unwrap()
            .2;
        assert_eq!(
            result_for_test(&reordered, &block, next(), None).unwrap().2,
            base
        );
        assert_eq!(
            result_for_test(&incidental, &block, next(), None)
                .unwrap()
                .2,
            base
        );
    }

    #[test]
    fn every_bound_input_changes_r() {
        let block = executed(&KeyPair::random());
        let r_of = |witness: &ExecWitness, block: &SignedBlock, next: ScheduleOutcome| {
            result_for_test(witness, block, next, None).unwrap().2
        };
        let base = r_of(&sample_witness(), &block, next());
        let mut write = sample_witness();
        write.writes[0].value = b"8".to_vec();
        assert_ne!(r_of(&write, &block, next()), base);
        let mut read = sample_witness();
        read.reads[1].value = b"4".to_vec();
        assert_ne!(r_of(&read, &block, next()), base);
        let mut other = block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection");
        other
            .set_execution_outputs(
                Vec::new(),
                1,
                Default::default(),
                Vec::new(),
                Default::default(),
                Default::default(),
                &crate::execution_output_test_support::structural_output_limits(),
            )
            .unwrap();
        assert_eq!(other.hash(), block.hash());
        assert_ne!(r_of(&sample_witness(), &other, next()), base);
        assert_ne!(
            r_of(&sample_witness(), &executed(&KeyPair::random()), next()),
            base
        );
        assert_ne!(
            r_of(&sample_witness(), &block, outcome(epoch(&[1, 2, 3, 5]))),
            base
        );
        let mut seed = epoch(&[1, 2, 3, 4]);
        seed.leader_seed[0] ^= 1;
        assert_ne!(r_of(&sample_witness(), &block, outcome(seed)), base);
        let params = ChainParams::default();
        for changed in [
            ChainParams {
                block_time: params.block_time + 1,
                ..params
            },
            ChainParams {
                payload_retry_interval: params.payload_retry_interval + 1,
                ..params
            },
            ChainParams {
                e_max: params.e_max + 1,
                ..params
            },
            ChainParams {
                a_max: params.a_max + 1,
                ..params
            },
            ChainParams {
                max_block_bytes: params.max_block_bytes - 1,
                ..params
            },
            ChainParams {
                epoch_length: params.epoch_length + 1,
                ..params
            },
        ] {
            let mut config = next();
            let ScheduledSlot::Ready(after) = &mut config.after_next else {
                unreachable!()
            };
            after.params = ChainParamsRecord::from_core(&changed);
            assert_ne!(r_of(&sample_witness(), &block, config), base, "{changed:?}");
        }
    }

    #[test]
    fn complete_context_rejects_missing_reordered_or_forged_material() {
        let context = epoch(&[1, 2, 3, 4]);
        let crypto = BlsCrypto::new();
        let admit = |context: &ValidatorEpochContextV1, crypto: &BlsCrypto| -> Result<(), String> {
            context.validate()?;
            crypto
                .admit_committee(context.committee.iter().map(|member| {
                    (
                        member.validator.public_key(),
                        member.proof_of_possession.as_slice(),
                    )
                }))
                .map_err(|(_, error)| error.to_string())?;
            Ok(())
        };
        admit(&context, &crypto).unwrap();
        assert_eq!(crypto.admitted_len(), 4);
        let frame = norito::encode_canonical(&context).unwrap();
        assert_eq!(
            norito::decode_canonical::<ValidatorEpochContextV1>(&frame).unwrap(),
            context
        );
        for mutation in 0..8 {
            let mut invalid = context.clone();
            match mutation {
                0 => invalid.committee.swap(0, 1),
                1 => invalid.committee[1] = invalid.committee[0].clone(),
                2 => {
                    invalid.committee.pop();
                }
                3 => invalid.committee[0].proof_of_possession.clear(),
                4 => invalid.committee[0].proof_of_possession[0] ^= 1,
                5 => {
                    invalid.committee[0].proof_of_possession =
                        invalid.committee[1].proof_of_possession.clone()
                }
                6 => invalid.authorization.authority_generation += 1,
                _ => invalid.authorization.authority_id[0] ^= 1,
            }
            let fresh = BlsCrypto::new();
            assert!(admit(&invalid, &fresh).is_err());
            assert_eq!(fresh.admitted_len(), 0, "admission remains all-or-nothing");
            assert!(
                admit(&invalid, &crypto).is_err(),
                "admitted keys cannot mask changed proofs"
            );
        }
        for count in [1usize, 3, 5, 32, 34] {
            let mut invalid = context.clone();
            invalid.committee = vec![context.committee[0].clone(); count];
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn result_requires_exact_context_graph_and_bounded_preimage() {
        let block = executed(&KeyPair::random());
        let (valid, preimage, _) =
            result_for_test(&sample_witness(), &block, next(), None).unwrap();
        assert_eq!(valid.schedule, next());
        assert_eq!(ExecutionResultCommitment::decode(&preimage).unwrap(), valid);
        for mutation in 0..5 {
            let mut invalid = valid.clone();
            match mutation {
                0 => invalid.height += 1,
                1 => invalid.schedule.current.committee[0].proof_of_possession[0] ^= 1,
                2 => {
                    invalid.schedule.current.committee.pop();
                }
                3 => invalid.schedule.current.leader_seed[0] ^= 1,
                _ => {
                    let ScheduledSlot::Ready(next) = &mut invalid.schedule.next else {
                        unreachable!()
                    };
                    next.height += 1;
                }
            }
            if matches!(mutation, 1..=3) {
                assert!(matches!(
                    norito::encode_canonical(&invalid),
                    Err(norito::Error::NonCanonicalEncoding)
                ));
            } else {
                assert!(
                    ExecutionResultCommitment::decode(&norito::encode_canonical(&invalid).unwrap())
                        .is_err()
                );
            }
        }
        assert_eq!(
            ExecutionResultCommitment::decode(&vec![0; MAX_RESULT_PREIMAGE_BYTES + 1]),
            Err(CommitmentError::PreimageLength(
                MAX_RESULT_PREIMAGE_BYTES + 1
            ))
        );
        let mut wide = valid.clone();
        wide.schedule.current.committee = vec![valid.schedule.current.committee[0].clone(); 97];
        // Keep the omitted epochs equal to their source so these probes reach decoder limits,
        // rather than the projection's earlier contradictory-graph rejection.
        let repeat_current = |value: &mut ExecutionResultCommitment| {
            for slot in [&mut value.schedule.next, &mut value.schedule.after_next] {
                let ScheduledSlot::Ready(config) = slot else {
                    unreachable!()
                };
                config.epoch = value.schedule.current.clone();
            }
        };
        repeat_current(&mut wide);
        let frame = norito::encode_canonical(&wide).unwrap();
        assert!(frame.len() < MAX_RESULT_PREIMAGE_BYTES);
        assert!(matches!(
            ExecutionResultCommitment::decode(&frame),
            Err(CommitmentError::Encoding(_))
        ));
        let mut long = valid.clone();
        long.schedule.current.committee[0]
            .proof_of_possession
            .push(0);
        repeat_current(&mut long);
        assert!(matches!(
            ExecutionResultCommitment::decode(&norito::encode_canonical(&long).unwrap()),
            Err(CommitmentError::Encoding(_))
        ));
        let mut huge = valid;
        huge.schedule.current.committee[0].proof_of_possession = vec![0; MAX_RESULT_PREIMAGE_BYTES];
        repeat_current(&mut huge);
        assert!(matches!(
            huge.preimage(),
            Err(CommitmentError::PreimageLength(_))
        ));
    }

    #[test]
    fn maximal_boundary_and_frozen_preparation_fit_the_preimage_bound() {
        use iroha_data_model::sumeragi::epoch::{
            BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochDecisionV1,
        };
        use iroha_data_model::{
            nexus::{ValidatorCommitteePreparationV1, ValidatorElectionPolicyV1},
            parameter::system::SumeragiNposParameters,
            sumeragi::epoch::ValidatorEpochBoundaryV1,
        };
        let mut current = epoch(&(1..=31u8).collect::<Vec<_>>());
        current.mode = ConsensusMode::Npos;
        current.authorization.last_height = 6;
        let mut next = current.clone();
        next.authorization = ValidatorEpochAuthorizationV1 {
            version: 1,
            network_id: current.network_id,
            epoch: current.authorization.epoch + 1,
            first_height: current.authorization.last_height + 1,
            last_height: 12,
            authority_generation: current.authorization.authority_generation,
            authority_id: current.generation().generation_id().unwrap(),
            beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                session_id: [0x41; 32],
                transcript_hash: [0x42; 32],
            }),
            previous_authorization_id: current.authorization.authorization_id().unwrap(),
            transition_id: [0; 32],
            decision: ValidatorEpochDecisionV1::Retain,
        };
        next.leader_seed = [0x32; 32];
        next.validate_successor(&current).unwrap();
        let mut policy = SumeragiNposParameters::default();
        policy.max_validators = 31;
        policy.epoch_length_blocks = std::num::NonZeroU64::new(6).unwrap();
        policy.evidence_horizon_blocks = 6;
        policy.slashing_delay_blocks = 6;
        let anchor =
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"bounded boundary anchor"));
        let preparation = ValidatorCommitteePreparationV1 {
            version: 1,
            network_id: current.network_id,
            selection_epoch: 0,
            selection_height: 6,
            selection_anchor: anchor,
            target_epoch: 2,
            first_height: 13,
            last_height: 18,
            authority_generation: 1,
            preparing_authorization_id: next.authorization.authorization_id().unwrap(),
            election_seed: [0x43; 32],
            eligibility: ValidatorElectionPolicyV1::from_npos_parameters(&policy).unwrap(),
            committee: current.committee.clone(),
        };
        let params = ChainParamsRecord::from_core(&ChainParams::default());
        let graph = ScheduleOutcome {
            height: 6,
            current: current.clone(),
            boundary: Some(ValidatorEpochBoundaryV1 {
                version: 1,
                height: 6,
                predecessor_context_id: current.context_id().unwrap(),
                selection_anchor: anchor,
                next: next.clone(),
                preparation: Some(preparation),
            }),
            next: ScheduledSlot::Ready(ScheduledConfig {
                height: 7,
                epoch: next.clone(),
                params,
            }),
            after_next: ScheduledSlot::Ready(ScheduledConfig {
                height: 8,
                epoch: next,
                params,
            }),
        };
        let block = executed(&KeyPair::random());
        let witness = with_context_write(sample_witness(), graph.current.network_id, 6);
        let value = ExecutionResultCommitment::new(
            6,
            execution_commitment(&witness, &block, &transition()).unwrap(),
            graph,
            None,
            context_proof(&witness),
        )
        .unwrap();
        let bytes = value
            .preimage()
            .expect("maximal valid graph fits protocol bound");
        assert!(bytes.len() <= MAX_RESULT_PREIMAGE_BYTES);
        assert_eq!(ExecutionResultCommitment::decode(&bytes).unwrap(), value);
    }

    /// Encoding-only fixture with no dynamic payload allocations. Its empty roster deliberately
    /// grants no signing authority; production first validates the real graph in execution_result.
    #[allow(unsafe_code)]
    fn allocation_free_encoding_owner(
        budget: &AllocationBudget,
    ) -> RetainedPayload<ExecutionResultCommitment> {
        let mut current = epoch(&[1, 2, 3, 4]);
        current.committee = Vec::new();
        let witness = with_context_write(sample_witness(), current.network_id, 2);
        let execution =
            execution_commitment(&witness, &executed(&KeyPair::random()), &transition()).unwrap();
        let value = ExecutionResultCommitment {
            height: 2,
            execution,
            schedule: outcome(current),
            beacon: None,
            native_lanes: context_proof(&witness),
        };
        let ledger = ChargedBuffer::new(0, budget).unwrap();
        // SAFETY: every Vec in this encoding-only payload has zero capacity; every remaining
        // field is fixed scalar/array storage. There are no dynamic payload allocations to fund.
        match unsafe { RetainedPayload::try_new(value, ledger, budget) } {
            Ok(owner) => owner,
            Err(_) => panic!("empty exact-source ledger"),
        }
    }

    #[test]
    fn charged_preimage_matches_canonical_bytes_and_releases_only_its_actual_buffer() {
        let budget = AllocationBudget::new(MAX_RESULT_PREIMAGE_BYTES);
        let owner = allocation_free_encoding_owner(&budget);
        let before = budget.reserved_bytes();
        let expected = owner.get().preimage().unwrap();
        let output = encode_result_preimage(&owner, &budget.clone()).unwrap();
        assert_eq!(output.as_slice(), expected.as_slice());
        assert_eq!(
            result_of_preimage(output.as_slice()),
            owner.get().result().unwrap()
        );
        assert!(output.belongs_to(&budget));
        assert_eq!(output.capacity(), expected.len());
        assert_eq!(budget.reserved_bytes(), before + expected.len());
        drop(output);
        assert_eq!(budget.reserved_bytes(), before);
        assert!(owner.belongs_to(&budget));
    }

    #[test]
    fn preimage_capacity_refusal_retains_the_same_result_for_retry_and_rejects_foreign_pool() {
        let budget = AllocationBudget::new(MAX_RESULT_PREIMAGE_BYTES);
        let owner = allocation_free_encoding_owner(&budget);
        let pointer = std::ptr::from_ref(owner.get());
        let length = norito::canonical_frame_len(owner.get()).unwrap();
        budget.set_limit_bytes(length);
        let occupied = ChargedBuffer::<u8>::new(1, &budget).unwrap();
        assert!(matches!(
            encode_result_preimage(&owner, &budget),
            Err(ResultPreimageError::Allocation(
                ChargedBufferError::Admission(iroha_allocation::AllocationRefusal::Capacity { .. })
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 1);
        assert_eq!(std::ptr::from_ref(owner.get()), pointer);
        let foreign = AllocationBudget::new(length);
        assert!(matches!(
            encode_result_preimage(&owner, &foreign),
            Err(ResultPreimageError::ForeignBudget)
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 1);
        drop(occupied);
        let output = encode_result_preimage(&owner, &budget).unwrap();
        assert_eq!(output.as_slice().len(), length);
        assert_eq!(std::ptr::from_ref(owner.get()), pointer);
        drop(output);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn charged_preimage_writer_refuses_growth_without_partial_append() {
        use std::io::Write as _;
        let budget = AllocationBudget::new(3);
        let mut bytes = ChargedBuffer::new(3, &budget).unwrap();
        {
            let mut writer = ResultPreimageWriter(&mut bytes);
            writer.write_all(&[1, 2]).unwrap();
            assert!(writer.write_all(&[3, 4]).is_err());
            writer.flush().unwrap();
        }
        assert_eq!(bytes.as_slice(), &[1, 2]);
        assert_eq!(budget.reserved_bytes(), 3);
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn digest_only_and_full_committee_retired_result_layouts_are_rejected() {
        #[derive(norito::NoritoSchema, NoritoSerialize, NoritoDeserialize)]
        #[norito_schema(name = "iroha_data_model::sumeragi_finality::ExecutionResultCommitment")]
        struct DigestOnlyResult {
            execution: ExecutionCommitment,
            next_committee_digest: [u8; 32],
            next_params: ChainParamsRecord,
        }
        #[derive(norito::NoritoSchema, NoritoSerialize, NoritoDeserialize)]
        #[norito_schema(name = "iroha_core::sumeragi::commitment::CommitteeMember")]
        struct RetiredMember {
            public_key: PublicKey,
            proof_of_possession: Vec<u8>,
        }
        #[derive(norito::NoritoSchema, NoritoSerialize, NoritoDeserialize)]
        #[norito_schema(name = "iroha_core::sumeragi::commitment::CommitteeAuthority")]
        struct RetiredAuthority {
            members: Vec<RetiredMember>,
        }
        #[derive(norito::NoritoSchema, NoritoSerialize, NoritoDeserialize)]
        #[norito_schema(name = "iroha_data_model::sumeragi_finality::ExecutionResultCommitment")]
        struct FullCommitteeResult {
            execution: ExecutionCommitment,
            next_committee: RetiredAuthority,
            next_params: ChainParamsRecord,
        }
        let execution = execution_commitment(
            &sample_witness(),
            &executed(&KeyPair::random()),
            &transition(),
        )
        .unwrap();
        let params = ChainParamsRecord::from_core(&ChainParams::default());
        let digest = DigestOnlyResult {
            execution,
            next_committee_digest: [3; 32],
            next_params: params,
        };
        let full = FullCommitteeResult {
            execution,
            next_committee: RetiredAuthority {
                members: members(&[1, 2, 3, 4])
                    .into_iter()
                    .map(|(public_key, proof_of_possession)| RetiredMember {
                        public_key,
                        proof_of_possession,
                    })
                    .collect(),
            },
            next_params: params,
        };
        for bytes in [
            norito::encode_canonical(&digest).unwrap(),
            norito::encode_canonical(&full).unwrap(),
        ] {
            assert!(ExecutionResultCommitment::decode(&bytes).is_err());
        }
    }
    #[test]
    fn commitment_binds_the_result_bearing_wire_and_roots() {
        let block = executed(&KeyPair::random());
        let commitment =
            execution_commitment(&sample_witness(), &block, &transition()).expect("commitment");
        let wire = block.encode_wire().expect("wire");
        assert_eq!(commitment.executed_block_wire_hash, Hash::new(&wire));
        assert_eq!(
            commitment.executed_block_wire_len,
            u64::try_from(wire.len()).unwrap()
        );
        assert_eq!(
            commitment.post_state_root,
            crate::exec_witness::roots::post_state_from_witness(&sample_witness())
        );
        assert_eq!(commitment.ordinary_writes_root, commitment.post_state_root);
        assert_eq!(
            commitment.parent_state_root,
            parent_state_from_witness(&sample_witness())
        );
        assert_eq!(
            commitment.transaction_output_commitment,
            block.output_merkle_commitment()
        );
        // A read-only block: the ordinary-write root is the empty tree's.
        let read_only = witness(vec![kv("config", "1")], Vec::new());
        let commitment =
            execution_commitment(&read_only, &block, &transition()).expect("commitment");
        assert_eq!(
            commitment.ordinary_writes_root,
            compute_post_state_root(&[], &[])
        );
        assert_ne!(commitment.post_state_root, commitment.ordinary_writes_root);
    }

    #[test]
    fn execution_commitment_streams_exact_full_wire_without_payload_or_frame_allocation() {
        use crate::test_allocations::allocations_during;

        let key = KeyPair::from_seed(vec![0xA3; 32], Algorithm::BlsNormal);
        let original = executed(&key);
        let empty_witness = witness(Vec::new(), Vec::new());
        let transition = transition();
        let mut previous_identity = None;
        for fragments in [0, 1, 128] {
            // Structural component fixture: no callback or consensus authenticity is inferred.
            // Change a genuine result field while retaining the same proposal and signature.
            let mut block = original
                .canonical_resultless_proposal()
                .expect("original complete proposal");
            block
                .set_execution_outputs(
                    Vec::new(),
                    fragments,
                    Default::default(),
                    Vec::new(),
                    Default::default(),
                    Default::default(),
                    &crate::execution_output_test_support::structural_output_limits(),
                )
                .unwrap();
            assert_eq!(block.hash(), original.hash());
            let original_signature = block
                .signatures()
                .next()
                .expect("actual original BLS signature")
                .signature()
                .payload()
                .as_ptr();
            let original_policy = std::ptr::from_ref(
                block
                    .da_proof_policies()
                    .expect("complete signed DA policy body"),
            );

            // The independently materialized full canonical wire is the comparison oracle,
            // and its actual physical census demonstrates the scratch this producer retires.
            let mut materialized = None;
            let materialized_allocations = allocations_during(|| {
                materialized = Some(block.encode_wire().expect("complete canonical wire"));
            });
            assert!(materialized_allocations >= 2);
            let wire = materialized.unwrap();
            let wire_pointer = wire.as_ptr();
            let expected = (wire.len() as u64, Hash::new(&wire));
            let mut commitment = None;
            let outer_flags = norito::core::header_flags::COMPACT_LEN;
            {
                let _outer_flags = norito::core::DecodeFlagsGuard::enter(outer_flags);
                let actual_allocations = allocations_during(|| {
                    commitment = Some(execution_commitment(&empty_witness, &block, &transition));
                });
                assert_eq!(
                    actual_allocations, 0,
                    "the real production producer must not allocate either complete wire buffer"
                );
                assert_eq!(norito::core::get_decode_flags(), outer_flags);
            }
            let commitment = commitment.unwrap().unwrap();
            let identity = (
                commitment.executed_block_wire_len,
                commitment.executed_block_wire_hash,
            );
            assert_eq!(identity, expected);
            assert_eq!(
                commitment.parent_world_state_root,
                transition.parent_world_state_root
            );
            assert_eq!(commitment.world_state_root, transition.world_state_root);
            assert_eq!(commitment.event_commitment, transition.event_commitment);
            assert_eq!(commitment.parent_state_root, Hash::new([]));
            assert_eq!(commitment.post_state_root, Hash::new([]));
            assert_eq!(commitment.ordinary_writes_root, Hash::new([]));
            assert_eq!(
                commitment.transaction_input_commitment,
                block.network_input_merkle_commitment()
            );
            assert_eq!(
                commitment.transaction_output_commitment,
                block.output_merkle_commitment()
            );
            assert_eq!(wire.as_ptr(), wire_pointer);
            assert_eq!(Hash::new(&wire), expected.1);
            assert_eq!(
                block
                    .signatures()
                    .next()
                    .unwrap()
                    .signature()
                    .payload()
                    .as_ptr(),
                original_signature
            );
            assert_eq!(
                std::ptr::from_ref(block.da_proof_policies().unwrap()),
                original_policy
            );
            assert_eq!(block.committed_fragment_count(), Some(fragments));
            if let Some(previous) = previous_identity {
                assert_ne!(
                    identity.1, previous,
                    "the complete result field participates"
                );
            }
            previous_identity = Some(identity.1);
        }

        // Nonempty execution witnesses and the complete authority/context graph still produce
        // exactly the same R when the independently encoded wire supplies its length and hash.
        let (result, preimage, digest) =
            result_for_test(&sample_witness(), &original, next(), None).unwrap();
        let wire = original.encode_wire().unwrap();
        let mut independent = result.clone();
        independent.execution.executed_block_wire_len = wire.len() as u64;
        independent.execution.executed_block_wire_hash = Hash::new(&wire);
        assert_eq!(independent, result);
        assert_eq!(independent.preimage().unwrap(), preimage);
        assert_eq!(independent.result().unwrap(), digest);
    }

    #[test]
    fn unexecuted_or_certified_blocks_are_refused() {
        let block = executed(&KeyPair::random());
        let proposal = block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection");
        assert_eq!(
            execution_commitment(&sample_witness(), &proposal, &transition()),
            Err(CommitmentError::MissingResult)
        );
        let certified = block.with_commit_certificate(Some(
            iroha_data_model::block::CommitCertificate::from_untrusted_parts(
                vec![1],
                vec![2],
                vec![3],
                vec![4],
            ),
        ));
        assert_eq!(
            execution_commitment(&sample_witness(), &certified, &transition()),
            Err(CommitmentError::CertifiedBlock)
        );
    }

    #[test]
    fn ordinary_write_commitment_binds_exact_last_write_wins_values() {
        // This is an ordinary State commitment control. It grants no separate monetary
        // receipt authenticity and exercises no retired receipt parser or authority policy.
        let block = executed(&KeyPair::random());
        let r_of = |witness: &ExecWitness, block: &SignedBlock, schedule: ScheduleOutcome| {
            result_for_test(witness, block, schedule, None).unwrap().2
        };
        let original = kv("ordinary/balance", "10");
        let changed = kv("ordinary/balance", "7");
        let single = witness(Vec::new(), vec![original.clone()]);
        let duplicate = witness(Vec::new(), vec![original.clone(), original.clone()]);
        let overwritten = witness(Vec::new(), vec![original, changed.clone()]);
        let final_value = witness(Vec::new(), vec![changed]);
        let original_commitment = execution_commitment(&single, &block, &transition()).unwrap();
        assert_eq!(
            execution_commitment(&duplicate, &block, &transition()).unwrap(),
            original_commitment,
            "an identical repeated write retains its exact canonical commitment"
        );
        let changed_commitment = execution_commitment(&overwritten, &block, &transition()).unwrap();
        assert_eq!(
            changed_commitment,
            execution_commitment(&final_value, &block, &transition()).unwrap(),
            "the exact final value owns the canonical last-write-wins root"
        );
        let (reads, writes) = witness_pairs(&overwritten);
        assert_eq!(
            changed_commitment.ordinary_writes_root,
            compute_post_state_root(&reads, &writes)
        );
        assert_ne!(
            changed_commitment.ordinary_writes_root,
            original_commitment.ordinary_writes_root
        );
        assert_eq!(
            r_of(&duplicate, &block, next()),
            r_of(&single, &block, next())
        );
        assert_ne!(
            r_of(&overwritten, &block, next()),
            r_of(&single, &block, next())
        );
        assert_eq!(
            r_of(&overwritten, &block, next()),
            r_of(&final_value, &block, next())
        );
    }

    #[test]
    fn charged_certificate_parts_preserve_core_frames_and_refuse_before_allocation() {
        use iroha_sumeragi::{
            message::{BlockHeader as Header, Qc, VoteKind},
            types::{AggregateSignature, Bitmap, EpochId, SIGNATURE_LEN},
        };
        // Codec and resource fixture only; these bytes grant no consensus authority.
        let epoch = EpochId {
            epoch: 7,
            context: Hash32([9; 32]),
        };
        let header = Header {
            instance: Hash32([1; 32]),
            epoch,
            height: 23,
            origin_view: 4,
            parent_hash: Hash32([2; 32]),
            parent_result: Hash32([3; 32]),
            payload_hash: Hash32([4; 32]),
            availability_digest: Hash32([10; 32]),
            payload_len: 0,
            proposer: 2,
            skipped_leaders: Vec::new(),
            control_witness: iroha_sumeragi::types::ControlWitness::empty(),
        };
        let qc = Qc {
            kind: VoteKind::Commit,
            instance: header.instance,
            epoch,
            height: header.height,
            view: 5,
            block_hash: Hash32([5; 32]),
            result: Hash32([6; 32]),
            signers: Bitmap::from_indices(4, [0, 2, 3]).unwrap(),
            agg_sig: AggregateSignature([7; SIGNATURE_LEN]),
        };
        let expected_header = norito::encode_canonical(&header).unwrap();
        let expected_qc = norito::encode_canonical(&qc).unwrap();
        let budget = AllocationBudget::new(expected_header.len() + expected_qc.len());
        let header_bytes = encode_certificate_part(
            CertificatePart::Header(&header),
            &budget,
            expected_header.len(),
        )
        .unwrap();
        assert_eq!(header_bytes.as_slice(), expected_header);
        assert!(header_bytes.belongs_to(&budget));
        assert!(matches!(
            encode_certificate_part(CertificatePart::Qc(&qc), &budget, expected_qc.len() - 1),
            Err(ResultPreimageError::PreimageLength(_))
        ));
        assert_eq!(budget.reserved_bytes(), expected_header.len());
        let mut occupied = ChargedBuffer::new(1, &budget).unwrap();
        occupied.append(&[0]).unwrap();
        assert!(matches!(
            encode_certificate_part(CertificatePart::Qc(&qc), &budget, expected_qc.len()),
            Err(ResultPreimageError::Allocation(_))
        ));
        drop(occupied);
        let qc_bytes =
            encode_certificate_part(CertificatePart::Qc(&qc), &budget, expected_qc.len()).unwrap();
        assert_eq!(qc_bytes.as_slice(), expected_qc);
        assert!(qc_bytes.belongs_to(&budget));
        assert_eq!(
            norito::schema::identity::frame_hash::<HeaderFrame<'_>>(),
            norito::schema::identity::frame_hash::<Header>()
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<QcFrame<'_>>(),
            norito::schema::identity::frame_hash::<Qc>()
        );
        drop(header_bytes);
        drop(qc_bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn chain_hash_is_the_iroha_hash() {
        assert_eq!(chain_hash(b"x").0, <[u8; 32]>::from(Hash::new(b"x")));
        let mut tagged = RESULT_TAG.to_vec();
        tagged.extend_from_slice(b"p");
        assert_eq!(result_of_preimage(b"p"), chain_hash(&tagged));
    }

    #[test]
    fn event_commitment_is_the_ordered_merkle_root_and_count() {
        use iroha_data_model::events::time::{TimeEvent, TimeInterval};
        let event = |since_ms: u64| {
            EventBox::Time(TimeEvent {
                interval: TimeInterval::new(
                    core::time::Duration::from_millis(since_ms),
                    core::time::Duration::from_millis(1),
                ),
            })
        };
        assert_eq!(event_commitment(&[]).unwrap(), None);
        let events = [event(1), event(2), event(3)];
        let commitment = event_commitment(&events).unwrap().unwrap();
        assert_eq!(commitment.leaf_count().get(), 3);
        let tree: MerkleTree<EventBox> = events.iter().map(HashOf::new).collect();
        assert_eq!(Some(*commitment.root()), tree.root());
        let reordered = [event(2), event(1), event(3)];
        assert_ne!(
            event_commitment(&reordered).unwrap(),
            Some(commitment),
            "emission order is bound"
        );
        assert_ne!(
            event_commitment(&events[..2]).unwrap(),
            Some(commitment),
            "every event is bound"
        );
    }

    #[test]
    fn execution_commitment_binds_the_complete_world_transition() {
        let block = executed(&KeyPair::random());
        let witness = sample_witness();
        let base = transition();
        let bound = execution_commitment(&witness, &block, &base).unwrap();
        assert_eq!(bound.parent_world_state_root, base.parent_world_state_root);
        assert_eq!(bound.world_state_root, base.world_state_root);
        assert_eq!(bound.event_commitment, None);
        for changed in [
            WorldStateTransition {
                parent_world_state_root: Hash::new(b"other parent world"),
                ..base
            },
            WorldStateTransition {
                world_state_root: Hash::new(b"other world"),
                ..base
            },
        ] {
            let other = execution_commitment(&witness, &block, &changed).unwrap();
            assert_ne!(other, bound);
            assert_eq!(
                (other.parent_state_root, other.post_state_root),
                (bound.parent_state_root, bound.post_state_root),
                "the witnessed roots do not see the World outside the witness"
            );
        }
    }
}
