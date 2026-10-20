use super::{
    SignedBlock,
    execution_context::BlockExecutionContextBundle,
    execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
    header::BlockHeader,
};
use crate::{
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, NposConsensusEffects},
    da::{
        commitment::{DaCommitmentBundle, DaProofPolicyBundle},
        pin_intent::DaPinIntentBundle,
    },
    events::data::prelude::AssetBatchTransferOutcome,
    fastpq::TransferTranscript,
    transaction::{
        error::TransactionRejectionReason,
        signed::{SignedTransaction, TransactionEntrypoint, TransactionResult},
    },
    trigger::DataTriggerSequence,
};
use iroha_crypto::{Hash, HashOf, MerkleError, MerkleProof, MerkleTree, MerkleTreeCommitment};
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    vec::Vec,
};
#[model]
mod model {
    use super::*;
    use crate::{consensus::NposConsensusEffects, da::commitment::DaCommitmentBundle};
    /// Core contents of a block.
    #[derive(
        Debug,
        Clone,
        Encode,
        IntoSchema,
        Decode,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(decode_fields)]
    #[allow(clippy::redundant_pub_crate)]
    pub(crate) struct BlockPayload {
        /// Essential metadata for a block in the chain.
        pub header: BlockHeader,
        /// Canonical external transaction entrypoints in consensus order.
        pub external_entrypoints: Vec<TransactionEntrypoint>,
        /// Optional DA commitment bundle embedded in this block.
        #[norito(required)]
        pub da_commitments: Option<DaCommitmentBundle>,
        /// Optional DA proof policy bundle embedded in this block.
        #[norito(required)]
        pub da_proof_policies: Option<DaProofPolicyBundle>,
        /// Optional DA pin intent bundle embedded in this block.
        #[norito(required)]
        pub da_pin_intents: Option<DaPinIntentBundle>,
        /// Deterministic `NPoS` effects embedded in this block.
        #[norito(required)]
        pub npos_consensus_effects: Option<NposConsensusEffects>,
        /// Current finalized threshold pulse, independent of the transaction body.
        #[norito(required)]
        pub global_beacon_pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
        /// Durable execution context for external entrypoints.
        ///
        /// New committed blocks include this context so replay does not need to
        /// re-derive route-dependent execution inputs from the current WSV.
        #[norito(required)]
        pub execution_context: Option<BlockExecutionContextBundle>,
    }
    /// Secondary block state resulting from execution.
    #[derive(
        Debug,
        Clone,
        Default,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct BlockResult {
        /// One full typed output per executed network input or internal invocation.
        pub outputs: Vec<ExecutionOutputV1>,
        /// Checked cache over complete typed output hashes, including source descriptors.
        pub output_merkle: MerkleTree<ExecutionOutputV1>,
        /// Number of successful execution fragments committed while executing this block.
        ///
        /// This includes network inputs, time triggers, and deterministic internal
        /// fragments folded into a block execution result.
        pub committed_fragment_count: u64,
        /// FASTPQ transfer transcripts grouped by exact execution-call hash.
        pub fastpq_transcripts: BTreeMap<Hash, Vec<TransferTranscript>>,
        /// Completed AXT envelopes recorded while executing the block.
        pub axt_envelopes: Vec<crate::nexus::AxtEnvelopeRecord>,
        /// Canonical AXT policy snapshot used while executing the block.
        pub axt_policy_snapshot: crate::nexus::AxtPolicySnapshot,
        /// Dataspaces whose AXT authorization changed at least once during execution.
        ///
        /// This sticky set authenticates transient same-block rotations that the
        /// final policy snapshot alone cannot reconstruct during Kura replay.
        pub axt_transitioned_dataspaces: BTreeSet<iroha_model_base::topology::DataSpaceId>,
    }
}
pub use self::model::{BlockPayload, BlockResult};
impl PartialEq for BlockPayload {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.external_entrypoints == other.external_entrypoints
            && self.execution_context == other.execution_context
            && self.da_commitments == other.da_commitments
            && self.da_proof_policies == other.da_proof_policies
            && self.da_pin_intents == other.da_pin_intents
            && self.npos_consensus_effects == other.npos_consensus_effects
            && self.global_beacon_pulse == other.global_beacon_pulse
    }
}
impl Eq for BlockPayload {}
impl PartialOrd for BlockPayload {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BlockPayload {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_npos_effects_hash = self.npos_consensus_effects.as_ref().map(HashOf::new);
        let other_npos_effects_hash = other.npos_consensus_effects.as_ref().map(HashOf::new);
        let self_pulse_hash = self.global_beacon_pulse.as_ref().map(HashOf::new);
        let other_pulse_hash = other.global_beacon_pulse.as_ref().map(HashOf::new);
        let self_execution_context_hash = self.execution_context.as_ref().map(HashOf::new);
        let other_execution_context_hash = other.execution_context.as_ref().map(HashOf::new);
        (
            &self.header,
            &self.external_entrypoints,
            &self_execution_context_hash,
            &self.da_commitments,
            &self.da_proof_policies,
            &self.da_pin_intents,
            &self_npos_effects_hash,
            &self_pulse_hash,
        )
            .cmp(&(
                &other.header,
                &other.external_entrypoints,
                &other_execution_context_hash,
                &other.da_commitments,
                &other.da_proof_policies,
                &other.da_pin_intents,
                &other_npos_effects_hash,
                &other_pulse_hash,
            ))
    }
}
impl PartialEq for BlockResult {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}
impl Eq for BlockResult {}
impl PartialOrd for BlockResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BlockResult {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.outputs,
            &self.output_merkle,
            &self.committed_fragment_count,
            &self.fastpq_transcripts,
            &self.axt_envelopes,
            &self.axt_policy_snapshot,
            &self.axt_transitioned_dataspaces,
        )
            .cmp(&(
                &other.outputs,
                &other.output_merkle,
                &other.committed_fragment_count,
                &other.fastpq_transcripts,
                &other.axt_envelopes,
                &other.axt_policy_snapshot,
                &other.axt_transitioned_dataspaces,
            ))
    }
}
impl fmt::Display for BlockPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({})", self.header)
    }
}
impl fmt::Display for BlockResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlockResult")
    }
}
impl SignedBlock {
    /// Borrow canonical external entrypoints in execution order.
    #[inline]
    pub fn external_entrypoints_slice(&self) -> &[TransactionEntrypoint] {
        self.payload.external_entrypoints.as_slice()
    }
    /// Number of external entrypoints (signed or authority-free) recorded in the block.
    #[inline]
    pub fn external_entrypoint_count(&self) -> usize {
        self.payload.external_entrypoints.len()
    }
    /// Borrow complete canonical network inputs: the block's external entrypoints in execution
    /// order.
    pub fn network_entrypoints(
        &self,
    ) -> impl ExactSizeIterator<Item = &TransactionEntrypoint> + DoubleEndedIterator {
        self.payload.external_entrypoints.iter()
    }
    /// Number of network input entries.
    pub fn network_entrypoint_count(&self) -> usize {
        self.payload.external_entrypoints.len()
    }
    /// Borrow one network input by canonical index without cloning its body.
    pub fn network_entrypoint_at(&self, index: usize) -> Option<&TransactionEntrypoint> {
        self.payload.external_entrypoints.get(index)
    }
    /// Return error for an OUTPUT index.
    pub fn output_error(&self, tx: usize) -> Option<&TransactionRejectionReason> {
        self.result
            .as_ref()
            .and_then(|result| result.outputs.get(tx))
            .and_then(|output| output.result().as_ref().err())
    }
    /// Block payload. Used for tests
    #[cfg(feature = "transparent_api")]
    pub fn payload(&self) -> &BlockPayload {
        &self.payload
    }
    /// Signed transactions originating from external sources.
    /// Sealed commitments and anonymous ballots are omitted; iterator positions
    /// therefore need not equal canonical network input indices.
    #[inline]
    pub fn external_transactions(
        &self,
    ) -> impl ExactSizeIterator<Item = &SignedTransaction> + DoubleEndedIterator {
        ExternalTransactionIterator::new(self)
    }
    /// External entrypoints in execution order.
    #[inline]
    pub fn external_entrypoints_cloned(
        &self,
    ) -> impl ExactSizeIterator<Item = TransactionEntrypoint> + DoubleEndedIterator + '_ {
        self.payload.external_entrypoints.iter().cloned()
    }
    /// Borrow one signed external transaction and return its canonical entrypoint hash.
    ///
    /// Sealed commitments and anonymous ballots have no signed transaction and return `None`. The lookup is
    /// constant-space and does not clone either the transaction or the complete entrypoint list.
    #[inline]
    pub fn external_signed_transaction_at(
        &self,
        index: usize,
    ) -> Option<(HashOf<TransactionEntrypoint>, &SignedTransaction)> {
        let entrypoint = self.payload.external_entrypoints.get(index)?;
        let hash = entrypoint.hash();
        let transaction = match entrypoint {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_)
            | TransactionEntrypoint::AnonymousBallot(_) => {
                return None;
            }
        };
        Some((hash, transaction))
    }
    /// Borrow one signed external transaction by canonical entrypoint index.
    ///
    /// Unlike [`Self::external_signed_transaction_at`], this avoids hashing the entrypoint and is
    /// useful to continue streaming an entrypoint after its hash has already been retained.
    #[inline]
    pub fn external_signed_transaction_ref_at(&self, index: usize) -> Option<&SignedTransaction> {
        match self.payload.external_entrypoints.get(index)? {
            TransactionEntrypoint::External(transaction) => Some(transaction),
            TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction()),
            TransactionEntrypoint::SealedCommitment(_)
            | TransactionEntrypoint::AnonymousBallot(_) => None,
        }
    }
    /// Durable execution context embedded in this block, if any.
    #[inline]
    pub fn execution_context(&self) -> Option<&BlockExecutionContextBundle> {
        self.payload.execution_context.as_ref()
    }
    /// Set or clear durable execution context and update the header hash accordingly.
    pub fn set_execution_context(&mut self, context: Option<BlockExecutionContextBundle>) {
        let context = context.filter(|bundle| !bundle.is_empty());
        if self.payload.execution_context != context {
            self.result = None;
        }
        let hash = context.as_ref().map(HashOf::new);
        self.payload.execution_context = context;
        self.payload.header.set_execution_context_hash(hash);
    }
    /// Optional DA commitment bundle embedded in this block.
    #[inline]
    pub fn da_commitments(&self) -> Option<&DaCommitmentBundle> {
        self.payload.da_commitments.as_ref()
    }
    /// Optional DA proof policy bundle embedded in this block.
    #[inline]
    pub fn da_proof_policies(&self) -> Option<&DaProofPolicyBundle> {
        self.payload.da_proof_policies.as_ref()
    }
    /// Set or clear the DA commitment bundle and update the header hash accordingly.
    pub fn set_da_commitments(&mut self, commitments: Option<DaCommitmentBundle>) {
        let commitments = commitments.filter(|bundle| !bundle.is_empty());
        let hash = commitments
            .as_ref()
            .and_then(DaCommitmentBundle::merkle_commitment);
        if self.payload.da_commitments != commitments {
            self.result = None;
        }
        self.payload.da_commitments = commitments;
        self.payload.header.set_da_commitments_hash(hash);
    }
    /// Set or clear the DA proof policy bundle and update the header hash accordingly.
    pub fn set_da_proof_policies(&mut self, policies: Option<DaProofPolicyBundle>) {
        let hash = policies.as_ref().map(HashOf::new);
        if self.payload.da_proof_policies != policies {
            self.result = None;
        }
        self.payload.da_proof_policies = policies;
        self.payload.header.set_da_proof_policies_hash(hash);
    }
    /// Optional DA pin intent bundle embedded in this block.
    #[inline]
    pub fn da_pin_intents(&self) -> Option<&DaPinIntentBundle> {
        self.payload.da_pin_intents.as_ref()
    }
    /// Set or clear the DA pin intent bundle and update the header hash accordingly.
    pub fn set_da_pin_intents(&mut self, intents: Option<DaPinIntentBundle>) {
        let intents = intents.filter(|bundle| !bundle.is_empty());
        let hash = intents
            .as_ref()
            .and_then(DaPinIntentBundle::merkle_commitment);
        if self.payload.da_pin_intents != intents {
            self.result = None;
        }
        self.payload.da_pin_intents = intents;
        self.payload.header.set_da_pin_intents_hash(hash);
    }
    /// Deterministic `NPoS` effects embedded in this block.
    #[inline]
    pub fn npos_consensus_effects(&self) -> Option<&NposConsensusEffects> {
        self.payload.npos_consensus_effects.as_ref()
    }
    /// Set or clear deterministic `NPoS` effects and update the header hash accordingly.
    pub fn set_npos_consensus_effects(&mut self, effects: Option<NposConsensusEffects>) {
        let effects = effects.filter(|bundle| !bundle.is_empty());
        let hash = effects.as_ref().map(HashOf::new);
        if self.payload.npos_consensus_effects != effects {
            self.result = None;
        }
        self.payload.npos_consensus_effects = effects;
        self.payload.header.set_npos_effects_hash(hash);
    }
    /// Finalized threshold pulse authenticated by the current proposal header.
    pub fn global_beacon_pulse(&self) -> Option<&FinalizedGlobalThresholdBeaconPulseV1> {
        self.payload.global_beacon_pulse.as_ref()
    }
    /// Replace the pulse, invalidating any execution result produced for another payload.
    pub fn set_global_beacon_pulse(
        &mut self,
        pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    ) {
        if self.payload.global_beacon_pulse != pulse {
            self.result = None;
        }
        self.payload
            .header
            .set_global_beacon_pulse_hash(pulse.as_ref().map(HashOf::new));
        self.payload.global_beacon_pulse = pulse;
    }
    /// Replace the ordered external entrypoints and update Merkle material accordingly.
    pub fn set_external_entrypoints(&mut self, entrypoints: Vec<TransactionEntrypoint>) {
        if self.payload.external_entrypoints != entrypoints {
            self.result = None;
        }
        self.payload.header.merkle_root = entrypoints
            .iter()
            .map(TransactionEntrypoint::hash)
            .collect::<MerkleTree<_>>()
            .root();
        self.payload.external_entrypoints = entrypoints;
    }
    /// Whether the proposal contains original consensus work.
    ///
    /// Network inputs and lane merges are work. Beacon controls, execution outputs,
    /// DA metadata and scheduling effects cannot create work.
    /// This predicate grants no admission or execution authority: each input still
    /// requires its normal signature, custody and deterministic execution checks.
    #[must_use]
    pub fn has_consensus_work(&self) -> bool {
        self.network_entrypoint_count() > 0
            || self
                .lane_merge()
                .is_some_and(|section| !section.merges.is_empty())
    }

    /// Check whether the block has entrypoints or deterministic artifacts.
    #[inline]
    pub fn is_empty(&self) -> bool {
        if self.external_entrypoint_count() != 0 {
            return false;
        }
        if self
            .result
            .as_ref()
            .is_some_and(|result| !result.outputs.is_empty())
        {
            return false;
        }
        if self
            .payload
            .da_commitments
            .as_ref()
            .is_some_and(|bundle| !bundle.is_empty())
        {
            return false;
        }
        if self
            .payload
            .da_pin_intents
            .as_ref()
            .is_some_and(|bundle| !bundle.is_empty())
        {
            return false;
        }
        if self
            .payload
            .npos_consensus_effects
            .as_ref()
            .is_some_and(|bundle| !bundle.is_empty())
        {
            return false;
        }
        if self
            .payload
            .execution_context
            .as_ref()
            .is_some_and(|context| !context.is_empty())
        {
            return false;
        }
        true
    }
    /// Hashes of the network inputs. Internal invocations are not inputs.
    pub fn network_input_hashes(
        &self,
    ) -> impl ExactSizeIterator<Item = HashOf<TransactionEntrypoint>> + DoubleEndedIterator + '_
    {
        self.network_entrypoints().map(TransactionEntrypoint::hash)
    }
    /// Recompute the complete network-input tree from its sole proposal source.
    pub fn network_input_merkle_tree(&self) -> MerkleTree<TransactionEntrypoint> {
        self.network_input_hashes().collect()
    }
    /// Network-input root and count.
    pub fn network_input_merkle_commitment(
        &self,
    ) -> Option<MerkleTreeCommitment<TransactionEntrypoint>> {
        self.network_input_merkle_tree().commitment()
    }
    /// Proof for one complete network-input position; no internal invocation has an input leaf.
    pub fn network_input_proof(&self, index: u32) -> Option<MerkleProof<TransactionEntrypoint>> {
        self.network_input_merkle_tree().get_proof(index)
    }
    /// Borrow all full typed outputs in canonical phase order. A proposal has no outputs.
    pub fn execution_outputs(&self) -> &[ExecutionOutputV1] {
        self.result
            .as_ref()
            .map_or(&[], |result| result.outputs.as_slice())
    }
    /// Full typed-output root/count, authenticated only by actual global execution finality.
    pub fn output_merkle_commitment(&self) -> Option<MerkleTreeCommitment<ExecutionOutputV1>> {
        self.result.as_ref()?.output_merkle.commitment()
    }
    /// Validate all output structure and the retained tree, without claiming execution authenticity.
    /// # Errors
    /// Rejects missing results, malformed ownership, or any altered cached node/leaf.
    pub fn validate_output_merkle_cache(&self) -> Result<(), MerkleError> {
        let result = self
            .result
            .as_ref()
            .ok_or_else(|| MerkleError::InvalidLayout("block outputs are missing".into()))?;
        self.validate_execution_result_structure()
            .map_err(MerkleError::InvalidLayout)?;
        result
            .output_merkle
            .validate_leaves(result.outputs.iter().map(HashOf::new))
    }
    /// Proof for one typed output position, independently of network-input positions.
    pub fn output_proof(&self, index: u32) -> Option<MerkleProof<ExecutionOutputV1>> {
        self.result.as_ref()?.output_merkle.get_proof(index)
    }
    /// Locate the explicit Network source join, never infer it from a result index.
    pub fn network_output_at(&self, input_index: u32) -> Option<(u32, &NetworkExecutionOutputV1)> {
        let output = self
            .execution_outputs()
            .get(usize::try_from(input_index).ok()?)?;
        match output {
            ExecutionOutputV1::Network(row) if row.input_index == input_index => {
                Some((input_index, row))
            }
            _ => None,
        }
    }
    /// Canonical full typed-output hashes, independently of the network-input tree.
    pub fn output_hashes(
        &self,
    ) -> impl ExactSizeIterator<Item = HashOf<ExecutionOutputV1>> + DoubleEndedIterator + '_ {
        self.execution_outputs().iter().map(HashOf::new)
    }
    /// Full transaction results projected from the one output owner. Indices are OUTPUT indices.
    pub fn output_results(
        &self,
    ) -> impl ExactSizeIterator<Item = &TransactionResult> + DoubleEndedIterator {
        self.execution_outputs()
            .iter()
            .map(ExecutionOutputV1::result)
    }
    /// FASTPQ transfer transcripts grouped by exact execution-call hash.
    #[inline]
    pub fn fastpq_transcripts(&self) -> &BTreeMap<Hash, Vec<TransferTranscript>> {
        &self.result_ref().fastpq_transcripts
    }
    /// Completed AXT envelopes recorded while executing the block.
    #[inline]
    pub fn axt_envelopes(&self) -> Option<&[crate::nexus::AxtEnvelopeRecord]> {
        self.result
            .as_ref()
            .map(|result| result.axt_envelopes.as_slice())
    }
    /// Independent-batch receipts for an exact network input's explicit output join.
    pub fn batch_transfer_outcomes_for(
        &self,
        entrypoint_hash: &HashOf<TransactionEntrypoint>,
    ) -> &[AssetBatchTransferOutcome] {
        self.network_input_hashes()
            .position(|hash| hash == *entrypoint_hash)
            .and_then(|index| u32::try_from(index).ok())
            .and_then(|index| self.network_output_at(index))
            .map_or(&[], |(_, output)| output.result.batch_transfer_outcomes())
    }
    /// AXT policy snapshot captured during execution, when results are present.
    #[inline]
    pub fn axt_policy_snapshot(&self) -> Option<&crate::nexus::AxtPolicySnapshot> {
        self.result
            .as_ref()
            .map(|result| &result.axt_policy_snapshot)
    }
    /// Sticky AXT authorization transitions captured during execution, when results are present.
    #[inline]
    pub fn axt_transitioned_dataspaces(
        &self,
    ) -> Option<&BTreeSet<iroha_model_base::topology::DataSpaceId>> {
        self.result
            .as_ref()
            .map(|result| &result.axt_transitioned_dataspaces)
    }
    /// Successful OUTPUT indices and data trigger sequences.
    pub fn successful_outputs(&self) -> impl Iterator<Item = (u64, &DataTriggerSequence)> {
        self.output_results()
            .enumerate()
            .filter_map(|(i, result)| result.as_ref().ok().map(|ok| (i as u64, ok)))
    }
    /// Failed OUTPUT indices and rejection reasons.
    pub fn failed_outputs(&self) -> impl Iterator<Item = (u64, &TransactionRejectionReason)> {
        self.output_results()
            .enumerate()
            .filter_map(|(i, result)| result.as_ref().err().map(|err| (i as u64, err)))
    }
}
struct ExternalTransactionIterator<'a> {
    entrypoints: &'a [TransactionEntrypoint],
    front: usize,
    back: usize,
    remaining: usize,
}
impl<'a> ExternalTransactionIterator<'a> {
    fn new(block: &'a SignedBlock) -> Self {
        let entrypoints = block.external_entrypoints_slice();
        let remaining = entrypoints
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    TransactionEntrypoint::External(_) | TransactionEntrypoint::SealedReveal(_)
                )
            })
            .count();
        Self {
            entrypoints,
            front: 0,
            back: entrypoints.len(),
            remaining,
        }
    }
    fn transaction_at(&self, index: usize) -> Option<&'a SignedTransaction> {
        match self.entrypoints.get(index)? {
            TransactionEntrypoint::External(transaction) => Some(transaction),
            TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction()),
            TransactionEntrypoint::SealedCommitment(_)
            | TransactionEntrypoint::AnonymousBallot(_) => None,
        }
    }
}
impl<'a> Iterator for ExternalTransactionIterator<'a> {
    type Item = &'a SignedTransaction;
    fn next(&mut self) -> Option<Self::Item> {
        while self.front < self.back {
            let idx = self.front;
            self.front += 1;
            if let Some(transaction) = self.transaction_at(idx) {
                self.remaining -= 1;
                return Some(transaction);
            }
        }
        None
    }
}
impl DoubleEndedIterator for ExternalTransactionIterator<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        while self.front < self.back {
            self.back -= 1;
            if let Some(transaction) = self.transaction_at(self.back) {
                self.remaining -= 1;
                return Some(transaction);
            }
        }
        None
    }
}
impl ExactSizeIterator for ExternalTransactionIterator<'_> {
    fn len(&self) -> usize {
        self.remaining
    }
}
