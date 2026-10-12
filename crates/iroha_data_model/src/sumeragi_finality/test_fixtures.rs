//! Genuine native BLS proof fixtures; caller-supplied results are synthetic, never executed World.
use super::*;
use crate::{
    account::AccountId,
    block::{
        CommitCertificate,
        builder::BlockBuilder,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        output_budget::ExecutionOutputLimits,
    },
    isi::{InstructionBox, Log, RegisterPeerWithPop, SetParameter},
    level::Level,
    parameter::{
        CustomParameter, Parameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            consensus_metadata,
        },
    },
    sumeragi::epoch::ValidatorEpochContextV1,
    transaction::{FeePaymentIntent, TransactionBuilder, TransactionResultInner},
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::{KeyPair, bls_normal_pop_prove};
use iroha_sumeragi::{
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::Signer,
    types::{Bitmap, ChainParams},
};
use std::{num::NonZeroU64, time::Duration};

// Only fixed public fixture keys enter this signer; it is never deployment custody.
struct FixtureSigner<'a> {
    public: CoreKey,
    key: &'a KeyPair,
}
impl Signer for FixtureSigner<'_> {
    fn public_key(&self) -> &CoreKey {
        &self.public
    }
    fn sign(&self, preimage: &[u8]) -> Signature {
        Signature(
            iroha_crypto::bls::consensus::sign_preimage(self.key.private_key(), preimage).unwrap(),
        )
    }
}

/// Author a genuine signed RS16 payload table for an independently selected fixture schedule.
///
/// The caller selects the complete height configuration, original allocation budget, ordered
/// proof-of-possession-verified validators and proposer key. This helper uses the production
/// authoring path; it executes no World transition and grants no deployment signing authority.
///
/// # Panics
/// Panics if the fixture committee, proposer, payload, header or budget is invalid.
#[must_use]
pub fn author_payload(
    header: CoreHeader,
    payload: &[u8],
    config: &iroha_sumeragi::types::HeightConfig,
    budget: &AllocationBudget,
    validators: &[FinalityValidator],
    proposer: &KeyPair,
) -> iroha_sumeragi::availability::AuthoredBody {
    let (crypto, committee) = ProofCrypto::new(validators).expect("genuine fixture committee");
    assert_eq!(
        config.committee, committee,
        "independently selected committee"
    );
    let public =
        consensus_key(&PeerId::new(proposer.public_key().clone())).expect("fixture BLS proposer");
    assert_eq!(config.committee.get(header.proposer), Some(&public));
    let signer = FixtureSigner {
        public,
        key: proposer,
    };
    let mut bytes = ChargedBuffer::new(payload.len(), budget).expect("fixture payload backing");
    bytes
        .append(payload)
        .expect("exact fixture payload capacity");
    let payload = PayloadBytes::from_charged(bytes, budget)
        .unwrap_or_else(|_| panic!("fixture proposal shared owner admission"));
    let instance = header.instance;
    PayloadAuthoring::new(header, payload)
        .complete(instance, config, budget, &crypto, &signer)
        .unwrap_or_else(|(_, error)| panic!("genuine fixture availability authoring: {error:?}"))
}

/// Wrap one synthetic execution body in the sole certified-result layout for a fixture.
///
/// The fixture has no SCCP effects, so its original block supplies an inactive header. This
/// helper neither executes World nor grants monetary or deployment authority.
///
/// # Panics
/// Panics when the supplied body does not bind the block or selected fixture root.
#[must_use]
pub fn certified_result_for_block(
    block: &SignedBlock,
    body: ExecutionResultCommitment,
    scope: CertifiedResultScope,
) -> CertifiedResultV1 {
    let header = SccpFinalityHeaderV1::inactive(
        body.schedule.current.network_id.as_bytes().to_owned(),
        block.header().height().get(),
        block.header().creation_time_ms,
    )
    .expect("fixture finality header");
    let result = CertifiedResultV1::new(header, body, scope).expect("fixture certified result");
    result
        .check_block(
            block.header().height().get(),
            block.header().creation_time_ms,
        )
        .expect("fixture block binding");
    result
}

/// A deterministic signed genesis and genuine exact-quorum native proof chain for tests.
///
/// Certifying supplied results is not World execution or monetary qualification. The public
/// fixed fixture keys must never be used as a deployment's trust root or signing credentials.
#[derive(Clone)]
pub struct NativeFinalityFixture {
    genesis: SignedBlock,
    first: SumeragiFinalityProof,
    tip: SumeragiFinalityProof,
    keys: Vec<KeyPair>,
    validators: Vec<FinalityValidator>,
    epoch: ValidatorEpochContextV1,
    verifier: SumeragiFinalityVerifier,
    chain_id: String,
}

impl Default for NativeFinalityFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeFinalityFixture {
    /// Construct a genesis prefix and one real three-of-four native H2 certificate.
    #[must_use]
    pub fn new() -> Self {
        let mut fixture = Self::start("portable-native-fixture");
        let block = fixture.block_with_submitted_work(fixture.next_header());
        fixture.certify(block);
        fixture
    }

    /// Construct an independently signed explicit-parameter genesis and genuine H2 certificate.
    /// Fixed public fixture keys and synthetic execution results grant no runtime authority.
    #[must_use]
    pub fn new_with_explicit_parameters() -> Self {
        let mut fixture = Self::start_with_explicit_parameters("portable-native-fixture");
        let block = fixture.block_with_submitted_work(fixture.next_header());
        fixture.certify(block);
        fixture
    }

    /// Start at a signed global genesis containing every explicit chain parameter.
    /// This fixture owner leaves H2 available for the caller's submitted work.
    #[must_use]
    pub fn start_with_explicit_parameters(chain_id: &str) -> Self {
        Self::start_with_mode_and_scope_parameters(
            chain_id,
            SumeragiConsensusMode::Permissioned,
            crate::block::consensus::SumeragiRootScope::Global,
            true,
        )
    }

    /// Start at deterministic signed genesis for a separately selected fixture chain label.
    /// The result-only H1 prefix alone does not authenticate genesis execution outputs.
    #[must_use]
    pub fn start(chain_id: &str) -> Self {
        Self::start_with_mode(chain_id, SumeragiConsensusMode::Permissioned)
    }

    /// Start a signed genesis with the explicitly selected consensus policy.
    /// All certificates are genuine native BLS; supplied execution results remain synthetic.
    #[must_use]
    pub fn start_with_mode(chain_id: &str, mode: SumeragiConsensusMode) -> Self {
        Self::start_with_mode_and_scope(
            chain_id,
            mode,
            crate::block::consensus::SumeragiRootScope::Global,
        )
    }

    /// Start a permissioned signed genesis with an explicit immutable root scope.
    /// Certificates use the resulting native instance; synthetic results do not execute World.
    #[must_use]
    pub fn start_with_scope(
        chain_id: &str,
        scope: crate::block::consensus::SumeragiRootScope,
    ) -> Self {
        Self::start_with_mode_and_scope(chain_id, SumeragiConsensusMode::Permissioned, scope)
    }

    fn start_with_mode_and_scope(
        chain_id: &str,
        mode: SumeragiConsensusMode,
        root_scope: crate::block::consensus::SumeragiRootScope,
    ) -> Self {
        Self::start_with_mode_and_scope_parameters(chain_id, mode, root_scope, false)
    }

    fn start_with_mode_and_scope_parameters(
        chain_id: &str,
        mode: SumeragiConsensusMode,
        root_scope: crate::block::consensus::SumeragiRootScope,
        explicit_parameters: bool,
    ) -> Self {
        Self::start_with_selected_npos_parameters(
            chain_id,
            mode,
            root_scope,
            explicit_parameters,
            crate::parameter::system::SumeragiNposParameters::default(),
            4,
        )
    }

    /// Start a permissioned Global genesis that signs `nexus_amx_context_hash` and appends
    /// `extra` signed genesis instructions (for example a lane policy). The fixed public
    /// fixture keys and synthetic results grant no runtime authority.
    #[must_use]
    pub fn start_with_genesis_extension(
        chain_id: &str,
        nexus_amx_context_hash: [u8; 32],
        extra: Vec<InstructionBox>,
    ) -> Self {
        Self::start_with_genesis_inputs(
            chain_id,
            SumeragiConsensusMode::Permissioned,
            crate::block::consensus::SumeragiRootScope::Global,
            false,
            crate::parameter::system::SumeragiNposParameters::default(),
            4,
            Some(nexus_amx_context_hash),
            extra,
        )
    }

    fn start_with_selected_npos_parameters(
        chain_id: &str,
        mode: SumeragiConsensusMode,
        root_scope: crate::block::consensus::SumeragiRootScope,
        explicit_parameters: bool,
        npos_parameters: crate::parameter::system::SumeragiNposParameters,
        committee_seats: usize,
    ) -> Self {
        Self::start_with_genesis_inputs(
            chain_id,
            mode,
            root_scope,
            explicit_parameters,
            npos_parameters,
            committee_seats,
            None,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_genesis_inputs(
        chain_id: &str,
        mode: SumeragiConsensusMode,
        root_scope: crate::block::consensus::SumeragiRootScope,
        explicit_parameters: bool,
        npos_parameters: crate::parameter::system::SumeragiNposParameters,
        committee_seats: usize,
        nexus_amx_context_hash: Option<[u8; 32]>,
        extra: Vec<InstructionBox>,
    ) -> Self {
        assert!(!chain_id.is_empty(), "fixture chain label must be selected");
        assert!((4..=31).contains(&committee_seats) && (committee_seats - 1).is_multiple_of(3));
        let mut keys: Vec<_> = (1..=committee_seats)
            .map(|seed| {
                KeyPair::from_seed(vec![u8::try_from(seed).unwrap(); 32], Algorithm::BlsNormal)
            })
            .collect();
        keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
        let validators: Vec<_> = keys
            .iter()
            .map(|key| FinalityValidator {
                public_key: key.public_key().clone(),
                proof_of_possession: bls_normal_pop_prove(key.private_key()).unwrap(),
            })
            .collect();
        let authority = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let metadata = ConsensusHandshakeMetadata {
            mode,
            block_cadence_ms: NonZeroU64::new(1000).unwrap(),
            wire_protocol_version: u32::from(crate::sumeragi::PROTOCOL_VERSION),
            consensus_fingerprint: ConsensusFingerprint::new([0x71; 32]),
            sumeragi_context: crate::block::consensus::SumeragiGenesisContextParameters {
                root_scope,
                nexus_amx_context_hash: nexus_amx_context_hash.unwrap_or(
                    crate::block::consensus::SumeragiGenesisContextParameters::recommended()
                        .nexus_amx_context_hash,
                ),
                ..crate::block::consensus::SumeragiGenesisContextParameters::recommended()
            },
        };
        let mut instructions: Vec<InstructionBox> = validators
            .iter()
            .map(|validator| {
                RegisterPeerWithPop::new(
                    PeerId::new(validator.public_key.clone()),
                    validator.proof_of_possession.clone(),
                )
                .into()
            })
            .collect();
        instructions.push(
            SetParameter::new(Parameter::Custom(CustomParameter::new(
                consensus_metadata::handshake_meta_id(),
                iroha_primitives::json::Json::new(metadata),
            )))
            .into(),
        );
        if mode == SumeragiConsensusMode::Npos {
            instructions.push(
                SetParameter::new(Parameter::Custom(npos_parameters.into_custom_parameter()))
                    .into(),
            );
        }
        if explicit_parameters {
            let parameters = crate::parameter::system::SumeragiParameters::default();
            assert_eq!(
                ChainParamsRecord::from_parameters(&parameters),
                ChainParamsRecord::from_core(&ChainParams::default())
            );
            instructions.extend(
                parameters
                    .parameters()
                    .map(|parameter| SetParameter::new(Parameter::Sumeragi(parameter)).into()),
            );
        }
        instructions.extend(extra);
        let mut tx = TransactionBuilder::new_genesis(
            AccountId::new(authority.public_key().clone()),
            FeePaymentIntent::authority(vec![], None),
        );
        tx.set_creation_time(Duration::from_millis(0));
        let tx = tx
            .with_instructions(instructions)
            .sign(authority.private_key());
        let genesis =
            SignedBlock::try_genesis(vec![tx], authority.private_key(), None, None).unwrap();
        let epoch = authenticated_genesis(&genesis)
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        let mut block = genesis.clone();
        Self::install_network_results(&mut block, vec![Ok(Vec::new())]);
        let result = Self::result(&block, &epoch);
        let result = certified_result_for_block(
            &block,
            result,
            CertifiedResultScope::from_root_scope(root_scope),
        );
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            vec![],
            vec![],
            result.preimage().unwrap(),
            vec![],
        )));
        let first = SumeragiFinalityProof {
            block_header: block.header(),
            block_wire: block.encode_wire().unwrap(),
            committee: validators.clone(),
        };
        let mut verifier =
            SumeragiFinalityVerifier::new(&genesis, chain_id, validators.clone()).unwrap();
        verifier.verify(&first).unwrap();
        Self {
            genesis,
            first: first.clone(),
            tip: first,
            keys,
            validators,
            epoch,
            verifier,
            chain_id: chain_id.into(),
        }
    }

    /// Exact genesis-derived network identity selected by this fixture.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        NetworkId::from_genesis_hash(self.genesis.hash())
    }
    /// Independently selected chain label used for native instance derivation.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Original signed genesis without a result-only certificate.
    #[must_use]
    pub fn genesis(&self) -> &SignedBlock {
        &self.genesis
    }
    /// Original height-one proof, required when constructing a full prefix.
    #[must_use]
    pub fn genesis_proof(&self) -> &SumeragiFinalityProof {
        &self.first
    }
    /// Last exact proof authenticated by the fixture's retained verifier.
    #[must_use]
    pub fn latest(&self) -> &SumeragiFinalityProof {
        &self.tip
    }
    /// Independent verifier retained at this fixture's authenticated tip.
    #[must_use]
    pub fn verifier(&self) -> SumeragiFinalityVerifier {
        self.verifier.clone()
    }
    /// Complete canonical checkpoint exported from the retained authenticated prefix.
    #[must_use]
    pub fn checkpoint(&self) -> SumeragiFinalityCheckpoint {
        self.verifier.export_checkpoint(&self.tip).unwrap()
    }
    /// Exact next Iroha header; caller-supplied payloads must preserve these parent coordinates.
    #[must_use]
    pub fn next_header(&self) -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(self.tip.height() + 1).unwrap(),
            Some(self.tip.block_header.hash()),
            None,
            self.tip.block_header.creation_time_ms + 1,
            0,
        )
    }

    /// Build nonempty, originally signed work for structural proof/custody tests.
    ///
    /// The transaction uses this fixture's network and is signed one millisecond before
    /// the supplied original proposal time, preserving the reviewed height-two fixture.
    /// Its success row is explicitly synthetic: this helper executes no World transition
    /// and grants no monetary or business-execution qualification. Certify the returned
    /// block only after its intended witness is selected, using the original fixture quorum.
    ///
    /// # Panics
    /// Panics if the proposal time is zero and cannot follow the submitted work.
    #[must_use]
    pub fn block_with_submitted_work(&self, header: BlockHeader) -> SignedBlock {
        let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let mut tx = TransactionBuilder::new(
            self.network_id(),
            AccountId::new(signer.public_key().clone()),
            FeePaymentIntent::authority(vec![], None),
        );
        tx.set_creation_time(Duration::from_millis(
            header
                .creation_time_ms
                .checked_sub(1)
                .expect("proposal follows submitted work"),
        ));
        let tx = tx
            .with_instructions([Log::new(Level::INFO, "fixture submitted work".into())])
            .sign(signer.private_key());
        let mut builder = BlockBuilder::new(header);
        builder.push_transaction(tx);
        let mut block = builder.build(crate::block::BlockSignatures::default());
        Self::install_network_results(&mut block, vec![Ok(Vec::new())]);
        block
    }

    /// Install explicit synthetic network outputs for codec/verifier tests.
    /// This does not execute the transaction instructions or transfer any assets.
    pub fn install_network_results(block: &mut SignedBlock, results: Vec<TransactionResultInner>) {
        let outputs = results
            .into_iter()
            .enumerate()
            .map(|(index, result)| {
                ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index: index.try_into().unwrap(),
                    result: result.into(),
                    completions: vec![],
                })
            })
            .collect();
        block
            .set_execution_outputs(
                outputs,
                0,
                std::collections::BTreeMap::default(),
                vec![],
                crate::nexus::AxtPolicySnapshot::default(),
                std::collections::BTreeSet::default(),
                &ExecutionOutputLimits {
                    max_outputs: 1024,
                    max_output_bytes: 16 * 1024 * 1024,
                    max_total_output_bytes: 32 * 1024 * 1024,
                    max_executed_wire_bytes: MAX_FINALITY_BLOCK_BYTES as u64,
                },
            )
            .unwrap();
    }

    /// Certify one caller-supplied synthetic result block with the real native exact-quorum QC.
    /// No World execution, monetary-policy verification or committee-transition claim is made.
    ///
    /// # Panics
    /// Panics if the block does not extend the fixture's exact tip or violates native proof rules.
    pub fn certify(&mut self, block: SignedBlock) -> SumeragiFinalityProof {
        let result = Self::result(&block, &self.epoch);
        self.certify_result(block, &result)
    }

    /// Certify an explicit synthetic ordered event stream with a genuine native QC.
    /// This helper executes no World transition; Core must separately test that
    /// only successful execution emits its system events and rollback removes them.
    ///
    /// # Panics
    /// Panics if the block is not the exact fixture successor or violates proof rules.
    pub fn certify_with_events(
        &mut self,
        block: SignedBlock,
        events: &[crate::events::EventBox],
    ) -> SumeragiFinalityProof {
        let tree: iroha_crypto::MerkleTree<crate::events::EventBox> =
            events.iter().map(HashOf::new).collect();
        let mut result = Self::result(&block, &self.epoch);
        result.execution.event_commitment = tree.commitment();
        result.validate().unwrap();
        self.certify_result(block, &result)
    }

    /// Certify an explicitly synthetic complete-World root for portable reader tests.
    /// This helper executes no World transition and grants no monetary authority.
    ///
    /// # Panics
    /// Panics if the block is not the exact fixture successor or violates proof rules.
    pub fn certify_with_world_root(
        &mut self,
        block: SignedBlock,
        world_root: Hash,
    ) -> SumeragiFinalityProof {
        let parent = self.verifier.verify_retained_decision(&self.tip).unwrap();
        let mut result = Self::result(&block, &self.epoch);
        result.execution.parent_world_state_root = parent.execution().world_state_root;
        result.execution.world_state_root = world_root;
        result.validate().unwrap();
        self.certify_result(block, &result)
    }

    /// Certify explicit synthetic ordinary writes with their mandatory native lane-state proof.
    /// The complete witness is checked and its exact scratch capacity admitted before signing.
    /// This helper executes no World transition and grants no monetary authority.
    ///
    /// # Panics
    /// Panics on a malformed witness, a foreign lane commitment, or a non-successor block.
    pub fn certify_with_witness(
        &mut self,
        block: SignedBlock,
        witness: &crate::block::consensus::ExecWitness,
    ) -> SumeragiFinalityProof {
        let scratch = NativeLaneStateProof::scratch_bytes(witness.writes.len()).unwrap();
        let proof = NativeLaneStateProof::from_witness(
            witness,
            &iroha_allocation::AllocationBudget::new(scratch),
        )
        .unwrap();
        let root = proof.computed_root().unwrap();
        assert!(proof.verify(self.network_id(), block.header().height().get(), root));
        let result = Self::result_with_lane_proof(&block, &self.epoch, proof, root);
        self.certify_result(block, &result)
    }

    fn certify_result(
        &mut self,
        mut block: SignedBlock,
        result: &ExecutionResultCommitment,
    ) -> SumeragiFinalityProof {
        assert_eq!(block.header().height().get(), self.tip.height() + 1);
        assert_eq!(
            block.header().prev_block_hash(),
            Some(self.tip.block_header.hash())
        );
        assert!(block.commit_certificate().is_none());
        let result = certified_result_for_block(
            &block,
            result.clone(),
            CertifiedResultScope::from_root_scope(self.verifier.root_scope()),
        );
        let parent = self.verifier.verify_retained_decision(&self.tip).unwrap();
        let (crypto, committee) = ProofCrypto::new(&self.validators).unwrap();
        let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
            panic!("fixture parent has no authenticated successor authority");
        };
        assert_eq!(scheduled.height, block.header().height().get());
        let config = scheduled.height_config().unwrap();
        assert_eq!(config.committee, committee);
        let signer = FixtureSigner {
            public: committee.members()[0].clone(),
            key: &self.keys[0],
        };
        // Admit the original proposal backing before serialization, then author its exact
        // signed RS16 table using the independently selected fixture height configuration.
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let payload_len = block.resultless_proposal_wire_len().unwrap();
        let mut bytes = ChargedBuffer::new(payload_len, &budget).unwrap();
        for _ in 0..payload_len {
            bytes.push_reserved(0);
        }
        let mut destination = bytes.as_mut_slice();
        block
            .write_resultless_proposal_wire(&mut destination)
            .unwrap();
        assert!(destination.is_empty());
        let payload = PayloadBytes::from_charged(bytes, &budget)
            .unwrap_or_else(|_| panic!("fixture proposal shared owner admission"));
        let header = CoreHeader {
            instance: self.verifier.instance(),
            epoch: config.epoch.id,
            height: block.header().height().get(),
            origin_view: block.header().view_change_index(),
            parent_hash: parent.core_hash(),
            parent_result: parent.result(),
            payload_hash: payload_hash(&crypto, payload.as_slice()),
            availability_digest: Hash32::ZERO,
            payload_len: payload_len.try_into().unwrap(),
            proposer: 0,
            skipped_leaders: vec![],
            control_witness: iroha_sumeragi::types::ControlWitness::empty(),
        };
        let authored = PayloadAuthoring::new(header, payload)
            .complete(self.verifier.instance(), &config, &budget, &crypto, &signer)
            .unwrap_or_else(|_| panic!("genuine fixture availability authoring"));
        let header = authored.body.header();
        let quorum = self.keys.len() - (self.keys.len() - 1) / 3;
        let mut qc = Qc {
            kind: VoteKind::Commit,
            instance: header.instance,
            epoch: header.epoch,
            height: header.height,
            view: header.origin_view,
            block_hash: header.hash(&crypto),
            result: result.result().unwrap(),
            signers: Bitmap::from_indices(self.keys.len(), 0..u32::try_from(quorum).unwrap())
                .unwrap(),
            agg_sig: AggregateSignature([0; 96]),
        };
        let shares: Vec<_> = self.keys[..quorum]
            .iter()
            .map(|key| {
                iroha_crypto::bls::consensus::sign_preimage(key.private_key(), &qc.preimage())
                    .unwrap()
            })
            .collect();
        let refs: Vec<_> = shares.iter().collect();
        qc.agg_sig = AggregateSignature(
            iroha_crypto::bls::consensus::aggregate(refs.iter().copied()).unwrap(),
        );
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            norito::encode_canonical(header).unwrap(),
            norito::encode_canonical(&qc).unwrap(),
            result.preimage().unwrap(),
            norito::encode_canonical(authored.body.availability()).unwrap(),
        )));
        let proof = SumeragiFinalityProof {
            block_header: block.header(),
            block_wire: block.encode_wire().unwrap(),
            committee: self.validators.clone(),
        };
        self.verifier.verify(&proof).unwrap();
        self.tip = proof.clone();
        proof
    }

    fn result(block: &SignedBlock, epoch: &ValidatorEpochContextV1) -> ExecutionResultCommitment {
        let (native_lanes, ordinary_root) = NativeLaneStateProof::empty_for_testing(
            epoch.network_id,
            block.header().height().get(),
        );
        Self::result_with_lane_proof(block, epoch, native_lanes, ordinary_root)
    }

    fn result_with_lane_proof(
        block: &SignedBlock,
        epoch: &ValidatorEpochContextV1,
        native_lanes: NativeLaneStateProof,
        ordinary_root: Hash,
    ) -> ExecutionResultCommitment {
        let height = block.header().height().get();
        let (len, hash) = block.executed_block_wire_identity().unwrap();
        let slot = |height| {
            ScheduledSlot::Ready(ScheduledConfig {
                height,
                epoch: epoch.clone(),
                params: ChainParamsRecord::from_core(&ChainParams::default()),
            })
        };
        ExecutionResultCommitment::new(
            height,
            ExecutionCommitment {
                parent_state_root: Hash::new(b"fixture parent"),
                post_state_root: ordinary_root,
                ordinary_writes_root: ordinary_root,
                parent_world_state_root: Hash::new(b"fixture parent world"),
                world_state_root: Hash::new(b"fixture world"),
                event_commitment: None,
                executed_block_wire_len: len,
                executed_block_wire_hash: hash,
                transaction_input_commitment: block.network_input_merkle_commitment(),
                transaction_output_commitment: block.output_merkle_commitment(),
            },
            ScheduleOutcome {
                height,
                current: epoch.clone(),
                boundary: None,
                next: slot(height + 1),
                after_next: slot(height + 2),
            },
            None,
            native_lanes,
        )
        .unwrap()
    }
}

mod genesis_dataspace;
pub use genesis_dataspace::*;
mod npos_capture;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authored_availability_binds_actual_proposer_payload_header_and_schedule() {
        use iroha_sumeragi::availability::verify_availability;
        let fixture = NativeFinalityFixture::new();
        let certified = fixture
            .latest()
            .decode_checked(CertifiedResultScope::TairaGlobal)
            .unwrap();
        let header = certified.header.clone().unwrap();
        let config = ScheduledConfig {
            height: header.height,
            epoch: certified
                .certified_result
                .commitment()
                .schedule
                .current
                .clone(),
            params: ChainParamsRecord::from_core(&ChainParams::default()),
        }
        .height_config()
        .unwrap();
        let payload = certified
            .block
            .canonical_resultless_proposal()
            .expect("valid original proposal")
            .encode_wire()
            .unwrap();
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let authored = author_payload(
            header,
            &payload,
            &config,
            &budget,
            &fixture.validators,
            &fixture.keys[0],
        );
        let (crypto, _) = ProofCrypto::new(&fixture.validators).unwrap();
        let header = authored.body.header();
        let frame = authored.body.availability().as_slice();
        verify_availability(header.instance, &config, header, frame, &crypto).unwrap();
        assert_eq!(authored.body.payload().as_slice(), payload);
        let mut changed = header.clone();
        changed.parent_result.0[0] ^= 1;
        assert!(verify_availability(header.instance, &config, &changed, frame, &crypto).is_err());
        let mut changed_config = config.clone();
        changed_config.epoch.id.context.0[0] ^= 1;
        assert!(
            verify_availability(header.instance, &changed_config, header, frame, &crypto).is_err()
        );
        let mut forged = frame.to_vec();
        *forged.last_mut().unwrap() ^= 1;
        assert!(verify_availability(header.instance, &config, header, &forged, &crypto).is_err());
    }

    #[test]
    fn structural_work_binds_original_signature_network_and_header_time() {
        let mut fixture = NativeFinalityFixture::start("structural-work-fixture");
        let mut header = fixture.next_header();
        header.creation_time_ms += 17;
        let block = fixture.block_with_submitted_work(header);
        assert_eq!(block.external_transactions().len(), 1);
        assert_eq!(block.execution_outputs().len(), 1);
        let transaction = block.external_transactions().next().unwrap();
        header.merkle_root =
            iroha_crypto::MerkleTree::from_iter([transaction.hash_as_entrypoint()]).root();
        assert_eq!(block.header(), header);
        assert_eq!(transaction.network_id(), Some(&fixture.network_id()));
        assert_eq!(
            transaction.creation_time(),
            Duration::from_millis(header.creation_time_ms - 1)
        );
        transaction.verify_signature().unwrap();
        let original_wire = block
            .canonical_resultless_proposal()
            .expect("valid original proposal")
            .encode_wire()
            .unwrap();
        let proof = fixture.certify(block);
        let certified = proof
            .decode_checked(CertifiedResultScope::TairaGlobal)
            .unwrap();
        assert_eq!(
            certified
                .block
                .canonical_resultless_proposal()
                .expect("valid original proposal")
                .encode_wire()
                .unwrap(),
            original_wire
        );
        fixture.verifier().verify_retained_decision(&proof).unwrap();
    }

    #[test]
    fn active_sccp_result_uses_original_root_scope_despite_genuine_quorum() {
        use crate::block::consensus::SumeragiRootScope;
        use crate::sumeragi_finality::certified_result::{FLAG_ACTIVE, context_committee_root};
        use crate::sumeragi_finality::tests::sign_qc;

        let parent = NativeFinalityFixture::new().network_id();
        for root in [
            SumeragiRootScope::Global,
            SumeragiRootScope::Dataspace {
                parent_network_id: parent,
                dataspace_id: iroha_model_base::topology::DataSpaceId::new(17),
            },
        ] {
            let mut fixture = NativeFinalityFixture::start_with_scope("active-sccp-scope", root);
            let mut selected = fixture.verifier();
            let block = fixture.block_with_submitted_work(fixture.next_header());
            let mut proof = fixture.certify(block);
            let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
            let original = block.commit_certificate().unwrap();
            let header = original.consensus_header().to_vec();
            let availability = original.availability().to_vec();
            let mut qc: Qc = norito::decode_canonical(original.commit_qc()).unwrap();
            let certified = CertifiedResultV1::decode(
                original.result_preimage(),
                CertifiedResultScope::from_root_scope(root),
            )
            .unwrap();
            let mut fields = certified.header().fields();
            fields.flags = FLAG_ACTIVE;
            fields.generation = 1;
            fields.committee_root =
                context_committee_root(&certified.commitment().schedule.current).unwrap();
            // Synthetic SCCP state with a genuine exact-quorum certificate. This does
            // not claim the test fixture executed a World transition.
            let active = CertifiedResultV1::new(
                SccpFinalityHeaderV1::from_fields(&fields).unwrap(),
                certified.into_parts().1,
                CertifiedResultScope::TairaGlobal,
            )
            .unwrap();
            qc.result = active.result().unwrap();
            sign_qc(&mut qc, &fixture.keys, &[0, 1, 2]);
            block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                header,
                norito::encode_canonical(&qc).unwrap(),
                active.preimage().unwrap(),
                availability,
            )));
            proof.block_wire = block.encode_wire().unwrap();
            assert!(
                proof
                    .decode_checked(CertifiedResultScope::TairaGlobal)
                    .is_ok()
            );
            assert!(
                proof
                    .decode_checked(CertifiedResultScope::NonGlobal)
                    .is_err()
            );
            let admitted = selected.verify(&proof);
            assert_eq!(admitted.is_ok(), root == SumeragiRootScope::Global);
            assert_eq!(selected.root_scope(), root);
        }
    }

    #[test]
    fn synthetic_witness_certification_binds_all_writes_and_rejects_foreign_height() {
        use crate::block::consensus::{ExecKv, ExecWitness};
        let mut fixture = NativeFinalityFixture::new();
        let height = fixture.latest().height() + 1;
        let state = SumeragiLaneStateCommitment::from_state(
            fixture.network_id(),
            height,
            &crate::sumeragi_lanes::SumeragiLaneState::default(),
        )
        .unwrap();
        let writes = ExecWitness {
            writes: vec![
                ExecKv {
                    key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
                    value: norito::encode_canonical(&state).unwrap(),
                },
                ExecKv {
                    key: b"synthetic-fixture-application".to_vec(),
                    value: vec![7],
                },
            ],
            ..ExecWitness::default()
        };
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let proof = fixture.certify_with_witness(block.clone(), &writes);
        assert_eq!(proof.height(), height);
        fixture.verifier().verify_retained_decision(&proof).unwrap();
        let next = fixture.block_with_submitted_work(fixture.next_header());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fixture.certify_with_witness(next, &writes)
            }))
            .is_err()
        );
        assert_eq!(fixture.latest(), &proof);
    }

    #[test]
    #[ignore = "explicit deterministic canonical checkpoint capture, not a qualification gate"]
    fn capture_native_checkpoint_fixtures() {
        let genesis = NativeFinalityFixture::start("portable-native-fixture");
        let second = NativeFinalityFixture::new();
        assert_eq!(genesis.genesis(), second.genesis());
        assert_eq!(genesis.network_id(), second.network_id());
        let first = genesis.checkpoint();
        let second_checkpoint = second.checkpoint();
        let first_bytes = first.encode_canonical().unwrap();
        let second_bytes = second_checkpoint.encode_canonical().unwrap();
        assert_eq!(
            SumeragiFinalityCheckpoint::decode_canonical(&first_bytes).unwrap(),
            first
        );
        assert_eq!(
            SumeragiFinalityCheckpoint::decode_canonical(&second_bytes).unwrap(),
            second_checkpoint
        );
        verify_checkpoint_page(
            second.network_id(),
            &first,
            &[genesis.latest().clone(), second.latest().clone()],
            2,
            4 * 1024 * 1024,
        )
        .unwrap();
        println!("NATIVE_CHECKPOINT_CHAIN_ID={}", genesis.chain_id());
        println!("NATIVE_CHECKPOINT_NETWORK_ID={}", genesis.network_id());
        println!("NATIVE_CHECKPOINT_H1={}", hex::encode(first_bytes));
        println!("NATIVE_CHECKPOINT_H2={}", hex::encode(second_bytes));
    }
    #[test]
    fn explicitly_selected_npos_fixture_binds_signed_epoch_policy() {
        let fixture = NativeFinalityFixture::start_with_mode(
            "native-npos-fixture",
            SumeragiConsensusMode::Npos,
        );
        let epoch = authenticated_genesis(fixture.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        assert_eq!(epoch.mode, crate::parameter::system::ConsensusMode::Npos);
        assert_eq!(epoch.authorization.first_height, 1);
        assert!(epoch.authorization.last_height >= 3);
        assert_eq!(epoch.network_id, fixture.network_id());
        let checkpoint = fixture.checkpoint();
        SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &fixture.network_id(),
            fixture.chain_id(),
        )
        .unwrap()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    }

    #[test]
    fn exact_native_fixture_checkpoint_and_successor_verify() {
        let first = NativeFinalityFixture::new();
        let second = NativeFinalityFixture::new();
        assert_eq!(first.network_id(), second.network_id());
        assert_eq!(first.latest(), second.latest());
        assert_eq!(first.latest().height(), 2);
        let checkpoint = first.checkpoint();
        assert_eq!(checkpoint.height(), 2);
        let restored =
            SumeragiFinalityCheckpoint::decode_canonical(&checkpoint.encode_canonical().unwrap())
                .unwrap();
        verify_checkpoint_page(
            first.network_id(),
            &restored,
            std::slice::from_ref(first.latest()),
            4,
            4 * 1024 * 1024,
        )
        .unwrap();
        let mut changed = first.latest().clone();
        changed.committee[0].proof_of_possession[0] ^= 1;
        assert!(
            verify_checkpoint_page(
                first.network_id(),
                &restored,
                &[changed],
                4,
                4 * 1024 * 1024
            )
            .is_err()
        );
        let foreign_chain = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &first.network_id(),
            "other chain",
        );
        assert!(foreign_chain.is_err());
    }
}
