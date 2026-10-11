//! Genuine native BLS certificates over explicitly synthetic execution results.
//! These portable verifier fixtures do not execute World, custody, DKG or Pasta application seals.
use super::*;
use halo2curves::{
    group::{Curve, GroupEncoding},
    pasta::{Fp, Fq, Pallas, Vesta},
};
use iroha_crypto::{
    Algorithm, Hash, KeyPair, Signature, SignatureOf, bls_normal_aggregate_signatures,
    bls_normal_pop_prove,
};
use iroha_data_model::{
    account::AccountId,
    block::{CommitCertificate, builder::BlockBuilder, decode_framed_signed_block},
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconPulseContextV1,
    },
    isi::{InstructionBox, Log, RegisterPeerWithPop, SetParameter, kagemusha_v1::*},
    level::Level,
    parameter::{
        CustomParameter, Parameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            SumeragiNposParameters, consensus_metadata,
        },
    },
    sumeragi::{
        SumeragiFootprint, SumeragiStatus,
        epoch::{
            BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorCommitteeMemberV1,
            ValidatorEpochAuthorizationV1, ValidatorEpochBoundaryV1, ValidatorEpochContextV1,
            ValidatorEpochDecisionV1,
        },
    },
    sumeragi_finality::{
        ChainParamsRecord, ExecutionCommitment, ExecutionResultCommitment, NativeLaneStateProof,
        ScheduleOutcome, ScheduledConfig, SumeragiFinalityAttestationBody, chain_hash, core_epoch,
        genesis_epoch, global_threshold_beacon_npos_successor_seed_v1,
        global_threshold_beacon_pulse_id_v1, global_threshold_beacon_pulse_payload_v1,
        test_fixtures::{NativeFinalityFixture, author_payload},
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_sumeragi::{
    message::{AttestationSignature, BlockHeader as CoreHeader, Qc, ResultWitness, VoteKind},
    preimage::{TAG_PAY, block_hash_preimage},
    types::{AggregateSignature, Bitmap, ChainParams, ControlWitness, Hash32},
};
use norito::codec::Encode as _;
use std::{cell::RefCell, collections::BTreeSet, ops::Range, time::Duration};

const SIZES: [usize; 3] = [4, 7, 10];
const CHALLENGE: [u8; 32] = [0xC1; 32];
const CHAIN: &str = "deployment-native-finality";
fn nz(height: u64) -> NonZeroU64 {
    NonZeroU64::new(height).unwrap()
}
fn key(index: usize) -> KeyPair {
    KeyPair::from_seed(
        Hash::new(format!("deploy-native-{index}"))
            .as_ref()
            .to_vec(),
        Algorithm::BlsNormal,
    )
}
fn peer(key: &KeyPair) -> PeerId {
    PeerId::new(key.public_key().clone())
}
fn ordered_keys(range: Range<usize>) -> Vec<KeyPair> {
    let mut keys: Vec<_> = range.map(key).collect();
    keys.sort_by_key(|k| k.public_key().try_to_bytes().unwrap().1.to_vec());
    keys
}
fn validators(keys: &[KeyPair]) -> Vec<FinalityValidator> {
    keys.iter()
        .map(|k| FinalityValidator {
            public_key: k.public_key().clone(),
            proof_of_possession: bls_normal_pop_prove(k.private_key()).unwrap(),
        })
        .collect()
}
fn pasta(keys: &[KeyPair], generation: u64) -> Vec<KagemushaMintFinalityValidatorKeysV1> {
    keys.iter()
        .enumerate()
        .map(|(index, k)| {
            let n = generation * 32 + index as u64 + 1;
            KagemushaMintFinalityValidatorKeysV1 {
                validator: peer(k),
                eq_proof_public_key: (Pallas::generator() * Fq::from(n))
                    .to_affine()
                    .to_bytes()
                    .as_ref()
                    .try_into()
                    .unwrap(),
                ep_proof_public_key: (Vesta::generator() * Fp::from(n))
                    .to_affine()
                    .to_bytes()
                    .as_ref()
                    .try_into()
                    .unwrap(),
            }
        })
        .collect()
}
fn block(proof: &SumeragiFinalityProof) -> SignedBlock {
    decode_framed_signed_block(&proof.block_wire).unwrap()
}
fn result(proof: &SumeragiFinalityProof) -> ExecutionResultCommitment {
    ExecutionResultCommitment::decode(block(proof).commit_certificate().unwrap().result_preimage())
        .unwrap()
}
fn core(proof: &SumeragiFinalityProof) -> CoreHeader {
    norito::decode_canonical(
        block(proof)
            .commit_certificate()
            .unwrap()
            .consensus_header(),
    )
    .unwrap()
}
/// Committee seat indices in certificate bitmap form.
fn seats(range: impl IntoIterator<Item = usize>) -> Vec<u32> {
    range
        .into_iter()
        .map(|seat| u32::try_from(seat).unwrap())
        .collect()
}
fn sign_qc(qc: &mut Qc, keys: &[KeyPair], indices: &[u32]) {
    qc.signers = Bitmap::from_indices(keys.len(), indices.iter().copied()).unwrap();
    let signatures: Vec<_> = indices
        .iter()
        .map(|i| Signature::try_new(keys[*i as usize].private_key(), &qc.preimage()).unwrap())
        .collect();
    qc.agg_sig = AggregateSignature(
        bls_normal_aggregate_signatures(
            &signatures
                .iter()
                .map(Signature::payload)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
}
fn replace_certificate(
    proof: &mut SumeragiFinalityProof,
    header: &CoreHeader,
    qc: &Qc,
    result: &ExecutionResultCommitment,
) {
    let mut b = block(proof);
    let availability = b.commit_certificate().unwrap().availability().to_vec();
    b.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        norito::encode_canonical(header).unwrap(),
        norito::encode_canonical(qc).unwrap(),
        result.preimage().unwrap(),
        availability,
    )));
    proof.block_wire = b.encode_wire().unwrap();
}
struct Epoch {
    keys: Vec<KeyPair>,
    context: ValidatorEpochContextV1,
}
struct Chain {
    anchor: GenesisAnchor,
    epochs: Vec<Epoch>,
    proofs: Vec<SumeragiFinalityProof>,
}
impl Chain {
    fn constant(size: usize, tip: u64) -> Self {
        Self::new(&[(0..size, tip + 3)], tip)
    }
    fn new(ranges: &[(Range<usize>, u64)], tip: u64) -> Self {
        let keys = ordered_keys(ranges[0].0.clone());
        let authority = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let metadata = ConsensusHandshakeMetadata {
            mode: SumeragiConsensusMode::Npos,
            block_cadence_ms: nz(1000),
            wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
            consensus_fingerprint: ConsensusFingerprint::new([0x71; 32]),
            kagemusha_mint_finality: KagemushaMintFinalityGenesisParametersV1 {
                authority_generation: KagemushaMintFinalityAuthorityGenerationTemplateV1 {
                    version: 1,
                    generation: 0,
                    validators: pasta(&keys, 0),
                },
            },
            sumeragi_context:
                iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
        };
        let mut instructions: Vec<InstructionBox> = validators(&keys)
            .into_iter()
            .map(|v| {
                RegisterPeerWithPop::new(PeerId::new(v.public_key), v.proof_of_possession).into()
            })
            .collect();
        instructions.push(
            SetParameter::new(Parameter::Custom(CustomParameter::new(
                consensus_metadata::handshake_meta_id(),
                iroha_primitives::json::Json::new(metadata),
            )))
            .into(),
        );
        let npos = SumeragiNposParameters {
            max_validators: 31,
            epoch_length_blocks: nz(ranges[0].1),
            evidence_horizon_blocks: 1,
            slashing_delay_blocks: 1,
            ..Default::default()
        };
        instructions
            .push(SetParameter::new(Parameter::Custom(npos.into_custom_parameter())).into());
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
        let network = NetworkId::from_genesis_hash(genesis.hash());
        let context = genesis_epoch(&genesis).unwrap();
        let mut epochs = vec![Epoch { keys, context }];
        for (range, end) in &ranges[1..] {
            let keys = ordered_keys(range.clone());
            let previous = &epochs.last().unwrap().context;
            let retained = validators(&keys)
                .iter()
                .map(|v| &v.public_key)
                .eq(previous.committee.iter().map(|v| v.validator.public_key()));
            let generation = previous.authority.generation + u64::from(!retained);
            let authority = if retained {
                previous.authority.clone()
            } else {
                KagemushaMintFinalityAuthorityGenerationV1 {
                    version: 1,
                    network_id: network,
                    generation,
                    validators: pasta(&keys, generation),
                }
            };
            let authorization = ValidatorEpochAuthorizationV1 {
                epoch: previous.authorization.epoch + 1,
                first_height: previous.authorization.last_height + 1,
                last_height: *end,
                authority_generation: generation,
                authority_id: authority.authority_id().unwrap(),
                beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                    session_id: [7; 32],
                    transcript_hash: [8; 32],
                }),
                previous_authorization_id: previous.authorization.authorization_id().unwrap(),
                transition_id: if retained {
                    [0; 32]
                } else {
                    [u8::try_from(generation).unwrap(); 32]
                },
                decision: if retained {
                    ValidatorEpochDecisionV1::Retain
                } else {
                    ValidatorEpochDecisionV1::Activate
                },
                ..previous.authorization
            };
            let committee = validators(&keys)
                .into_iter()
                .map(|v| ValidatorCommitteeMemberV1 {
                    validator: PeerId::new(v.public_key),
                    proof_of_possession: v.proof_of_possession,
                })
                .collect();
            epochs.push(Epoch {
                keys,
                context: ValidatorEpochContextV1 {
                    authority,
                    authorization,
                    committee,
                    leader_seed: [9; 32],
                    ..previous.clone()
                },
            });
        }
        let anchor = GenesisAnchor {
            network_id: network,
            chain_id: CHAIN.into(),
            genesis: genesis.clone(),
            validators: validators(&epochs[0].keys),
        };
        let mut chain = Self {
            anchor,
            epochs,
            proofs: vec![],
        };
        let mut native =
            SumeragiFinalityVerifier::new(&genesis, CHAIN, chain.anchor.validators.clone())
                .unwrap();
        for height in 1..=tip {
            let index = chain
                .epochs
                .iter()
                .position(|e| {
                    height >= e.context.authorization.first_height
                        && height <= e.context.authorization.last_height
                })
                .unwrap();
            let mut b = if height == 1 {
                genesis.clone()
            } else {
                let mut builder = BlockBuilder::new(BlockHeader::new(
                    nz(height),
                    Some(chain.proof(height - 1).block_header.hash()),
                    None,
                    height,
                    0,
                ));
                let mut tx = TransactionBuilder::new(
                    network,
                    AccountId::new(authority.public_key().clone()),
                    FeePaymentIntent::authority(vec![], None),
                );
                tx.set_creation_time(Duration::from_millis(height));
                builder.push_transaction(
                    tx.with_instructions([Log::new(
                        Level::INFO,
                        format!("native fixture {height}"),
                    )])
                    .sign(authority.private_key()),
                );
                builder.build(iroha_data_model::block::BlockSignatures::default())
            };
            NativeFinalityFixture::install_network_results(&mut b, vec![Ok(Vec::default())]);
            let context = chain.epochs[index].context.clone();
            let parent = height
                .checked_sub(1)
                .filter(|h| *h > 0)
                .map(|h| chain.proof(h).clone());
            let parent_hash = parent.as_ref().map_or(Hash32([1; 32]), |p| {
                if p.height() == 1 {
                    Hash32(Hash::from(p.block_header.hash()).into())
                } else {
                    chain_hash(&block_hash_preimage(&core(p)))
                }
            });
            let parent_result = parent
                .as_ref()
                .map_or(Hash32([1; 32]), |p| result(p).result().unwrap());
            let boundary = if height == context.authorization.last_height {
                let pulse = result(parent.as_ref().unwrap()).beacon.unwrap();
                chain.epochs[index + 1].context.leader_seed =
                    global_threshold_beacon_npos_successor_seed_v1(
                        &pulse,
                        height,
                        context.authorization.epoch + 1,
                    );
                Some(ValidatorEpochBoundaryV1 {
                    version: 1,
                    height,
                    predecessor_context_id: context.context_id().unwrap(),
                    selection_anchor: parent.as_ref().unwrap().block_header.hash(),
                    next: chain.epochs[index + 1].context.clone(),
                    preparation: None,
                })
            } else {
                None
            };
            let authorized = boundary.as_ref().map_or(&context, |b| &b.next);
            let params = ChainParamsRecord::from_core(&ChainParams::default());
            let slot = |h| {
                if h <= authorized.authorization.last_height {
                    ScheduledSlot::Ready(ScheduledConfig {
                        height: h,
                        epoch: authorized.clone(),
                        params,
                    })
                } else {
                    ScheduledSlot::PendingBoundary {
                        height: h,
                        boundary_height: authorized.authorization.last_height,
                        predecessor_context_id: authorized.context_id().unwrap(),
                        params,
                    }
                }
            };
            let schedule = ScheduleOutcome {
                height,
                current: context.clone(),
                next: slot(height + 1),
                after_next: slot(height + 2),
                boundary,
            };
            let beacon = if height > 1 && height + 1 == context.authorization.last_height {
                // The QC certifies this synthetic execution's public pulse. Threshold session/DKG
                // execution is deliberately outside this portable-finality fixture's claim.
                let beacon_key = KeyPair::from_seed(vec![77; 32], Algorithm::BlsSmall);
                let mut pulse = FinalizedGlobalThresholdBeaconPulseV1 {
                    version: 1,
                    network_id: network,
                    session_id: [7; 32],
                    roster_hash: [6; 32],
                    transcript_hash: [8; 32],
                    context: GlobalThresholdBeaconPulseContextV1 {
                        instance: native.instance().0,
                        epoch: context.authorization.epoch,
                        epoch_context_id: context.context_id().unwrap(),
                        parent_consensus_hash: parent_hash.0,
                        parent_result: parent_result.0,
                    },
                    height,
                    round: 0,
                    finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
                        height: height - 1,
                        block_hash: parent.as_ref().unwrap().block_header.hash(),
                    },
                    signature: [0; 48],
                    seed: [0; 32],
                    pulse_id: [0; 32],
                };
                pulse.signature = Signature::try_new(
                    beacon_key.private_key(),
                    &global_threshold_beacon_pulse_payload_v1(&pulse),
                )
                .unwrap()
                .payload()
                .try_into()
                .unwrap();
                pulse.seed = Hash::new(pulse.signature).into();
                pulse.pulse_id = global_threshold_beacon_pulse_id_v1(&pulse, pulse.seed);
                Some(pulse)
            } else {
                None
            };
            let (len, hash) = b.executed_block_wire_identity().unwrap();
            let (native_lanes, ordinary_root) =
                NativeLaneStateProof::empty_for_testing(network, height);
            let commitment = ExecutionResultCommitment::new(
                height,
                ExecutionCommitment {
                    parent_state_root: Hash::new(b"synthetic parent"),
                    post_state_root: ordinary_root,
                    ordinary_writes_root: ordinary_root,
                    kagemusha_top_up_root: None,
                    kagemusha_top_up_count: 0,
                    parent_world_state_root: Hash::new(b"synthetic parent world"),
                    world_state_root: Hash::new(b"synthetic world"),
                    event_commitment: None,
                    executed_block_wire_len: len,
                    executed_block_wire_hash: hash,
                    transaction_input_commitment: b.network_input_merkle_commitment(),
                    transaction_output_commitment: b.output_merkle_commitment(),
                },
                schedule,
                beacon,
                native_lanes,
            )
            .unwrap();
            let certificate = if height == 1 {
                CommitCertificate::from_untrusted_parts(
                    vec![],
                    vec![],
                    commitment.preimage().unwrap(),
                    vec![],
                )
            } else {
                let payload = b
                    .canonical_resultless_proposal()
                    .expect("valid original proposal")
                    .encode_wire()
                    .unwrap();
                let header = CoreHeader {
                    instance: native.instance(),
                    epoch: core_epoch(&context).unwrap().id,
                    height,
                    origin_view: 0,
                    parent_hash,
                    parent_result,
                    payload_hash: Hash32(Hash::new_from_chunks(&[TAG_PAY, &payload]).into()),
                    availability_digest: Hash32::ZERO,
                    payload_len: payload.len().try_into().unwrap(),
                    proposer: 0,
                    skipped_leaders: vec![],
                    control_witness: ControlWitness::empty(),
                    attest: commitment.schedule.boundary.is_some(),
                };
                let keys = &chain.epochs[index].keys;
                let parent_decision = native
                    .verify_retained_decision(parent.as_ref().unwrap())
                    .unwrap();
                let ScheduledSlot::Ready(scheduled) = &parent_decision.commitment().schedule.next
                else {
                    panic!("fixture parent must authorize the proposed height");
                };
                assert_eq!(scheduled.height, height);
                let config = scheduled.height_config().unwrap();
                let budget = iroha_allocation::AllocationBudget::new(128 * 1024 * 1024);
                let authored = author_payload(
                    header,
                    &payload,
                    &config,
                    &budget,
                    &validators(keys),
                    &keys[0],
                );
                let header = authored.body.header();
                let q = CommitteeSize::new(keys.len()).unwrap().quorum();
                let mut qc = Qc {
                    kind: VoteKind::Commit,
                    instance: header.instance,
                    epoch: header.epoch,
                    height,
                    view: 0,
                    block_hash: chain_hash(&block_hash_preimage(header)),
                    result: commitment.result().unwrap(),
                    attest: header.attest,
                    signers: Bitmap::new(keys.len()),
                    agg_sig: AggregateSignature([0; 96]),
                    attestations: vec![],
                    attestation_witness: None,
                };
                if qc.attest {
                    // Application-specific Pasta seal verification is not performed by this verifier.
                    qc.attestations =
                        vec![
                            AttestationSignature::try_from_slice(b"synthetic application seal")
                                .unwrap();
                            q
                        ];
                    qc.attestation_witness = Some(
                        ResultWitness::from_untrusted(commitment.preimage().unwrap()).unwrap(),
                    );
                }
                sign_qc(&mut qc, keys, &seats(0..q));
                CommitCertificate::from_untrusted_parts(
                    norito::encode_canonical(header).unwrap(),
                    norito::encode_canonical(&qc).unwrap(),
                    commitment.preimage().unwrap(),
                    norito::encode_canonical(authored.body.availability()).unwrap(),
                )
            };
            b.set_commit_certificate(Some(certificate));
            let proof = SumeragiFinalityProof {
                block_header: b.header(),
                block_wire: b.encode_wire().unwrap(),
                committee: validators(&chain.epochs[index].keys),
            };
            native.verify(&proof).unwrap();
            chain.proofs.push(proof);
        }
        chain
    }
    fn proof(&self, height: u64) -> &SumeragiFinalityProof {
        &self.proofs[usize::try_from(height - 1).unwrap()]
    }
    fn epoch(&self, height: u64) -> &Epoch {
        self.epochs
            .iter()
            .find(|e| {
                height >= e.context.authorization.first_height
                    && height <= e.context.authorization.last_height
            })
            .unwrap()
    }
    fn verifier(&self) -> FinalityVerifier {
        FinalityVerifier::from_genesis(&self.anchor, self.proof(1)).unwrap()
    }
    fn verifier_at(&self, height: u64) -> FinalityVerifier {
        let mut v = self.verifier();
        v.advance(&Source::new(self), self.proof(height)).unwrap();
        v
    }
    fn attest(&self, k: &KeyPair, height: u64) -> SumeragiFinalityAttestation {
        let body = SumeragiFinalityAttestationBody {
            observed_at_unix_ms: 1_000_000,
            challenge: CHALLENGE,
            network_id: self.anchor.network_id,
            node_id: peer(k),
            node_fingerprint: Hash::new(peer(k).encode()),
            build_fingerprint: Hash::new(b"build"),
            config_fingerprint: Hash::new(b"config"),
            genesis_block_hash: self.anchor.genesis.hash(),
            genesis_finality_proof: self.proof(1).clone(),
            status: SumeragiStatus {
                protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
                config_fingerprint: Hash::new(b"config"),
                beacon_horizon: None,
                instance: SumeragiFinalityVerifier::new(
                    &self.anchor.genesis,
                    CHAIN,
                    self.anchor.validators.clone(),
                )
                .unwrap()
                .instance()
                .0,
                height: height + 1,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: height,
                applied_height: height,
                awaiting: false,
                signer: Some(k.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: SumeragiFootprint::default(),
            },
            finality_proof: self.proof(height).clone(),
        };
        let signature = SignatureOf::try_from_hash(k.private_key(), body.signing_hash()).unwrap();
        SumeragiFinalityAttestation { body, signature }
    }
    fn alternate(&self, height: u64) -> SumeragiFinalityProof {
        let mut p = self.proof(height).clone();
        let h = core(&p);
        let r = result(&p);
        let mut qc: Qc =
            norito::decode_canonical(block(&p).commit_certificate().unwrap().commit_qc()).unwrap();
        let keys = &self.epoch(height).keys;
        let q = CommitteeSize::new(keys.len()).unwrap().quorum();
        sign_qc(&mut qc, keys, &seats(1..=q));
        replace_certificate(&mut p, &h, &qc, &r);
        p
    }
}
struct Source<'a> {
    chain: &'a Chain,
    /// Highest height the source serves; above it every request fails.
    served: u64,
    proofs: RefCell<BTreeMap<u64, SumeragiFinalityProof>>,
    tips: BTreeMap<PeerId, u64>,
    faults: BTreeSet<PeerId>,
    substitutions: BTreeMap<PeerId, PeerId>,
    attestation_overrides: BTreeMap<PeerId, SumeragiFinalityAttestation>,
    proof_calls: RefCell<Vec<u64>>,
    reads: RefCell<Vec<PeerId>>,
}
impl<'a> Source<'a> {
    fn new(chain: &'a Chain) -> Self {
        Self {
            chain,
            served: chain.proofs.len() as u64,
            proofs: RefCell::new(BTreeMap::new()),
            tips: BTreeMap::new(),
            faults: BTreeSet::new(),
            substitutions: BTreeMap::new(),
            attestation_overrides: BTreeMap::new(),
            proof_calls: RefCell::new(vec![]),
            reads: RefCell::new(vec![]),
        }
    }
}
impl FinalitySource for Source<'_> {
    type Error = std::io::Error;
    fn finality_proof(&self, height: NonZeroU64) -> Result<SumeragiFinalityProof, Self::Error> {
        self.proof_calls.borrow_mut().push(height.get());
        if let Some(proof) = self.proofs.borrow().get(&height.get()) {
            return Ok(proof.clone());
        }
        if height.get() > self.served {
            return Err(std::io::Error::other("height not served"));
        }
        Ok(self.chain.proof(height.get()).clone())
    }
    fn latest_attestation(
        &self,
        p: &PeerId,
        c: &[u8; 32],
    ) -> Result<SumeragiFinalityAttestation, Self::Error> {
        assert_eq!(*c, CHALLENGE);
        self.reads.borrow_mut().push(p.clone());
        if self.faults.contains(p) {
            return Err(std::io::Error::other("offline"));
        }
        if let Some(attestation) = self.attestation_overrides.get(p) {
            return Ok(attestation.clone());
        }
        let actual = self.substitutions.get(p).unwrap_or(p);
        let k = self
            .chain
            .epochs
            .iter()
            .flat_map(|e| &e.keys)
            .find(|k| peer(k) == *actual)
            .unwrap();
        Ok(self.chain.attest(
            k,
            *self
                .tips
                .get(p)
                .unwrap_or(&(self.chain.proofs.len() as u64)),
        ))
    }
}
fn resign(a: &mut SumeragiFinalityAttestation, k: &KeyPair) {
    a.signature = SignatureOf::try_from_hash(k.private_key(), a.body.signing_hash()).unwrap();
}
fn commit_qc(proof: &SumeragiFinalityProof) -> Qc {
    norito::decode_canonical(block(proof).commit_certificate().unwrap().commit_qc()).unwrap()
}
/// Name `named` in the signer bitmap but aggregate the signatures of `signers` over `message`.
fn forge_qc(qc: &mut Qc, members: usize, named: &[u32], signers: &[&KeyPair], message: &[u8]) {
    qc.signers = Bitmap::from_indices(members, named.iter().copied()).unwrap();
    let signatures: Vec<_> = signers
        .iter()
        .map(|k| Signature::try_new(k.private_key(), message).unwrap())
        .collect();
    qc.agg_sig = AggregateSignature(
        bls_normal_aggregate_signatures(
            &signatures
                .iter()
                .map(Signature::payload)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
}
/// `context` with its equal-vote committee and paired Pasta authority replaced by `keys`.
fn with_committee(context: &ValidatorEpochContextV1, keys: &[KeyPair]) -> ValidatorEpochContextV1 {
    let authority = KagemushaMintFinalityAuthorityGenerationV1 {
        validators: pasta(keys, 900),
        ..context.authority.clone()
    };
    let authorization = ValidatorEpochAuthorizationV1 {
        authority_id: authority.authority_id().unwrap(),
        ..context.authorization
    };
    ValidatorEpochContextV1 {
        authority,
        authorization,
        committee: validators(keys)
            .into_iter()
            .map(|v| ValidatorCommitteeMemberV1 {
                validator: PeerId::new(v.public_key),
                proof_of_possession: v.proof_of_possession,
            })
            .collect(),
        ..context.clone()
    }
}
/// Re-certify `proof`'s block under `context` with an exact quorum of `keys`. The result is a
/// self-consistent certificate of the committee it names; only the authenticated schedule
/// can tell whether that committee governs the height.
fn recertify(
    proof: &SumeragiFinalityProof,
    context: &ValidatorEpochContextV1,
    keys: &[KeyPair],
) -> SumeragiFinalityProof {
    let mut p = proof.clone();
    let mut r = result(&p);
    r.schedule.current = context.clone();
    for slot in [&mut r.schedule.next, &mut r.schedule.after_next] {
        if let ScheduledSlot::Ready(config) = slot {
            config.epoch = context.clone();
        }
    }
    let mut h = core(&p);
    h.epoch = core_epoch(context).unwrap().id;
    let mut qc = commit_qc(&p);
    qc.epoch = h.epoch;
    qc.block_hash = chain_hash(&block_hash_preimage(&h));
    qc.result = r.result().unwrap();
    let q = CommitteeSize::new(keys.len()).unwrap().quorum();
    sign_qc(&mut qc, keys, &seats(0..q));
    replace_certificate(&mut p, &h, &qc, &r);
    p.committee = validators(keys);
    p
}
/// `member`'s genuinely signed statement of a tip at `height` whose certificate is internally
/// consistent, but signed by a foreign committee that the certificate itself names.
fn fake_claim(chain: &Chain, member: &KeyPair, height: u64) -> SumeragiFinalityAttestation {
    let context = &chain.epoch(height).context;
    let foreign = ordered_keys(200..200 + context.committee.len());
    let mut attestation = chain.attest(member, height);
    attestation.body.finality_proof = recertify(
        chain.proof(height),
        &with_committee(context, &foreign),
        &foreign,
    );
    resign(&mut attestation, member);
    attestation
}

#[test]
fn committee_size_accepts_exact_3f_plus_1_from_4_to_31() {
    for n in 0..=140 {
        assert_eq!(
            CommitteeSize::new(n).is_ok(),
            (4..=31).contains(&n) && (n - 1) % 3 == 0
        );
    }
    for n in SIZES {
        let s = CommitteeSize::new(n).unwrap();
        assert_eq!(s.members(), n);
        assert_eq!(s.quorum(), 2 * s.faults() + 1);
    }
}
#[test]
fn genesis_anchor_pins_signed_body_ordered_roster_network_and_chain() {
    for size in SIZES {
        let chain = Chain::constant(size, 2);
        let v = chain.verifier();
        assert_eq!(v.committee_size().members(), size);
        assert_eq!(v.checkpoint().height(), 1);
        assert_eq!(v.checkpoint().network_id(), chain.anchor.network_id);
        assert_eq!(v.checkpoint().chain_id(), CHAIN);
        let mut bad = chain.anchor.clone();
        bad.validators.swap(0, 1);
        assert!(FinalityVerifier::from_genesis(&bad, chain.proof(1)).is_err());
        let mut bad = chain.anchor.clone();
        bad.validators[0].proof_of_possession[0] ^= 1;
        assert!(FinalityVerifier::from_genesis(&bad, chain.proof(1)).is_err());
        let mut bad = chain.anchor.clone();
        bad.network_id =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")));
        assert!(matches!(
            FinalityVerifier::from_genesis(&bad, chain.proof(1)),
            Err(FinalityError::WrongNetwork { .. })
        ));
        assert!(FinalityVerifier::from_genesis(&chain.anchor, chain.proof(2)).is_err());
    }
}
#[test]
fn advance_within_epoch_fetches_every_missing_successor() {
    for size in SIZES {
        let c = Chain::constant(size, 6);
        let s = Source::new(&c);
        let mut v = c.verifier();
        assert_eq!(v.advance(&s, c.proof(6)).unwrap(), 4);
        assert_eq!(*s.proof_calls.borrow(), [2, 3, 4, 5]);
        assert_eq!(v.checkpoint().height(), 6);
    }
}
#[test]
fn advance_is_idempotent_and_never_moves_backward() {
    let c = Chain::constant(4, 4);
    let s = Source::new(&c);
    let mut v = c.verifier_at(4);
    let cp = v.checkpoint().clone();
    assert_eq!(v.advance(&s, c.proof(4)).unwrap(), 0);
    assert!(s.proof_calls.borrow().is_empty());
    assert!(matches!(
        v.advance(&s, c.proof(3)),
        Err(FinalityError::StaleTip { .. })
    ));
    assert_eq!(*v.checkpoint(), cp);
    assert_eq!(v.advance(&s, &c.alternate(4)).unwrap(), 0);
}
#[test]
fn advance_verifies_contiguous_four_seven_four_and_non_four_committees() {
    let c = Chain::new(&[(0..4, 3), (0..7, 6), (3..7, 9)], 8);
    let s = Source::new(&c);
    let mut v = c.verifier();
    assert_eq!(v.advance(&s, c.proof(8)).unwrap(), 6);
    assert_eq!(*s.proof_calls.borrow(), [2, 3, 4, 5, 6, 7]);
    assert_eq!(v.committee_size().members(), 4);
    let c = Chain::new(&[(0..7, 3), (0..10, 6), (0..7, 9)], 8);
    assert_eq!(c.verifier_at(8).committee_size().members(), 7);
}
#[test]
fn retained_generations_advance_scheduling_epoch_without_key_substitution() {
    let c = Chain::new(&[(0..4, 3), (0..4, 6), (0..4, 9)], 8);
    assert_eq!(c.epochs[0].context.authority, c.epochs[2].context.authority);
    assert_ne!(
        c.epochs[0].context.context_id().unwrap(),
        c.epochs[2].context.context_id().unwrap()
    );
    assert_eq!(c.verifier_at(8).checkpoint().height(), 8);
}
#[test]
fn advance_rejects_missing_or_reordered_successors_atomically() {
    let c = Chain::constant(4, 5);
    for actual in [1, 3, 4] {
        let s = Source::new(&c);
        s.proofs.borrow_mut().insert(2, c.proof(actual).clone());
        let mut v = c.verifier();
        let cp = v.checkpoint().clone();
        assert!(matches!(
            v.advance(&s, c.proof(5)),
            Err(FinalityError::UnexpectedHeight { expected: 2, .. })
        ));
        assert_eq!(*v.checkpoint(), cp);
    }
}
#[test]
fn exact_quorum_requires_distinct_members_and_valid_possession_proofs() {
    for size in SIZES {
        let chain = Chain::constant(size, 2);
        let q = CommitteeSize::new(size).unwrap().quorum();
        for count in [q - 1, q + 1] {
            let mut p = chain.proof(2).clone();
            let h = core(&p);
            let r = result(&p);
            let mut qc: Qc =
                norito::decode_canonical(block(&p).commit_certificate().unwrap().commit_qc())
                    .unwrap();
            sign_qc(&mut qc, &chain.epoch(2).keys, &seats(0..count));
            replace_certificate(&mut p, &h, &qc, &r);
            assert!(chain.verifier().advance(&Source::new(&chain), &p).is_err());
        }
        let mut p = chain.proof(2).clone();
        p.committee[1] = p.committee[0].clone();
        assert!(chain.verifier().advance(&Source::new(&chain), &p).is_err());
        let mut p = chain.proof(2).clone();
        p.committee[0].proof_of_possession[0] ^= 1;
        assert!(chain.verifier().advance(&Source::new(&chain), &p).is_err());
        let mut p = chain.proof(2).clone();
        p.committee.swap(0, 1);
        assert!(chain.verifier().advance(&Source::new(&chain), &p).is_err());
        assert!(Bitmap::from_indices(size, seats([size])).is_none());
    }
}
#[test]
fn advance_rejects_mutated_proofs_and_keeps_original_checkpoint() {
    let chain = Chain::constant(4, 4);
    for mutation in 0..7 {
        let mut p = chain.proof(4).clone();
        let mut h = core(&p);
        let mut r = result(&p);
        let mut qc: Qc =
            norito::decode_canonical(block(&p).commit_certificate().unwrap().commit_qc()).unwrap();
        match mutation {
            0 => h.parent_result.0[0] ^= 1,
            1 => h.instance.0[0] ^= 1,
            2 => h.epoch.context.0[0] ^= 1,
            3 => qc.agg_sig.0[0] ^= 1,
            4 => qc.result.0[0] ^= 1,
            5 => r.execution.parent_state_root = Hash::new(b"changed"),
            _ => h.payload_hash.0[0] ^= 1,
        }
        replace_certificate(&mut p, &h, &qc, &r);
        let mut v = chain.verifier();
        let cp = v.checkpoint().clone();
        assert!(
            v.advance(&Source::new(&chain), &p).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(*v.checkpoint(), cp);
    }
}
#[test]
fn altered_boundary_cannot_select_a_foreign_committee_or_freshness_seed() {
    let chain = Chain::new(&[(0..4, 3), (0..7, 6), (3..7, 9)], 5);
    for mutation in 0..3 {
        let mut p = chain.proof(3).clone();
        let h = core(&p);
        let mut r = result(&p);
        let mut qc: Qc =
            norito::decode_canonical(block(&p).commit_certificate().unwrap().commit_qc()).unwrap();
        let b = r.schedule.boundary.as_mut().unwrap();
        match mutation {
            0 => b.next.leader_seed[0] ^= 1,
            1 => b.selection_anchor = HashOf::from_untyped_unchecked(Hash::new(b"wrong parent")),
            _ => b.predecessor_context_id[0] ^= 1,
        }
        // Re-sign the entire changed result. A genuine incumbent quorum is still insufficient
        // to bypass deterministic epoch/parent/pulse bindings.
        if let Some(b) = &r.schedule.boundary {
            for slot in [&mut r.schedule.next, &mut r.schedule.after_next] {
                if let ScheduledSlot::Ready(config) = slot {
                    config.epoch = b.next.clone();
                }
            }
        }
        qc.result = r.result().unwrap();
        sign_qc(&mut qc, &chain.epoch(3).keys, &[0, 1, 2]);
        replace_certificate(&mut p, &h, &qc, &r);
        let source = Source::new(&chain);
        source.proofs.borrow_mut().insert(3, p);
        let mut verifier = chain.verifier();
        let cp = verifier.checkpoint().clone();
        assert!(verifier.advance(&source, chain.proof(5)).is_err());
        assert_eq!(*verifier.checkpoint(), cp);
    }
}
#[test]
fn complete_native_checkpoint_roundtrips_and_requires_independent_network_and_chain() {
    let c = Chain::new(&[(0..4, 3), (0..7, 6), (3..7, 9)], 7);
    for h in 1..=7 {
        let v = c.verifier_at(h);
        let bytes = v.checkpoint().encode_canonical().unwrap();
        let cp = SumeragiFinalityCheckpoint::decode_canonical(&bytes).unwrap();
        assert_eq!(&cp, v.checkpoint());
        let resumed =
            FinalityVerifier::from_checkpoint(cp.clone(), c.anchor.network_id, CHAIN).unwrap();
        assert_eq!(resumed, v);
        assert!(
            FinalityVerifier::from_checkpoint(cp.clone(), c.anchor.network_id, "foreign-chain")
                .is_err()
        );
        assert!(
            FinalityVerifier::from_checkpoint(
                cp,
                NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign"))),
                CHAIN
            )
            .is_err()
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SumeragiFinalityCheckpoint::decode_canonical(&trailing).is_err());
        assert!(SumeragiFinalityCheckpoint::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
    }
}
#[test]
fn restart_retains_exact_previous_decision_but_refuses_older_prefix_claims() {
    let c = Chain::constant(4, 5);
    let cp = c.verifier_at(5).checkpoint().clone();
    let v = FinalityVerifier::from_checkpoint(cp, c.anchor.network_id, CHAIN).unwrap();
    let k = &c.epoch(5).keys[0];
    assert!(v.verify_attestation(&CHALLENGE, &c.attest(k, 4)).is_ok());
    assert!(matches!(
        v.verify_attestation(&CHALLENGE, &c.attest(k, 3)),
        Err(FinalityError::OutsideRetainedPrefix { .. })
    ));
}
#[test]
fn proof_count_and_byte_budgets_refuse_without_publishing_progress() {
    let c = Chain::constant(4, 4);
    let mut v = c.verifier();
    let cp = v.checkpoint().clone();
    let s = Source::new(&c);
    let mut claimed = c.proof(4).clone();
    claimed.block_header = BlockHeader::new(nz(u64::MAX), Some(cp.block_hash()), None, 4, 0);
    assert!(matches!(
        v.advance(&s, &claimed),
        Err(FinalityError::ResourceLimit("proof count"))
    ));
    assert!(s.proof_calls.borrow().is_empty());
    let mut budget = Budget {
        proofs: 4,
        bytes: c.proof(2).block_wire.len(),
    };
    assert!(matches!(
        v.advance_with_budget(&s, c.proof(4), &mut budget),
        Err(FinalityError::ResourceLimit("proof bytes"))
    ));
    assert_eq!(*v.checkpoint(), cp);
}
#[test]
fn attestations_require_exactly_distinct_current_members() {
    for size in SIZES {
        let c = Chain::constant(size, 3);
        let v = c.verifier_at(3);
        let q = v.committee_size().quorum();
        let all: Vec<_> = c.epoch(3).keys.iter().map(|k| c.attest(k, 3)).collect();
        assert_eq!(
            v.attestation_quorum(&CHALLENGE, &all).unwrap().verified(),
            size
        );
        assert!(v.attestation_quorum(&CHALLENGE, &all[..q - 1]).is_err());
        let mut duplicated = all[..q - 1].to_vec();
        duplicated.extend(vec![all[0].clone(); size]);
        assert!(v.attestation_quorum(&CHALLENGE, &duplicated).is_err());
        assert_eq!(
            v.attestation_quorum(&CHALLENGE, &all[..q])
                .unwrap()
                .verified(),
            q
        );
        let outsider = c.attest(&key(100), 3);
        assert!(matches!(
            v.verify_attestation(&CHALLENGE, &outsider),
            Err(FinalityError::NotInCommittee { .. })
        ));
    }
}
#[test]
fn attestations_bind_challenge_signature_network_status_and_runtime_identity() {
    let c = Chain::constant(4, 3);
    let v = c.verifier_at(3);
    let k = &c.epoch(3).keys[0];
    for mutation in 0..9 {
        let mut a = c.attest(k, 3);
        match mutation {
            0 => a.body.challenge = [8; 32],
            1 => {
                a.body.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"foreign"),
                ))
            }
            2 => a.body.status.applied_height = 2,
            3 => a.body.status.committed_height = 2,
            4 => a.body.status.instance[0] ^= 1,
            5 => a.body.node_fingerprint = Hash::new(b"other"),
            6 => a.body.status.signer = Some(key(100).public_key().clone()),
            7 => a.body.genesis_block_hash = HashOf::from_untyped_unchecked(Hash::new(b"foreign")),
            _ => a.body.config_fingerprint = Hash::new(b"changed after signing"),
        }
        if mutation != 8 {
            resign(&mut a, k);
        }
        assert!(
            v.verify_attestation(&CHALLENGE, &a).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(matches!(
        v.verify_attestation(&[0; 32], &c.attest(k, 3)),
        Err(FinalityError::ZeroChallenge)
    ));
}
#[test]
fn independent_certificate_witnesses_attest_same_authenticated_decision() {
    let c = Chain::constant(7, 4);
    let v = c.verifier_at(4);
    for h in [3, 4] {
        let k = &c.epoch(4).keys[0];
        let mut a = c.attest(k, h);
        a.body.finality_proof = c.alternate(h);
        resign(&mut a, k);
        assert!(v.verify_attestation(&CHALLENGE, &a).is_ok());
    }
}
#[test]
fn genuinely_signed_conflicting_result_is_rejected_even_one_block_behind() {
    let chain = Chain::constant(4, 5);
    let verifier = chain.verifier_at(5);
    for height in [4, 5] {
        let mut p = chain.proof(height).clone();
        let h = core(&p);
        let mut r = result(&p);
        r.execution.parent_state_root = Hash::new(b"conflicting execution");
        let mut qc: Qc =
            norito::decode_canonical(block(&p).commit_certificate().unwrap().commit_qc()).unwrap();
        qc.result = r.result().unwrap();
        sign_qc(&mut qc, &chain.epoch(height).keys, &[0, 1, 2]);
        replace_certificate(&mut p, &h, &qc, &r);
        assert!(p.decode_checked().is_ok());
        let member = &chain.epoch(5).keys[0];
        let mut attestation = chain.attest(member, height);
        attestation.body.finality_proof = p;
        resign(&mut attestation, member);
        assert!(
            verifier
                .verify_attestation(&CHALLENGE, &attestation)
                .is_err()
        );
    }
}
#[test]
fn future_attestation_requires_contiguous_advance() {
    let c = Chain::constant(4, 5);
    let v = c.verifier_at(3);
    assert!(matches!(
        v.verify_attestation(&CHALLENGE, &c.attest(&c.epoch(5).keys[0], 5)),
        Err(FinalityError::AheadOfCheckpoint { .. })
    ));
}
#[test]
fn observe_reads_every_member_and_promotes_only_fresh_quorum() {
    for size in SIZES {
        let c = Chain::constant(size, 4);
        let mut v = c.verifier();
        let s = Source::new(&c);
        let q = v.observe(&s, &CHALLENGE).unwrap();
        assert_eq!(q.verified(), size);
        assert_eq!(s.reads.borrow().len(), size);
        assert_eq!(*s.proof_calls.borrow(), [2, 3]);
        assert_eq!(v.checkpoint().height(), 4);
    }
}
#[test]
fn observe_follows_authenticated_rotation_and_counts_members_just_behind_boundary() {
    let c = Chain::new(&[(0..4, 3), (0..7, 6), (3..7, 9)], 7);
    let mut v = c.verifier();
    let s = Source::new(&c);
    assert_eq!(v.observe(&s, &CHALLENGE).unwrap().verified(), 4);
    assert_eq!(v.checkpoint().height(), 7);
    assert_eq!(
        s.reads.borrow().iter().collect::<BTreeSet<_>>().len(),
        s.reads.borrow().len()
    );
    let c = Chain::new(&[(0..4, 3), (0..7, 6), (3..7, 9)], 4);
    let mut v = c.verifier_at(3);
    let mut s = Source::new(&c);
    for k in &c.epoch(4).keys[..3] {
        s.tips.insert(peer(k), 3);
    }
    assert_eq!(v.observe(&s, &CHALLENGE).unwrap().verified(), 7);
    assert_eq!(v.checkpoint().height(), 4);
}
#[test]
fn observe_tolerates_f_faults_and_rolls_back_with_f_plus_one() {
    for size in SIZES {
        let c = Chain::constant(size, 4);
        let f = CommitteeSize::new(size).unwrap().faults();
        for faults in [f, f + 1] {
            let mut s = Source::new(&c);
            s.faults.extend(c.epoch(4).keys[..faults].iter().map(peer));
            let mut v = c.verifier();
            let cp = v.checkpoint().clone();
            let result = v.observe(&s, &CHALLENGE);
            if faults == f {
                assert_eq!(result.unwrap().verified(), size - f);
                assert_eq!(v.checkpoint().height(), 4);
            } else {
                assert!(matches!(
                    result,
                    Err(FinalityError::InsufficientAttestations(_))
                ));
                assert_eq!(*v.checkpoint(), cp);
            }
        }
    }
}
#[test]
fn observe_rejects_zero_challenge_and_substituted_nodes_without_advancing() {
    let c = Chain::constant(4, 4);
    let mut v = c.verifier();
    let cp = v.checkpoint().clone();
    let mut s = Source::new(&c);
    assert!(matches!(
        v.observe(&s, &[0; 32]),
        Err(FinalityError::ZeroChallenge)
    ));
    assert!(s.reads.borrow().is_empty());
    for k in &c.epoch(4).keys {
        s.substitutions.insert(peer(k), peer(&c.epoch(4).keys[0]));
    }
    assert!(v.observe(&s, &CHALLENGE).is_err());
    assert_eq!(*v.checkpoint(), cp);
}
#[test]
fn invalid_higher_tip_does_not_block_a_valid_lower_quorum() {
    let chain = Chain::constant(4, 5);
    let keys = &chain.epoch(4).keys;
    // One member claims H5 while the source answers H4 with a reordered proof. The other
    // members' own H4 proofs bridge that gap; the source is asked for each height once.
    for fake in [true, false] {
        let mut source = Source::new(&chain);
        for k in keys {
            source.tips.insert(peer(k), 4);
        }
        source.tips.insert(peer(&keys[0]), 5);
        if fake {
            source
                .attestation_overrides
                .insert(peer(&keys[0]), fake_claim(&chain, &keys[0], 5));
        }
        source.proofs.borrow_mut().insert(4, chain.proof(3).clone());
        let mut verifier = chain.verifier();
        let report = verifier.observe(&source, &CHALLENGE).unwrap();
        let (_, outcome) = report
            .peers
            .iter()
            .find(|(member, _)| *member == peer(&keys[0]))
            .unwrap();
        if fake {
            // The invalid H5 claim is rejected for its member alone.
            assert_eq!((report.verified(), verifier.checkpoint().height()), (3, 4));
            assert!(matches!(
                outcome,
                AttestationOutcome::Rejected(FinalityError::Native(_))
            ));
        } else {
            // A genuine H5 extends the prefix that the other members' H4 proofs reached.
            assert_eq!((report.verified(), verifier.checkpoint().height()), (4, 5));
            assert!(matches!(
                outcome,
                AttestationOutcome::Verified(tip) if tip.height.get() == 5
            ));
        }
        assert_eq!(*source.proof_calls.borrow(), [2, 3, 4]);
    }
}

#[test]
fn observation_keeps_original_verified_responses_across_boundary_reads() {
    for members in SIZES {
        let chain = Chain::new(&[(0..members, 3), (0..members, 20)], 5);
        let nodes = &chain.epoch(5).keys;
        let behind = CommitteeSize::new(members).unwrap().faults() + 1;
        let mut source = Source::new(&chain);
        source.tips.insert(peer(&nodes[0]), 2);
        for node in &nodes[1..behind] {
            source.tips.insert(peer(node), 3);
        }
        let mut verifier = chain.verifier();
        let report = verifier.observe(&source, &CHALLENGE).unwrap();
        assert_eq!(report.height.get(), 5);
        assert_eq!(report.verified(), members);
        assert_eq!(*source.proof_calls.borrow(), [2, 3, 4]);
        let mut heights = report
            .peers
            .iter()
            .filter_map(|(_, result)| match result {
                AttestationOutcome::Verified(tip) => Some(tip.height.get()),
                _ => None,
            })
            .collect::<Vec<_>>();
        heights.sort_unstable();
        assert_eq!(heights[0], 2);
        assert!(heights[1..behind].iter().all(|h| *h == 3));
        assert!(heights[behind..].iter().all(|h| *h == 5));
    }
}

#[test]
fn observation_does_not_promote_a_signed_conflict_from_an_earlier_verified_position() {
    let chain = Chain::new(&[(0..4, 3), (0..4, 20)], 5);
    let mut source = Source::new(&chain);
    let key = &chain.epoch(5).keys[0];
    let mut attestation = chain.attest(key, 2);
    let proof = &mut attestation.body.finality_proof;
    let header = core(proof);
    let mut commitment = result(proof);
    commitment.execution.parent_state_root = Hash::new(b"conflicting early result");
    let mut qc: Qc =
        norito::decode_canonical(block(proof).commit_certificate().unwrap().commit_qc()).unwrap();
    qc.result = commitment.result().unwrap();
    sign_qc(&mut qc, &chain.epoch(2).keys, &[0, 1, 2]);
    replace_certificate(proof, &header, &qc, &commitment);
    assert!(proof.decode_checked().is_ok());
    resign(&mut attestation, key);
    source.attestation_overrides.insert(peer(key), attestation);
    let report = chain.verifier().observe(&source, &CHALLENGE).unwrap();
    assert_eq!(report.verified(), 3);
    assert!(matches!(
        report
            .peers
            .iter()
            .find(|(p, _)| *p == peer(key))
            .unwrap()
            .1,
        AttestationOutcome::Rejected(_)
    ));
}

#[test]
fn observation_rejects_responses_older_than_the_previous_epoch() {
    let chain = Chain::new(&[(0..4, 3), (0..4, 6), (0..4, 20)], 8);
    let mut source = Source::new(&chain);
    source.tips.insert(peer(&chain.epoch(8).keys[0]), 2);
    let report = chain.verifier().observe(&source, &CHALLENGE).unwrap();
    assert_eq!(report.verified(), 3);
}

#[test]
fn native_result_decode_bounds_complete_committee_graphs_and_preserves_outer_limits() {
    for size in [4, 7, 10, 31] {
        let chain = Chain::constant(size, 2);
        let proof = chain.proof(2);
        let carrier = block(proof);
        let bytes = carrier.commit_certificate().unwrap().result_preimage();
        let decoded = ExecutionResultCommitment::decode(bytes).unwrap();
        assert_eq!(decoded.schedule.current.committee.len(), size);
        assert_eq!(decoded.preimage().unwrap(), bytes);
        assert!(ExecutionResultCommitment::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(ExecutionResultCommitment::decode(&trailing).is_err());
        let outer_refusal = norito::with_decode_limits(
            norito::DecodeLimits::new(96, bytes.len(), 8192, 0, 32),
            || Ok(ExecutionResultCommitment::decode(bytes)),
        );
        assert!(
            matches!(outer_refusal, Err(_) | Ok(Err(_))),
            "inner canonical policy cannot replace the caller's exhausted budget"
        );
    }
    let oversized = vec![0; iroha_data_model::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES + 1];
    assert!(matches!(
        ExecutionResultCommitment::decode(&oversized),
        Err(iroha_data_model::sumeragi_finality::CommitmentError::PreimageLength(_))
    ));
    // A boundary repeats complete target credentials in its exact atomic successor slots.
    let chain = Chain::new(&[(0..4, 3), (0..31, 6), (0..4, 9)], 5);
    let mut verifier = chain.verifier();
    verifier
        .advance(&Source::new(&chain), chain.proof(5))
        .unwrap();
    assert_eq!(verifier.committee_size().members(), 31);
}

#[test]
fn self_consistent_certificate_of_a_foreign_committee_is_rejected() {
    for size in SIZES {
        let chain = Chain::constant(size, 3);
        let foreign = ordered_keys(200..200 + size);
        let context = with_committee(&chain.epoch(2).context, &foreign);
        let proof = recertify(chain.proof(2), &context, &foreign);
        // Structurally, the proof is an exact quorum of the committee it names.
        proof.decode_checked().unwrap();
        let mut verifier = chain.verifier();
        let checkpoint = verifier.checkpoint().clone();
        assert!(matches!(
            verifier.advance(&Source::new(&chain), &proof),
            Err(FinalityError::Native(_))
        ));
        // As an intermediate successor it cannot carry the verifier to a genuine tip either.
        let source = Source::new(&chain);
        source.proofs.borrow_mut().insert(2, proof.clone());
        assert!(verifier.advance(&source, chain.proof(3)).is_err());
        assert_eq!(*verifier.checkpoint(), checkpoint);
        // Nor does a genuine member's statement count when it carries this certificate.
        let verifier = chain.verifier_at(2);
        let member = &chain.epoch(2).keys[0];
        let mut attestation = chain.attest(member, 2);
        attestation.body.finality_proof = proof;
        resign(&mut attestation, member);
        assert!(matches!(
            verifier.verify_attestation(&CHALLENGE, &attestation),
            Err(FinalityError::Native(_))
        ));
    }
}

#[test]
fn epoch_handoff_admits_only_the_committee_its_boundary_certified() {
    let chain = Chain::new(&[(0..4, 3), (0..7, 6), (3..7, 9)], 5);
    let mut verifier = chain.verifier_at(3);
    let checkpoint = verifier.checkpoint().clone();
    assert_eq!(verifier.committee_size().members(), 4);
    // The boundary at height 3 certified the seven-member successor, which signs height 4.
    verifier
        .advance(&Source::new(&chain), chain.proof(5))
        .unwrap();
    assert_eq!(verifier.committee_size().members(), 7);
    // A self-consistent foreign committee, or the retired incumbent extending its own epoch
    // past the boundary, certifies height 4 with an exact quorum of the committee it names.
    let foreign = ordered_keys(200..207);
    let mut extended = chain.epoch(3).context.clone();
    extended.authorization.last_height = 9;
    for substitute in [
        recertify(
            chain.proof(4),
            &with_committee(&chain.epoch(4).context, &foreign),
            &foreign,
        ),
        recertify(chain.proof(4), &extended, &chain.epoch(3).keys),
    ] {
        substitute.decode_checked().unwrap();
        let source = Source::new(&chain);
        source.proofs.borrow_mut().insert(4, substitute.clone());
        let mut verifier =
            FinalityVerifier::from_checkpoint(checkpoint.clone(), chain.anchor.network_id, CHAIN)
                .unwrap();
        assert!(matches!(
            verifier.advance(&source, &substitute),
            Err(FinalityError::Native(_))
        ));
        assert!(verifier.advance(&source, chain.proof(5)).is_err());
        assert_eq!(*verifier.checkpoint(), checkpoint);
    }
}

#[test]
fn forged_quorum_certificates_are_rejected_without_progress() {
    for size in SIZES {
        let chain = Chain::constant(size, 2);
        let keys = &chain.epoch(2).keys;
        let q = CommitteeSize::new(size).unwrap().quorum();
        let named = seats(0..q);
        let outsider = key(1000);
        let original = commit_qc(chain.proof(2));
        let mut elsewhere = original.clone();
        elsewhere.height += 1;
        let members = keys[..q].iter().collect::<Vec<_>>();
        let mut with_outsider = members[..q - 1].to_vec();
        with_outsider.push(&outsider);
        for (signers, message) in [
            // One named member's signature comes from a key outside the committee.
            (with_outsider, original.preimage()),
            // The bitmap names an exact quorum, but one named member never signed.
            (members[..q - 1].to_vec(), original.preimage()),
            // Every named member signed, but a different certificate.
            (members, elsewhere.preimage()),
        ] {
            let mut qc = original.clone();
            forge_qc(&mut qc, size, &named, &signers, &message);
            let mut proof = chain.proof(2).clone();
            let header = core(&proof);
            let commitment = result(&proof);
            replace_certificate(&mut proof, &header, &qc, &commitment);
            assert!(proof.decode_checked().is_err());
            let mut verifier = chain.verifier();
            let checkpoint = verifier.checkpoint().clone();
            assert!(matches!(
                verifier.advance(&Source::new(&chain), &proof),
                Err(FinalityError::Native(_))
            ));
            assert_eq!(*verifier.checkpoint(), checkpoint);
        }
    }
}

#[test]
fn stale_challenge_statements_never_count_toward_a_quorum() {
    for size in SIZES {
        let chain = Chain::constant(size, 3);
        let keys = &chain.epoch(3).keys;
        let f = CommitteeSize::new(size).unwrap().faults();
        let replay = |k: &KeyPair| {
            let mut attestation = chain.attest(k, 3);
            attestation.body.challenge = [0x5A; 32];
            resign(&mut attestation, k);
            attestation
        };
        let verifier = chain.verifier_at(3);
        let stale = keys.iter().map(replay).collect::<Vec<_>>();
        assert!(matches!(
            verifier.verify_attestation(&CHALLENGE, &stale[0]),
            Err(FinalityError::StaleChallenge)
        ));
        let Err(FinalityError::InsufficientAttestations(report)) =
            verifier.attestation_quorum(&CHALLENGE, &stale)
        else {
            panic!("statements for another challenge formed a quorum");
        };
        assert_eq!(report.verified(), 0);
        assert!(report.peers.iter().all(|(_, outcome)| matches!(
            outcome,
            AttestationOutcome::Rejected(FinalityError::StaleChallenge)
        )));
        assert!(matches!(
            verifier.attestation_quorum(&[0; 32], &stale),
            Err(FinalityError::ZeroChallenge)
        ));
        // An observation tolerates f replayed members; f + 1 leave too few fresh statements.
        for replayed in [f, f + 1] {
            let mut source = Source::new(&chain);
            for k in &keys[..replayed] {
                source.attestation_overrides.insert(peer(k), replay(k));
            }
            let mut verifier = chain.verifier();
            let checkpoint = verifier.checkpoint().clone();
            match verifier.observe(&source, &CHALLENGE) {
                Ok(report) if replayed == f => {
                    assert_eq!(report.verified(), size - f);
                    assert_eq!(verifier.checkpoint().height(), 3);
                }
                Err(FinalityError::InsufficientAttestations(report)) if replayed > f => {
                    assert_eq!(
                        (report.verified(), report.required),
                        (size - f - 1, size - f)
                    );
                    assert_eq!(*verifier.checkpoint(), checkpoint);
                }
                other => panic!("unexpected observation with {replayed} replayed: {other:?}"),
            }
        }
    }
}

#[test]
fn insufficient_attestations_report_every_member_outcome() {
    let chain = Chain::constant(7, 3);
    let verifier = chain.verifier_at(3);
    let keys = &chain.epoch(3).keys;
    let q = verifier.committee_size().quorum();
    let mut supplied = keys[..q - 1]
        .iter()
        .map(|k| chain.attest(k, 3))
        .collect::<Vec<_>>();
    // Member q - 1's statement signed with member 0's key, and a statement from an outsider.
    let mut forged = chain.attest(&keys[q - 1], 3);
    resign(&mut forged, &keys[0]);
    supplied.push(forged);
    supplied.push(chain.attest(&key(100), 3));
    let Err(FinalityError::InsufficientAttestations(report)) =
        verifier.attestation_quorum(&CHALLENGE, &supplied)
    else {
        panic!("q - 1 genuine statements formed a quorum");
    };
    assert_eq!((report.verified(), report.required), (q - 1, q));
    assert_eq!(report.height.get(), 3);
    assert_eq!(report.block_hash, chain.proof(3).block_header.hash());
    assert_eq!(report.peers.len(), keys.len());
    for (index, (member, outcome)) in report.peers.iter().enumerate() {
        assert_eq!(*member, peer(&keys[index]));
        match index {
            i if i < q - 1 => assert!(matches!(
                outcome,
                AttestationOutcome::Verified(tip) if tip.height.get() == 3
            )),
            i if i == q - 1 => assert!(matches!(
                outcome,
                AttestationOutcome::Rejected(FinalityError::Native(_))
            )),
            _ => assert!(matches!(outcome, AttestationOutcome::Missing)),
        }
    }
}

#[test]
fn foreign_network_genesis_or_chain_label_is_refused() {
    let chain = Chain::constant(4, 3);
    let other = Chain::constant(4, 4);
    assert_ne!(chain.anchor.network_id, other.anchor.network_id);
    assert!(matches!(
        FinalityVerifier::from_genesis(&chain.anchor, other.proof(1)),
        Err(FinalityError::WrongGenesis)
    ));
    let mut anchor = chain.anchor.clone();
    anchor.network_id = other.anchor.network_id;
    assert!(matches!(
        FinalityVerifier::from_genesis(&anchor, chain.proof(1)),
        Err(FinalityError::WrongNetwork { .. })
    ));
    assert!(
        FinalityVerifier::from_checkpoint(
            other.verifier_at(3).checkpoint().clone(),
            chain.anchor.network_id,
            CHAIN
        )
        .is_err()
    );
    // The same validator keys sign for both networks; the statement's network decides.
    let verifier = chain.verifier_at(3);
    assert!(matches!(
        verifier.verify_attestation(&CHALLENGE, &other.attest(&other.epoch(3).keys[0], 3)),
        Err(FinalityError::WrongNetwork { .. })
    ));
    let mut verifier = chain.verifier();
    assert!(
        verifier
            .advance(&Source::new(&other), other.proof(3))
            .is_err()
    );
    // A chain label selects the consensus instance: the right genesis under another label
    // anchors, but no certified successor extends it.
    let mut anchor = chain.anchor.clone();
    anchor.chain_id = "foreign-chain".into();
    let mut verifier = FinalityVerifier::from_genesis(&anchor, chain.proof(1)).unwrap();
    assert!(matches!(
        verifier.advance(&Source::new(&chain), chain.proof(3)),
        Err(FinalityError::Native(_))
    ));
    assert_eq!(verifier.checkpoint().height(), 1);
}

#[test]
fn lagging_checkpoint_is_caught_up_across_observations_before_any_publish() {
    let chain = Chain::constant(4, 8);
    let source = Source::new(&chain);
    let page = || Budget {
        proofs: 3,
        bytes: MAX_ADVANCE_BYTES,
    };
    let mut verifier = chain.verifier();
    assert!(!verifier.promote_verified_progress());
    let checkpoint = verifier.checkpoint().clone();
    let member = &chain.epoch(8).keys[0];
    // Every member's tip lies beyond one three-proof observation budget. Each observation keeps
    // what its budget verified for the next one, and none publishes it without a fresh quorum.
    for reached in [4, 7] {
        let result = verifier.observe_with_budget(&source, &CHALLENGE, &mut page());
        assert!(
            matches!(
                result,
                Err(FinalityError::CatchingUp { verified, claimed: 8 }) if verified == reached
            ),
            "{result:?}"
        );
        assert_eq!(*verifier.checkpoint(), checkpoint);
        assert_eq!(
            verifier
                .pending
                .as_ref()
                .map(SumeragiFinalityCheckpoint::height),
            Some(reached)
        );
        assert!(matches!(
            verifier.verify_attestation(&CHALLENGE, &chain.attest(member, 8)),
            Err(FinalityError::AheadOfCheckpoint { checkpoint: 1, .. })
        ));
    }
    let report = verifier
        .observe_with_budget(&source, &CHALLENGE, &mut page())
        .unwrap();
    assert_eq!((report.verified(), verifier.checkpoint().height()), (4, 8));
    assert!(verifier.pending.is_none());
    assert!(!verifier.promote_verified_progress());
    // Each successor was fetched once across the observations; H8 came from the members.
    assert_eq!(*source.proof_calls.borrow(), [2, 3, 4, 5, 6, 7]);
}

#[test]
fn durable_parent_observation_retains_bounded_certified_progress_but_never_readiness() {
    use crate::bootstrap::{
        BootstrapError, NetworkRelease, ParentFinalityStore, ReleaseCheckpointStore, ReleaseTrust,
        SignedNetworkCheckpoint,
    };

    let chain = Chain::constant(4, 8);
    let source = Source::new(&chain);
    let checkpoint = chain.verifier_at(2).checkpoint().clone();
    let signer = KeyPair::from_seed(vec![0xD7; 32], Algorithm::Ed25519);
    let release = NetworkRelease {
        network_name: "bounded-progress".into(),
        serial: 1,
        generation: 1,
        network_id: checkpoint.network_id(),
        chain_id: checkpoint.chain_id().into(),
        issued_at_ms: 1_000,
        expires_at_ms: 10_000,
        torii_roots: vec!["https://torii.example/".into()],
        account_chain_discriminant: 753,
        native_world_schema: Hash::new(b"independently qualified fixture World schema"),
        peers: checkpoint
            .tip()
            .committee
            .iter()
            .map(|validator| crate::bootstrap::ReleasePeer {
                node_id: iroha_model_base::peer::PeerId::new(validator.public_key.clone()),
                torii_root: "https://torii.example/".into(),
            })
            .collect(),
        faucet: None,
        build_registry: None,
        checkpoint_hash: Hash::new(checkpoint.encode_canonical().unwrap()),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_hash: checkpoint.block_hash().into(),
    };
    let bytes = SignedNetworkCheckpoint::sign(release, &checkpoint, signer.private_key())
        .unwrap()
        .encode_canonical()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let release_store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let bootstrap = release_store
        .authenticate(
            &ReleaseTrust::new("bounded-progress".into(), signer.public_key().clone(), 1).unwrap(),
            &bytes,
            2_000,
        )
        .unwrap();
    let path = directory.path().join("runtime");
    let mut runtime = ParentFinalityStore::open(&path, &bootstrap).unwrap();
    let page = || Budget {
        proofs: 2,
        bytes: MAX_ADVANCE_BYTES,
    };
    for reached in [4, 6] {
        let before = std::fs::read(path.join("verified.nrt")).unwrap();
        let result = runtime
            .observe_for_testing(|next| next.observe_with_budget(&source, &CHALLENGE, &mut page()));
        assert!(
            matches!(
                result,
                Err(BootstrapError::Finality(FinalityError::CatchingUp {
                    verified,
                    claimed: 8,
                })) if verified == reached
            ),
            "{result:?}"
        );
        assert_eq!(runtime.verifier().checkpoint().height(), reached);
        assert_eq!(runtime.verifier().verified_tip().unwrap().height(), reached);
        let retained = std::fs::read(path.join("verified.nrt")).unwrap();
        assert_ne!(retained, before);
        drop(runtime);
        runtime = ParentFinalityStore::open(&path, &bootstrap).unwrap();
        assert_eq!(runtime.verifier().checkpoint().height(), reached);
        // A restart and a certificate-only prefix cannot replace live challenged quorum.
        let mut offline = Source::new(&chain);
        offline.faults.extend(chain.epoch(8).keys.iter().map(peer));
        assert!(matches!(
            runtime.observe(&offline, &CHALLENGE),
            Err(BootstrapError::Finality(
                FinalityError::InsufficientAttestations(_)
            ))
        ));
        assert_eq!(runtime.verifier().checkpoint().height(), reached);
        assert_eq!(std::fs::read(path.join("verified.nrt")).unwrap(), retained);
    }
    let quorum = runtime
        .observe_for_testing(|next| next.observe_with_budget(&source, &CHALLENGE, &mut page()))
        .unwrap();
    assert_eq!(
        (quorum.verified(), quorum.required, quorum.height.get()),
        (4, 3, 8)
    );
    assert_eq!(runtime.verifier().checkpoint().height(), 8);
    // The incomplete pages survive each reopen; no previously certified successor is fetched again.
    assert_eq!(*source.proof_calls.borrow(), [3, 4, 5, 6, 7]);
}

#[test]
fn catch_up_publishes_bounded_verified_pages_explicitly() {
    let chain = Chain::constant(4, 8);
    let source = Source::new(&chain);
    let page = || Budget {
        proofs: 3,
        bytes: MAX_ADVANCE_BYTES,
    };
    let mut verifier = chain.verifier();
    for (height, fetched) in [(4, vec![2, 3, 4]), (7, vec![5, 6, 7]), (8, vec![8])] {
        source.proof_calls.borrow_mut().clear();
        assert_eq!(
            verifier
                .catch_up_with_budget(&source, nz(8), &mut page())
                .unwrap(),
            height
        );
        assert_eq!(*source.proof_calls.borrow(), fetched);
        assert_eq!(verifier.checkpoint().height(), height);
    }
    source.proof_calls.borrow_mut().clear();
    assert_eq!(verifier.catch_up(&source, nz(3)).unwrap(), 8);
    assert!(source.proof_calls.borrow().is_empty());
    assert_eq!(verifier.observe(&source, &CHALLENGE).unwrap().verified(), 4);
}

#[test]
fn managed_custody_retains_catching_up_prefix_without_claiming_freshness() {
    use crate::managed::native_operation::retain_observation;
    let chain = Chain::constant(4, 8);
    let source = Source::new(&chain);
    let temporary = tempfile::tempdir().unwrap();
    let directory =
        iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("custody")).unwrap();
    let mut verifier = chain.verifier_at(2);
    for expected in [4, 6] {
        let result = verifier.observe_with_budget(
            &source,
            &CHALLENGE,
            &mut Budget {
                proofs: 2,
                bytes: MAX_ADVANCE_BYTES,
            },
        );
        assert!(
            matches!(&result, Err(FinalityError::CatchingUp { verified, .. }) if *verified == expected)
        );
        assert!(retain_observation(&directory, &mut verifier, result).is_err());
        let bytes = directory
            .read("current-checkpoint.nrt", 32 * 1024 * 1024)
            .unwrap();
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&bytes).unwrap();
        verifier =
            FinalityVerifier::from_checkpoint(checkpoint, chain.anchor.network_id, CHAIN).unwrap();
        assert_eq!(verifier.checkpoint().height(), expected);
        let mut offline = Source::new(&chain);
        offline.faults.extend(chain.epoch(8).keys.iter().map(peer));
        let failure = verifier.observe(&offline, &CHALLENGE);
        assert!(retain_observation(&directory, &mut verifier, failure).is_err());
        assert_eq!(
            directory
                .read("current-checkpoint.nrt", 32 * 1024 * 1024)
                .unwrap()
                .as_slice(),
            bytes.as_slice()
        );
    }
    let observed = verifier.observe_with_budget(
        &source,
        &CHALLENGE,
        &mut Budget {
            proofs: 2,
            bytes: MAX_ADVANCE_BYTES,
        },
    );
    retain_observation(&directory, &mut verifier, observed).unwrap();
    assert_eq!(verifier.checkpoint().height(), 8);
    assert_eq!(*source.proof_calls.borrow(), [3, 4, 5, 6, 7]);
}

#[test]
fn managed_custody_false_carrier_hint_cannot_pin_original_recovery() {
    use crate::managed::native_operation::{replay_start, verify_carrier};
    let chain = Chain::constant(4, 8);
    let source = Source::new(&chain);
    let original = chain.verifier_at(2);
    let carrier = block(chain.proof(4));
    let transaction = carrier.external_transactions().next().unwrap();
    let wire = transaction.encode_wire_v1().unwrap();
    let false_progress = chain.verifier_at(7);
    assert!(verify_carrier(&false_progress, transaction).is_err());
    let mut replay = replay_start(original.clone(), Some(false_progress), 4).unwrap();
    assert_eq!(replay.checkpoint().height(), 2);
    replay.catch_up(&source, nz(4)).unwrap();
    let confirmed = verify_carrier(&replay, transaction).unwrap();
    assert_eq!(confirmed.height, 4);
    assert_eq!(confirmed.block_time_ms, carrier.header().creation_time_ms);
    assert_eq!(confirmed.transaction_hash, transaction.hash());
    assert_eq!(transaction.encode_wire_v1().unwrap(), wire);
    assert!(replay_start(original, Some(replay), 2).is_err());
}

#[test]
fn managed_custody_original_carrier_survives_unavailable_current_quorum() {
    use crate::managed::native_operation::retained_carrier;
    let chain = Chain::constant(4, 5);
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("custody");
    let directory = iroha_fs::PrivateDirectory::open_or_create(&path).unwrap();
    let carrier = chain.verifier_at(4);
    let block = block(chain.proof(4));
    let transaction = block.external_transactions().next().unwrap();
    directory
        .write_atomic(
            "carrier.nrt",
            &carrier.checkpoint().encode_canonical().unwrap(),
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    drop(directory);
    let directory = iroha_fs::PrivateDirectory::open(&path).unwrap();
    let mut offline = Source::new(&chain);
    offline.faults.extend(chain.epoch(5).keys.iter().map(peer));
    let mut observed = carrier;
    assert!(observed.observe(&offline, &CHALLENGE).is_err());
    let retained = retained_carrier(&directory, chain.anchor.network_id, CHAIN, transaction)
        .unwrap()
        .unwrap();
    assert_eq!(retained.height, 4);
    assert_eq!(retained.transaction_hash, transaction.hash());
    let other = chain.verifier_at(5).verified_tip().unwrap();
    let different_transaction = other.block().external_transactions().next().unwrap();
    assert!(
        retained_carrier(
            &directory,
            chain.anchor.network_id,
            CHAIN,
            different_transaction
        )
        .is_err()
    );
    assert!(
        retained_carrier(
            &directory,
            chain.anchor.network_id,
            "another-chain",
            transaction
        )
        .is_err()
    );
}

#[test]
fn catch_up_stops_before_the_byte_budget_and_publishes_only_verified_pages() {
    let chain = Chain::constant(4, 5);
    let source = Source::new(&chain);
    let mut verifier = chain.verifier();
    let checkpoint = verifier.checkpoint().clone();
    let first = chain.proof(2).block_wire.len();
    // A first successor alone beyond the byte budget refuses without progress.
    assert!(matches!(
        verifier.catch_up_with_budget(
            &source,
            nz(5),
            &mut Budget {
                proofs: 8,
                bytes: first - 1,
            }
        ),
        Err(FinalityError::ResourceLimit("proof bytes"))
    ));
    assert_eq!(*verifier.checkpoint(), checkpoint);
    // Otherwise the page ends before the successor that would exceed it.
    let two = first + chain.proof(3).block_wire.len();
    assert_eq!(
        verifier
            .catch_up_with_budget(
                &source,
                nz(5),
                &mut Budget {
                    proofs: 8,
                    bytes: two,
                }
            )
            .unwrap(),
        3
    );
    let paged = verifier.checkpoint().clone();
    // A reordered or invalid successor anywhere in a page publishes nothing from that page.
    let reordered = Source::new(&chain);
    reordered
        .proofs
        .borrow_mut()
        .insert(4, chain.proof(3).clone());
    assert!(matches!(
        verifier.catch_up(&reordered, nz(5)),
        Err(FinalityError::UnexpectedHeight {
            expected: 4,
            actual: 3
        })
    ));
    let mut invalid = chain.proof(5).clone();
    invalid.committee[0].proof_of_possession[0] ^= 1;
    let tampered = Source::new(&chain);
    tampered.proofs.borrow_mut().insert(5, invalid);
    assert!(matches!(
        verifier.catch_up(&tampered, nz(5)),
        Err(FinalityError::Native(_))
    ));
    assert_eq!(*verifier.checkpoint(), paged);
    assert_eq!(verifier.catch_up(&source, nz(5)).unwrap(), 5);
}

#[test]
fn fake_tip_member_cannot_starve_an_honest_quorum_behind_a_lagging_checkpoint() {
    for size in SIZES {
        // Nine certified blocks exist and the source serves seven, the honest tip. The checkpoint
        // lags six blocks behind, more than half of an eight-proof observation budget, so
        // verifying the prefix again for a second claim would exhaust it.
        let chain = Chain::constant(size, 9);
        let keys = &chain.epoch(7).keys;
        let byzantine = &keys[0];
        // One member claims the honest height, then a height beyond it, with a certificate that
        // is internally consistent but signed by a foreign committee it names.
        for claim in [7, 9] {
            let mut source = Source::new(&chain);
            source.served = 7;
            for k in keys {
                source.tips.insert(peer(k), 7);
            }
            source
                .attestation_overrides
                .insert(peer(byzantine), fake_claim(&chain, byzantine, claim));
            let mut verifier = chain.verifier();
            let report = verifier
                .observe_with_budget(
                    &source,
                    &CHALLENGE,
                    &mut Budget {
                        proofs: 8,
                        bytes: MAX_ADVANCE_BYTES,
                    },
                )
                .unwrap();
            assert_eq!((report.height.get(), report.verified()), (7, size - 1));
            assert_eq!(report.block_hash, chain.proof(7).block_header.hash());
            assert_eq!(verifier.checkpoint().height(), 7);
            for (member, outcome) in &report.peers {
                if *member != peer(byzantine) {
                    assert!(matches!(
                        outcome,
                        AttestationOutcome::Verified(tip) if tip.height.get() == 7
                    ));
                } else if claim == 7 {
                    assert!(matches!(
                        outcome,
                        AttestationOutcome::Rejected(FinalityError::Native(_))
                    ));
                } else {
                    assert!(matches!(
                        outcome,
                        AttestationOutcome::Rejected(FinalityError::AheadOfCheckpoint {
                            checkpoint: 7,
                            height: 9
                        })
                    ));
                }
            }
            // Each height is requested once; the honest tip comes from a member's own proof,
            // and the one request above the served range fails without a retry.
            let expected: Vec<u64> = if claim == 7 {
                (2..=6).collect()
            } else {
                (2..=8).collect()
            };
            assert_eq!(*source.proof_calls.borrow(), expected);
        }
    }
}

#[test]
fn budget_exhaustion_on_one_claim_does_not_abort_the_observation() {
    for size in [4, 7] {
        let chain = Chain::constant(size, 9);
        let keys = &chain.epoch(9).keys;
        let mut source = Source::new(&chain);
        for k in keys {
            source.tips.insert(peer(k), 4);
        }
        // One member attests a genuine tip that the proof count covers but the bytes do not.
        source.tips.insert(peer(&keys[0]), 9);
        let bytes: usize = (2..=6)
            .map(|height| chain.proof(height).block_wire.len())
            .sum();
        let mut verifier = chain.verifier();
        let report = verifier
            .observe_with_budget(&source, &CHALLENGE, &mut Budget { proofs: 16, bytes })
            .unwrap();
        assert_eq!(report.verified(), size - 1);
        // The prefix stops where the bytes ran out, above every honest tip it confirms.
        assert_eq!(verifier.checkpoint().height(), 6);
        for (member, outcome) in &report.peers {
            if *member == peer(&keys[0]) {
                assert!(matches!(
                    outcome,
                    AttestationOutcome::Rejected(FinalityError::ResourceLimit("proof bytes"))
                ));
            } else {
                assert!(matches!(
                    outcome,
                    AttestationOutcome::Verified(tip) if tip.height.get() == 4
                ));
            }
        }
    }
}

#[test]
fn observations_reject_incomplete_transport_batches_before_advancing() {
    struct ShortBatch<'a>(Source<'a>);
    impl FinalitySource for ShortBatch<'_> {
        type Error = std::io::Error;
        fn finality_proof(&self, height: NonZeroU64) -> Result<SumeragiFinalityProof, Self::Error> {
            self.0.finality_proof(height)
        }
        fn latest_attestation(
            &self,
            peer: &PeerId,
            challenge: &[u8; 32],
        ) -> Result<SumeragiFinalityAttestation, Self::Error> {
            self.0.latest_attestation(peer, challenge)
        }
        fn latest_attestations(
            &self,
            peers: &[PeerId],
            challenge: &[u8; 32],
        ) -> Vec<Result<SumeragiFinalityAttestation, Self::Error>> {
            let mut reads = self.0.latest_attestations(peers, challenge);
            reads.pop();
            reads
        }
    }
    let chain = Chain::constant(4, 3);
    let mut verifier = chain.verifier_at(2);
    let before = verifier.checkpoint().clone();
    assert!(matches!(
        verifier.observe(&ShortBatch(Source::new(&chain)), &CHALLENGE),
        Err(FinalityError::ResourceLimit(
            "attestation batch cardinality"
        ))
    ));
    assert_eq!(verifier.checkpoint(), &before);
}

#[test]
fn verified_tip_is_exactly_the_independently_retained_certified_execution() {
    let chain = Chain::constant(4, 3);
    let mut verifier = chain.verifier_at(2);
    let previous = verifier.verified_tip().unwrap();
    assert_eq!(previous.height(), 2);
    assert_eq!(
        previous.commitment().schedule.current.network_id,
        chain.anchor.network_id
    );
    verifier
        .advance(&Source::new(&chain), chain.proof(3))
        .unwrap();
    let next = verifier.verified_tip().unwrap();
    assert_eq!(next.height(), 3);
    assert_ne!(next.commitment(), previous.commitment());
    let restored = FinalityVerifier::from_checkpoint(
        verifier.checkpoint().clone(),
        chain.anchor.network_id,
        CHAIN,
    )
    .unwrap();
    assert_eq!(
        restored.verified_tip().unwrap().commitment(),
        next.commitment()
    );
}

#[test]
fn original_genesis_policy_decode_refusal_preserves_exact_source_and_retry() {
    use iroha_data_model::sumeragi_finality::GenesisReadError;
    let chain = Chain::constant(4, 1);
    let original = chain.anchor.genesis.encode_wire().unwrap();
    let original_proof = norito::encode_canonical(chain.proof(1)).unwrap();
    let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let producer =
        norito::with_decode_limits_scope(no_allocation, || genesis_epoch(&chain.anchor.genesis))
            .unwrap_err();
    assert!(
        matches!(
            producer,
            GenesisReadError::Json(norito::json::Error::DecodeResourceLimit)
        ),
        "{producer:?}"
    );
    let error = norito::with_decode_limits_scope(no_allocation, || {
        FinalityVerifier::from_genesis(&chain.anchor, chain.proof(1))
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            FinalityError::Genesis(GenesisReadError::Json(
                norito::json::Error::DecodeResourceLimit
            ))
        ),
        "{error:?}"
    );
    assert_eq!(chain.anchor.genesis.encode_wire().unwrap(), original);
    assert_eq!(
        norito::encode_canonical(chain.proof(1)).unwrap(),
        original_proof
    );
    let expected = chain.verifier();
    let checkpoint = expected.checkpoint().clone();
    let refusal = norito::with_decode_limits_scope(no_allocation, || {
        FinalityVerifier::from_checkpoint(
            checkpoint.clone(),
            chain.anchor.network_id,
            &chain.anchor.chain_id,
        )
    })
    .unwrap_err();
    let FinalityError::DecodeResource(original) = refusal else {
        panic!("{refusal:?}");
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(
        matches!(original.into_error().decode_resource_error(), Some(
        norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
    ) if attempted > 0)
    );
    let retried = FinalityVerifier::from_checkpoint(
        checkpoint.clone(),
        chain.anchor.network_id,
        &chain.anchor.chain_id,
    )
    .unwrap();
    assert_eq!(retried.checkpoint(), &checkpoint);
    assert_eq!(chain.verifier().checkpoint(), &checkpoint);
}

#[test]
fn checkpoint_npos_refusal_follows_a_completed_original_binary_read() {
    use iroha_data_model::sumeragi_finality::GenesisReadError;
    let chain = Chain::constant(4, 1);
    let expected = chain.verifier();
    let checkpoint = expected.checkpoint().clone();
    let original = checkpoint.encode_canonical().unwrap();
    let wire = chain
        .anchor
        .genesis
        .canonical_resultless_proposal()
        .unwrap()
        .encode_wire()
        .unwrap();
    let ceiling = 8 * 1024 * 1024;
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let decode = || {
        norito::with_decode_limits_scope(norito::canonical_decode_limits(wire.len()), || {
            decode_framed_signed_block(&wire)
        })
    };
    let original_binary_cost = norito::with_decode_limits_scope(limits(ceiling), || {
        let decoded = decode().unwrap();
        assert_eq!(decoded.hash(), chain.anchor.genesis.hash());
        let norito::Error::TotalAllocationExceeded { attempted, limit } =
            norito::core::reserve_decode_allocation(ceiling + 1).unwrap_err()
        else {
            panic!("non-charging cumulative allocation observation");
        };
        assert_eq!(limit, u64::try_from(ceiling).unwrap());
        usize::try_from(attempted).unwrap() - ceiling - 1
    });
    assert!(original_binary_cost > 0);
    norito::with_decode_limits_scope(limits(original_binary_cost), || {
        let decoded = decode().expect("entire original binary frame fits before policy");
        assert_eq!(decoded.hash(), chain.anchor.genesis.hash());
        let error = genesis_epoch(&decoded).unwrap_err();
        assert!(
            matches!(
                error,
                GenesisReadError::Json(norito::json::Error::DecodeResourceLimit)
            ),
            "{error:?}"
        );
    });
    let error = norito::with_decode_limits_scope(limits(original_binary_cost), || {
        FinalityVerifier::from_checkpoint(
            checkpoint.clone(),
            chain.anchor.network_id,
            &chain.anchor.chain_id,
        )
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            FinalityError::Genesis(GenesisReadError::Json(
                norito::json::Error::DecodeResourceLimit
            ))
        ),
        "{error:?}"
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
    let retried = FinalityVerifier::from_checkpoint(
        checkpoint.clone(),
        chain.anchor.network_id,
        &chain.anchor.chain_id,
    )
    .unwrap();
    assert_eq!(retried.checkpoint(), &checkpoint);
}

#[test]
fn verified_tip_memo_is_shared_by_clones_without_changing_equality_or_advancement() {
    let chain = Chain::constant(4, 3);
    let verifier = chain.verifier_at(2);
    let mut cloned = verifier.clone();
    let independent = FinalityVerifier::from_checkpoint(
        verifier.checkpoint().clone(),
        chain.anchor.network_id,
        CHAIN,
    )
    .unwrap();
    assert!(Arc::ptr_eq(&verifier.verified_tip, &cloned.verified_tip));
    assert!(!Arc::ptr_eq(
        &verifier.verified_tip,
        &independent.verified_tip
    ));
    assert!(verifier.verified_tip.get().is_none());
    assert_eq!(verifier, independent);
    let verified = verifier.verified_tip().unwrap();
    assert_eq!(
        verified.block().encode_wire().unwrap(),
        chain.proof(2).block_wire
    );
    assert!(cloned.verified_tip.get().is_some());
    assert!(independent.verified_tip.get().is_none());
    assert_eq!(verifier, independent);
    assert_eq!(
        cloned.verified_tip().unwrap().context_id(),
        verified.context_id()
    );
    cloned
        .advance(&Source::new(&chain), chain.proof(3))
        .unwrap();
    assert!(!Arc::ptr_eq(&verifier.verified_tip, &cloned.verified_tip));
    assert!(cloned.verified_tip.get().is_none());
    assert_eq!(cloned.verified_tip().unwrap().height(), 3);
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
    assert_eq!(verifier, independent);
    assert_ne!(verifier, cloned);
}

#[test]
fn verified_tip_memo_is_replaced_by_catch_up_and_successful_observation() {
    let chain = Chain::constant(4, 5);
    let source = Source::new(&chain);
    let mut verifier = chain.verifier_at(2);
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
    let original = verifier.clone();
    assert_eq!(verifier.catch_up(&source, nz(4)).unwrap(), 4);
    assert!(!Arc::ptr_eq(&verifier.verified_tip, &original.verified_tip));
    assert!(verifier.verified_tip.get().is_none());
    assert_eq!(verifier.verified_tip().unwrap().height(), 4);
    let caught_up = verifier.clone();
    let report = verifier.observe(&source, &CHALLENGE).unwrap();
    assert_eq!((report.height.get(), report.verified()), (5, 4));
    assert!(!Arc::ptr_eq(
        &verifier.verified_tip,
        &caught_up.verified_tip
    ));
    assert!(verifier.verified_tip.get().is_none());
    let verified = verifier.verified_tip().unwrap();
    assert_eq!(verified.height(), 5);
    assert_eq!(verified.header().hash(), chain.proof(5).block_header.hash());
    assert_eq!(caught_up.verified_tip().unwrap().height(), 4);
    assert_eq!(original.verified_tip().unwrap().height(), 2);
}

#[test]
fn verified_tip_memo_keeps_pending_progress_separate_until_explicit_promotion() {
    let chain = Chain::constant(4, 5);
    let mut verifier = chain.verifier_at(2);
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
    let original = verifier.clone();
    let result = verifier.observe_with_budget(
        &Source::new(&chain),
        &CHALLENGE,
        &mut Budget {
            proofs: 1,
            bytes: MAX_ADVANCE_BYTES,
        },
    );
    assert!(
        matches!(
            result,
            Err(FinalityError::CatchingUp {
                verified: 3,
                claimed: 5
            })
        ),
        "{result:?}"
    );
    assert_eq!(verifier.checkpoint(), original.checkpoint());
    assert_eq!(verifier.pending.as_ref().unwrap().height(), 3);
    assert!(Arc::ptr_eq(&verifier.verified_tip, &original.verified_tip));
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
    assert_ne!(verifier, original);
    let pending = verifier.clone();
    assert_eq!(verifier, pending);
    assert!(verifier.promote_verified_progress());
    assert!(!Arc::ptr_eq(&verifier.verified_tip, &pending.verified_tip));
    assert!(verifier.verified_tip.get().is_none());
    assert!(verifier.pending.is_none());
    assert_eq!(verifier.verified_tip().unwrap().height(), 3);
    assert_eq!(pending.verified_tip().unwrap().height(), 2);
    assert_eq!(pending.pending.as_ref().unwrap().height(), 3);
    let promoted = Arc::clone(&verifier.verified_tip);
    assert!(!verifier.promote_verified_progress());
    assert!(Arc::ptr_eq(&verifier.verified_tip, &promoted));
}

#[test]
fn verified_tip_memo_keeps_failures_retryable_and_rechecks_new_certificate_witnesses() {
    let chain = Chain::constant(4, 3);
    let mut verifier = chain.verifier_at(2);
    let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    for _ in 0..2 {
        let refusal = norito::with_decode_limits_scope(no_allocation, || verifier.verified_tip());
        assert!(
            matches!(refusal, Err(FinalityError::DecodeResource(_))),
            "{refusal:?}"
        );
        assert!(verifier.verified_tip.get().is_none());
    }
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
    let memo = Arc::clone(&verifier.verified_tip);
    let checkpoint = verifier.checkpoint().clone();
    let mut alternate = chain.alternate(2);
    let member = &chain.epoch(2).keys[0];
    let mut attestation = chain.attest(member, 2);
    attestation.body.finality_proof = alternate.clone();
    resign(&mut attestation, member);
    assert!(
        verifier
            .verify_attestation(&CHALLENGE, &attestation)
            .is_ok()
    );
    assert_eq!(
        verifier.advance(&Source::new(&chain), &alternate).unwrap(),
        0
    );
    let mut qc = commit_qc(&alternate);
    qc.agg_sig.0[0] ^= 1;
    let header = core(&alternate);
    let execution = result(&alternate);
    replace_certificate(&mut alternate, &header, &qc, &execution);
    assert_eq!(alternate.block_header, chain.proof(2).block_header);
    assert!(matches!(
        verifier.advance(&Source::new(&chain), &alternate),
        Err(FinalityError::Native(_))
    ));
    attestation.body.finality_proof = alternate;
    resign(&mut attestation, member);
    // The fresh outer signature is valid; the newly supplied certificate witness is not.
    attestation
        .signature
        .verify_hash(member.public_key(), attestation.body.signing_hash())
        .unwrap();
    assert!(matches!(
        verifier.verify_attestation(&CHALLENGE, &attestation),
        Err(FinalityError::Native(_))
    ));
    let mut successor = chain.proof(3).clone();
    let mut qc = commit_qc(&successor);
    qc.agg_sig.0[0] ^= 1;
    let header = core(&successor);
    let execution = result(&successor);
    replace_certificate(&mut successor, &header, &qc, &execution);
    assert!(matches!(
        verifier.advance(&Source::new(&chain), &successor),
        Err(FinalityError::Native(_))
    ));
    let mut stale = chain.attest(member, 2);
    stale.body.challenge = [0x5A; 32];
    resign(&mut stale, member);
    assert!(matches!(
        verifier.verify_attestation(&CHALLENGE, &stale),
        Err(FinalityError::StaleChallenge)
    ));
    assert_eq!(verifier.checkpoint(), &checkpoint);
    assert!(Arc::ptr_eq(&verifier.verified_tip, &memo));
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
}
