//! Ensure the Norito consensus message types support encode/decode roundtrips.
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    block::{
        Header as BlockHeader,
        consensus::{
            ConsensusGenesisModeParams, ConsensusGenesisParams, Evidence, EvidenceAttribution,
            EvidenceOffender, EvidencePenaltyStatus, EvidenceRecord, ExecKv, ExecWitness,
            ExecWitnessMsg, NposGenesisParams,
        },
        consensus::{SumeragiGenesisContextParameters, ValidatorPower},
    },
    sumeragi::{
        BeaconHorizonStatusV1, PROTOCOL_VERSION, SumeragiFootprint, SumeragiHaltReason,
        SumeragiStatus,
        epoch::{
            BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochAuthorizationV1,
            ValidatorEpochDecisionV1, ValidatorGenerationV1,
        },
    },
};
use iroha_model_base::peer::PeerId;
use norito::codec::{Decode, DecodeAll, Encode};
use std::{convert::TryFrom, fmt::Debug, num::NonZeroU64};
fn sample_hash(seed: u8) -> Hash {
    let mut bytes = [0u8; Hash::LENGTH];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let idx_u8 = u8::try_from(idx).expect("hash length fits in u8");
        *byte = seed.wrapping_add(idx_u8);
    }
    Hash::prehashed(bytes)
}
fn sample_block_hash(seed: u8) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(sample_hash(seed))
}

fn validator_generation(
    network_id: NetworkId,
    generation: u64,
    roster: &[ValidatorPower],
) -> ValidatorGenerationV1 {
    ValidatorGenerationV1 {
        network_id,
        generation,
        validators: roster
            .iter()
            .map(|validator| validator.validator.clone())
            .collect(),
    }
}

fn genesis_authorization(
    generation: &ValidatorGenerationV1,
    last_height: u64,
) -> ValidatorEpochAuthorizationV1 {
    let authorization = ValidatorEpochAuthorizationV1 {
        version: 1,
        network_id: generation.network_id,
        epoch: 0,
        first_height: 1,
        last_height,
        authority_generation: generation.generation,
        authority_id: generation
            .generation_id()
            .expect("valid fixture generation"),
        beacon: BeaconEpochBindingV1::Bootstrap,
        previous_authorization_id: [0; 32],
        transition_id: [0; 32],
        decision: ValidatorEpochDecisionV1::Genesis,
    };
    authorization
        .validate_against_generation(generation)
        .expect("valid fixture genesis authorization");
    authorization
}
fn sample_bytes(seed: u8, len: usize) -> Vec<u8> {
    assert!(u8::try_from(len).is_ok(), "len must fit in u8");
    (0..len)
        .map(|idx| {
            let idx_u8 = u8::try_from(idx).expect("iterator bound checked");
            seed.wrapping_add(idx_u8)
        })
        .collect()
}
fn checked_bls_peer_id_from_seed(seed: u8) -> PeerId {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
        .expect("derive checked BLS consensus fixture keypair");
    PeerId::new(key_pair.public_key().clone())
}
fn assert_roundtrip<T>(value: &T)
where
    T: Encode + Decode + PartialEq + Debug,
{
    let bytes = Encode::encode(value);
    let mut cursor = bytes.as_slice();
    let decoded = <T as Decode>::decode(&mut cursor).expect("decode succeeds");
    assert!(cursor.is_empty(), "decoder must consume all bytes");
    assert_eq!(decoded, *value, "roundtrip must preserve value");
}
#[derive(Clone)]
struct DeterministicRng(u64);
impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        const A: u64 = 6_364_136_223_846_793_005;
        const C: u64 = 1_442_695_040_888_963_407;
        self.0 = self.0.wrapping_mul(A).wrapping_add(C);
        self.0
    }
    fn next_u32(&mut self) -> u32 {
        let masked = self.next_u64() & u64::from(u32::MAX);
        u32::try_from(masked).expect("masked value fits into u32")
    }
    fn next_u8(&mut self) -> u8 {
        let masked = self.next_u64() & u64::from(u8::MAX);
        u8::try_from(masked).expect("masked value fits into u8")
    }
    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }
    fn up_to(&mut self, upper_inclusive: usize) -> usize {
        if upper_inclusive == 0 {
            0
        } else {
            let upper =
                u64::try_from(upper_inclusive).expect("upper bound must fit into u64 for testing");
            let sample = match upper.checked_add(1) {
                Some(modulus) => self.next_u64() % modulus,
                None => self.next_u64(),
            };
            usize::try_from(sample).expect("sample must fit into usize for testing")
        }
    }
    fn array32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for byte in &mut bytes {
            *byte = self.next_u8();
        }
        bytes
    }
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.up_to(max_len);
        (0..len).map(|_| self.next_u8()).collect()
    }
}
fn rng_hash(rng: &mut DeterministicRng) -> Hash {
    Hash::prehashed(rng.array32())
}
fn rng_block_hash(rng: &mut DeterministicRng) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(rng_hash(rng))
}
fn recommended_genesis_context() -> SumeragiGenesisContextParameters {
    SumeragiGenesisContextParameters::recommended()
}
fn rng_consensus_genesis_params(rng: &mut DeterministicRng) -> ConsensusGenesisParams {
    let mode = if rng.next_bool() {
        ConsensusGenesisModeParams::Npos(rng_npos_genesis_params(rng))
    } else {
        ConsensusGenesisModeParams::Permissioned
    };
    ConsensusGenesisParams {
        block_cadence_ms: NonZeroU64::new(rng.next_u64()).unwrap_or(NonZeroU64::MIN),
        block_max_transactions: NonZeroU64::new(rng.next_u64()).unwrap_or(NonZeroU64::MIN),
        mode,
        protocol_version: rng.next_u32(),
        sumeragi_context: recommended_genesis_context(),
    }
}
fn rng_npos_genesis_params(rng: &mut DeterministicRng) -> NposGenesisParams {
    let mut epoch_seed = [0u8; 32];
    for chunk in epoch_seed.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    NposGenesisParams {
        epoch_length_blocks: NonZeroU64::new(rng.next_u64()).unwrap_or(NonZeroU64::MIN),
        epoch_seed,
        max_validators: rng.next_u32(),
        min_self_bond: rng.next_u64().into(),
        min_nomination_bond: rng.next_u64().into(),
        finality_margin_blocks: rng.next_u64(),
        evidence_horizon_blocks: rng.next_u64(),
        activation_lag_blocks: rng.next_u64(),
        slashing_delay_blocks: rng.next_u64(),
    }
}
fn rng_exec_kv(rng: &mut DeterministicRng) -> ExecKv {
    ExecKv {
        key: rng.bytes(16),
        value: rng.bytes(24),
    }
}
fn rng_exec_witness(rng: &mut DeterministicRng) -> ExecWitness {
    let read_len = rng.up_to(3);
    let write_len = rng.up_to(3);
    let mut reads = Vec::with_capacity(read_len);
    for _ in 0..read_len {
        reads.push(rng_exec_kv(rng));
    }
    let mut writes = Vec::with_capacity(write_len);
    for _ in 0..write_len {
        writes.push(rng_exec_kv(rng));
    }
    ExecWitness {
        reads,
        writes,
        fastpq_transcripts: Vec::new(),
        fastpq_batches: Vec::new(),
    }
}
fn rng_exec_witness_msg(rng: &mut DeterministicRng) -> ExecWitnessMsg {
    ExecWitnessMsg {
        block_hash: rng_block_hash(rng),
        height: rng.next_u64(),
        view: rng.next_u64(),
        epoch: rng.next_u64(),
        witness: rng_exec_witness(rng),
    }
}
// Codec fixtures carry original signed artifacts; they do not establish chain admission.
fn rng_evidence(rng: &mut DeterministicRng) -> Evidence {
    use iroha_sumeragi::{
        message::{Evidence as NativeEvidence, Vote, VoteKind},
        types::{EpochId, Hash32, SIGNATURE_LEN, Signature as NativeSignature},
    };
    let key = KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::BlsNormal).unwrap();
    let instance = Hash32(rng.array32());
    let epoch = EpochId {
        epoch: rng.next_u64(),
        context: Hash32(rng.array32()),
    };
    let height = rng.next_u64().max(1);
    let view = rng.next_u64();
    let result = Hash32(rng.array32());
    let vote = |subject: u8| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance,
            epoch,
            height,
            view,
            block_hash: Hash32([subject; 32]),
            result,
            signer: 0,
            sig: NativeSignature([0; SIGNATURE_LEN]),
        };
        vote.sig = NativeSignature(
            iroha_crypto::Signature::new(key.private_key(), &vote.preimage())
                .payload()
                .try_into()
                .unwrap(),
        );
        vote
    };
    Evidence::from_native(&NativeEvidence::VoteEquivocation(vote(0xA2), vote(0xA3))).unwrap()
}
fn fixture_attribution(evidence: &Evidence) -> EvidenceAttribution {
    let iroha_sumeragi::message::Evidence::VoteEquivocation(vote, _) =
        evidence.decode_native().unwrap()
    else {
        panic!("native fixture vote pair")
    };
    EvidenceAttribution {
        scope: iroha_data_model::block::consensus::EvidenceScope::Root,
        instance: vote.instance.0,
        height: vote.height,
        epoch: vote.epoch.epoch,
        context_id: vote.epoch.context.0,
        authority_generation: [0xA4; 32],
        offenders: vec![EvidenceOffender {
            lane_stake: None,
            signer: vote.signer,
            peer_id: checked_bls_peer_id_from_seed(0xA1),
        }],
        safety_violation: false,
    }
}
#[test]
fn validator_generations_and_epoch_authorizations_roundtrip() {
    let mut rng = DeterministicRng::new(0xE1D3_0031);
    let rng = &mut rng;
    let mut roster = [0xA1, 0xA2, 0xA3, 0xA4]
        .into_iter()
        .map(|seed| ValidatorPower {
            validator: checked_bls_peer_id_from_seed(seed),
            power: 1,
        })
        .collect::<Vec<_>>();
    roster.sort();
    for authorization_case in 0..3 {
        let height = rng.next_u64().max(2);
        let network_id = NetworkId::from_genesis_hash(rng_block_hash(rng));
        let incumbent = validator_generation(network_id, 0, &roster);
        let (authorization, generation) = if authorization_case == 0 {
            (genesis_authorization(&incumbent, height), incumbent)
        } else {
            let previous = genesis_authorization(&incumbent, 1);
            let retained = authorization_case == 1;
            let generation = if retained {
                incumbent
            } else {
                validator_generation(network_id, 1, &roster)
            };
            let authorization = ValidatorEpochAuthorizationV1 {
                version: 1,
                network_id,
                epoch: 1,
                first_height: 2,
                last_height: height,
                authority_generation: generation.generation,
                authority_id: generation
                    .generation_id()
                    .expect("valid fixture successor generation"),
                beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                    session_id: [0xB1; 32],
                    transcript_hash: [0xB2; 32],
                }),
                previous_authorization_id: previous
                    .authorization_id()
                    .expect("valid fixture predecessor"),
                transition_id: if retained { [0; 32] } else { [0xB3; 32] },
                decision: if retained {
                    ValidatorEpochDecisionV1::Retain
                } else {
                    ValidatorEpochDecisionV1::Activate
                },
            };
            authorization
                .validate_against_generation(&generation)
                .expect("valid successor generation binding");
            authorization
                .validate_successor(&previous)
                .expect("contiguous fixture authorization");
            (authorization, generation)
        };

        generation.validate().expect("valid fixture generation");
        assert_roundtrip(&authorization);
    }
}
fn rng_evidence_record(rng: &mut DeterministicRng, evidence: Evidence) -> EvidenceRecord {
    EvidenceRecord {
        attribution: fixture_attribution(&evidence),
        evidence,
        recorded_at_height: rng.next_u64(),
        recorded_at_view: rng.next_u64(),
        recorded_at_ms: rng.next_u64(),
        penalty_status: EvidencePenaltyStatus::Pending,
    }
}
fn rng_native_status(rng: &mut DeterministicRng) -> SumeragiStatus {
    let key = checked_bls_peer_id_from_seed(0x71).public_key().clone();
    SumeragiStatus {
        protocol_version: PROTOCOL_VERSION,
        config_fingerprint: rng_hash(rng),
        beacon_horizon: rng.next_bool().then(|| BeaconHorizonStatusV1 {
            epoch_length_blocks: rng.next_u64(),
            next_required_pulse_height: rng.next_bool().then(|| rng.next_u64()),
            active_session_id: rng.next_bool().then(|| rng.array32()),
            session_covers_next_pulse: rng.next_bool(),
            local_provider_ready: rng.next_bool(),
        }),
        instance: rng.array32(),
        height: rng.next_u64(),
        view: rng.next_u64(),
        stage: (rng.next_u64() % 3) as u8,
        leader: rng.next_bool().then(|| key.clone()),
        proxy_tail: rng.next_bool().then(|| key.clone()),
        high_qc_view: rng.next_bool().then(|| rng.next_u64()),
        level: rng.next_u32(),
        start_level: rng.next_u32(),
        t_retx_ms: rng.next_u64(),
        committed_height: rng.next_u64(),
        applied_height: rng.next_u64(),
        awaiting: rng.next_bool(),
        signer: rng.next_bool().then_some(key),
        unanchored: rng.next_bool(),
        abstaining: rng.next_bool(),
        halted: rng
            .next_bool()
            .then(|| SumeragiHaltReason::SafetyViolation(rng.next_u64())),
        footprint: SumeragiFootprint {
            votes: rng.next_u64(),
            timeouts: rng.next_u64(),
            blocks: rng.next_u64(),
            exec_entries: rng.next_u64(),
            wants: rng.next_u64(),
            pending_apply: rng.next_u64(),
            sync_entries: rng.next_u64(),
            sync_bytes: rng.next_u64(),
            peers: rng.next_u64(),
            recent_headers: rng.next_u64(),
            configs: rng.next_u64(),
            cert_cache: rng.next_u64(),
            evidence_keys: rng.next_u64(),
            probe: rng.next_u64(),
        },
    }
}
#[test]
fn consensus_genesis_norito_roundtrip() {
    let npos = NposGenesisParams {
        epoch_length_blocks: NonZeroU64::new(120).unwrap(),
        epoch_seed: [0x11; 32],
        max_validators: 19,
        min_self_bond: 10_u64.into(),
        min_nomination_bond: 2_u64.into(),
        finality_margin_blocks: 9,
        evidence_horizon_blocks: 1_024,
        activation_lag_blocks: 12,
        slashing_delay_blocks: 17,
    };
    let with_npos = ConsensusGenesisParams {
        block_cadence_ms: NonZeroU64::new(750).unwrap(),
        block_max_transactions: NonZeroU64::new(512).unwrap(),
        mode: ConsensusGenesisModeParams::Npos(npos.clone()),
        protocol_version: u32::from(PROTOCOL_VERSION),
        sumeragi_context: recommended_genesis_context(),
    };
    let without_npos = ConsensusGenesisParams {
        mode: ConsensusGenesisModeParams::Permissioned,
        ..with_npos.clone()
    };
    assert_roundtrip(&npos);
    assert_roundtrip(&with_npos);
    assert_roundtrip(&without_npos);
}
#[test]
fn consensus_persistence_norito_roundtrip() {
    let evidence = rng_evidence(&mut DeterministicRng::new(0xE1D3_0002));
    let evidence_record = EvidenceRecord {
        attribution: fixture_attribution(&evidence),
        evidence: evidence.clone(),
        recorded_at_height: 44,
        recorded_at_view: 8,
        recorded_at_ms: 1_702_000_123,
        penalty_status: EvidencePenaltyStatus::Applied { height: 45 },
    };
    let exec_witness = ExecWitness {
        reads: vec![ExecKv {
            key: sample_bytes(0x20, 4),
            value: sample_bytes(0x21, 6),
        }],
        writes: vec![ExecKv {
            key: sample_bytes(0x22, 5),
            value: sample_bytes(0x23, 7),
        }],
        fastpq_transcripts: Vec::new(),
        fastpq_batches: Vec::new(),
    };
    let exec_witness_msg = ExecWitnessMsg {
        block_hash: sample_block_hash(0x0F),
        height: 44,
        view: 7,
        epoch: 2,
        witness: exec_witness.clone(),
    };
    assert_roundtrip(&evidence_record);
    assert_roundtrip(&exec_witness);
    assert_roundtrip(&exec_witness_msg);
    let mut rng = DeterministicRng::new(0xE1D3_0003);
    for _ in 0..32 {
        let evidence = rng_evidence(&mut rng);
        assert_roundtrip(&rng_evidence_record(&mut rng, evidence));
    }
}
#[test]
fn evidence_record_rejects_shortened_pre_release_binary_layouts() {
    #[derive(Encode)]
    struct PreReleaseEvidenceRecord {
        evidence: Evidence,
        recorded_at_height: u64,
        recorded_at_view: u64,
        recorded_at_ms: u64,
    }
    #[derive(Encode)]
    struct PreReleaseEvidenceRecordWithoutNullableSlots {
        evidence: Evidence,
        recorded_at_height: u64,
        recorded_at_view: u64,
        recorded_at_ms: u64,
        penalty_applied: bool,
        penalty_cancelled: bool,
    }

    let evidence = rng_evidence(&mut DeterministicRng::new(0xE1D3_0084));
    let record = EvidenceRecord {
        attribution: fixture_attribution(&evidence),
        evidence,
        recorded_at_height: 84,
        recorded_at_view: 9,
        recorded_at_ms: 1_702_000_456,
        penalty_status: EvidencePenaltyStatus::Applied { height: 85 },
    };
    assert_roundtrip(&record);
    let shortened_record = PreReleaseEvidenceRecord {
        evidence: record.evidence.clone(),
        recorded_at_height: record.recorded_at_height,
        recorded_at_view: record.recorded_at_view,
        recorded_at_ms: record.recorded_at_ms,
    }
    .encode();
    assert!(
        EvidenceRecord::decode_all(&mut shortened_record.as_slice()).is_err(),
        "EvidenceRecord must reject the pre-release layout without penalty state"
    );

    let pending_record = EvidenceRecord {
        attribution: record.attribution.clone(),
        evidence: record.evidence.clone(),
        recorded_at_height: 86,
        recorded_at_view: 10,
        recorded_at_ms: 1_702_000_789,
        penalty_status: EvidencePenaltyStatus::Pending,
    };
    assert_roundtrip(&pending_record);
    let omitted_nullable_slots = PreReleaseEvidenceRecordWithoutNullableSlots {
        evidence: pending_record.evidence.clone(),
        recorded_at_height: pending_record.recorded_at_height,
        recorded_at_view: pending_record.recorded_at_view,
        recorded_at_ms: pending_record.recorded_at_ms,
        penalty_applied: false,
        penalty_cancelled: false,
    }
    .encode();
    assert!(
        EvidenceRecord::decode_all(&mut omitted_nullable_slots.as_slice()).is_err(),
        "EvidenceRecord must reject the retired independent-boolean penalty layout"
    );
}
#[test]
fn native_evidence_json_is_closed_and_exact() {
    let evidence = rng_evidence(&mut DeterministicRng::new(0xE1D3_0090));
    let json = norito::json::to_value(&evidence).unwrap();
    assert_eq!(
        norito::json::from_value::<Evidence>(json.clone()).unwrap(),
        evidence
    );
    assert_eq!(
        json.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["native"]
    );
    assert!(norito::json::from_value::<Evidence>(norito::json!({})).is_err());
    let mut unknown = json;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("equivocation".into(), norito::json::Value::Null);
    assert!(norito::json::from_value::<Evidence>(unknown).is_err());
}
#[test]
fn consensus_roundtrip_deterministic_fuzz() {
    let mut rng = DeterministicRng::new(0xD4E5_F607_89AB_CDEF);
    for _ in 0..64 {
        let status = rng_native_status(&mut rng);
        assert_roundtrip(&status);
        let genesis = rng_consensus_genesis_params(&mut rng);
        if let ConsensusGenesisModeParams::Npos(npos) = &genesis.mode {
            assert_roundtrip(npos);
        }
        let genesis_bytes = genesis.encode();
        let mut genesis_cursor = genesis_bytes.as_slice();
        let decoded_genesis =
            ConsensusGenesisParams::decode(&mut genesis_cursor).expect("decode genesis");
        assert!(
            genesis_cursor.is_empty(),
            "genesis decode must consume all bytes"
        );
        if decoded_genesis != genesis {
            eprintln!(
                "consensus genesis mismatch\n  original: {genesis:?}\n  decoded:  {decoded_genesis:?}\n  bytes: {genesis_bytes:02x?}"
            );
            panic!("consensus genesis roundtrip mismatch");
        }
        let exec_kv = rng_exec_kv(&mut rng);
        assert_roundtrip(&exec_kv);
        let exec_witness = rng_exec_witness(&mut rng);
        assert_roundtrip(&exec_witness);
        let exec_witness_msg = rng_exec_witness_msg(&mut rng);
        assert_roundtrip(&exec_witness_msg);
    }
}
#[test]
fn native_status_requires_all_twenty_one_fields_and_explicit_nullable_slots() {
    let status = rng_native_status(&mut DeterministicRng::new(0xE1D3_0091));
    let json = norito::json::to_value(&status).unwrap();
    let object = json.as_object().unwrap();
    assert_eq!(object.len(), 21);
    for field in object.keys() {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            norito::json::from_value::<SumeragiStatus>(missing).is_err(),
            "missing {field}"
        );
    }
    for retired in [
        "highest_prepare_qc",
        "locked_prepare_qc",
        "height_context",
        "phase",
    ] {
        let mut unknown = json.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert(retired.into(), norito::json::Value::Null);
        assert!(norito::json::from_value::<SumeragiStatus>(unknown).is_err());
    }
}

#[test]
fn penalty_lifecycle_accepts_only_pending_and_applied_in_canonical_binary_and_json() {
    for status in [
        EvidencePenaltyStatus::Pending,
        EvidencePenaltyStatus::Applied { height: 0 },
        EvidencePenaltyStatus::Applied { height: 45 },
        EvidencePenaltyStatus::Applied { height: u64::MAX },
    ] {
        assert_roundtrip(&status);
        let framed = norito::to_bytes(&status).expect("canonical current schema and header");
        assert_eq!(
            norito::decode_from_bytes::<EvidencePenaltyStatus>(&framed).unwrap(),
            status
        );
        let json = norito::json::to_json(&status).unwrap();
        assert_eq!(
            norito::json::from_str::<EvidencePenaltyStatus>(&json).unwrap(),
            status
        );
        assert_eq!(
            status.is_terminal(),
            matches!(status, EvidencePenaltyStatus::Applied { .. })
        );
    }
}

#[test]
fn penalty_lifecycle_rejects_retired_binary_tag_json_tag_missing_and_defaulted_details() {
    // Canonical derive_enum_serialize emits a u32 discriminator, then the
    // named height field. The retired third variant had the identical height
    // field. Mutate only that discriminator of an actually encoded payload;
    // no retired codec, header repair, schema substitution or fallback exists.
    let applied = EvidencePenaltyStatus::Applied { height: 45 }.encode();
    let original_tag = 1_u32.encode();
    let retired_tag = 2_u32.encode();
    assert_eq!(original_tag.len(), 4);
    assert_eq!(retired_tag.len(), original_tag.len());
    assert_eq!(&applied[..original_tag.len()], original_tag.as_slice());
    let mut retired = applied.clone();
    retired[..retired_tag.len()].copy_from_slice(&retired_tag);
    assert_eq!(
        &retired[retired_tag.len()..],
        &applied[original_tag.len()..]
    );
    assert!(EvidencePenaltyStatus::decode_all(&mut retired.as_slice()).is_err());
    for json in [
        r#"{"status":"cancelled","details":{"height":45}}"#,
        r#"{"status":"cancelled","details":null}"#,
        r#"{"status":"pending"}"#,
        r#"{"status":"applied","details":{}}"#,
        r#"{"status":"applied","details":null}"#,
        r#"{"status":"applied","details":{"height":45,"cancelled":true}}"#,
        r#"{}"#,
    ] {
        assert!(
            norito::json::from_str::<EvidencePenaltyStatus>(json).is_err(),
            "rejected lifecycle: {json}"
        );
    }
}
