//! Test-only inverse of Load's no-incoming Q0 public frame.
//!
//! Decoding produces DATA, never a deciding claim or installed source. The
//! validating helper runs the unchanged native preparation before the proof-entry
//! cut. Only the ignored genuine test constructs parameters, keys or proofs.

use group::prime::PrimeCurveAffine;
use iroha_pasta::EqAffine;

use rand_chacha::rand_core::{CryptoRng, RngCore};

use super::*;

const LOAD_SELECTOR: u8 = 1;
const LOAD_SOURCE_K: u32 = 12;
const MAX_SIGMA_BYTES: usize = 10_000;
type Frame = Vec<Vec<[u8; 32]>>;

#[derive(Debug)]
struct LoadData {
    instances: Vec<Vec<Fq>>,
    statement: Fp,
    proof: Vec<u8>,
    length: u32,
    part: FoldInput<Eq>,
}

fn frame(instances: &[Vec<Fq>]) -> Frame {
    instances
        .iter()
        .map(|column| column.iter().map(PrimeField::to_repr).collect())
        .collect()
}

fn fp(value: Fq) -> Result<Fp, &'static str> {
    Fp::from_repr(value.to_repr())
        .into_option()
        .ok_or("noncanonical Fp embedding")
}

// The extent is independently selected by the admitted sigma descriptor, not
// read from the supplied public length word. The smaller synthetic DATA test
// also exercises a nonempty final padding byte without deriving any parameters.
fn decode_load(frame: &Frame, proof_length: usize) -> Result<LoadData, &'static str> {
    if proof_length == 0 || proof_length > MAX_SIGMA_BYTES || proof_length % 32 != 0 {
        return Err("sigma extent");
    }
    let tape_length = proof_length.checked_add(4).ok_or("sigma extent")?;
    let chunks = tape_length.div_ceil(31);
    let lengths = [1 + chunks + 16, 2, 1, 1, 1];
    if frame.len() != lengths.len() || frame.iter().zip(lengths).any(|(c, n)| c.len() != n) {
        return Err("Load public shape");
    }
    let instances = frame
        .iter()
        .map(|column| {
            column
                .iter()
                .map(|word| Fq::from_repr(*word).into_option().ok_or("noncanonical Fq"))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    if instances[2] != [Fq::from(u64::from(LOAD_SELECTOR))] {
        return Err("Load key selector");
    }
    if instances[3] != [Fq::ONE] {
        return Err("own verdict");
    }
    if instances[4] != [Fq::from(u64::from(LOAD_SOURCE_K))] {
        return Err("Load source k");
    }
    let statement = fp(instances[0][0])?;
    let capacity = chunks.checked_mul(31).ok_or("sigma extent")?;
    let mut tape = Vec::with_capacity(capacity);
    for word in &frame[0][1..1 + chunks] {
        if word[31] != 0 {
            return Err("chunk above 248 bits");
        }
        tape.extend_from_slice(&word[..31]);
    }
    let length = u32::from_le_bytes(tape[..4].try_into().expect("four-byte prefix"));
    if usize::try_from(length).ok() != Some(proof_length) {
        return Err("LE32 original length");
    }
    if tape[tape_length..].iter().any(|byte| *byte != 0) {
        return Err("nonzero final padding");
    }
    let mut challenges = [Fp::ZERO; 16];
    for (output, input) in challenges.iter_mut().zip(&instances[0][1 + chunks..]) {
        *output = fp(*input)?;
    }
    let g = EqAffine::from_xy(instances[1][0], instances[1][1])
        .into_option()
        .ok_or("invalid part coordinates")?;
    let part = FoldInput::from_normalized(g, LOAD_SOURCE_K, challenges)
        .map_err(|_| "noncanonical normalized part")?;
    Ok(LoadData {
        instances,
        statement,
        proof: tape[4..tape_length].to_vec(),
        length,
        part,
    })
}

// `catalog_key` is the exact key selected by the installed route's selector1,
// not an arbitrary witness recovered from a digest. This private test helper
// neither imports a catalog nor creates a production admission capability.
fn validate_load(
    plan: &QSigmaPlan,
    catalog_key: &VerifyingKey<Eq>,
    public: &Frame,
    params: &PinnedParams<Eq>,
    salt: Fq,
    config: &FoldConfig,
) -> Result<PreparedQSigma, QSigmaError> {
    if plan.incoming.is_some()
        || plan.fold.is_some()
        || plan.part_source_k() != LOAD_SOURCE_K
        || plan.own.key_index(catalog_key)? != LOAD_SELECTOR
    {
        return Err(QSigmaError::UnauthorizedKey);
    }
    let decoded = decode_load(public, plan.own.verifier.proof_length())
        .map_err(|_| QSigmaError::Layout(LayoutError::Synthesis))?;
    let prepared = plan.prepare(
        SigmaSlotWitness {
            key: catalog_key.clone(),
            statement: decoded.statement,
            proof: decoded.proof,
            length: decoded.length,
        },
        None,
        params,
        salt,
        config,
    )?;
    // prepare derives the transcript opening and decides it. A finite proposed
    // G/u is insufficient, and native acceptance must bind every supplied field.
    if prepared.instances != decoded.instances || prepared.part != decoded.part {
        return Err(QSigmaError::Layout(LayoutError::Synthesis));
    }
    Ok(prepared)
}

fn data_frame(proof_length: usize) -> (Frame, Vec<u8>, FoldInput<Eq>) {
    let proof: Vec<_> = (0..proof_length)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let mut tape = u32::try_from(proof_length).unwrap().to_le_bytes().to_vec();
    tape.extend_from_slice(&proof);
    let mut first = vec![scalar(Fp::from(73))];
    first.extend(
        tape.chunks(31).map(|chunk| {
            segment_value::<Fq>(chunk, ByteOrder::Little).expect("31-byte DATA chunk")
        }),
    );
    let mut u = [Fp::ONE; 16];
    u[..4].fill(Fp::ZERO);
    first.extend(u.map(scalar));
    let g = EqAffine::generator();
    let (x, y) = g.coordinates().unwrap();
    let part = FoldInput::from_normalized(g, LOAD_SOURCE_K, u).unwrap();
    (
        frame(&[
            first,
            vec![x, y],
            vec![Fq::ONE],
            vec![Fq::ONE],
            vec![Fq::from(12)],
        ]),
        proof,
        part,
    )
}

fn first_non_fp() -> [u8; 32] {
    let mut bytes = (-Fp::ONE).to_repr();
    for byte in &mut bytes {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    bytes
}

#[test]
fn load_public_data_roundtrip_and_exact_historical_shape() {
    for extent in [32, 3296] {
        let (public, proof, part) = data_frame(extent);
        let decoded = decode_load(&public, extent).unwrap();
        assert_eq!(decoded.statement, Fp::from(73));
        assert_eq!(decoded.proof, proof);
        assert_eq!(usize::try_from(decoded.length).unwrap(), extent);
        assert_eq!(decoded.part, part);
        assert_eq!(frame(&decoded.instances), public);
        if extent == 3296 {
            assert_eq!(
                public.iter().map(Vec::len).collect::<Vec<_>>(),
                [124, 2, 1, 1, 1]
            );
        }
    }
    // Neither patterned proof bytes nor the generator DATA claim is admitted.
}

#[test]
fn load_public_rejects_shape_extent_and_noncanonical_fields() {
    let (original, _, _) = data_frame(32);
    for extent in [0, 31, 10_016, usize::MAX] {
        assert_eq!(decode_load(&original, extent).unwrap_err(), "sigma extent");
    }
    for column in 0..5 {
        let mut public = original.clone();
        public[column].pop();
        assert_eq!(decode_load(&public, 32).unwrap_err(), "Load public shape");
        let mut public = original.clone();
        public[column][0] = [255; 32];
        assert_eq!(decode_load(&public, 32).unwrap_err(), "noncanonical Fq");
    }
    let mut public = original;
    public.push(vec![]);
    assert_eq!(decode_load(&public, 32).unwrap_err(), "Load public shape");
}

#[test]
fn load_public_rejects_tape_aliases_length_and_padding() {
    let (original, _, _) = data_frame(32);
    let mut public = original.clone();
    public[0][1][31] = 1;
    assert_eq!(
        decode_load(&public, 32).unwrap_err(),
        "chunk above 248 bits"
    );
    let mut public = original.clone();
    public[0][1][..4].copy_from_slice(&32_u32.to_be_bytes());
    assert_eq!(
        decode_load(&public, 32).unwrap_err(),
        "LE32 original length"
    );
    let mut public = original.clone();
    public[0][1][0] = 31;
    assert_eq!(
        decode_load(&public, 32).unwrap_err(),
        "LE32 original length"
    );
    let mut public = original;
    public[0][2][5] = 1; // 36 used bytes; second segment has exactly five.
    assert_eq!(
        decode_load(&public, 32).unwrap_err(),
        "nonzero final padding"
    );
}

#[test]
fn load_public_rejects_selector_verdict_source_k_and_fp_aliases() {
    let (original, _, _) = data_frame(32);
    for (column, value, error) in [
        (2, 2, "Load key selector"),
        (2, 16, "Load key selector"),
        (3, 0, "own verdict"),
        (3, 2, "own verdict"),
        (4, 14, "Load source k"),
        (4, 32, "Load source k"),
    ] {
        let mut public = original.clone();
        public[column][0] = Fq::from(value).to_repr();
        assert_eq!(decode_load(&public, 32).unwrap_err(), error);
    }
    for row in [0, 3 + 4] {
        let mut public = original.clone();
        public[0][row] = first_non_fp();
        assert_eq!(
            decode_load(&public, 32).unwrap_err(),
            "noncanonical Fp embedding"
        );
    }
}

#[test]
fn load_public_rejects_invalid_points_and_noncanonical_normalization() {
    let (original, _, _) = data_frame(32);
    let mut public = original.clone();
    public[1] = vec![Fq::ZERO.to_repr(); 2];
    assert!(decode_load(&public, 32).is_err());
    for row in [3, 3 + 3, 3 + 4, 3 + 15] {
        let mut public = original.clone();
        public[0][row] = if row < 7 { Fq::ONE } else { Fq::ZERO }.to_repr();
        assert_eq!(
            decode_load(&public, 32).unwrap_err(),
            "noncanonical normalized part"
        );
    }
    let mut public = original;
    let (x, y) = (-EqAffine::generator()).coordinates().unwrap();
    public[1] = vec![x.to_repr(), y.to_repr()];
    assert!(decode_load(&public, 32).is_ok()); // finite DATA, still not decided
}

// These two small helpers are the exact existing tests/common/bootstrap.rs
// witness/rebind recipe, with crate-local imports; no fixture authority/API is
// added. tests/admin_sigma.rs::load_witness supplies the final Load transition.
fn bootstrap_witness() -> crate::admin_sigma::BootstrapWitness {
    use crate::{
        tree::{IndexedTree, QuotaUsageTree, QuotaWindowTree},
        witness::core_index as core,
    };
    let mut w = crate::admin_sigma::BootstrapWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ONE; 18],
        statement: [Fp::ZERO; 26],
    };
    w.core[core::LIFECYCLE] = Fp::ONE;
    for (i, value) in w.core.iter_mut().enumerate().take(8).skip(1) {
        *value = Fp::from(u64::try_from(i).unwrap());
    }
    let empty = IndexedTree::<Fp>::new().root();
    w.core[core::CONSUMED_CREDIT_ROOT..=core::FEE_CLAIM_ROOT].fill(empty);
    w.core[core::QUOTA_USAGE_ROOT] =
        QuotaUsageTree::<Fp>::new(&QuotaWindowTree::new(&[]).unwrap()).root();
    w.core[core::STATE_NONCE] = Fp::from(77);
    w.rest[7] = empty;
    w.lineage[3] = Fp::from(9);
    w.lineage[4] = Fp::from(10);
    w.lineage[14] = Fp::ZERO;
    w.lineage[15] = empty;
    w.lineage[16] = empty;
    w.lineage[17] = Fp::from(91);
    w.statement[0] = Fp::ONE;
    w.statement[16] = Fp::ONE;
    w.statement[17..21].copy_from_slice(&[Fp::ONE, Fp::from(2), Fp::from(3), Fp::from(4)]);
    bootstrap_rebind(&mut w);
    w
}

fn bootstrap_rebind(w: &mut crate::admin_sigma::BootstrapWitness) {
    use crate::witness::{CORE_DOMAIN, REST_DOMAIN, core_index as core};
    use iroha_pasta::poseidon::hash_with_domain;
    let mut preimage = w.core.to_vec();
    preimage.push(hash_with_domain(REST_DOMAIN, &w.rest));
    w.lineage[5] = hash_with_domain(CORE_DOMAIN, &preimage);
    w.lineage[1..3].copy_from_slice(&w.core[core::SCHEME..=core::SCHEME + 1]);
    w.lineage[6..8].copy_from_slice(&w.core[core::WALLET..core::WALLET + 2]);
    w.lineage[8] = w.core[core::CREDENTIAL];
    w.lineage[13] = w.core[core::LIFECYCLE]
        + Fp::from(256) * w.core[core::POLICY_EPOCH]
        + Fp::from_u128(1 << 72) * w.core[core::ENABLED_CONTROLS];
    w.statement[1..3].copy_from_slice(&w.lineage[3..5]);
    w.statement[3..7].copy_from_slice(&w.core[core::SCHEME..core::ASSET + 2]);
    w.statement[7] = w.core[core::CREDENTIAL];
    w.statement[8] = w.core[core::LIFECYCLE];
    w.statement[9] = w.core[core::SEQUENCE];
    w.statement[10] = w.core[core::NEXT_LOAD];
    w.statement[15] = w.lineage[5];
}

fn load_witness() -> crate::admin_sigma::LoadWitness {
    use crate::{
        admin_sigma::{LoadWitness, StateWitness},
        witness::core_index,
    };
    let before = bootstrap_witness();
    let mut after = before;
    after.core[core_index::BALANCE] = Fp::from(100);
    after.core[core_index::NEXT_LOAD] = Fp::ONE;
    after.core[core_index::SEQUENCE] = Fp::ONE;
    after.core[core_index::STATE_NONCE] += Fp::ONE;
    after.core[core_index::LOAD_REDEEM_ROOT] = Fp::from(99);
    bootstrap_rebind(&mut after);
    let mut statement = after.statement;
    statement[14] = before.lineage[5];
    statement[16] = Fp::from(2);
    statement[17..].fill(Fp::ZERO);
    statement[17] = Fp::from(55);
    statement[19] = Fp::from(100);
    statement[20] = Fp::from(3);
    LoadWitness {
        predecessor: StateWitness::from(&before),
        successor: StateWitness::from(&after),
        statement,
    }
}

// Record the real recovery provider boundary, not the prover's internal
// ChaCha scalar consumption. Current recovery requests one 32-byte draw.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RecoveryEvent {
    Context([u8; 32]),
    NextU32(u32),
    NextU64(u64),
    Fill(Vec<u8>),
    TryFill(Vec<u8>),
}
type RecoveryLog = std::sync::Arc<std::sync::Mutex<Vec<RecoveryEvent>>>;
struct RecordedRng {
    inner: rand_chacha::ChaCha20Rng,
    log: RecoveryLog,
}
impl RngCore for RecordedRng {
    fn next_u32(&mut self) -> u32 {
        let value = self.inner.next_u32();
        self.log.lock().unwrap().push(RecoveryEvent::NextU32(value));
        value
    }
    fn next_u64(&mut self) -> u64 {
        let value = self.inner.next_u64();
        self.log.lock().unwrap().push(RecoveryEvent::NextU64(value));
        value
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        self.log
            .lock()
            .unwrap()
            .push(RecoveryEvent::Fill(dest.to_vec()));
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
        self.inner.try_fill_bytes(dest)?;
        self.log
            .lock()
            .unwrap()
            .push(RecoveryEvent::TryFill(dest.to_vec()));
        Ok(())
    }
}
impl CryptoRng for RecordedRng {}
fn recovery(seed: u8, log: RecoveryLog) -> ProverRandomness<'static> {
    use rand_chacha::rand_core::SeedableRng as _;
    ProverRandomness::recovery(move |context: &[u8; 32]| {
        log.lock().unwrap().push(RecoveryEvent::Context(*context));
        Ok::<_, std::convert::Infallible>(RecordedRng {
            inner: rand_chacha::ChaCha20Rng::from_seed([seed; 32]),
            log,
        })
    })
}
fn assert_recovery(log: &RecoveryLog) {
    let events = log.lock().unwrap();
    assert!(
        matches!(events.as_slice(), [RecoveryEvent::Context(_), RecoveryEvent::TryFill(bytes)] if bytes.len() == 32)
    );
}

#[test]
#[ignore = "genuine Load sigma k12 plus two serialized-bus2 Q0 k16 proofs; explicit resource handoff"]
fn genuine_load_public_inverse_prepared_and_native_proof_parity() {
    use crate::admin_sigma::LoadCircuit;
    let sigma_params = PinnedParams::<Eq>::derive(12).unwrap();
    let sigma_circuit = LoadCircuit::new(&load_witness());
    let sigma_instances = sigma_circuit.instances();
    let mut keygen = KeygenConfigV2::pipa_r(LoadCircuit::instance_types().to_vec());
    keygen.coset_cache = CosetCachePolicy::OnDemand;
    let sigma_key = keygen_pk_v2(&sigma_params, &sigma_circuit, &keygen).unwrap();
    let sigma = iroha_plonk::create_proof_owned_with_claim(
        &sigma_params,
        &sigma_key,
        Witness::from_circuit(&sigma_key, &sigma_circuit, &sigma_instances).unwrap(),
        recovery(189, RecoveryLog::default()),
        ProverConfig::default(),
    )
    .unwrap();
    iroha_plonk::verify_full(
        &sigma_params,
        sigma_key.binding(),
        sigma_key.vk(),
        &sigma_instances,
        &sigma.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    sigma
        .opening
        .decide(&sigma_params, MemoryBudget::DEFAULT)
        .unwrap();
    let inner = PinnedParams::<Eq>::derive(16).unwrap();
    let class = SigmaClass::new(
        VerifierPlan::new(sigma_key.binding().clone(), sigma_params).unwrap(),
        vec![(
            LOAD_SELECTOR,
            sigma_key
                .vk()
                .kagemusha_digest(sigma_key.binding())
                .unwrap(),
        )],
    )
    .unwrap();
    let catalog_key = sigma_key.vk().clone();
    let own = SigmaSlotWitness {
        key: catalog_key.clone(),
        statement: sigma_instances[0][0],
        length: u32::try_from(sigma.proof.len()).unwrap(),
        proof: sigma.proof,
    };
    drop(sigma_key);
    let plan = QSigmaPlan::new(class, None, &inner).unwrap();
    let original = plan
        .prepare(own, None, &inner, Fq::from(97), &FoldConfig::default())
        .unwrap();
    let public = frame(original.instances());
    let restored = validate_load(
        &plan,
        &catalog_key,
        &public,
        &inner,
        Fq::from(97),
        &FoldConfig::default(),
    )
    .unwrap();
    assert!(original.circuit.known && restored.circuit.known);
    assert!(
        original.circuit.witness.incoming.is_none() && restored.circuit.witness.incoming.is_none()
    );
    assert_eq!(
        restored.circuit.witness.own.key.to_bytes(),
        original.circuit.witness.own.key.to_bytes()
    );
    assert_eq!(
        restored.circuit.witness.own.statement,
        original.circuit.witness.own.statement
    );
    assert_eq!(
        restored.circuit.witness.own.proof,
        original.circuit.witness.own.proof
    );
    assert_eq!(
        restored.circuit.witness.own.length,
        original.circuit.witness.own.length
    );
    assert_eq!(
        restored.circuit.plan.own.entries,
        original.circuit.plan.own.entries
    );
    assert_eq!(
        restored.circuit.plan.own.verifier.binding(),
        original.circuit.plan.own.verifier.binding()
    );
    assert!(restored.circuit.plan.incoming.is_none() && restored.circuit.plan.fold.is_none());
    assert_eq!(restored.circuit.plan.trivial, original.circuit.plan.trivial);
    assert_eq!(restored.instances, original.instances);
    assert_eq!(restored.part, original.part);
    assert_eq!(
        restored.part,
        FoldInput::from_opening(*sigma.opening.g(), sigma.opening.challenges()).unwrap()
    );

    // Canonical but different installed key: refuse before native proof entry.
    let mut foreign = catalog_key.to_bytes().to_vec();
    foreign[10..42].copy_from_slice(&iroha_plonk::transcript::encode_point::<Eq>(
        &(-catalog_key.fixed_commitments()[0]),
    ));
    let foreign = VerifyingKey::<Eq>::read(&foreign, plan.own.verifier.binding()).unwrap();
    assert!(
        validate_load(
            &plan,
            &foreign,
            &public,
            &inner,
            Fq::from(97),
            &FoldConfig::default()
        )
        .is_err()
    );
    for (column, row) in [(0, 0), (0, 1)] {
        let mut changed = original.instances.clone();
        changed[column][row] += Fq::ONE;
        assert!(
            validate_load(
                &plan,
                &catalog_key,
                &frame(&changed),
                &inner,
                Fq::from(97),
                &FoldConfig::default()
            )
            .is_err()
        );
    }
    let mut changed = public.clone();
    changed[0][1][4] ^= 1; // first actual proof byte, leaving LE32/padding intact
    assert!(decode_load(&changed, original.circuit.witness.own.proof.len()).is_ok());
    assert!(
        validate_load(
            &plan,
            &catalog_key,
            &changed,
            &inner,
            Fq::from(97),
            &FoldConfig::default()
        )
        .is_err()
    );
    let mut changed = original.instances.clone();
    let challenge = &mut changed[0][plan.challenge_range().start + 4];
    *challenge = if *challenge == Fq::ONE {
        Fq::from(2)
    } else {
        Fq::ONE
    };
    assert!(decode_load(&frame(&changed), original.circuit.witness.own.proof.len()).is_ok());
    assert!(
        validate_load(
            &plan,
            &catalog_key,
            &frame(&changed),
            &inner,
            Fq::from(97),
            &FoldConfig::default()
        )
        .is_err()
    );
    let mut changed = original.instances.clone();
    let (x, y) = (-*original.part.g()).coordinates().unwrap();
    changed[1] = vec![x, y];
    assert!(decode_load(&frame(&changed), original.circuit.witness.own.proof.len()).is_ok());
    assert!(
        validate_load(
            &plan,
            &catalog_key,
            &frame(&changed),
            &inner,
            Fq::from(97),
            &FoldConfig::default()
        )
        .is_err()
    );

    // All decode/prepare/opening/decide work above is BEFORE the selected cut.
    let outer = PinnedParams::<Ep>::derive(16).unwrap();
    let source = QSigmaSource::new(plan.clone(), catalog_key.clone(), None).unwrap();
    assert_eq!(source.own_key.to_bytes(), catalog_key.to_bytes());
    let mut q_config = KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec());
    q_config.coset_cache = CosetCachePolicy::OnDemand;
    let q_key = keygen_pk_v2(&outer, &source.source_circuit().unwrap(), &q_config).unwrap();
    let q_original = q_key.artifact_bytes_v2().unwrap();
    let prover = QSigmaProver::from_original_artifact_serialized_foreign(
        &source,
        outer,
        q_key.binding().encoded(),
        q_key.vk().to_bytes(),
        &q_original,
        iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: q_original.len(),
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        },
        2,
    )
    .unwrap();
    drop(q_key);
    drop(q_original);
    let first_log = RecoveryLog::default();
    let second_log = RecoveryLog::default();
    let first = prover
        .prove(
            &original,
            recovery(82, first_log.clone()),
            ProverConfig::default(),
        )
        .unwrap();
    let second = prover
        .prove(
            &restored,
            recovery(82, second_log.clone()),
            ProverConfig::default(),
        )
        .unwrap();
    assert_eq!(*first_log.lock().unwrap(), *second_log.lock().unwrap());
    assert_recovery(&first_log);
    assert_recovery(&second_log);
    assert_eq!(first.bytes, second.bytes);
    assert_eq!(first.instances, second.instances);
    assert_eq!(first.part, second.part);
    for proof in [&first, &second] {
        assert_eq!(proof.instances, original.instances);
        assert_eq!(proof.part, original.part);
        iroha_plonk::verify_full(
            prover.params(),
            prover.binding(),
            prover.verifying_key(),
            &proof.instances,
            &proof.bytes,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        proof.part.decide(&inner, MemoryBudget::DEFAULT).unwrap();
    }
    println!(
        "LOAD_PUBLIC_INVERSE sigma_proofs=1 q0_proofs=2 keygens=2 strict_imports=1 serialized_buses=2 selector=1 complete_native_verification=true qualification=false"
    );
}
