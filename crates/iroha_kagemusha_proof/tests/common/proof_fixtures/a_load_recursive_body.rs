// Shared genuine builder items. Registered tests remain in the integration harness.
use iroha_kagemusha_proof::{
    a_relation::native::{
        artifact::KeyArtifact,
        load::{Inputs, Plan, Prover},
    },
    admin_sigma::StateWitness,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget};
use iroha_plonk::{DescriptorBinding, ProverConfig, VerifyingKey, keys::pk::artifact::ReadConfig};
use iroha_plonk_recursion::{AccumulatorT, FoldConfig, FoldInput};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Exact original serialized source artifact; native import checks its complete layout.
pub struct Original {
    /// Canonical source descriptor.
    pub descriptor: Vec<u8>,
    /// Original verifying key.
    pub verifying_key: Vec<u8>,
    path: PathBuf,
    length: usize,
    sha256: [u8; 32],
}
impl Original {
    /// Persist a driver-owned regenerable original and retain only its exact identity.
    /// Existing bytes must match; a live imported key is never kept by this handle.
    pub fn persist(
        path: &Path,
        descriptor: Vec<u8>,
        verifying_key: Vec<u8>,
        bytes: Vec<u8>,
    ) -> Self {
        assert!(!bytes.is_empty() && bytes.len() <= 256 << 20);
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                assert!(metadata.file_type().is_file());
                assert_eq!(metadata.len(), u64::try_from(bytes.len()).unwrap());
                assert_eq!(
                    Sha256::digest(fs::read(path).unwrap()),
                    Sha256::digest(&bytes)
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let pending = path.with_extension("pending");
                match fs::symlink_metadata(&pending) {
                    Ok(metadata) => {
                        assert!(metadata.file_type().is_file());
                        fs::remove_file(&pending).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("unavailable original staging: {error}"),
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&pending)
                    .unwrap();
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
                fs::hard_link(&pending, path).unwrap();
                fs::remove_file(pending).unwrap();
                File::open(path.parent().unwrap())
                    .unwrap()
                    .sync_all()
                    .unwrap();
            }
            Err(error) => panic!("unavailable original artifact: {error}"),
        }
        Self {
            path: path.into(),
            length: bytes.len(),
            sha256: Sha256::digest(bytes).into(),
            descriptor,
            verifying_key,
        }
    }
    fn read(&self, maximum: usize) -> Vec<u8> {
        assert!(self.length <= maximum);
        assert!(
            fs::symlink_metadata(&self.path)
                .unwrap()
                .file_type()
                .is_file()
        );
        let file = File::open(&self.path).unwrap();
        assert_eq!(
            file.metadata().unwrap().len(),
            u64::try_from(self.length).unwrap()
        );
        let mut bytes = Vec::with_capacity(self.length);
        file.take(u64::try_from(self.length).unwrap() + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), self.length);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), self.sha256);
        bytes
    }
    fn metadata<C: iroha_pasta::PastaCurve>(&self) -> KeyArtifact<C> {
        let binding = DescriptorBinding::decode_v2(&self.descriptor).unwrap();
        let key = VerifyingKey::read(&self.verifying_key, &binding).unwrap();
        KeyArtifact::new(binding, key).unwrap()
    }
}
/// Required independently installed source plan and finalized originals.
/// The native producer verifies every original proof and both carried claims.
pub struct InstalledLoad {
    /// Installed monetary source plan binding the native-authorized receipt and Advance.
    pub plan: Plan,
    /// The one actual terminal A source artifact; no W follows it.
    pub terminal: Original,
    /// Exact native-authorized receipt and predecessor/Q originals.
    pub inputs: Inputs,
    /// Finite original-artifact reader bounds.
    pub read: ReadConfig,
}
/// A real fixture owner must rebuild originals for each exact selected predecessor.
/// The callback supplies evidence only; it cannot override native verification.
pub type LoadFixture = Arc<dyn Fn(&bootstrap_outer::RootedBootstrapOmega) -> InstalledLoad>;

/// Actual terminal artifacts for the outer and subsequent-operation assertions.
#[derive(Clone)]
pub struct AuthenticatedLoad {
    /// Actual terminal A key.
    pub key: VerifyingKey<Eq>,
    /// Actual terminal A descriptor.
    pub binding: DescriptorBinding,
    /// Original terminal A proof.
    pub proof: Vec<u8>,
    /// Exact terminal frame.
    pub instances: Vec<Fp>,
    /// Derived original terminal A opening.
    pub opening: FoldInput<Eq>,
    /// Fully verified carried Pallas obligation.
    pub pallas: AccumulatorT<Ep>,
    /// Fully verified predecessor Vesta obligation.
    pub predecessor_vesta: AccumulatorT<Eq>,
    /// Exact funded successor state.
    pub state: StateWitness,
    /// Original native-authorized Load receipt consumed by this proof chain.
    pub receipt: [u8; 282],
}

/// Import the required original, prove the single terminal A and replay its checkpoint
/// from canonical original bytes. The signed Advance binds the native-authorized receipt.
pub fn authenticated_load(
    rooted: &bootstrap_outer::RootedBootstrapOmega,
    fixture: &LoadFixture,
) -> AuthenticatedLoad {
    let source = fixture(rooted);
    assert_eq!(source.inputs.predecessor.proof, rooted.proof);
    assert_eq!(
        source.inputs.predecessor.pallas,
        rooted.source.pallas.to_bytes()
    );
    assert_eq!(source.inputs.predecessor.vesta, rooted.vesta.to_bytes());
    assert_eq!(
        source.inputs.state.predecessor.core,
        rooted.source.state.core
    );
    assert_eq!(
        source.inputs.state.predecessor.rest,
        rooted.source.state.rest
    );
    assert_eq!(
        source.inputs.state.predecessor.lineage,
        rooted.source.state.lineage
    );
    // Genuine originals are mandatory for these substitutions: no host verdict
    // or freshly invented source claim stands in for a finalized positive case.
    for substitution in 0..10 {
        let mut bad = source.inputs.clone();
        match substitution {
            0 => bad.receipt[2] ^= 1,
            1 => bad.receipt[66] ^= 1,
            2 => bad.receipt[130] ^= 1,
            3 => bad.receipt[146] ^= 1,
            4 => bad.receipt[0] ^= 1,
            5 => bad.q[0].proof.push(0),
            6 => bad.q[0].proof[0] ^= 1,
            7 => bad.predecessor.proof[0] ^= 1,
            8 => bad.state.predecessor.lineage[0] += Fp::from(1),
            _ => bad.q[0].instances[0][0] += Fq::from(1),
        }
        assert!(
            source.plan.prepare(bad, MemoryBudget::DEFAULT).is_err(),
            "source substitution {substitution}"
        );
    }
    let state = source.inputs.state.successor;
    let receipt = source.inputs.receipt;
    let other = Prover::from_artifacts(source.plan.clone(), source.terminal.metadata())
        .expect("the original Load source must match the installed plan");
    let prover = Prover::from_artifacts(source.plan, source.terminal.metadata())
        .expect("the original Load source must match the installed plan");
    let binding = prover.descriptors()[0].clone();
    let key = VerifyingKey::read(&source.terminal.verifying_key, &binding).unwrap();
    // D6a (DP §7.4 test 8): a detached session resumes only on the prover instance
    // that prepared it, never on an identically installed one.
    let detached = prover
        .prepare(source.inputs.clone(), MemoryBudget::DEFAULT)
        .expect("native-authorized receipt, predecessor and Q originals are mandatory")
        .into_retained();
    assert!(matches!(
        other.resume(detached),
        Err(iroha_kagemusha_proof::a_relation::native::load::Error::Input)
    ));
    drop(other);
    let inputs = source.inputs;
    let mut session = prover
        .prepare(inputs.clone(), MemoryBudget::DEFAULT)
        .expect("native-authorized receipt, predecessor and Q originals are mandatory");
    let fold = FoldConfig::default();
    let config = ProverConfig::default();
    let active_seal = prover
        .import_terminal(
            &source.terminal.read(source.read.maximum_bytes),
            source.read,
        )
        .unwrap();
    let active = prover.bind_terminal(&active_seal, None).unwrap();
    let terminal = session
        .terminal(
            &active,
            common::public_fixture_tape(201),
            &fold,
            common::fresh_randomness(),
            config,
        )
        .unwrap();
    let mut changed = terminal.proof.clone();
    changed[0] ^= 1;
    assert!(
        session
            .restore_terminal(changed, &terminal.pallas.to_bytes(), MemoryBudget::DEFAULT)
            .is_err()
    );
    let pallas = terminal.pallas.to_bytes();
    for malformed in [&pallas[..pallas.len() - 1], &[0xff; 544][..]] {
        assert!(
            session
                .restore_terminal(terminal.proof.clone(), malformed, MemoryBudget::DEFAULT)
                .is_err(),
            "terminal restore rejects malformed carried Pallas bytes"
        );
    }
    // This predecessor claim already decided in the genuine rooted Bootstrap.
    // Being valid by itself does not make it the claim bound by this Load proof.
    let wrong_pallas = rooted.source.pallas.to_bytes();
    assert_ne!(pallas, wrong_pallas);
    assert!(
        session
            .restore_terminal(terminal.proof.clone(), &wrong_pallas, MemoryBudget::DEFAULT)
            .is_err(),
        "terminal restore rejects a different genuine deciding Pallas claim"
    );
    let encoded = session
        .encode_terminal_checkpoint(&terminal, MemoryBudget::DEFAULT)
        .unwrap();
    let mut trailing = encoded.clone();
    trailing.push(0);
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for malformed in [&encoded[..encoded.len() - 1], &trailing[..], &corrupt[..]] {
        assert!(
            session
                .restore_terminal_checkpoint(malformed, MemoryBudget::DEFAULT)
                .is_err(),
            "terminal checkpoint rejects truncated, trailing or corrupted originals"
        );
    }
    let mut wrong_frame = terminal.clone();
    wrong_frame.instances[0] += Fp::from(1);
    assert!(
        session
            .encode_terminal_checkpoint(&wrong_frame, MemoryBudget::DEFAULT)
            .is_err(),
        "terminal checkpoint cannot substitute the lineage digest"
    );
    // D6a: the session detached and resumed between fold calls restores the durable
    // checkpoint strictly from its bytes.
    session = prover
        .resume(session.into_retained())
        .expect("the preparing prover instance resumes its own session");
    let resumed = session
        .restore_terminal_checkpoint(&encoded, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(resumed.proof, terminal.proof);
    assert_eq!(resumed.instances, terminal.instances);
    assert_eq!(resumed.pallas, terminal.pallas);
    assert_eq!(resumed.predecessor_vesta, terminal.predecessor_vesta);
    assert_eq!(resumed.opening, terminal.opening);
    drop(session);
    // Cold replay has no retained preparation or terminal witness. It must preserve
    // these exact proof bytes and claims after re-verifying the original inputs.
    let restarted = prover
        .prepare(inputs, MemoryBudget::DEFAULT)
        .expect("fresh preparation re-verifies the same Load originals");
    let replayed = restarted
        .restore_terminal_checkpoint(&encoded, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(replayed.proof, terminal.proof);
    assert_eq!(replayed.instances, terminal.instances);
    assert_eq!(replayed.pallas, terminal.pallas);
    assert_eq!(replayed.predecessor_vesta, terminal.predecessor_vesta);
    assert_eq!(replayed.opening, terminal.opening);
    assert_eq!(
        restarted
            .encode_terminal_checkpoint(&replayed, MemoryBudget::DEFAULT)
            .unwrap(),
        encoded
    );
    AuthenticatedLoad {
        key,
        binding,
        proof: replayed.proof,
        instances: replayed.instances,
        opening: replayed.opening,
        pallas: replayed.pallas,
        predecessor_vesta: replayed.predecessor_vesta,
        state,
        receipt,
    }
}
