use FheProofFamily::{BootstrapKey, FullBootstrapExecution, InputAdmission, PublicKey};
use FheValidationScenario::{
    AttachmentMetadataDrift, CanonicalEnvelope, CanonicalVerifierName, CommitmentAndEnvelopeHash,
    InputAdmissionBackendMismatch, OpenVerifyEnvelopeDrift, OversizedPayloads,
    PublicInputShapeReplay, PublishedBounds,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FheProofFamily {
    InputAdmission,
    PublicKey,
    BootstrapKey,
    FullBootstrapExecution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FheValidationScenario {
    PublicInputShapeReplay,
    PublishedBounds,
    OversizedPayloads,
    CanonicalVerifierName,
    InputAdmissionBackendMismatch,
    CanonicalEnvelope,
    CommitmentAndEnvelopeHash,
    OpenVerifyEnvelopeDrift,
    AttachmentMetadataDrift,
}

const FHE_PROOF_VALIDATION_CASE_IDS: [&str; 27] = [
    "fhe_input_admission_proof_validate_rejects_public_input_shape_replay",
    "fhe_input_admission_open_verify_bounds_match_published_caps",
    "fhe_input_admission_proof_validate_rejects_oversized_proof_payloads",
    "fhe_input_admission_proof_validate_requires_canonical_vk_ref_name",
    "fhe_input_admission_proof_validate_rejects_backend_mismatch",
    "fhe_public_key_proof_validate_accepts_canonical_envelope",
    "fhe_public_key_proof_validate_requires_vk_commitment_and_matching_envelope_hash",
    "fhe_public_key_proof_validate_rejects_open_verify_envelope_drift",
    "fhe_public_key_proof_validate_rejects_public_input_shape_replay",
    "fhe_public_key_proof_open_verify_bounds_match_published_caps",
    "fhe_public_key_proof_validate_rejects_oversized_proof_payloads",
    "fhe_public_key_proof_validate_rejects_attachment_metadata_drift",
    "fhe_bootstrap_key_proof_validate_accepts_canonical_envelope",
    "fhe_bootstrap_key_proof_validate_requires_vk_commitment_and_matching_envelope_hash",
    "fhe_bootstrap_key_proof_validate_rejects_open_verify_envelope_drift",
    "fhe_bootstrap_key_proof_validate_rejects_public_input_shape_replay",
    "fhe_bootstrap_key_proof_open_verify_bounds_match_published_caps",
    "fhe_bootstrap_key_proof_validate_rejects_oversized_proof_payloads",
    "fhe_bootstrap_key_proof_validate_requires_canonical_vk_ref_name",
    "fhe_bootstrap_key_proof_validate_rejects_attachment_metadata_drift",
    "fhe_full_bootstrap_execution_proof_validate_accepts_canonical_envelope",
    "fhe_full_bootstrap_execution_proof_validate_requires_vk_commitment_and_matching_envelope_hash",
    "fhe_full_bootstrap_execution_proof_validate_rejects_open_verify_envelope_drift",
    "fhe_full_bootstrap_execution_proof_validate_rejects_public_input_shape_replay",
    "fhe_full_bootstrap_execution_proof_open_verify_bounds_match_published_caps",
    "fhe_full_bootstrap_execution_proof_validate_rejects_oversized_proof_payloads",
    "fhe_full_bootstrap_execution_proof_validate_rejects_attachment_metadata_drift",
];

const FHE_PROOF_VALIDATION_ROUTES: [(FheProofFamily, FheValidationScenario); 27] = [
    (InputAdmission, PublicInputShapeReplay),
    (InputAdmission, PublishedBounds),
    (InputAdmission, OversizedPayloads),
    (InputAdmission, CanonicalVerifierName),
    (InputAdmission, InputAdmissionBackendMismatch),
    (PublicKey, CanonicalEnvelope),
    (PublicKey, CommitmentAndEnvelopeHash),
    (PublicKey, OpenVerifyEnvelopeDrift),
    (PublicKey, PublicInputShapeReplay),
    (PublicKey, PublishedBounds),
    (PublicKey, OversizedPayloads),
    (PublicKey, AttachmentMetadataDrift),
    (BootstrapKey, CanonicalEnvelope),
    (BootstrapKey, CommitmentAndEnvelopeHash),
    (BootstrapKey, OpenVerifyEnvelopeDrift),
    (BootstrapKey, PublicInputShapeReplay),
    (BootstrapKey, PublishedBounds),
    (BootstrapKey, OversizedPayloads),
    (BootstrapKey, CanonicalVerifierName),
    (BootstrapKey, AttachmentMetadataDrift),
    (FullBootstrapExecution, CanonicalEnvelope),
    (FullBootstrapExecution, CommitmentAndEnvelopeHash),
    (FullBootstrapExecution, OpenVerifyEnvelopeDrift),
    (FullBootstrapExecution, PublicInputShapeReplay),
    (FullBootstrapExecution, PublishedBounds),
    (FullBootstrapExecution, OversizedPayloads),
    (FullBootstrapExecution, AttachmentMetadataDrift),
];

#[derive(Clone, Copy)]
struct FheProofProfile {
    fill_byte: u8,
    other_statement_seed: u8,
    canonical_commitment: u8,
    forged_commitment: u8,
    circuit_id: &'static str,
    wrong_circuit_id: &'static str,
    public_inputs_schema: &'static [u8],
    wrong_public_inputs_schema: &'static [u8],
    verifier_alias: &'static str,
    max_open_verify_bytes: usize,
    max_stark_wrapper_bytes: usize,
    max_native_envelope_bytes: usize,
}

impl FheProofFamily {
    fn profile(self) -> FheProofProfile {
        match self {
            Self::InputAdmission => FheProofProfile {
                fill_byte: 0xA5,
                other_statement_seed: 21,
                canonical_commitment: 0x42,
                forged_commitment: 0xA4,
                circuit_id: SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
                wrong_circuit_id: "soracloud_fhe_input_admission_v2",
                public_inputs_schema: SORACLOUD_FHE_INPUT_ADMISSION_PUBLIC_INPUTS_SCHEMA_V1,
                wrong_public_inputs_schema: b"soracloud:fhe-input-admission:public-inputs:v2",
                verifier_alias: "soracloud_fhe_input_admission_alias_v1",
                max_open_verify_bytes: SORACLOUD_FHE_INPUT_ADMISSION_MAX_OPEN_VERIFY_BYTES,
                max_stark_wrapper_bytes: SORACLOUD_FHE_INPUT_ADMISSION_MAX_STARK_WRAPPER_BYTES,
                max_native_envelope_bytes: SORACLOUD_FHE_INPUT_ADMISSION_MAX_NATIVE_ENVELOPE_BYTES,
            },
            Self::PublicKey => FheProofProfile {
                fill_byte: 0xAA,
                other_statement_seed: 15,
                canonical_commitment: 0x4A,
                forged_commitment: 0xA4,
                circuit_id: SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
                wrong_circuit_id: "soracloud_fhe_public_key_v2",
                public_inputs_schema: SORACLOUD_FHE_PUBLIC_KEY_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
                wrong_public_inputs_schema: b"soracloud:fhe-public-key:public-inputs:v2",
                verifier_alias: "soracloud_fhe_public_key_alias_v1",
                max_open_verify_bytes: SORACLOUD_FHE_PUBLIC_KEY_PROOF_MAX_OPEN_VERIFY_BYTES,
                max_stark_wrapper_bytes: SORACLOUD_FHE_PUBLIC_KEY_PROOF_MAX_STARK_WRAPPER_BYTES,
                max_native_envelope_bytes: SORACLOUD_FHE_PUBLIC_KEY_PROOF_MAX_NATIVE_ENVELOPE_BYTES,
            },
            Self::BootstrapKey => FheProofProfile {
                fill_byte: 0xB5,
                other_statement_seed: 21,
                canonical_commitment: 0x52,
                forged_commitment: 0x25,
                circuit_id: SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
                wrong_circuit_id: "soracloud_fhe_bootstrap_key_proof_v2",
                public_inputs_schema: SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
                wrong_public_inputs_schema: b"soracloud:fhe-bootstrap-key:public-inputs:v2",
                verifier_alias: "soracloud_fhe_bootstrap_key_alias_v1",
                max_open_verify_bytes: SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_MAX_OPEN_VERIFY_BYTES,
                max_stark_wrapper_bytes: SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_MAX_STARK_WRAPPER_BYTES,
                max_native_envelope_bytes:
                    SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_MAX_NATIVE_ENVELOPE_BYTES,
            },
            Self::FullBootstrapExecution => FheProofProfile {
                fill_byte: 0xD5,
                other_statement_seed: 21,
                canonical_commitment: 0x63,
                forged_commitment: 0x27,
                circuit_id: SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
                wrong_circuit_id: "iroha_bfv_full_bootstrap_v2",
                public_inputs_schema:
                    SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
                wrong_public_inputs_schema:
                    b"soracloud:fhe-full-bootstrap-execution:public-inputs:v2",
                verifier_alias: "soracloud_fhe_full_bootstrap_execution_alias_v1",
                max_open_verify_bytes:
                    SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_MAX_OPEN_VERIFY_BYTES,
                max_stark_wrapper_bytes:
                    SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_MAX_STARK_WRAPPER_BYTES,
                max_native_envelope_bytes:
                    SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_MAX_NATIVE_ENVELOPE_BYTES,
            },
        }
    }

    fn sample(self) -> FheProof {
        match self {
            Self::InputAdmission => {
                FheProof::InputAdmission(Box::new(sample_fhe_input_admission_proof()))
            }
            Self::PublicKey => FheProof::PublicKey(Box::new(sample_fhe_public_key_proof())),
            Self::BootstrapKey => {
                FheProof::BootstrapKey(Box::new(sample_fhe_bootstrap_key_proof()))
            }
            Self::FullBootstrapExecution => FheProof::FullBootstrapExecution(Box::new(
                sample_fhe_full_bootstrap_execution_proof(),
            )),
        }
    }

    fn bounds(self) -> OpenVerifyEnvelopeBounds {
        match self {
            Self::InputAdmission => soracloud_fhe_input_admission_open_verify_bounds(),
            Self::PublicKey => soracloud_fhe_public_key_proof_open_verify_bounds(),
            Self::BootstrapKey => soracloud_fhe_bootstrap_key_proof_open_verify_bounds(),
            Self::FullBootstrapExecution => {
                soracloud_fhe_full_bootstrap_execution_proof_open_verify_bounds()
            }
        }
    }

    fn schema_hash(self) -> [u8; 32] {
        match self {
            Self::PublicKey => soracloud_fhe_public_key_proof_public_inputs_schema_hash_v1(),
            Self::BootstrapKey => soracloud_fhe_bootstrap_key_proof_public_inputs_schema_hash_v1(),
            Self::FullBootstrapExecution => {
                soracloud_fhe_full_bootstrap_execution_proof_public_inputs_schema_hash_v1()
            }
            Self::InputAdmission => unreachable!("input admission has no canonical-envelope case"),
        }
    }
}

#[derive(Clone)]
enum FheProof {
    InputAdmission(Box<SoracloudFheInputAdmissionProofV1>),
    PublicKey(Box<SoracloudFhePublicKeyProofV1>),
    BootstrapKey(Box<SoracloudFheBootstrapKeyProofV1>),
    FullBootstrapExecution(Box<SoracloudFheFullBootstrapExecutionProofV1>),
}

impl FheProof {
    fn attachment(&self) -> &ProofAttachment {
        match self {
            Self::InputAdmission(proof) => &proof.proof,
            Self::PublicKey(proof) => &proof.proof,
            Self::BootstrapKey(proof) => &proof.proof,
            Self::FullBootstrapExecution(proof) => &proof.proof,
        }
    }

    fn attachment_mut(&mut self) -> &mut ProofAttachment {
        match self {
            Self::InputAdmission(proof) => &mut proof.proof,
            Self::PublicKey(proof) => &mut proof.proof,
            Self::BootstrapKey(proof) => &mut proof.proof,
            Self::FullBootstrapExecution(proof) => &mut proof.proof,
        }
    }

    fn statement_hash(&self) -> Hash {
        match self {
            Self::InputAdmission(proof) => proof.statement_hash,
            Self::PublicKey(proof) => proof.statement_hash,
            Self::BootstrapKey(proof) => proof.statement_hash,
            Self::FullBootstrapExecution(proof) => proof.statement_hash,
        }
    }

    fn validate(&self) -> Result<(), SoracloudManifestError> {
        match self {
            Self::InputAdmission(proof) => proof.validate(),
            Self::PublicKey(proof) => proof.validate(),
            Self::BootstrapKey(proof) => proof.validate(),
            Self::FullBootstrapExecution(proof) => proof.validate(),
        }
    }

    fn replace_envelope(&mut self, envelope: &OpenVerifyEnvelope) {
        match self {
            Self::InputAdmission(proof) => {
                replace_fhe_input_admission_open_verify_envelope(proof, envelope)
            }
            Self::PublicKey(proof) => replace_fhe_public_key_open_verify_envelope(proof, envelope),
            Self::BootstrapKey(proof) => {
                replace_fhe_bootstrap_key_open_verify_envelope(proof, envelope)
            }
            Self::FullBootstrapExecution(proof) => {
                replace_fhe_full_bootstrap_execution_open_verify_envelope(proof, envelope)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum FheErrorExpectation {
    InvalidField(&'static str),
    EmptyField(&'static str),
}

fn assert_fhe_valid(proof: &FheProof, id: &str, expectation: &str) {
    if let Err(err) = proof.validate() {
        panic!("{id}: {expectation}: {err}");
    }
}

fn assert_fhe_rejected(
    proof: &FheProof,
    id: &str,
    label: &str,
    expected: FheErrorExpectation,
    reason: Option<&str>,
) {
    let err = match proof.validate() {
        Ok(()) => panic!("{id}: {label}"),
        Err(err) => err,
    };
    match (expected, &err) {
        (
            FheErrorExpectation::InvalidField(expected),
            SoracloudManifestError::InvalidField { field, .. },
        )
        | (
            FheErrorExpectation::EmptyField(expected),
            SoracloudManifestError::EmptyField { field, .. },
        ) => assert_eq!(*field, expected, "{id}: unexpected error: {err}"),
        _ => panic!("{id}: unexpected error: {err}"),
    }
    if let Some(reason) = reason {
        assert!(
            err.to_string().contains(reason),
            "{id}: unexpected error: {err}"
        );
    }
}

fn decode_fhe_envelope(proof: &FheProof, id: &str) -> OpenVerifyEnvelope {
    match norito::decode_from_bytes::<OpenVerifyEnvelope>(&proof.attachment().proof.bytes) {
        Ok(envelope) => envelope,
        Err(err) => panic!("{id}: decode sample OpenVerifyEnvelope: {err}"),
    }
}

fn decode_fhe_open_proof(envelope: &OpenVerifyEnvelope, id: &str) -> StarkFriOpenProofV1 {
    match norito::decode_from_bytes::<StarkFriOpenProofV1>(&envelope.proof_bytes) {
        Ok(proof) => proof,
        Err(err) => panic!("{id}: decode sample STARK public-input wrapper: {err}"),
    }
}

fn encode_fhe_open_proof(proof: &StarkFriOpenProofV1, id: &str, label: &str) -> Vec<u8> {
    match norito::to_bytes(proof) {
        Ok(bytes) => bytes,
        Err(err) => panic!("{id}: {label}: {err}"),
    }
}

#[derive(Clone, Copy)]
enum PublicInputShapeMutation {
    ExtraRow,
    ExtraColumn,
    DuplicateStatement,
}

fn run_public_input_shape_replay(family: FheProofFamily, id: &str) {
    let sample = family.sample();
    let envelope = decode_fhe_envelope(&sample, id);
    let open_proof = decode_fhe_open_proof(&envelope, id);
    let statement = <[u8; Hash::LENGTH]>::from(sample.statement_hash());
    let other_statement =
        <[u8; Hash::LENGTH]>::from(sample_hash(family.profile().other_statement_seed));
    let mutations = [
        (
            PublicInputShapeMutation::ExtraRow,
            "extra STARK public-input row must be rejected",
        ),
        (
            PublicInputShapeMutation::ExtraColumn,
            "extra STARK public-input column must be rejected",
        ),
        (
            PublicInputShapeMutation::DuplicateStatement,
            "duplicate STARK public-input statement must be rejected",
        ),
    ];
    for (mutation, label) in mutations {
        let public_inputs = match mutation {
            PublicInputShapeMutation::ExtraRow => {
                vec![vec![statement], vec![other_statement]]
            }
            PublicInputShapeMutation::ExtraColumn => vec![vec![statement, other_statement]],
            PublicInputShapeMutation::DuplicateStatement => {
                vec![vec![statement], vec![statement]]
            }
        };
        let mut proof = sample.clone();
        let mut replay_envelope = envelope.clone();
        let mut replay_open = open_proof.clone();
        replay_open.public_inputs = public_inputs;
        replay_envelope.proof_bytes =
            encode_fhe_open_proof(&replay_open, id, "encode replay-shaped STARK wrapper");
        proof.replace_envelope(&replay_envelope);
        assert_fhe_rejected(
            &proof,
            id,
            label,
            FheErrorExpectation::InvalidField("proof.proof.bytes"),
            None,
        );
    }
}

fn run_published_bounds(family: FheProofFamily, id: &str) {
    let profile = family.profile();
    let bounds = family.bounds();
    assert_eq!(
        bounds.max_circuit_id_bytes,
        profile.circuit_id.len(),
        "{id}"
    );
    assert_eq!(
        bounds.max_public_input_bytes,
        profile.public_inputs_schema.len(),
        "{id}"
    );
    assert_eq!(
        bounds.max_proof_bytes, profile.max_stark_wrapper_bytes,
        "{id}"
    );
    assert_eq!(bounds.max_aux_bytes, 0, "{id}");
    assert!(!bounds.allow_aux, "{id}");
    assert!(bounds.require_nonzero_vk_hash, "{id}");
}

fn run_oversized_payloads(family: FheProofFamily, id: &str) {
    let profile = family.profile();
    let sample = family.sample();
    let envelope = decode_fhe_envelope(&sample, id);
    let open_proof = decode_fhe_open_proof(&envelope, id);

    let mut oversized_outer = sample.clone();
    oversized_outer.attachment_mut().proof.bytes =
        vec![profile.fill_byte; profile.max_open_verify_bytes + 1];
    let envelope_hash = <[u8; 32]>::from(Hash::new(&oversized_outer.attachment().proof.bytes));
    oversized_outer.attachment_mut().envelope_hash = Some(envelope_hash);
    assert_fhe_rejected(
        &oversized_outer,
        id,
        "oversized OpenVerify envelope bytes must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        (family != FullBootstrapExecution).then_some("OpenVerifyEnvelope length"),
    );

    let mut oversized_circuit = sample.clone();
    let mut oversized_circuit_envelope = envelope.clone();
    oversized_circuit_envelope.circuit_id = format!("{}_x", profile.circuit_id);
    oversized_circuit.replace_envelope(&oversized_circuit_envelope);
    assert_fhe_rejected(
        &oversized_circuit,
        id,
        "oversized OpenVerify circuit id must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        Some("circuit id length"),
    );

    let mut oversized_schema = sample.clone();
    let mut oversized_schema_envelope = envelope.clone();
    oversized_schema_envelope.public_inputs = profile.public_inputs_schema.to_vec();
    oversized_schema_envelope.public_inputs.push(b'x');
    oversized_schema.replace_envelope(&oversized_schema_envelope);
    assert_fhe_rejected(
        &oversized_schema,
        id,
        "oversized OpenVerify public-input schema must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        Some("public inputs length"),
    );

    let mut oversized_wrapper = sample.clone();
    let mut oversized_wrapper_envelope = envelope.clone();
    oversized_wrapper_envelope.proof_bytes =
        vec![profile.fill_byte; profile.max_stark_wrapper_bytes + 1];
    oversized_wrapper.replace_envelope(&oversized_wrapper_envelope);
    assert_fhe_rejected(
        &oversized_wrapper,
        id,
        "oversized STARK wrapper bytes must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        Some("proof bytes length"),
    );

    let mut oversized_native = sample;
    let mut oversized_native_envelope = envelope;
    let mut oversized_native_open = open_proof;
    oversized_native_open.envelope_bytes =
        vec![profile.fill_byte; profile.max_native_envelope_bytes + 1];
    oversized_native_envelope.proof_bytes =
        encode_fhe_open_proof(&oversized_native_open, id, "encode oversized STARK wrapper");
    oversized_native.replace_envelope(&oversized_native_envelope);
    assert_fhe_rejected(
        &oversized_native,
        id,
        "oversized native STARK envelope bytes must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        Some("native envelope bytes length"),
    );
}

fn run_canonical_verifier_name(family: FheProofFamily, id: &str) {
    let mut proof = family.sample();
    proof.attachment_mut().vk_ref.name = family.profile().verifier_alias.to_string();
    let label = match family {
        InputAdmission => "non-canonical FHE verifier id must be rejected",
        BootstrapKey => "non-canonical bootstrap-key verifier id must be rejected",
        _ => panic!("{id}: canonical-verifier-name case has unsupported family"),
    };
    assert_fhe_rejected(
        &proof,
        id,
        label,
        FheErrorExpectation::InvalidField("proof.vk_ref.name"),
        None,
    );
}

fn run_input_admission_backend_mismatch(id: &str) {
    let mut admission = InputAdmission.sample();
    admission.attachment_mut().proof.backend = "stark/fri/other".into();
    assert_fhe_rejected(
        &admission,
        id,
        "mismatched proof backend must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.backend"),
        None,
    );

    let mut wrong_stark_profile = InputAdmission.sample();
    wrong_stark_profile.attachment_mut().backend = "stark/fri/poseidon2-goldilocks".into();
    let backend = wrong_stark_profile.attachment().backend.clone();
    wrong_stark_profile.attachment_mut().proof.backend = backend.clone();
    wrong_stark_profile.attachment_mut().vk_ref.backend = backend;
    assert_fhe_rejected(
        &wrong_stark_profile,
        id,
        "alternate STARK/FRI profile must be rejected",
        FheErrorExpectation::InvalidField("proof.backend"),
        Some("canonical BFV STARK/FRI backend"),
    );

    let mut unsupported = InputAdmission.sample();
    unsupported.attachment_mut().backend = "stark/fri/debug-proof".into();
    let backend = unsupported.attachment().backend.clone();
    unsupported.attachment_mut().proof.backend = backend.clone();
    unsupported.attachment_mut().vk_ref.backend = backend;
    assert_fhe_rejected(
        &unsupported,
        id,
        "unsupported FHE admission backend must be rejected",
        FheErrorExpectation::InvalidField("proof.backend"),
        None,
    );
}

fn run_canonical_envelope(family: FheProofFamily, id: &str) {
    let proof = family.sample();
    let label = match family {
        PublicKey => "canonical public-key proof envelope must validate",
        BootstrapKey => "canonical bootstrap-key proof envelope must validate",
        FullBootstrapExecution => "canonical full-bootstrap execution proof validates",
        InputAdmission => panic!("{id}: canonical-envelope case has unsupported family"),
    };
    assert_fhe_valid(&proof, id, label);
    let profile = family.profile();
    if family == FullBootstrapExecution {
        let envelope = decode_fhe_envelope(&proof, id);
        assert_eq!(envelope.circuit_id, profile.circuit_id, "{id}");
        assert_eq!(envelope.public_inputs, profile.public_inputs_schema, "{id}");
    }
    assert_eq!(
        family.schema_hash(),
        <[u8; 32]>::from(Hash::new(profile.public_inputs_schema)),
        "{id}"
    );
}

fn run_commitment_and_envelope_hash(family: FheProofFamily, id: &str) {
    let profile = family.profile();
    let mut proof = family.sample();
    proof.attachment_mut().vk_commitment = None;
    assert_fhe_rejected(
        &proof,
        id,
        "missing vk_commitment must be rejected",
        FheErrorExpectation::InvalidField("proof.vk_commitment"),
        None,
    );

    proof.attachment_mut().vk_commitment = Some([profile.canonical_commitment; 32]);
    proof.attachment_mut().envelope_hash = None;
    assert_fhe_rejected(
        &proof,
        id,
        "missing envelope hash must be rejected",
        FheErrorExpectation::InvalidField("proof.envelope_hash"),
        None,
    );

    let envelope_hash = <[u8; 32]>::from(Hash::new(&proof.attachment().proof.bytes));
    proof.attachment_mut().envelope_hash = Some(envelope_hash);
    assert_fhe_valid(&proof, id, "matching envelope hash must be accepted");

    let mut forged_commitment = proof.clone();
    forged_commitment.attachment_mut().vk_commitment = Some([profile.forged_commitment; 32]);
    assert_fhe_rejected(
        &forged_commitment,
        id,
        "forged vk_commitment must be rejected",
        FheErrorExpectation::InvalidField("proof.vk_commitment"),
        None,
    );

    let mut forged_hash = proof.attachment().envelope_hash.expect("matching hash");
    forged_hash[0] ^= 0x01;
    proof.attachment_mut().envelope_hash = Some(forged_hash);
    assert_fhe_rejected(
        &proof,
        id,
        "forged envelope hash must be rejected",
        FheErrorExpectation::InvalidField("proof"),
        None,
    );
}

fn run_open_verify_envelope_drift(family: FheProofFamily, id: &str) {
    let profile = family.profile();
    let sample = family.sample();
    let envelope = decode_fhe_envelope(&sample, id);
    let open_proof = decode_fhe_open_proof(&envelope, id);

    let mut malformed = sample.clone();
    malformed.attachment_mut().proof.bytes = vec![profile.fill_byte];
    let envelope_hash = <[u8; 32]>::from(Hash::new(&malformed.attachment().proof.bytes));
    malformed.attachment_mut().envelope_hash = Some(envelope_hash);
    assert_fhe_rejected(
        &malformed,
        id,
        "malformed OpenVerify bytes must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        None,
    );

    let mut wrong_backend = sample.clone();
    let mut wrong_backend_envelope = envelope.clone();
    wrong_backend_envelope.backend = BackendTag::NativePipaRPasta;
    wrong_backend.replace_envelope(&wrong_backend_envelope);
    assert_fhe_rejected(
        &wrong_backend,
        id,
        "OpenVerify backend drift must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        None,
    );

    let mut wrong_circuit = sample.clone();
    let mut wrong_circuit_envelope = envelope.clone();
    assert_ne!(profile.wrong_circuit_id, profile.circuit_id, "{id}");
    assert!(
        profile.wrong_circuit_id.len() <= family.bounds().max_circuit_id_bytes,
        "{id}: circuit-id drift fixture must remain structurally admissible"
    );
    wrong_circuit_envelope.circuit_id = profile.wrong_circuit_id.to_string();
    wrong_circuit.replace_envelope(&wrong_circuit_envelope);
    assert_fhe_rejected(
        &wrong_circuit,
        id,
        "OpenVerify circuit id drift must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        Some("OpenVerifyEnvelope circuit id must be canonical v1"),
    );

    if family == FullBootstrapExecution {
        reject_wrong_open_verify_schema(&sample, &envelope, profile, id);
        let mut wrong_vk_hash = sample.clone();
        let mut wrong_vk_hash_envelope = envelope.clone();
        wrong_vk_hash_envelope.vk_hash = [0xA4; 32];
        wrong_vk_hash.replace_envelope(&wrong_vk_hash_envelope);
        assert_fhe_rejected(
            &wrong_vk_hash,
            id,
            "OpenVerify verifier-key commitment drift must be rejected",
            FheErrorExpectation::InvalidField("proof.vk_commitment"),
            None,
        );
    }

    let mut wrong_wrapper_version = sample.clone();
    let mut wrong_wrapper_version_envelope = envelope.clone();
    let mut version_drift = open_proof.clone();
    version_drift.version = 2;
    wrong_wrapper_version_envelope.proof_bytes =
        encode_fhe_open_proof(&version_drift, id, "encode version-drifted STARK wrapper");
    wrong_wrapper_version.replace_envelope(&wrong_wrapper_version_envelope);
    assert_fhe_rejected(
        &wrong_wrapper_version,
        id,
        "STARK wrapper version drift must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        None,
    );

    let mut wrong_statement = sample.clone();
    let mut wrong_statement_envelope = envelope.clone();
    let mut statement_drift = open_proof.clone();
    statement_drift.public_inputs = vec![vec![<[u8; Hash::LENGTH]>::from(sample_hash(99))]];
    wrong_statement_envelope.proof_bytes = encode_fhe_open_proof(
        &statement_drift,
        id,
        "encode statement-drifted STARK wrapper",
    );
    wrong_statement.replace_envelope(&wrong_statement_envelope);
    assert_fhe_rejected(
        &wrong_statement,
        id,
        "STARK wrapper statement drift must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        None,
    );

    if family != FullBootstrapExecution {
        reject_wrong_open_verify_schema(&sample, &envelope, profile, id);
    }

    let mut empty_native = sample.clone();
    let mut empty_native_envelope = envelope.clone();
    let mut empty_native_open = open_proof.clone();
    empty_native_open.envelope_bytes.clear();
    empty_native_envelope.proof_bytes =
        encode_fhe_open_proof(&empty_native_open, id, "encode empty-native STARK wrapper");
    empty_native.replace_envelope(&empty_native_envelope);
    assert_fhe_rejected(
        &empty_native,
        id,
        "empty native STARK envelope bytes must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        None,
    );

    let mut all_zero_native = sample;
    let mut all_zero_native_envelope = envelope;
    let mut all_zero_native_open = open_proof;
    all_zero_native_open.envelope_bytes = vec![0; 32];
    all_zero_native_envelope.proof_bytes =
        encode_fhe_open_proof(&all_zero_native_open, id, "encode all-zero STARK wrapper");
    all_zero_native.replace_envelope(&all_zero_native_envelope);
    assert_fhe_rejected(
        &all_zero_native,
        id,
        "all-zero native STARK envelope bytes must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        Some("all-zero"),
    );
}

fn reject_wrong_open_verify_schema(
    sample: &FheProof,
    envelope: &OpenVerifyEnvelope,
    profile: FheProofProfile,
    id: &str,
) {
    let mut wrong_schema = sample.clone();
    let mut wrong_schema_envelope = envelope.clone();
    wrong_schema_envelope.public_inputs = profile.wrong_public_inputs_schema.to_vec();
    wrong_schema.replace_envelope(&wrong_schema_envelope);
    assert_fhe_rejected(
        &wrong_schema,
        id,
        "OpenVerify public-input schema drift must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.bytes"),
        None,
    );
}

fn run_attachment_metadata_drift(family: FheProofFamily, id: &str) {
    let mut proof_backend_mismatch = family.sample();
    proof_backend_mismatch.attachment_mut().proof.backend = "stark/fri/other".into();
    assert_fhe_rejected(
        &proof_backend_mismatch,
        id,
        "mismatched proof backend must be rejected",
        FheErrorExpectation::InvalidField("proof.proof.backend"),
        None,
    );

    let mut vk_backend_mismatch = family.sample();
    vk_backend_mismatch.attachment_mut().vk_ref.backend = "stark/fri/other".into();
    let vk_label = if family == PublicKey {
        "mismatched verifier backend must be rejected"
    } else {
        "mismatched verifier-key backend must be rejected"
    };
    assert_fhe_rejected(
        &vk_backend_mismatch,
        id,
        vk_label,
        FheErrorExpectation::InvalidField("proof.vk_ref.backend"),
        None,
    );

    if family != BootstrapKey {
        let mut wrong_vk_ref = family.sample();
        wrong_vk_ref.attachment_mut().vk_ref.name = family.profile().verifier_alias.to_string();
        let label = if family == PublicKey {
            "non-canonical public-key verifier id must be rejected"
        } else {
            "non-canonical full-bootstrap execution verifier id must be rejected"
        };
        assert_fhe_rejected(
            &wrong_vk_ref,
            id,
            label,
            FheErrorExpectation::InvalidField("proof.vk_ref.name"),
            None,
        );
    }

    let mut wrong_stark_profile = family.sample();
    wrong_stark_profile.attachment_mut().backend = "stark/fri/poseidon2-goldilocks".into();
    let backend = wrong_stark_profile.attachment().backend.clone();
    wrong_stark_profile.attachment_mut().proof.backend = backend.clone();
    wrong_stark_profile.attachment_mut().vk_ref.backend = backend;
    let profile_label = if family == FullBootstrapExecution {
        "non-canonical full-bootstrap execution STARK profile must be rejected"
    } else {
        "alternate STARK/FRI profile must be rejected"
    };
    let profile_reason = if family == FullBootstrapExecution {
        "canonical BFV full-bootstrap"
    } else {
        "canonical BFV STARK/FRI backend"
    };
    assert_fhe_rejected(
        &wrong_stark_profile,
        id,
        profile_label,
        FheErrorExpectation::InvalidField("proof.backend"),
        Some(profile_reason),
    );

    let mut unsupported = family.sample();
    unsupported.attachment_mut().backend = "stark/fri/debug-proof".into();
    let backend = unsupported.attachment().backend.clone();
    unsupported.attachment_mut().proof.backend = backend.clone();
    unsupported.attachment_mut().vk_ref.backend = backend;
    let unsupported_label = match family {
        PublicKey => "unsupported public-key proof backend must be rejected",
        BootstrapKey => "unsupported bootstrap-key proof backend must be rejected",
        FullBootstrapExecution => {
            "unsupported full-bootstrap execution proof backend must be rejected"
        }
        InputAdmission => panic!("{id}: attachment-metadata case has unsupported family"),
    };
    assert_fhe_rejected(
        &unsupported,
        id,
        unsupported_label,
        FheErrorExpectation::InvalidField("proof.backend"),
        None,
    );

    if family == BootstrapKey {
        let mut empty_backend = family.sample();
        empty_backend.attachment_mut().backend = " \t ".into();
        assert_fhe_rejected(
            &empty_backend,
            id,
            "empty bootstrap-key proof backend must be rejected",
            FheErrorExpectation::EmptyField("proof.backend"),
            None,
        );
    }
}

fn run_fhe_proof_validation_case(
    family: FheProofFamily,
    scenario: FheValidationScenario,
    id: &str,
) {
    match scenario {
        PublicInputShapeReplay => run_public_input_shape_replay(family, id),
        PublishedBounds => run_published_bounds(family, id),
        OversizedPayloads => run_oversized_payloads(family, id),
        CanonicalVerifierName => run_canonical_verifier_name(family, id),
        InputAdmissionBackendMismatch => run_input_admission_backend_mismatch(id),
        CanonicalEnvelope => run_canonical_envelope(family, id),
        CommitmentAndEnvelopeHash => run_commitment_and_envelope_hash(family, id),
        OpenVerifyEnvelopeDrift => run_open_verify_envelope_drift(family, id),
        AttachmentMetadataDrift => run_attachment_metadata_drift(family, id),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn fhe_proof_validation_matrix() {
    for (index, id) in FHE_PROOF_VALIDATION_CASE_IDS.into_iter().enumerate() {
        let (family, scenario) = FHE_PROOF_VALIDATION_ROUTES[index];
        run_fhe_proof_validation_case(family, scenario, id);
    }
}
#[test]
fn rollout_provenance_payload_encodes_canonical_tuple() {
    let governance_tx_hash = sample_hash(1);
    let encoded = encode_rollout_provenance_payload(
        "web_portal",
        "rollout-42",
        true,
        Some(50),
        governance_tx_hash,
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&(
        "web_portal",
        "rollout-42",
        true,
        Some(50u8),
        governance_tx_hash,
    ))
    .expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_deploy_provenance_payload_encodes_canonical_tuple() {
    let manifest = sample_agent_apartment_manifest();
    let encoded = encode_agent_deploy_provenance_payload(manifest.clone(), 10_000, 500_000)
        .expect("encode payload");
    let expected = norito::to_bytes(&(manifest, 10_000u64, 500_000u64)).expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_lease_renew_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_lease_renew_provenance_payload("agent-apartment", 20_000)
        .expect("encode payload");
    let expected = norito::to_bytes(&("agent-apartment", 20_000u64)).expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_restart_provenance_payload_encodes_canonical_tuple() {
    let encoded =
        encode_agent_restart_provenance_payload("agent-apartment", "apply patched policy")
            .expect("encode payload");
    let expected =
        norito::to_bytes(&("agent-apartment", "apply patched policy")).expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_policy_revoke_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_policy_revoke_provenance_payload(
        "agent-apartment",
        "wallet.spend",
        Some("limit exceeded"),
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&("agent-apartment", "wallet.spend", Some("limit exceeded")))
        .expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_wallet_spend_provenance_payload_encodes_canonical_tuple() {
    let amount = xor_quantity_from_nanos(1_250_000);
    let encoded = encode_agent_wallet_spend_provenance_payload(
        "agent-apartment",
        "spend-req-9",
        "61CtjvNd9T3THAR65GsMVHr82Bjc",
        &amount,
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&(
        "agent-apartment",
        "spend-req-9",
        "61CtjvNd9T3THAR65GsMVHr82Bjc",
        amount,
    ))
    .expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_wallet_request_id_v1_policy_is_exact() {
    assert!(is_canonical_agent_wallet_request_id_v1("wallet-request:1"));
    assert!(is_canonical_agent_wallet_request_id_v1("wallet request 1"));
    assert!(!is_canonical_agent_wallet_request_id_v1(""));
    assert!(!is_canonical_agent_wallet_request_id_v1(" request-1"));
    assert!(!is_canonical_agent_wallet_request_id_v1("request-1 "));
    assert!(!is_canonical_agent_wallet_request_id_v1("request\n1"));
    assert!(!is_canonical_agent_wallet_request_id_v1(
        &"x".repeat(SORA_AGENT_WALLET_REQUEST_ID_MAX_BYTES_V1 + 1)
    ));
}
#[test]
fn agent_wallet_approve_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_wallet_approve_provenance_payload("agent-apartment", "spend-req-9")
        .expect("encode payload");
    let expected = norito::to_bytes(&("agent-apartment", "spend-req-9")).expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_message_send_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_message_send_provenance_payload(
        "apartment-a",
        "apartment-b",
        "ops",
        "{\"ping\":true}",
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&("apartment-a", "apartment-b", "ops", "{\"ping\":true}"))
        .expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_message_ack_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_message_ack_provenance_payload("agent-apartment", "msg-1")
        .expect("encode payload");
    let expected = norito::to_bytes(&("agent-apartment", "msg-1")).expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_artifact_allow_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_artifact_allow_provenance_payload(
        "agent-apartment",
        "QmArtifactHash",
        Some("QmProvenanceHash"),
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&(
        "agent-apartment",
        "QmArtifactHash",
        Some("QmProvenanceHash"),
    ))
    .expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_autonomy_run_provenance_payload_encodes_canonical_tuple() {
    let encoded = encode_agent_autonomy_run_provenance_payload(
        "agent-apartment",
        "QmArtifactHash",
        Some("QmProvenanceHash"),
        42_000,
        "nightly-retrain",
        Some("{\"inputs\":[\"alpha\",\"beta\"]}"),
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&(
        "agent-apartment",
        "QmArtifactHash",
        Some("QmProvenanceHash"),
        42_000u64,
        "nightly-retrain",
        Some("{\"inputs\":[\"alpha\",\"beta\"]}"),
    ))
    .expect("encode tuple");
    assert_eq!(encoded, expected);
}
#[test]
fn agent_autonomy_run_provenance_payload_preserves_exact_workflow_json_bytes() {
    let workflow_input_json = " { \"input\" : 1 } ";
    let encoded = encode_agent_autonomy_run_provenance_payload(
        "agent-apartment",
        "QmArtifactHash",
        None,
        42_000,
        "nightly-retrain",
        Some(workflow_input_json),
    )
    .expect("encode payload");
    let expected = norito::to_bytes(&(
        "agent-apartment",
        "QmArtifactHash",
        None::<&str>,
        42_000u64,
        "nightly-retrain",
        Some(workflow_input_json),
    ))
    .expect("encode exact tuple");
    assert_eq!(encoded, expected);
}
