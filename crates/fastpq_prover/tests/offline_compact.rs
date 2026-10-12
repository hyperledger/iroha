//! Public-consumer coverage for the normal offline quantity artifact library.

use fastpq_prover as test_prover;
use fastpq_prover as prover;
#[path = "support/complete_effect_fixture.rs"]
mod effect_fixture;
use effect_fixture::EffectFixture;
use fastpq_prover::offline_compact::{ExpectedExecutionEffects, execution_effect_profile_id};
#[path = "support/producer_funding.rs"]
mod producer_funding;
use producer_funding::prove_quantity_axt_artifact;

use fastpq_prover::{
    AXT_DEFAULT_PARAMETER, Error, ProofSemantics, PublicInputs, VerifyLimits,
    gadgets::public_transfer_statement::{
        PublicTransferLimits, TransferSmtBuildLimits, prepare_quantity_public_transfers,
        quantity_rows_for_public_preparation,
    },
    offline_compact::{
        BundleVerificationLimits, ExpectedAxtContext, ExpectedStatement, ProvingError,
        ProvingLimits, VerificationError, VerificationLimits, quantity_artifact_resources,
        quantity_profile_id, verify_quantity_axt_artifact,
    },
    verify_axt_proof_envelope,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::AssetDefinitionId,
    fastpq::{
        FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME,
        FASTPQ_ORDINARY_COMPACT_ARTIFACT_V1_SCHEMA_NAME, FastpqAxtCompactArtifactV1,
        FastpqAxtPreProofMirrorsV1, FastpqAxtPublicMetadataV1, FastpqCompactArtifactDecodeError,
        FastpqCompactArtifactDecodeLimits, FastpqOperationKind, FastpqOrdinaryCompactArtifactV1,
        FastpqPublicInputs, FastpqPublicTransferDeltaV1, FastpqPublicTransferStatementV1,
        FastpqPublicTransferTranscriptV1, FastpqStateTransition,
    },
    nexus::{AxtFastpqBinding, AxtProofEnvelope},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use norito::{NoritoSerialize, core::DecodeLimits};

fn policy() -> VerificationLimits {
    VerificationLimits {
        transport: FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: 1_000_000,
            max_bundle_frame_bytes: 500_000,
            norito: DecodeLimits::new(1_000_000, 1_000_000, 2_000_000, 8_000_000, 32),
        },
        public_statement: PublicTransferLimits::default(),
        bundle: BundleVerificationLimits {
            max_segments: 2,
            max_wire_bytes: 500_000,
            max_total_segment_bytes: 400_000,
            max_total_statement_bytes: 500_000,
            max_total_queries: 154,
            max_total_decode_allocation_charges: 8_000_000,
            segment: VerifyLimits {
                max_queries: 77,
                ..VerifyLimits::default()
            },
        },
        max_segment_decode_allocation_charges: 4_000_000,
        total_decode: DecodeLimits::new(1_000_000, 1_000_000, 4_000_000, 16_000_000, 32),
    }
}

#[test]
fn public_resource_plan_exposes_masked_geometry_and_separate_carrier_costs() {
    let one = quantity_artifact_resources(1, 0).unwrap();
    let two = quantity_artifact_resources(2, policy().bundle.max_total_statement_bytes).unwrap();
    // The implemented base-field masking keeps the fixed wire below the existing
    // ceilings. Row payload alone is not the complete child/carrier budget.
    assert_eq!(one.queries_per_segment, 77);
    assert_eq!(one.minimum_segment_row_bytes, 77 * 301 * size_of::<u64>());
    assert_eq!(
        two.minimum_bundle_row_bytes,
        2 * one.minimum_segment_row_bytes
    );
    assert_eq!(one.maximum_segment_frame_bytes, 500_084);
    assert!(one.maximum_segment_frame_bytes <= 512 * 1024);
    assert!(two.maximum_bundle_frame_bytes <= 1024 * 1024);
    assert!(one.maximum_segment_frame_bytes > policy().transport.max_bundle_frame_bytes);
    assert!(two.maximum_total_segment_frame_bytes > policy().bundle.max_total_segment_bytes);
    assert!(one.maximum_segment_frame_bytes > one.minimum_segment_row_bytes);
    assert!(two.maximum_bundle_frame_bytes > two.maximum_total_segment_frame_bytes);
    assert_eq!(two.total_queries, 2 * one.queries_per_segment);
    assert!(two.segment_charge_bytes > one.segment_charge_bytes);
    assert!(quantity_artifact_resources(0, 0).is_err());
    assert!(quantity_artifact_resources(usize::MAX, 0).is_err());
}

// These independent public roots are fixture expectations, not ledger authority.
// The ordinary quantity preparation is real; no private witness or proof is built.
fn fixture() -> (FastpqPublicTransferStatementV1, ExpectedStatement) {
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let mut sender = Quantity::from(u128::MAX);
    let mut receiver = Quantity::zero();
    let mut deltas = Vec::new();
    for _ in 0..2 {
        let next_sender = sender.try_sub(&Quantity::one()).unwrap();
        let next_receiver = receiver.try_add(&Quantity::one()).unwrap();
        deltas.push(FastpqPublicTransferDeltaV1 {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset.clone(),
            amount: Quantity::one(),
            from_balance_before: sender,
            from_balance_after: next_sender.clone(),
            to_balance_before: receiver,
            to_balance_after: next_receiver.clone(),
        });
        sender = next_sender;
        receiver = next_receiver;
    }
    let claims = vec![FastpqPublicTransferTranscriptV1 {
        batch_hash: Hash::new(b"offline quantity source"),
        deltas,
        authority_digest: Hash::new(b"offline authority fixture"),
        poseidon_preimage_digest: None,
    }];
    let mut dsid = [0; 16];
    dsid[..8].copy_from_slice(&7_u64.to_le_bytes());
    let inputs = PublicInputs {
        dsid,
        slot: 19,
        old_root: Hash::prehashed([1; 32]).into(),
        new_root: Hash::prehashed([2; 32]).into(),
        perm_root: [3; 32],
        tx_set_hash: [4; 32],
    };
    let limits = PublicTransferLimits::default();
    let rows =
        quantity_rows_for_public_preparation(&claims, inputs, limits, limits.max_rows).unwrap();
    let prepared = prepare_quantity_public_transfers(
        &rows,
        &claims,
        inputs,
        ProofSemantics::StateTransition,
        limits,
    )
    .unwrap();
    let mut expected = ExpectedStatement {
        inputs: FastpqPublicInputs {
            dsid: inputs.dsid,
            slot: inputs.slot,
            old_root: inputs.old_root,
            new_root: inputs.new_root,
            perm_root: inputs.perm_root,
            tx_set_hash: inputs.tx_set_hash,
        },
        ordering_hash: prepared.ordering_hash().into(),
        public_statement_digest: [0; 32],
    };
    drop(prepared);
    let statement = FastpqPublicTransferStatementV1 {
        public_inputs: expected.inputs,
        ordering_hash: expected.ordering_hash,
        transitions: rows
            .into_iter()
            .map(|row| FastpqStateTransition {
                key: row.key,
                pre_value: row.pre_value,
                post_value: row.post_value,
                operation: FastpqOperationKind::Transfer,
            })
            .collect(),
        transcripts: claims,
    };
    expected.public_statement_digest =
        Hash::new(norito::encode_canonical(&statement).unwrap()).into();
    (statement, expected)
}

fn ordinary(statement: &FastpqPublicTransferStatementV1, bundle_frame: Vec<u8>) -> Vec<u8> {
    norito::encode_canonical(&EffectFixture::from_transfer_facts(statement).artifact(bundle_frame))
        .unwrap()
}
fn effects() -> EffectFixture {
    EffectFixture::from_transfer_facts(&fixture().0)
}

#[test]
fn expectations_stream_the_complete_canonical_caller_statement() {
    let (statement, independent) = fixture();
    assert_eq!(
        ExpectedStatement::from_statement(&statement).unwrap(),
        independent
    );
    for flags in
        (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            ExpectedStatement::from_statement(&statement).unwrap(),
            independent
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
    for mutate in 0..4 {
        let mut changed = statement.clone();
        match mutate {
            0 => changed.transcripts[0].authority_digest = Hash::new(b"changed authority"),
            1 => changed.transcripts[0].deltas[0].amount = Quantity::from(2_u128),
            2 => changed.transitions[0].key.push(0),
            _ => changed.public_inputs.slot += 1,
        }
        let actual = ExpectedStatement::from_statement(&changed).unwrap();
        assert_ne!(
            actual.public_statement_digest,
            independent.public_statement_digest
        );
        assert_eq!(actual.inputs, changed.public_inputs);
        assert_eq!(actual.ordering_hash, changed.ordering_hash);
        assert_eq!(
            actual.public_statement_digest,
            <[u8; 32]>::from(Hash::new(norito::encode_canonical(&changed).unwrap()))
        );
    }
}

fn binding() -> AxtFastpqBinding {
    AxtFastpqBinding {
        parameter: AXT_DEFAULT_PARAMETER.into(),
        source_dsid: 7,
        source_dataspace: "source".into(),
        source_receipt_id: "receipt-1".into(),
        source_tx_commitment: "11".repeat(32),
        claim_type: "authorization".into(),
        claim_digest: "22".repeat(32),
        witness_commitment: "33".repeat(32),
        policy_commitment: "44".repeat(32),
        verified_effect_type: "restricted_effect".into(),
        corridor: "test-corridor".into(),
        verifier_id: "fastpq".into(),
        verifier_version: "v1".into(),
        target_dsids: vec![9],
        effect_binding: None,
        remote_spend_intent_commitments: Vec::new(),
    }
}

fn metadata() -> FastpqAxtPublicMetadataV1 {
    FastpqAxtPublicMetadataV1 {
        source_transfer_occurrences: Vec::new(),
        parameter: AXT_DEFAULT_PARAMETER.into(),
        entry_hash: [0x11; 32],
        committed_amount: None,
        expiry_slot: 23_u64.to_le_bytes(),
        manifest_root: [0x42; 32],
        da_commitment: [0; 33],
    }
}

fn mirrors() -> FastpqAxtPreProofMirrorsV1 {
    FastpqAxtPreProofMirrorsV1 {
        dsid: DataSpaceId::new(7),
        manifest_root: [0x42; 32],
        da_commitment: None,
        committed_amount: None,
        expiry_slot: Some(23),
    }
}

// A negative carrier fixture uses the exact public nominal wire identity. It
// never manufactures a successful child, or selects an AIR through facade inputs.
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "offline_compact::CandidateCarrier",
    frame = "fastpq_prover::compact_v1::ExecutionEffectBundleV1"
)]
struct CandidateCarrier {
    version: u16,
    intermediate_roots: Vec<[u8; 32]>,
    segments: Vec<Vec<u8>>,
}

fn carrier(segments: Vec<Vec<u8>>) -> Vec<u8> {
    norito::encode_canonical(&CandidateCarrier {
        version: 1,
        intermediate_roots: vec![Hash::prehashed([9; 32]).into()],
        segments,
    })
    .unwrap()
}

#[test]
fn complete_effect_fixture_preserves_quantities_and_derives_typed_key_roots() {
    use iroha_data_model::fastpq::FastpqExecutionEffectKindV1;
    let (transfer, _) = fixture();
    let effect = EffectFixture::from_transfer_facts(&transfer);
    let expected_count: usize = transfer
        .transcripts
        .iter()
        .map(|claim| claim.deltas.len())
        .sum();
    assert_eq!(effect.statement.effects.effects.len(), expected_count);
    assert_eq!(effect.source.effect_count as usize, expected_count);
    assert_eq!(effect.statement.transitions.len(), 2 * expected_count);
    assert_ne!(
        effect.statement.public_inputs.old_root,
        transfer.public_inputs.old_root
    );
    assert_ne!(
        effect.statement.public_inputs.new_root,
        transfer.public_inputs.new_root
    );
    for (ordinal, ((claim, delta), actual)) in transfer
        .transcripts
        .iter()
        .flat_map(|claim| claim.deltas.iter().map(move |delta| (claim, delta)))
        .zip(&effect.statement.effects.effects)
        .enumerate()
    {
        assert_eq!(actual.ordinal as usize, ordinal);
        assert_eq!(actual.authority_digest, claim.authority_digest);
        let FastpqExecutionEffectKindV1::Transfer(actual) = &actual.kind else {
            panic!("this fixture must preserve each transfer occurrence");
        };
        assert_eq!(actual.source.asset.definition, delta.asset_definition);
        assert_eq!(actual.destination.asset, actual.source.asset);
        assert_eq!(actual.source.account, delta.from_account);
        assert_eq!(actual.destination.account, delta.to_account);
        assert_eq!(actual.amount, delta.amount);
        assert_eq!(actual.source_before, delta.from_balance_before);
        assert_eq!(actual.source_after, delta.from_balance_after);
        assert_eq!(actual.destination_before, delta.to_balance_before);
        assert_eq!(actual.destination_after, delta.to_balance_after);
    }
    let facts = effect.facts();
    assert_eq!(
        Into::<[u8; 32]>::into(facts.effects_digest),
        effect.source.effects_digest
    );
    assert_eq!(facts.public_inputs, effect.statement.public_inputs);
    assert_eq!(
        effect.expected().statement.statement_digest,
        facts.statement_digest
    );
}

#[test]
fn public_quantity_verifier_requires_all_seven_independent_expected_inputs() {
    let independent = effects();
    let bytes = norito::encode_canonical(&independent.artifact(carrier(vec![vec![0]; 2]))).unwrap();
    for index in 0..6 {
        let mut wrong = independent.facts();
        match index {
            0 => wrong.public_inputs.dsid[0] ^= 1,
            1 => wrong.public_inputs.slot ^= 1,
            2 => wrong.public_inputs.old_root[0] ^= 1,
            3 => wrong.public_inputs.new_root[0] ^= 1,
            4 => wrong.public_inputs.perm_root[0] ^= 1,
            _ => wrong.public_inputs.tx_set_hash[0] ^= 1,
        }
        assert!(matches!(independent.verify_expected(&bytes,
            ExpectedExecutionEffects { source: &independent.source, statement: wrong }, &policy()),
            Err(VerificationError::Verify(Error::TransferInvariant { details }))
                if details == "execution effect independent statement expectation mismatch"));
    }
    // Ordering belongs to the full canonical statement, not a redundant expectation field.
    let mut altered = independent.artifact(vec![0]);
    altered.statement.ordering_hash[0] ^= 1;
    assert!(matches!(
        independent.verify(&norito::encode_canonical(&altered).unwrap(), &policy()),
        Err(VerificationError::Verify(Error::PublicIoMismatch {
            field: "compact_artifact_public_statement_digest"
        }))
    ));
}

#[test]
fn public_quantity_verifier_rejects_header_drift_before_malformed_child_decode() {
    for authority_header in [true, false] {
        let (mut statement, expected) = fixture();
        if authority_header {
            statement.transcripts[0].authority_digest = Hash::new(b"substituted authority header");
        } else {
            statement.transcripts[0].batch_hash = Hash::new(b"substituted call header");
        }
        assert_eq!(statement.public_inputs, expected.inputs);
        assert_eq!(statement.ordering_hash, expected.ordering_hash);
        let independent = effects();
        let mut effect = independent.artifact(vec![0]);
        if authority_header {
            effect.statement.effects.effects[0].authority_digest =
                Hash::new(b"substituted authority header");
        } else {
            effect.statement.effects.context.entry.entry_hash =
                Hash::new(b"substituted call header");
        }
        assert_eq!(
            effect.statement.public_inputs,
            independent.statement.public_inputs
        );
        assert_eq!(
            effect.statement.ordering_hash,
            independent.statement.ordering_hash
        );
        let ordinary_bytes = norito::encode_canonical(&effect).unwrap();
        let binding = binding();
        let metadata = metadata();
        let mirrors = mirrors();
        let axt_bytes = norito::encode_canonical(&FastpqAxtCompactArtifactV1 {
            profile_id: quantity_profile_id(),
            statement,
            binding: binding.clone(),
            metadata: metadata.clone(),
            mirrors,
            remote_spend_claims: None,
            bundle_frame: vec![0],
        })
        .unwrap();
        for result in [
            independent.verify(&ordinary_bytes, &policy()),
            verify_quantity_axt_artifact(
                &axt_bytes,
                expected,
                ExpectedAxtContext {
                    binding: &binding,
                    metadata: &metadata,
                    mirrors,
                    remote_spend_claims: None,
                },
                policy(),
            ),
        ] {
            assert!(matches!(
                result,
                Err(VerificationError::Verify(Error::PublicIoMismatch {
                    field: "compact_artifact_public_statement_digest",
                }))
            ));
        }
    }
}

#[test]
fn public_axt_verifier_compares_independent_metadata_mirrors_and_remote_presence() {
    let (statement, expected) = fixture();
    let binding = binding();
    let metadata = metadata();
    let mirrors = mirrors();
    let context = ExpectedAxtContext {
        binding: &binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: None,
    };
    let artifact = FastpqAxtCompactArtifactV1 {
        profile_id: quantity_profile_id(),
        statement,
        binding: binding.clone(),
        metadata: metadata.clone(),
        mirrors,
        remote_spend_claims: None,
        bundle_frame: vec![0],
    };
    for case in 0..5 {
        let mut changed = artifact.clone();
        match case {
            0 => changed.binding.source_receipt_id.push('x'),
            1 => changed.metadata.entry_hash[0] ^= 1,
            2 => changed.mirrors.expiry_slot = Some(24),
            3 => changed.remote_spend_claims = Some(Vec::new()),
            _ => changed.metadata.committed_amount = Some([0; 16]),
        }
        let bytes = norito::encode_canonical(&changed).unwrap();
        assert!(matches!(
            verify_quantity_axt_artifact(&bytes, expected, context, policy()),
            Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
        ));
    }
}

#[test]
fn public_verifier_enforces_cumulative_queries_frames_and_statement_caps_before_children() {
    let (statement, _) = fixture();
    let independent = EffectFixture::from_transfer_facts(&statement);
    let bytes = ordinary(&statement, carrier(vec![vec![0, 0], vec![0, 0]]));
    for (label, limits) in [
        (
            "max_bundle_segments",
            VerificationLimits {
                bundle: BundleVerificationLimits {
                    max_segments: 1,
                    ..policy().bundle
                },
                ..policy()
            },
        ),
        (
            "max_bundle_queries",
            VerificationLimits {
                bundle: BundleVerificationLimits {
                    max_total_queries: 153,
                    ..policy().bundle
                },
                ..policy()
            },
        ),
    ] {
        assert!(matches!(
            independent.verify(&bytes, &limits),
            Err(VerificationError::Verify(Error::VerifierLimitExceeded { limit, .. })) if limit == label
        ));
    }
    // The shared carrier decoder enforces its derived cumulative element cap
    // before the later explicit sum check or any child decoding.
    let mut limits = policy();
    limits.bundle.max_total_segment_bytes = 3;
    assert!(matches!(
        independent.verify(&bytes, &limits),
        Err(VerificationError::Verify(Error::Encode(
            norito::Error::TotalElementsExceeded { .. }
        )))
    ));
    let mut limits = policy();
    limits.bundle.max_total_statement_bytes = 0;
    assert!(matches!(
        independent.verify(&bytes, &limits),
        Err(VerificationError::Verify(
            Error::VerifierLimitExceeded { .. }
        ))
    ));
}

#[test]
fn public_verifier_preserves_raw_and_enclosing_decode_limits() {
    let (statement, _) = fixture();
    let independent = EffectFixture::from_transfer_facts(&statement);
    let bytes = ordinary(&statement, vec![0, 0]);
    let zero = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
    let mut limits = policy();
    limits.transport.max_wire_bytes = bytes.len() - 1;
    let (result, usage) =
        norito::core::with_decode_limits_measured(zero, || independent.verify(&bytes, &limits));
    assert!(matches!(
        result,
        Err(VerificationError::Transport(
            FastpqCompactArtifactDecodeError::WireBytes { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert!(matches!(
        norito::core::with_decode_limits_scope(zero, || independent.verify(&bytes, &policy())),
        Err(VerificationError::Transport(
            FastpqCompactArtifactDecodeError::Norito(norito::Error::TotalAllocationExceeded { .. })
        ))
    ));
    let mut limits = policy();
    limits.transport.max_bundle_frame_bytes = 1;
    assert!(matches!(
        independent.verify(&bytes, &limits),
        Err(VerificationError::Transport(
            FastpqCompactArtifactDecodeError::BundleBytes { actual: 2, max: 1 }
        ))
    ));
}

#[test]
fn public_quantity_profile_and_route_are_fixed_and_codec_context_is_restored() {
    let expected_profile = execution_effect_profile_id();
    let expected_axt_profile = quantity_profile_id();
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(execution_effect_profile_id(), expected_profile);
        assert_eq!(quantity_profile_id(), expected_axt_profile);
        assert_ne!(quantity_profile_id(), expected_profile);
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
    let (statement, expected) = fixture();
    let independent = EffectFixture::from_transfer_facts(&statement);
    let mut artifact = independent.artifact(vec![0]);
    artifact.profile_id.0[0] ^= 1;
    assert!(matches!(
        independent.verify(&norito::encode_canonical(&artifact).unwrap(), &policy()),
        Err(VerificationError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
    artifact.profile_id = expected_profile;
    let bytes = norito::encode_canonical(&artifact).unwrap();
    let binding = binding();
    let metadata = metadata();
    assert!(matches!(
        verify_quantity_axt_artifact(
            &bytes,
            expected,
            ExpectedAxtContext {
                binding: &binding,
                metadata: &metadata,
                mirrors: mirrors(),
                remote_spend_claims: None
            },
            policy()
        ),
        Err(VerificationError::Transport(
            FastpqCompactArtifactDecodeError::Norito(_)
        ))
    ));
}

#[test]
fn public_verifier_never_accepts_missing_or_empty_child_occurrences() {
    let (statement, _) = fixture();
    let independent = EffectFixture::from_transfer_facts(&statement);
    for children in [Vec::new(), vec![vec![0]], vec![vec![0], Vec::new()]] {
        let bytes = ordinary(&statement, carrier(children));
        assert!(matches!(
            independent.verify(&bytes, &policy()),
            Err(VerificationError::Verify(Error::TransferInvariant { .. }))
        ));
    }
}

#[test]
fn axt_ingress_rejects_truncated_canonical_artifacts_and_wrong_schemas() {
    let mut transfer_binding = binding();
    transfer_binding.claim_type = "tx_predicate".into();
    fastpq_prover::validate_axt_transfer_claim_binding(&transfer_binding).unwrap();
    for schema in [
        FASTPQ_ORDINARY_COMPACT_ARTIFACT_V1_SCHEMA_NAME,
        FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME,
    ] {
        let mut header = norito::encode_canonical(&0_u8).unwrap();
        header[6..22].copy_from_slice(&norito::core::schema_hash_for_name(schema));
        header.truncate(norito::core::Header::SIZE);
        header[23..31].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut envelope = AxtProofEnvelope {
            dsid: DataSpaceId::new(7),
            manifest_root: [0x42; 32],
            da_commitment: None,
            proof: header,
            fastpq_binding: Some(transfer_binding.clone()),
            committed_amount: None,
            amount_commitment: None,
        };
        assert!(matches!(
            verify_axt_proof_envelope(&envelope),
            Err(Error::InvalidAxtBinding { details })
                if details.starts_with("invalid canonical AXT artifact:")
        ));
        // Opaque effects fail at the semantic boundary, before artifact decoding.
        envelope.fastpq_binding = Some(binding());
        assert!(matches!(
            verify_axt_proof_envelope(&envelope),
            Err(Error::InvalidProofSemantics { .. })
        ));
    }
}

/// Verification policy with producer-sized transport, decoder and proof budgets.
fn producer_policy() -> VerificationLimits {
    let mut verification = policy();
    verification.transport.max_wire_bytes = 20 * 1024 * 1024;
    verification.transport.max_bundle_frame_bytes = 16 * 1024 * 1024;
    verification.transport.norito = DecodeLimits::new(
        20 * 1024 * 1024,
        20 * 1024 * 1024,
        25 * 1024 * 1024,
        96 * 1024 * 1024,
        32,
    );
    verification.total_decode = DecodeLimits::new(
        20 * 1024 * 1024,
        20 * 1024 * 1024,
        30 * 1024 * 1024,
        192 * 1024 * 1024,
        32,
    );
    verification.bundle.max_wire_bytes = 16 * 1024 * 1024;
    verification.bundle.max_total_segment_bytes = 16 * 1024 * 1024;
    verification.bundle.segment.max_proof_bytes = 5 * 1024 * 1024;
    verification
}

/// Each exhausted public, bundle or proving-work ceiling rejects before a trace.
fn assert_producer_limits_reject(
    statement: &FastpqPublicTransferStatementV1,
    expected: ExpectedStatement,
    proving: ProvingLimits,
    verification: &VerificationLimits,
) {
    for name in [
        "max_public_transfer_rows",
        "max_public_transfer_transcripts",
        "max_public_transfer_deltas",
        "max_bundle_segments",
        "max_queries",
        "max_bundle_queries",
        "max_proof_bytes",
        "max_bundle_segment_bytes",
        "max_compact_prover_trace_cells",
        "max_compact_prover_segment_charge_bytes",
        "max_compact_prover_segment_work_units",
        "max_compact_producer_statement_bytes",
    ] {
        let mut limits = *verification;
        let mut work = proving;
        match name {
            "max_public_transfer_rows" => limits.public_statement.max_rows = 0,
            "max_public_transfer_transcripts" => limits.public_statement.max_transcripts = 0,
            "max_public_transfer_deltas" => limits.public_statement.max_deltas = 0,
            "max_bundle_segments" => limits.bundle.max_segments = 1,
            "max_queries" => limits.bundle.segment.max_queries = 76,
            "max_bundle_queries" => limits.bundle.max_total_queries = 153,
            "max_proof_bytes" => limits.bundle.segment.max_proof_bytes = 0,
            "max_bundle_segment_bytes" => limits.bundle.max_total_segment_bytes = 0,
            "max_compact_prover_trace_cells" => work.max_total_trace_cells = 0,
            "max_compact_prover_segment_charge_bytes" => work.max_segment_charge_bytes = 0,
            "max_compact_prover_segment_work_units" => work.max_segment_work_units = 0,
            "max_compact_producer_statement_bytes" => limits.public_statement.max_public_bytes = 0,
            _ => unreachable!(),
        }
        let effect = EffectFixture::from_transfer_facts(statement);
        let actual_name = match name {
            "max_public_transfer_rows" => "max_execution_effect_rows",
            "max_public_transfer_deltas" => "max_execution_effects",
            other => other,
        };
        let binding = binding();
        let metadata = metadata();
        let result = if name == "max_public_transfer_transcripts" {
            prove_quantity_axt_artifact(
                statement,
                expected,
                ExpectedAxtContext {
                    binding: &binding,
                    metadata: &metadata,
                    mirrors: mirrors(),
                    remote_spend_claims: None,
                },
                work,
                limits,
            )
        } else {
            effect.prove(work, &limits)
        };
        assert!(
            matches!(
                result,
                Err(ProvingError::Prove(Error::VerifierLimitExceeded { limit, .. })) if limit == actual_name
            ),
            "expected public producer limit {name}"
        );
    }
}

/// Each decoder budget below the mandatory row payload rejects before a trace.
fn assert_producer_decode_limits_reject(
    statement: &FastpqPublicTransferStatementV1,
    proving: ProvingLimits,
    verification: &VerificationLimits,
) {
    for name in [
        "max_compact_producer_segment_decode_allocation_charges",
        "max_compact_producer_bundle_decode_allocation_charges",
    ] {
        let mut limited = *verification;
        if name == "max_compact_producer_segment_decode_allocation_charges" {
            limited.max_segment_decode_allocation_charges = 0;
        } else {
            limited.bundle.max_total_decode_allocation_charges = 0;
        }
        assert!(
            matches!(
                EffectFixture::from_transfer_facts(statement).prove(proving, &limited),
                Err(ProvingError::Prove(Error::VerifierLimitExceeded { limit, max: 0, .. }))
                    if limit == name
            ),
            "expected public producer decoder limit {name}"
        );
    }
    for (total, names) in [
        (
            false,
            [
                "max_compact_producer_transport_decode_sequence_elements",
                "max_compact_producer_transport_decode_field_bytes",
                "max_compact_producer_transport_decode_total_elements",
                "max_compact_producer_transport_decode_allocation_charges",
                "max_compact_producer_transport_decode_nesting_depth",
            ],
        ),
        (
            true,
            [
                "max_compact_producer_total_decode_sequence_elements",
                "max_compact_producer_total_decode_field_bytes",
                "max_compact_producer_total_decode_total_elements",
                "max_compact_producer_total_decode_allocation_charges",
                "max_compact_producer_total_decode_nesting_depth",
            ],
        ),
    ] {
        for (dimension, name) in names.into_iter().enumerate() {
            let mut limited = *verification;
            let original = if total {
                limited.total_decode
            } else {
                limited.transport.norito
            };
            let mut values = [
                original.max_sequence_elements(),
                original.max_field_bytes(),
                original.max_total_elements(),
                original.max_total_allocated_bytes(),
                original.max_nesting_depth(),
            ];
            values[dimension] = 0;
            let decode = DecodeLimits::new(values[0], values[1], values[2], values[3], values[4]);
            if total {
                limited.total_decode = decode;
            } else {
                limited.transport.norito = decode;
            }
            assert!(
                matches!(
                    EffectFixture::from_transfer_facts(statement).prove(proving, &limited),
                    Err(ProvingError::Prove(Error::VerifierLimitExceeded { limit, max: 0, .. }))
                        if limit == name
                ),
                "expected public producer decoder limit {name}"
            );
        }
    }
}

/// Opaque AXT routes and mismatched source commitments reject before a trace.
fn assert_producer_axt_context_rejects(
    statement: &FastpqPublicTransferStatementV1,
    expected: ExpectedStatement,
    proving: ProvingLimits,
    verification: &VerificationLimits,
) {
    let binding = binding();
    let metadata = metadata();
    let rejected = prove_quantity_axt_artifact(
        statement,
        expected,
        ExpectedAxtContext {
            binding: &binding,
            metadata: &metadata,
            mirrors: mirrors(),
            remote_spend_claims: None,
        },
        proving,
        *verification,
    );
    assert!(
        matches!(&rejected,
            Err(ProvingError::Prove(Error::InvalidProofSemantics { profile, details }))
                if *profile == "axt_opaque_effect"
                    && details == "generic AXT consumers require a witnessed transfer claim; opaque effect carriers require independent authenticated-effect validation"
        ),
        "opaque AXT producer returned {rejected:?}"
    );
    // The earlier fixture selects the opaque route. Select a canonical transfer
    // binding here, retaining an intentionally different source commitment, so
    // the next rejection specifically exercises original transcript linkage.
    let mut transfer_binding = binding;
    transfer_binding.claim_type = "tx_predicate".into();
    fastpq_prover::validate_axt_transfer_claim_binding(&transfer_binding).unwrap();
    assert_ne!(
        statement.transcripts[0].batch_hash.as_ref(),
        metadata.entry_hash.as_slice()
    );
    let rejected = prove_quantity_axt_artifact(
        statement,
        expected,
        ExpectedAxtContext {
            binding: &transfer_binding,
            metadata: &metadata,
            mirrors: mirrors(),
            remote_spend_claims: None,
        },
        proving,
        *verification,
    );
    assert!(
        matches!(&rejected,
            Err(ProvingError::Prove(Error::InvalidAxtBinding { details }))
                if details == "transfer transcript batch_hash does not match source_tx_commitment"
        ),
        "mismatched AXT source commitment returned {rejected:?}"
    );
}

#[test]
fn public_producer_rejects_limits_expectation_drift_and_false_roots_without_a_trace() {
    // One public producer test owns these serial negative requests. Concurrent
    // producer calls intentionally return Busy, so parallel test cases would
    // obscure the particular admission failure being asserted here.
    let (statement, expected) = fixture();
    let proving = ProvingLimits {
        digest_execution: fastpq_prover::DigestExecutionV1::Cpu,
        private_smt: TransferSmtBuildLimits::for_update_limit(4).unwrap(),
        max_total_trace_cells: usize::MAX,
        max_segment_charge_bytes: usize::MAX,
        max_segment_work_units: usize::MAX,
    };
    let verification = producer_policy();
    assert_producer_limits_reject(&statement, expected, proving, &verification);
    assert_producer_decode_limits_reject(&statement, proving, &verification);
    let independent = EffectFixture::from_transfer_facts(&statement);
    for index in 0..6 {
        let mut wrong = independent.facts();
        match index {
            0 => wrong.public_inputs.dsid[0] ^= 1,
            1 => wrong.public_inputs.slot ^= 1,
            2 => wrong.public_inputs.old_root[0] ^= 1,
            3 => wrong.public_inputs.new_root[0] ^= 1,
            4 => wrong.public_inputs.perm_root[0] ^= 1,
            _ => wrong.public_inputs.tx_set_hash[0] ^= 1,
        }
        assert!(matches!(independent.prove_offered(&independent.statement,
            ExpectedExecutionEffects { source: &independent.source, statement: wrong },
            proving, &verification), Err(ProvingError::Prove(Error::TransferInvariant { details }))
                if details == "execution effect independent statement expectation mismatch"));
    }
    let mut wrong_order = independent.statement.clone();
    wrong_order.ordering_hash[0] ^= 1;
    assert!(matches!(
        independent.prove_offered(&wrong_order, independent.expected(), proving, &verification),
        Err(ProvingError::Prove(Error::PublicIoMismatch {
            field: "compact_public_statement_digest"
        }))
    ));
    let mut changed = independent.statement.clone();
    changed.effects.effects[0].authority_digest = Hash::new(b"changed producer authority");
    assert!(matches!(
        independent.prove_offered(&changed, independent.expected(), proving, &verification),
        Err(ProvingError::Prove(Error::PublicIoMismatch {
            field: "compact_public_statement_digest"
        }))
    ));
    // An independently expected but false touched-tree endpoint is never replaced.
    let mut false_roots = independent.clone();
    false_roots.statement.public_inputs.old_root = Hash::new(b"false expected touched root").into();
    assert!(
        matches!(false_roots.prove(proving,&verification),Err(ProvingError::Prove(Error::TransferInvariant{details})) if details.contains("execution effect derived roots differ from public inputs"))
    );
    assert_producer_axt_context_rejects(&statement, expected, proving, &verification);
    // Keep public-producer admission negatives under this single serial owner.
    maximum::assert_maximum_context_preflight();
}

#[path = "support/offline_compact_capture.rs"]
mod capture;

#[path = "support/offline_compact_single.rs"]
mod single;

#[path = "support/offline_compact_two.rs"]
mod two;

#[path = "support/offline_compact_maximum.rs"]
mod maximum;

#[test]
#[ignore = "requires fresh FASTPQ_TEST_ORDINARY_ARTIFACT and FASTPQ_TEST_AXT_ARTIFACT"]
fn captured_deep_artifacts_verify_with_normal_library_and_independent_context() {
    // An integration target links fastpq_prover without its backend cfg(test) helpers.
    // Reconstruct all expectations before reading either untrusted artifact.
    let fixture = capture::CaptureFixture::new();
    let effect = EffectFixture::from_transfer_facts(&fixture.statement);
    let context = fixture.context();
    let limits = capture::capture_policy();
    for (is_axt, variable, label) in [
        (false, "FASTPQ_TEST_ORDINARY_ARTIFACT", "ordinary"),
        (true, "FASTPQ_TEST_AXT_ARTIFACT", "axt"),
    ] {
        let bytes = capture::read_capture(variable, label);
        let expected = if is_axt {
            fixture.expected
        } else {
            effect.public_expectation()
        };
        let verify = |bytes: &[u8], expected: ExpectedStatement| {
            if is_axt {
                verify_quantity_axt_artifact(bytes, expected, context, limits)
            } else {
                let mut facts = effect.facts();
                facts.public_inputs = expected.inputs;
                facts.statement_digest =
                    Hash::from_marked_bytes(expected.public_statement_digest).unwrap();
                effect.verify_expected(
                    bytes,
                    ExpectedExecutionEffects {
                        source: &effect.source,
                        statement: facts,
                    },
                    &limits,
                )
            }
        };
        let accepted = verify(&bytes, expected).unwrap();
        assert_eq!(accepted.expected_statement(), expected);
        assert_eq!(accepted.segments(), 2);
        assert_eq!(accepted.air_row_roots().len(), 2);
        assert_eq!(
            accepted.identity().profile_id,
            if is_axt {
                quantity_profile_id()
            } else {
                execution_effect_profile_id()
            }
        );
        assert_eq!(
            accepted.identity().artifact_bytes,
            u64::try_from(bytes.len()).unwrap()
        );
        assert!(accepted.bundle_frame_bytes() <= 1024 * 1024);

        let mut wrong = expected;
        wrong.public_statement_digest[0] ^= 1;
        assert!(matches!(
            verify(&bytes, wrong),
            Err(VerificationError::Verify(Error::PublicIoMismatch {
                field: "compact_artifact_public_statement_digest"
            }))
        ));
        let mut wrong = expected;
        wrong.inputs.slot ^= 1;
        if is_axt {
            assert!(matches!(
                verify(&bytes, wrong),
                Err(VerificationError::Verify(Error::PublicIoMismatch {
                    field: "compact_model_public_io"
                }))
            ));
        } else {
            // Preserve an independent public-input mismatch under the original digest.
            assert!(matches!(verify(&bytes, wrong),
                Err(VerificationError::Verify(Error::TransferInvariant { details }))
                    if details == "execution effect independent statement expectation mismatch"));
        }
        assert!(verify(&[], expected).is_err());
        assert!(verify(&bytes[..bytes.len() - 1], expected).is_err());
        let mut malformed = bytes.clone();
        *malformed.last_mut().unwrap() ^= 1;
        assert!(verify(&malformed, expected).is_err());
        if is_axt {
            let mut wrong = context;
            wrong.mirrors.expiry_slot = Some(457);
            assert!(matches!(
                verify_quantity_axt_artifact(&bytes, expected, wrong, limits),
                Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
            ));
            let mut wrong = context;
            wrong.remote_spend_claims = None;
            assert!(matches!(
                verify_quantity_axt_artifact(&bytes, expected, wrong, limits),
                Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
            ));
        }
    }
}

#[test]
fn canonical_axt_batch_producer_preflights_without_a_replay_prover() {
    let binding = binding();
    let mut batch = fastpq_prover::TransitionBatch::new("unknown-profile", PublicInputs::default());
    assert!(matches!(
        producer_funding::prove_axt_bound_batch(&batch, &binding),
        Err(Error::ParameterMismatch { expected, actual })
            if expected == AXT_DEFAULT_PARAMETER && actual == "unknown-profile"
    ));
    batch.parameter = AXT_DEFAULT_PARAMETER.into();
    assert!(matches!(
        producer_funding::prove_axt_bound_batch(&batch, &binding),
        Err(Error::InvalidProofSemantics { .. })
    ));
    let mut noncanonical = binding;
    noncanonical.parameter = format!(" {AXT_DEFAULT_PARAMETER} ");
    assert!(matches!(
        producer_funding::prove_axt_bound_batch(&batch, &noncanonical),
        Err(Error::InvalidAxtBinding { .. })
    ));
}
