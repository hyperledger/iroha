//! Full-domain artifact identity, context and inherited decode-budget regressions.

use super::effect_test_support::{EffectFixture, verify as verify_effect};
use super::*;
use crate::backend::compact_quantity_tests::{QuantityCase, QuantityFixture};
use iroha_data_model::fastpq::{FastpqAxtPreProofMirrorsV1, FastpqAxtPublicMetadataV1};

fn policy() -> ArtifactLimits {
    ArtifactLimits {
        transport: FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: 20 * 1024 * 1024,
            max_bundle_frame_bytes: 16 * 1024 * 1024,
            norito: DecodeLimits::new(
                20 * 1024 * 1024,
                20 * 1024 * 1024,
                25 * 1024 * 1024,
                96 * 1024 * 1024,
                32,
            ),
        },
        public_statement: PublicTransferLimits::default(),
        bundle: BundleLimits {
            max_segments: 2,
            max_wire_bytes: 16 * 1024 * 1024,
            max_total_segment_bytes: 16 * 1024 * 1024,
            max_total_statement_bytes: 512 * 1024,
            max_total_queries: 2 * QUERY_COUNT,
            max_total_decode_allocation_charges: 128 * 1024 * 1024,
            segment: crate::VerifyLimits {
                max_proof_bytes: 5 * 1024 * 1024,
                max_queries: QUERY_COUNT,
                ..crate::VerifyLimits::default()
            },
        },
        max_segment_decode_allocation_charges: 64 * 1024 * 1024,
        total_decode: DecodeLimits::new(
            20 * 1024 * 1024,
            20 * 1024 * 1024,
            30 * 1024 * 1024,
            192 * 1024 * 1024,
            32,
        ),
    }
}

fn fixture() -> QuantityFixture {
    let (fixture, private) = QuantityFixture::new(QuantityCase::MixedScale, 2);
    drop(private);
    fixture
}

fn ordinary(fixture: &QuantityFixture, frame: Vec<u8>) -> FastpqOrdinaryCompactArtifactV1 {
    EffectFixture::from_transfer_facts(&fixture.model()).artifact(frame)
}
fn effect_fixture(fixture: &QuantityFixture) -> EffectFixture {
    EffectFixture::from_transfer_facts(&fixture.model())
}

fn axt(fixture: &QuantityFixture, frame: Vec<u8>) -> FastpqAxtCompactArtifactV1 {
    let context = fixture.context();
    let metadata = context.metadata;
    let mirrors = context.mirrors;
    FastpqAxtCompactArtifactV1 {
        profile_id: quantity_diagnostic_profile_id(),
        statement: fixture.model(),
        binding: context.binding.clone(),
        metadata: FastpqAxtPublicMetadataV1 {
            source_transfer_occurrences: metadata.source_transfer_occurrences.to_vec(),
            parameter: metadata.parameter.to_owned(),
            entry_hash: metadata.entry_hash.try_into().unwrap(),
            committed_amount: metadata.committed_amount.map(|b| b.try_into().unwrap()),
            expiry_slot: metadata.expiry_slot.try_into().unwrap(),
            manifest_root: metadata.manifest_root.try_into().unwrap(),
            da_commitment: metadata.da_commitment.try_into().unwrap(),
        },
        mirrors: FastpqAxtPreProofMirrorsV1 {
            dsid: mirrors.dsid,
            manifest_root: mirrors.manifest_root,
            da_commitment: mirrors.da_commitment,
            committed_amount: mirrors.committed_amount,
            expiry_slot: mirrors.expiry_slot,
        },
        remote_spend_claims: context.remote_spend_claims.map(<[_]>::to_vec),
        bundle_frame: frame,
    }
}

#[test]
fn fixed_quantity_profile_is_nominal_distinct_and_codec_independent() {
    let expected = quantity_diagnostic_profile_id();
    assert_ne!(expected, diagnostic_profile_id());
    assert_eq!(
        hex::encode(diagnostic_profile_id().0),
        // Exact predecessor u64 identity remains useful as a negative fixture.
        "0f1fcc226630bbf6f89e84dc6a4841868e4835b8d4a5d6a9261f057194a70676"
    );
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(quantity_diagnostic_profile_id(), expected);
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
    eprintln!("quantity_artifact_profile={}", hex::encode(expected.0));
}

// Frozen input bytes for predecessor rejection only; no old hash/transcript code.
const PREDECESSOR_IDENTITY: &[u8] = b"fastpq:compact:goldilocks-six-lane:h6:g-field-blocks:q375:c401:342cols:923slots:65536rows:8blowup:17folds:v1";
const PREDECESSOR_TAPE_BYTES: [u32; 22] = [
    48, 10_944, 29_568, 96, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
    3_216,
];

// Exact descriptor retained solely as a rejection fixture from the previous
// quantity profile. Field order and both declared Norito identities are the
// predecessor's original values; no production constructor or decoder uses it.
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_model_statement::candidate_artifact::QuantityArtifactProfile",
    frame = "fastpq_prover::compact_v1::QuantityArtifactProfileV1"
)]
struct PredecessorQuantityArtifactProfile {
    version: u16,
    catalog: &'static str,
    protocol: &'static str,
    compact_geometry_identity: Vec<u8>,
    lane_parameter_sha3_256: [u8; 32],
    tape_bytes: [u32; 22],
    quantity_value_schema: &'static str,
    quantity_context_schema: &'static str,
    value_hash_domain: Vec<u8>,
    relation_identities: [&'static str; 4],
}

fn predecessor_quantity_profile() -> FastpqCompactProfileIdV1 {
    let description = PredecessorQuantityArtifactProfile {
        version: 1,
        catalog: fastpq_isi::FASTPQ_CATALOG_V1,
        protocol: fastpq_isi::FASTPQ_FINAL_V1.name,
        compact_geometry_identity: PREDECESSOR_IDENTITY.to_vec(),
        lane_parameter_sha3_256: fastpq_isi::GOLDILOCKS_DIGEST384_PARAMETER_SHA3_256_V1,
        tape_bytes: PREDECESSOR_TAPE_BYTES,
        quantity_value_schema: "fastpq_prover::public_transfer::QuantityValueV1",
        quantity_context_schema: "fastpq_prover::compact_v1::QuantityTransferContextV1",
        value_hash_domain: b"fastpq:quantity:v1:smt:value|".to_vec(),
        relation_identities: [
            FastpqQuantityUnits::TRANSFER_IDENTITY,
            FastpqQuantityUnits::AXT_IDENTITY,
            FastpqQuantityUnits::BATCH_IDENTITY,
            FastpqQuantityUnits::AXT_BATCH_IDENTITY,
        ],
    };
    FastpqCompactProfileIdV1(Sha256::digest(norito::encode_canonical(&description).unwrap()).into())
}

fn assert_profile_rejected_before_child_decode(
    fixture: &QuantityFixture,
    profile_id: FastpqCompactProfileIdV1,
) {
    let mut ordinary = ordinary(fixture, vec![0]);
    let mut axt = axt(fixture, vec![0]);
    ordinary.profile_id = profile_id;
    axt.profile_id = profile_id;
    let expected = fixture.expected();
    let statement_digest = statement_digest(&fixture.model(), usize::MAX).unwrap();
    assert!(matches!(
        verify_effect(
            &norito::encode_canonical(&ordinary).unwrap(),
            &effect_fixture(fixture),
            policy(),
        ),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
    assert!(matches!(
        verify_bound_quantity_axt_artifact(
            &norito::encode_canonical(&axt).unwrap(),
            &expected,
            statement_digest,
            fixture.context(),
            policy(),
        ),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
}

#[test]
fn deep_quantity_descriptor_binds_actual_protocol_and_preserves_value_relations() {
    use norito::schema::identity::NoritoSchema as _;

    let descriptor = DeepQuantityArtifactProfile::fixed();
    assert_eq!(
        DeepQuantityArtifactProfile::frame_name(),
        "fastpq_prover::deep_compact::QuantityArtifactProfileV1"
    );
    assert_eq!(descriptor.version, 1);
    assert_eq!(descriptor.catalog, fastpq_isi::FASTPQ_CATALOG_V1);
    assert_eq!(
        descriptor.transcript_profile,
        crate::backend::transcript_profile::profile().as_bytes()
    );
    assert_eq!(
        descriptor.transcript_profile,
        crate::air::q77::transcript_profile().as_bytes()
    );
    assert_ne!(descriptor.transcript_profile, PREDECESSOR_IDENTITY);
    assert_eq!(descriptor.trace_rows, 65_536);
    assert_eq!(descriptor.trace_root, 0xbe5b_4f4b_47ee_4647);
    assert_eq!(descriptor.lde_rows, 8_388_608);
    assert_eq!(descriptor.lde_root, 0x35c4_528b_4aa6_2eb8);
    assert_eq!(descriptor.coset_offset, COSET_OFFSET);
    assert_eq!(descriptor.committed_columns, 301);
    assert_eq!(descriptor.public_column_layout, LAYOUT_ID);
    assert_eq!(descriptor.constraints, 923);
    assert_eq!(descriptor.modulus, 0xffff_ffff_0000_0001);
    assert_eq!(descriptor.extension_degree, 4);
    assert_eq!(descriptor.extension_nonresidue, 7);
    assert_eq!(
        descriptor.extension_schema,
        crate::GoldilocksFp4V1::frame_name()
    );
    assert_eq!(descriptor.extension_bytes, 32);
    assert_eq!(descriptor.commitment_algorithm, "FIPS202:SHA3-256:suffix06");
    assert_eq!(descriptor.commitment_bytes, 32);
    assert_eq!(
        descriptor.transcript_algorithm,
        "FIPS202:SHAKE256:suffix1f:atomic-raw-tapes"
    );
    assert_eq!(descriptor.trace_mask_coefficients, 162);
    assert_eq!(descriptor.quotient_mask_coefficients, 78);
    assert_eq!(
        descriptor.fiber_encoding,
        "arity-tag:omit-smallest-known-incoming-coordinate"
    );
    assert_eq!(descriptor.fri_arities, [16, 16, 8, 8, 4]);
    assert_eq!(
        descriptor.fri_lengths,
        [8_388_608, 524_288, 32_768, 4_096, 512, 128]
    );
    assert_eq!(descriptor.fri_degrees, [131_072, 8_192, 512, 64, 8, 2]);
    assert_eq!(descriptor.query_count, 77);
    assert_eq!(descriptor.query_candidates, 87);
    assert_eq!(
        descriptor.tape_bytes,
        [32, 29_584, 80, 80, 80, 80, 80, 80, 80, 744]
    );
    assert_eq!(
        descriptor.proof_frame_schema,
        "fastpq_prover::deep_compact::Sha3MaskedCompositionProofV1"
    );
    assert_eq!(
        descriptor.proof_frame_hash,
        norito::schema::identity::frame_hash::<DeepProof>()
    );
    assert_eq!(
        descriptor.quantity_value_schema,
        "fastpq_prover::public_transfer::QuantityValueV1"
    );
    assert_eq!(
        descriptor.quantity_context_schema,
        "fastpq_prover::compact_v1::QuantityTransferContextV1"
    );
    assert_eq!(
        descriptor.value_hash_domain,
        b"fastpq:quantity:v1:smt:value|"
    );
    assert_eq!(
        descriptor.relation_identities,
        [
            FastpqQuantityUnits::BATCH_IDENTITY,
            FastpqQuantityUnits::AXT_BATCH_IDENTITY
        ]
    );
    assert_eq!(descriptor.profile_id(), quantity_diagnostic_profile_id());
}

#[test]
fn every_deep_descriptor_field_changes_the_fixed_artifact_profile() {
    let fixture = fixture();
    let fixed = DeepQuantityArtifactProfile::fixed();
    let expected = fixed.profile_id();
    let reject = |changed: DeepQuantityArtifactProfile| {
        let profile = changed.profile_id();
        assert_ne!(profile, expected);
        assert_profile_rejected_before_child_decode(&fixture, profile);
    };
    macro_rules! change {
        ($field:ident, $value:expr) => {{
            let mut changed = fixed.clone();
            changed.$field = $value;
            reject(changed);
        }};
    }
    change!(version, 2);
    change!(catalog, "different catalog");
    change!(transcript_profile, PREDECESSOR_IDENTITY.to_vec());
    change!(trace_rows, 32_768);
    change!(trace_root, fixed.trace_root ^ 1);
    change!(lde_rows, 524_288);
    change!(lde_root, fastpq_isi::FASTPQ_FINAL_V1.lde_root);
    change!(coset_offset, fixed.coset_offset ^ 1);
    change!(committed_columns, 342);
    change!(public_column_layout, "different column layout");
    change!(constraints, 922);
    change!(modulus, fixed.modulus - 1);
    change!(extension_degree, 2);
    change!(extension_nonresidue, 11);
    change!(extension_schema, "different extension".to_owned());
    change!(extension_bytes, 16);
    change!(commitment_algorithm, "different commitment primitive");
    change!(commitment_bytes, 48);
    change!(transcript_algorithm, "different transcript primitive");
    change!(trace_mask_coefficients, 161);
    change!(quotient_mask_coefficients, 77);
    change!(fiber_encoding, "different fiber encoding");
    change!(query_count, 375);
    change!(query_candidates, 75);
    change!(proof_frame_schema, "different proof frame".to_owned());
    change!(proof_frame_hash, [0; 16]);
    change!(quantity_value_schema, "different value frame");
    change!(quantity_context_schema, "different context frame");
    change!(value_hash_domain, b"different value domain".to_vec());
    for index in 0..5 {
        let mut changed = fixed.clone();
        changed.fri_arities[index] *= 2;
        reject(changed);
    }
    for index in 0..6 {
        let mut changed = fixed.clone();
        changed.fri_lengths[index] *= 2;
        reject(changed);
        let mut changed = fixed.clone();
        changed.fri_degrees[index] *= 2;
        reject(changed);
    }
    for index in 0..10 {
        let mut changed = fixed.clone();
        changed.tape_bytes[index] += 48;
        reject(changed);
    }
    for index in 0..2 {
        let mut changed = fixed.clone();
        changed.relation_identities[index] = "different outer relation";
        reject(changed);
    }
    let mut changed = fixed.clone();
    changed.relation_identities.swap(0, 1);
    reject(changed);
}

#[test]
fn predecessor_quantity_profile_is_rejected_on_both_bound_routes() {
    let predecessor = predecessor_quantity_profile();
    assert_ne!(predecessor, quantity_diagnostic_profile_id());
    assert_ne!(predecessor, diagnostic_profile_id());
    assert_profile_rejected_before_child_decode(&fixture(), predecessor);
}

#[test]
fn advertised_profiles_and_structural_route_cannot_select_quantity_verifiers() {
    let f = fixture();
    let expected = effect_fixture(&f);
    let ordinary_bytes = norito::encode_canonical(&ordinary(&f, vec![])).unwrap();
    let axt_bytes = norito::encode_canonical(&axt(&f, vec![])).unwrap();
    let mut retired = ordinary(&f, vec![]);
    retired.profile_id = quantity_diagnostic_profile_id();
    assert!(matches!(
        verify_effect(
            &norito::encode_canonical(&retired).unwrap(),
            &expected,
            policy()
        ),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
    assert!(matches!(
        verify_axt_artifact(&axt_bytes, &f.expected(), f.context(), policy()),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
    let mut changed = ordinary(&f, vec![]);
    changed.profile_id = diagnostic_profile_id();
    let bytes = norito::encode_canonical(&changed).unwrap();
    assert!(matches!(
        verify_effect(&bytes, &expected, policy()),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
    // The retired u64 profile is negative data, no selectable ordinary implementation.
    assert!(matches!(
        verify_effect(&ordinary_bytes, &expected, policy()),
        Err(ArtifactError::Verify(_))
    ));
    assert!(matches!(
        verify_effect(&axt_bytes, &expected, policy()),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::Norito(_)
        ))
    ));
    assert!(matches!(
        verify_quantity_axt_artifact(&ordinary_bytes, &f.expected(), f.context(), policy()),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::Norito(_)
        ))
    ));
}

#[test]
fn quantity_artifact_compares_every_expected_input_before_child_decode() {
    let f = fixture();
    let independent = effect_fixture(&f);
    let n = independent.statement.effects.effects.len();
    let carrier = norito::encode_canonical(
        &crate::backend::compact_bundle::execution_effect::EffectBundleWire {
            version: 1,
            intermediate_roots: vec![Hash::new(b"invalid child fixture interior").into(); n - 1],
            segments: vec![vec![0]; n],
        },
    )
    .unwrap();
    let ordinary = norito::encode_canonical(&independent.artifact(carrier)).unwrap();
    let axt = norito::encode_canonical(&axt(&f, vec![0])).unwrap();
    for index in 0..7 {
        let mut expected = f.expected();
        match index {
            0 => expected.dsid[0] ^= 1,
            1 => expected.slot ^= 1,
            2 => expected.old_root[0] ^= 1,
            3 => expected.new_root[0] ^= 1,
            4 => expected.perm_root[0] ^= 1,
            5 => expected.tx_set_hash[0] ^= 1,
            _ => expected.ordering_hash[0] ^= 1,
        }
        if index < 6 {
            let mut facts = independent.facts();
            match index {
                0 => facts.public_inputs.dsid[0] ^= 1,
                1 => facts.public_inputs.slot ^= 1,
                2 => facts.public_inputs.old_root[0] ^= 1,
                3 => facts.public_inputs.new_root[0] ^= 1,
                4 => facts.public_inputs.perm_root[0] ^= 1,
                _ => facts.public_inputs.tx_set_hash[0] ^= 1,
            }
            assert!(matches!(super::effect_test_support::verify_expected(
                &ordinary, &independent, crate::offline_compact::ExpectedExecutionEffects {
                    source: &independent.source, statement: facts,
                }, policy()), Err(ArtifactError::Verify(Error::TransferInvariant { details }))
                    if details == "execution effect independent statement expectation mismatch"));
        } else {
            let mut offered = independent.artifact(vec![0]);
            offered.statement.ordering_hash[0] ^= 1;
            assert!(matches!(
                verify_effect(
                    &norito::encode_canonical(&offered).unwrap(),
                    &independent,
                    policy()
                ),
                Err(ArtifactError::Verify(Error::PublicIoMismatch {
                    field: "compact_artifact_public_statement_digest"
                }))
            ));
        }
        assert!(matches!(
            verify_quantity_axt_artifact(&axt, &expected, f.context(), policy()),
            Err(ArtifactError::Verify(Error::PublicIoMismatch { .. }))
        ));
    }
}

#[test]
fn quantity_artifact_requires_original_axt_advertisements_and_remote_preimages() {
    let f = fixture();
    let original = axt(&f, vec![0]);
    for i in 0..4 {
        let mut changed = original.clone();
        match i {
            0 => changed.binding.source_receipt_id.push('x'),
            1 => changed.metadata.parameter.push('x'),
            2 => changed.mirrors.manifest_root[0] ^= 1,
            _ => changed
                .remote_spend_claims
                .as_mut()
                .unwrap()
                .pop()
                .map(|_| ())
                .unwrap(),
        }
        let bytes = norito::encode_canonical(&changed).unwrap();
        assert!(matches!(
            verify_quantity_axt_artifact(&bytes, &f.expected(), f.context(), policy()),
            Err(ArtifactError::Verify(Error::PublicIoMismatch { .. }))
        ));
    }
}

#[test]
fn quantity_artifact_raw_and_inherited_caps_precede_untrusted_allocations() {
    let f = fixture();
    let independent = effect_fixture(&f);
    let expected = f.expected();
    let mut limits = policy();
    limits.transport.max_wire_bytes = 0;
    assert!(matches!(
        verify_effect(&[0], &independent, limits),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::WireBytes { .. }
        ))
    ));
    assert!(matches!(
        verify_quantity_axt_artifact(&[0], &expected, f.context(), limits),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::WireBytes { .. }
        ))
    ));
    let bytes = norito::encode_canonical(&ordinary(&f, vec![0])).unwrap();
    assert!(
        norito::core::with_decode_limits_scope(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || verify_effect(&bytes, &independent, policy())
        )
        .is_err()
    );
    let mut limits = policy();
    limits.transport.max_bundle_frame_bytes = 0;
    assert!(matches!(
        verify_effect(&bytes, &independent, limits),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::BundleBytes { .. }
        ))
    ));
}

#[test]
fn quantity_artifact_false_rows_do_not_reach_the_proof_decoder() {
    let f = fixture();
    let mut artifact = ordinary(&f, vec![0]);
    artifact.statement.transitions[0].pre_value = 1_u64.to_le_bytes().to_vec();
    let bytes = norito::encode_canonical(&artifact).unwrap();
    assert!(matches!(
        verify_effect(&bytes, &effect_fixture(&f), policy()),
        Err(ArtifactError::Verify(_))
    ));
    let limits = PublicTransferLimits {
        max_public_bytes: 0,
        ..PublicTransferLimits::default()
    };
    assert!(matches!(
        verify_effect(
            &norito::encode_canonical(&ordinary(&f, vec![0])).unwrap(),
            &effect_fixture(&f),
            ArtifactLimits {
                public_statement: limits,
                ..policy()
            }
        ),
        Err(ArtifactError::Verify(Error::VerifierLimitExceeded { .. }))
    ));
}

#[test]
fn public_quantity_construction_preserves_enclosing_decode_allocation_budget() {
    use crate::gadgets::public_transfer_statement::{
        TransferSmtBuildLimits, materialize_quantity_public_transfers,
        prepare_quantity_public_transfers,
    };
    let f = fixture();
    // Balance keys use canonical identity encoding, independently of account display.
    // The actual bounded decode here is each QuantityValueV1 transition value.
    let budget = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
    let prepared = norito::core::with_decode_limits_scope(budget, || {
        prepare_quantity_public_transfers(
            &f.rows,
            &f.claims,
            f.inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits::default(),
        )
    });
    assert!(matches!(
        prepared,
        Err(Error::Encode(norito::Error::TotalAllocationExceeded {
            attempted,
            limit: 0,
        })) if attempted > 0
    ));
    let materialized = norito::core::with_decode_limits_scope(budget, || {
        {
            // This test fixture owns its finite tree pool; production supplies its original owner.
            let tree_claims = &f.claims;
            let tree_limits = TransferSmtBuildLimits::for_update_limit(4).unwrap();
            let tree_updates = tree_claims
                .iter()
                .try_fold(0_usize, |count, claim| {
                    count.checked_add(claim.deltas.len())
                })
                .expect("fixture effect count fits")
                .checked_mul(2)
                .expect("fixture row count fits");
            let tree_bytes = tree_limits
                .allocation_bytes(tree_updates, tree_updates)
                .expect("fixture tree allocation demand fits");
            let tree_budget = iroha_allocation::AllocationBudget::new(tree_bytes);
            let mut tree_reservation = tree_budget
                .try_reserve_bytes(tree_bytes)
                .expect("fixture owns complete tree credit");
            materialize_quantity_public_transfers(
                tree_claims,
                f.inputs,
                ProofSemantics::StateTransition,
                PublicTransferLimits::default(),
                tree_limits,
                &tree_budget,
                &mut tree_reservation,
            )
        }
    });
    assert!(matches!(
        materialized,
        Err(Error::Encode(norito::Error::TotalAllocationExceeded {
            attempted,
            limit: 0,
        })) if attempted > 0
    ));

    // A rejected nested decode must release its scope. The same immutable public
    // inputs still prepare and materialize to the original rows, roots and order.
    let restored = f.prepare(ProofSemantics::StateTransition);
    assert_eq!(restored.transitions(), f.rows.as_slice());
    assert_eq!(*restored.public_inputs(), f.inputs);
    let materialized = {
        // This test fixture owns its finite tree pool; production supplies its original owner.
        let tree_claims = &f.claims;
        let tree_limits = TransferSmtBuildLimits::for_update_limit(4).unwrap();
        let tree_updates = tree_claims
            .iter()
            .try_fold(0_usize, |count, claim| {
                count.checked_add(claim.deltas.len())
            })
            .expect("fixture effect count fits")
            .checked_mul(2)
            .expect("fixture row count fits");
        let tree_bytes = tree_limits
            .allocation_bytes(tree_updates, tree_updates)
            .expect("fixture tree allocation demand fits");
        let tree_budget = iroha_allocation::AllocationBudget::new(tree_bytes);
        let mut tree_reservation = tree_budget
            .try_reserve_bytes(tree_bytes)
            .expect("fixture owns complete tree credit");
        materialize_quantity_public_transfers(
            tree_claims,
            f.inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits::default(),
            tree_limits,
            &tree_budget,
            &mut tree_reservation,
        )
    }
    .unwrap();
    assert_eq!(materialized.transitions(), f.rows.as_slice());
    assert_eq!(materialized.public_inputs(), f.inputs);
    assert_eq!(materialized.ordering_hash(), restored.ordering_hash());
}

/// Public canonical descriptor pin: the tracked golden of the frozen artifact
/// descriptor. It pins bytes of the current source and is no approval of them.
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
struct ReviewedProfilePin {
    descriptor_bytes: usize,
    canonical_frame_hex: String,
    profile_sha256: String,
}

#[test]
#[ignore = "prints the native canonical q77 descriptor; the output replaces fixtures/fastpq/q77-quantity-profile.json when the frozen profile changes deliberately"]
fn emit_canonical_q77_quantity_profile_for_review() {
    let descriptor = DeepQuantityArtifactProfile::fixed();
    let bytes = norito::encode_canonical(&descriptor).unwrap();
    let observed = ReviewedProfilePin {
        descriptor_bytes: bytes.len(),
        canonical_frame_hex: hex::encode(&bytes),
        profile_sha256: hex::encode(descriptor.profile_id().0),
    };
    assert_eq!(observed.profile_sha256, hex::encode(Sha256::digest(&bytes)));
    assert_eq!(descriptor.profile_id(), quantity_diagnostic_profile_id());
    println!(
        "observed_q77_profile={}",
        norito::json::to_json(&observed).unwrap()
    );
}

#[test]
fn reviewed_q77_quantity_profile_matches_exact_canonical_descriptor() {
    // The tracked pin is the golden of the frozen descriptor. A deliberate
    // change of the transcript profile or of the artifact descriptor
    // regenerates it with `emit_canonical_q77_quantity_profile_for_review`.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/fastpq/q77-quantity-profile.json");
    let bytes = std::fs::read(path).expect("tracked q77 descriptor pin");
    let pin: ReviewedProfilePin = norito::json::from_slice(&bytes).unwrap();
    let descriptor = DeepQuantityArtifactProfile::fixed();
    let canonical = norito::encode_canonical(&descriptor).unwrap();
    assert_eq!(pin.descriptor_bytes, canonical.len());
    assert_eq!(pin.canonical_frame_hex, hex::encode(&canonical));
    assert_eq!(pin.profile_sha256, hex::encode(Sha256::digest(&canonical)));
    assert_eq!(pin.profile_sha256, hex::encode(descriptor.profile_id().0));
    // The descriptor carries the frozen transcript descriptor bytes in full.
    let transcript = crate::air::q77::transcript_profile().as_bytes();
    assert!(
        canonical
            .windows(transcript.len())
            .any(|window| window == transcript)
    );
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(norito::encode_canonical(&descriptor).unwrap(), canonical);
        assert_eq!(
            hex::encode(quantity_diagnostic_profile_id().0),
            pin.profile_sha256
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
}
