//! Candidate model transport, independent-context and cumulative-budget regressions.

use super::effect_test_support::{EffectFixture, verify as verify_effect};
use super::*;
use crate::backend::compact_axt_context::tests::Fixture;
use iroha_data_model::fastpq::{FastpqAxtPreProofMirrorsV1, FastpqAxtPublicMetadataV1};

fn context(fixture: &Fixture) -> AxtVerificationContext<'_> {
    AxtVerificationContext {
        binding: &fixture.binding,
        metadata: fixture.metadata(),
        mirrors: fixture.outer,
        remote_spend_claims: fixture.remote.as_deref(),
    }
}

fn limits() -> ArtifactLimits {
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
            max_total_queries: 154,
            max_total_decode_allocation_charges: 128 * 1024 * 1024,
            segment: crate::VerifyLimits {
                max_proof_bytes: 4_326_227,
                max_queries: 77,
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

fn ordinary(
    fixture: &Fixture,
    bundle_frame: Vec<u8>,
) -> (FastpqOrdinaryCompactArtifactV1, EffectFixture) {
    let prepared = fixture.prepare(ProofSemantics::StateTransition);
    let source = EffectFixture::from_transfer_facts(&super::super::tests::model(&prepared));
    (source.artifact(bundle_frame), source)
}

fn axt(fixture: &Fixture, bundle_frame: Vec<u8>) -> (FastpqAxtCompactArtifactV1, PublicIO) {
    let prepared = fixture.prepare(ProofSemantics::AxtTransferClaim);
    let expected = fixture.expected(&prepared);
    let metadata = fixture.metadata();
    (
        FastpqAxtCompactArtifactV1 {
            profile_id: diagnostic_profile_id(),
            statement: super::super::tests::model(&prepared),
            binding: fixture.binding.clone(),
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
                dsid: fixture.outer.dsid,
                manifest_root: fixture.outer.manifest_root,
                da_commitment: fixture.outer.da_commitment,
                committed_amount: fixture.outer.committed_amount,
                expiry_slot: fixture.outer.expiry_slot,
            },
            remote_spend_claims: fixture.remote.clone(),
            bundle_frame,
        },
        expected,
    )
}

#[test]
fn fixed_profile_and_nominal_route_cannot_be_chosen_by_artifact() {
    assert_eq!(
        hex::encode(diagnostic_profile_id().0),
        "0f1fcc226630bbf6f89e84dc6a4841868e4835b8d4a5d6a9261f057194a70676"
    );
    let fixture = Fixture::new(false);
    let (ordinary, expected) = ordinary(&fixture, Vec::new());
    let (axt, _) = axt(&fixture, Vec::new());
    let mut wrong = ordinary.clone();
    wrong.profile_id.0[0] ^= 1;
    assert!(matches!(
        verify_effect(
            &norito::encode_canonical(&wrong).unwrap(),
            &expected,
            &limits()
        ),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::ProfileMismatch
        ))
    ));
    assert!(matches!(
        verify_effect(
            &norito::encode_canonical(&axt).unwrap(),
            &expected,
            &limits()
        ),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::Norito(_)
        ))
    ));
    assert!(matches!(
        verify_axt_artifact(
            &norito::encode_canonical(&ordinary).unwrap(),
            &fixture.expected(&fixture.prepare(ProofSemantics::AxtTransferClaim)),
            context(&fixture),
            limits()
        ),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::Norito(_)
        ))
    ));
}

#[test]
fn raw_cap_precedes_decode_and_outer_budget_cannot_be_relaxed() {
    let fixture = Fixture::new(false);
    let (artifact, expected) = ordinary(&fixture, Vec::new());
    let bytes = norito::encode_canonical(&artifact).unwrap();
    let mut policy = limits();
    policy.transport.max_wire_bytes = bytes.len() - 1;
    let zero = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
    let (result, usage) = norito::core::with_decode_limits_measured(zero, || {
        verify_effect(&bytes, &expected, &policy)
    });
    assert!(matches!(
        result,
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::WireBytes { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert!(matches!(
        norito::core::with_decode_limits_scope(zero, || verify_effect(
            &bytes,
            &expected,
            &limits()
        )),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::Norito(norito::Error::TotalAllocationExceeded { .. })
        ))
    ));
    let mut policy = limits();
    policy.total_decode = zero;
    assert!(matches!(
        verify_effect(&bytes, &expected, &policy),
        Err(ArtifactError::Transport(
            FastpqCompactArtifactDecodeError::Norito(norito::Error::TotalAllocationExceeded { .. })
        ))
    ));
}

#[test]
fn all_public_expectations_are_checked_before_child_decoding() {
    let fixture = Fixture::new(false);
    let (artifact, expected) = ordinary(&fixture, Vec::new());
    for index in 0..7 {
        let mut altered = artifact.clone();
        let public = &mut altered.statement.public_inputs;
        match index {
            0 => public.dsid[0] ^= 1,
            1 => public.slot ^= 1,
            2 => public.old_root[0] ^= 1,
            3 => public.new_root[0] ^= 1,
            4 => public.perm_root[0] ^= 1,
            5 => public.tx_set_hash[0] ^= 1,
            _ => altered.statement.ordering_hash[0] ^= 1,
        }
        assert!(matches!(
            verify_effect(
                &norito::encode_canonical(&altered).unwrap(),
                &expected,
                &limits()
            ),
            Err(ArtifactError::Verify(Error::PublicIoMismatch {
                field: "compact_artifact_public_statement_digest"
            }))
        ));
    }
    let mut policy = limits();
    policy.public_statement.max_rows = 0;
    assert!(matches!(
        verify_effect(
            &norito::encode_canonical(&artifact).unwrap(),
            &expected,
            &policy
        ),
        Err(ArtifactError::Verify(Error::VerifierLimitExceeded {
            limit: "max_execution_effect_rows",
            ..
        }))
    ));
}

#[test]
fn all_axt_advertisements_must_match_independent_caller_context() {
    let fixture = Fixture::new(true);
    let (artifact, expected) = axt(&fixture, Vec::new());
    validate_axt_advertisement(&artifact, context(&fixture)).unwrap();
    for index in 0..16 {
        let mut altered = artifact.clone();
        let field = match index {
            0 => {
                altered.binding.parameter.push('x');
                "compact_artifact_binding"
            }
            1 => {
                altered.metadata.parameter.push('x');
                "compact_artifact_parameter"
            }
            2 => {
                altered.metadata.entry_hash[0] ^= 1;
                "compact_artifact_entry_hash"
            }
            3 => {
                altered.metadata.committed_amount = Some([0; 16]);
                "compact_artifact_amount_bytes"
            }
            4 => {
                altered.metadata.expiry_slot[0] ^= 1;
                "compact_artifact_expiry_bytes"
            }
            5 => {
                altered.metadata.manifest_root[0] ^= 1;
                "compact_artifact_manifest_bytes"
            }
            6 => {
                altered.metadata.da_commitment[0] ^= 1;
                "compact_artifact_da_bytes"
            }
            7 => {
                altered.mirrors.dsid = iroha_model_base::topology::DataSpaceId::new(u64::MAX);
                "compact_artifact_mirror_dsid"
            }
            8 => {
                altered.mirrors.manifest_root[0] ^= 1;
                "compact_artifact_mirror_manifest"
            }
            9 => {
                altered.mirrors.da_commitment = Some([0; 32]);
                "compact_artifact_mirror_da"
            }
            10 => {
                altered.mirrors.committed_amount = Some(0);
                "compact_artifact_mirror_amount"
            }
            11 => {
                altered.mirrors.expiry_slot = Some(0);
                "compact_artifact_mirror_expiry"
            }
            12 => {
                altered.remote_spend_claims = None;
                "compact_artifact_remote_claims"
            }
            13 => {
                altered.remote_spend_claims = Some(Vec::new());
                "compact_artifact_remote_claims"
            }
            15 => {
                altered.metadata.source_transfer_occurrences[0].source_success_receipt_digest[0] ^=
                    1;
                "compact_artifact_source_occurrences"
            }
            _ => {
                altered.metadata.committed_amount = None;
                "compact_artifact_amount_bytes"
            }
        };
        let result = verify_axt_artifact(
            &norito::encode_canonical(&altered).unwrap(),
            &expected,
            context(&fixture),
            limits(),
        );
        assert!(
            matches!(result, Err(ArtifactError::Verify(Error::PublicIoMismatch { field: actual })) if actual == field),
            "case {index}: {result:?}"
        );
    }
    let no_remote = Fixture::new(false);
    let (mut altered, _) = axt(&no_remote, Vec::new());
    altered.remote_spend_claims = Some(Vec::new());
    assert!(validate_axt_advertisement(&altered, context(&no_remote)).is_err());
}

#[test]
fn canonical_model_transport_is_independent_of_ambient_flags() {
    let fixture = Fixture::new(false);
    let (artifact, expected) = ordinary(&fixture, Vec::new());
    let bytes = norito::encode_canonical(&artifact).unwrap();
    for flags in (u8::MIN..=u8::MAX).filter(|&f| norito::core::validate_header_flags(f).is_ok()) {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(norito::encode_canonical(&artifact).unwrap(), bytes);
        let result = verify_effect(&bytes, &expected, &limits());
        // Valid model facts reach the intentionally absent child carrier.
        assert!(
            matches!(result, Err(ArtifactError::Verify(Error::Encode(_)))),
            "{result:?}"
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
}

#[test]
fn identity_statement_digest_is_canonical_and_bounded_before_output_allocation() {
    let fixture = Fixture::new(false);
    let (effect, _) = ordinary(&fixture, Vec::new());
    let view=crate::gadgets::public_transfer_statement::execution_effect::SourceExecutionEffectStatement::from_owned(&effect.statement);
    let effect_bytes = norito::encode_canonical(&effect.statement).unwrap();
    assert_eq!(
        view.digest(effect_bytes.len()).unwrap(),
        iroha_data_model::fastpq::execution_effect_statement_digest_v1(&effect.statement).unwrap()
    );
    assert!(view.digest(effect_bytes.len() - 1).is_err());
    let (artifact, _) = axt(&fixture, Vec::new());
    let canonical = norito::encode_canonical(&artifact.statement).unwrap();
    let expected: [u8; 32] = Hash::new(&canonical).into();
    for flags in (u8::MIN..=u8::MAX).filter(|&f| norito::core::validate_header_flags(f).is_ok()) {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            statement_digest(&artifact.statement, canonical.len()).unwrap(),
            expected
        );
        assert!(matches!(
            statement_digest(&artifact.statement, canonical.len() - 1),
            Err(Error::VerifierLimitExceeded {
                limit: "max_compact_identity_statement_bytes",
                ..
            })
        ));
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
}
