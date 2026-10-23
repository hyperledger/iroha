// Focused first-release Exact12 release and deployment manifest tests.

use iroha_crypto::{Algorithm, KeyPair, Signature};

fn release_manifest_test_key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("derive deterministic synthetic manifest key")
}

fn release_manifest_test_signature(key: &KeyPair, payload: &[u8]) -> Signature {
    Signature::try_new(key.private_key(), payload).expect("sign synthetic manifest payload")
}

fn release_manifest_placeholder_signature() -> Signature {
    Signature::from_bytes(&[1; 64])
}

fn synthetic_valid_release_manifest() -> PrivacyExact12ReleaseManifestV1 {
    let protocols = PrivacyProtocolIdV1::ALL
        .into_iter()
        .enumerate()
        .map(|(index, protocol_id)| {
            let parameter_digest =
                PrivacyParameterDigestV1::new(raw(u8::try_from(index + 1).expect("small index")));
            let verifier_digest =
                PrivacyVerifierDigestV1::new(raw(u8::try_from(index + 21).expect("small index")));
            let security_claim = PrivacySecurityClaimV1 {
                catalog_commitment: PrivacyExact12CatalogCommitmentV1::canonical(),
                protocol_id,
                security_model: protocol_id.security_model(),
                target_security_bits: PRIVACY_MINIMUM_SECURITY_BITS_V1,
                achieved_security_bits: PRIVACY_MINIMUM_SECURITY_BITS_V1,
                parameter_digest,
                verifier_digest,
                reduction_digest: PrivacySecurityReductionDigestV1::new(raw(u8::try_from(
                    index + 41,
                )
                .expect("small index"))),
                audit_bundle_digest: PrivacyAuditBundleDigestV1::new([0; 32]),
            };
            PrivacyReleaseProtocolBindingV1 {
                protocol_id,
                proof_system_id: protocol_id.expected_proof_system(),
                engine_id: protocol_id.expected_engine(),
                parameter_id: PrivacyParameterIdV1::new(raw(
                    u8::try_from(index + 201).expect("small index")
                )),
                parameter_digest,
                verifier_digest,
                statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(u8::try_from(
                    index + 61,
                )
                .expect("small index"))),
                engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(u8::try_from(
                    index + 81,
                )
                .expect("small index"))),
                security_claim,
                security_claim_digest: PrivacySecurityClaimDigestV1::new([0; 32]),
            }
        })
        .collect::<Vec<_>>();

    let mut stage_receipts = Vec::with_capacity(PRIVACY_EXACT12_RELEASE_STAGE_RECEIPTS_V1);
    let mut proof_artifacts = Vec::with_capacity(PRIVACY_EXACT12_RELEASE_PROOF_ARTIFACTS_V1);
    for (protocol_index, protocol_id) in PrivacyProtocolIdV1::ALL.into_iter().enumerate() {
        let binding = &protocols[protocol_index];
        for (stage_index, stage) in PrivacyReleaseStageV1::ALL.into_iter().enumerate() {
            let stage_ordinal =
                protocol_index * PRIVACY_EXACT12_RELEASE_STAGES_PER_PROTOCOL_V1 + stage_index;
            let receipt_digest = PrivacyReleaseArtifactDigestV1::new(raw(u8::try_from(
                stage_ordinal + 1,
            )
            .expect("48 stages fit u8")));
            stage_receipts.push(PrivacyReleaseStageReceiptV1 {
                stage_ordinal: u16::try_from(stage_ordinal).expect("48 stages fit u16"),
                protocol_id,
                stage,
                security_claim_digest: binding.security_claim_digest,
                parameter_digest: binding.parameter_digest,
                verifier_digest: binding.verifier_digest,
                engine_manifest_digest: binding.engine_manifest_digest,
                receipt_digest,
            });
            for stage_artifact_ordinal in
                0..privacy_exact12_release_proof_artifact_count_v1(protocol_id, stage)
            {
                let artifact_index = proof_artifacts.len();
                proof_artifacts.push(PrivacyReleaseProofArtifactV1 {
                    protocol_id,
                    stage,
                    stage_artifact_ordinal,
                    stage_receipt_digest: receipt_digest,
                    security_claim_digest: binding.security_claim_digest,
                    parameter_digest: binding.parameter_digest,
                    verifier_digest: binding.verifier_digest,
                    engine_manifest_digest: binding.engine_manifest_digest,
                    artifact_digest: PrivacyReleaseArtifactDigestV1::new(raw(u8::try_from(
                        artifact_index + 101,
                    )
                    .expect("54 artifacts fit seed range"))),
                });
            }
        }
    }

    let binary_digest = PrivacyReleaseArtifactDigestV1::new(raw(240));
    let fixture_corpus_digest = PrivacyReleaseArtifactDigestV1::new(raw(159));
    let deterministic_output_digest = PrivacyReleaseArtifactDigestV1::new(raw(176));
    let mut manifest = PrivacyExact12ReleaseManifestV1 {
        version: PRIVACY_EXACT12_RELEASE_MANIFEST_VERSION_V1,
        catalog_id: String::from_utf8(PRIVACY_EXACT12_CATALOG_ID_V1.to_vec())
            .expect("the pinned catalog identity is ASCII"),
        catalog_commitment: PrivacyExact12CatalogCommitmentV1::canonical(),
        source: PrivacyReleaseSourceIdentityV1 {
            source_tree_digest: PrivacyReleaseArtifactDigestV1::new(raw(250)),
            source_tree_clean: true,
            toolchain_id: "synthetic-rust-toolchain".to_owned(),
            toolchain_digest: PrivacyReleaseArtifactDigestV1::new(raw(251)),
            cargo_lock_digest: PrivacyReleaseArtifactDigestV1::new(raw(252)),
        },
        abi_version: PRIVACY_EXACT12_ABI_VERSION_V1,
        abi_hash: PrivacyReleaseArtifactDigestV1::new(raw(253)),
        syscall_list_digest: PrivacyReleaseArtifactDigestV1::new(raw(254)),
        executables: vec![
            PrivacyReleaseExecutableArtifactV1 {
                kind: PrivacyReleaseExecutableKindV1::Binary,
                name: "synthetic-iroha3d".to_owned(),
                artifact_digest: binary_digest,
            },
            PrivacyReleaseExecutableArtifactV1 {
                kind: PrivacyReleaseExecutableKindV1::ContainerImage,
                name: "synthetic-iroha3d-image".to_owned(),
                artifact_digest: PrivacyReleaseArtifactDigestV1::new(raw(241)),
            },
        ],
        protocols,
        stage_receipts,
        proof_artifacts,
        sdk_packages: PrivacyReleaseSdkConsumerV1::ALL
            .into_iter()
            .enumerate()
            .map(|(index, consumer)| PrivacyReleaseSdkPackageV1 {
                consumer,
                package_name: format!("synthetic-sdk-{index}"),
                package_version: "1.0.0-test".to_owned(),
                package_digest: PrivacyReleaseArtifactDigestV1::new(raw(
                    u8::try_from(index + 160).expect("small SDK index")
                )),
                fixture_corpus_digest,
            })
            .collect(),
        hardware_results: PrivacyReleaseHardwareBackendV1::ALL
            .into_iter()
            .enumerate()
            .map(|(index, backend)| PrivacyReleaseHardwareResultV1 {
                backend,
                tested_binary_digest: binary_digest,
                deterministic_output_digest,
                scalar_reference_digest: deterministic_output_digest,
                result_digest: PrivacyReleaseArtifactDigestV1::new(raw(
                    u8::try_from(index + 170).expect("small hardware index")
                )),
                runtime_self_test_passed: true,
            })
            .collect(),
        release_artifact_set_digest: PrivacyReleaseArtifactDigestV1::new([0; 32]),
        audits: Vec::new(),
        audit_bundle_digest: PrivacyAuditBundleDigestV1::new([0; 32]),
        release_signatures: Vec::new(),
        manifest_digest: PrivacyExact12ReleaseManifestDigestV1::new([0; 32]),
    };
    manifest.release_artifact_set_digest = manifest
        .computed_release_artifact_set_digest()
        .expect("digest synthetic artifact set");

    manifest.audits = PrivacyReleaseAuditClassV1::ALL
        .into_iter()
        .enumerate()
        .map(|(index, audit_class)| {
            let auditor =
                release_manifest_test_key(u8::try_from(index + 0x40).expect("small auditor index"));
            let mut disposition = PrivacyAcceptedMediumDispositionV1 {
                finding_digest: PrivacyReleaseArtifactDigestV1::new(raw(
                    u8::try_from(index + 50).expect("small finding index")
                )),
                disposition_digest: PrivacyReleaseArtifactDigestV1::new(raw(u8::try_from(
                    index + 60,
                )
                .expect("small disposition index"))),
                release_artifact_set_digest: manifest.release_artifact_set_digest,
                signature: release_manifest_placeholder_signature(),
            };
            disposition.signature = release_manifest_test_signature(
                &auditor,
                &disposition
                    .signing_bytes()
                    .expect("encode synthetic Medium disposition"),
            );
            let mut audit = PrivacyReleaseAuditV1 {
                audit_class,
                report_digest: PrivacyReleaseArtifactDigestV1::new(raw(
                    u8::try_from(index + 70).expect("small report index")
                )),
                release_artifact_set_digest: manifest.release_artifact_set_digest,
                open_critical_findings: 0,
                open_high_findings: 0,
                accepted_medium_dispositions: vec![disposition],
                auditor: auditor.public_key().clone(),
                signature: release_manifest_placeholder_signature(),
            };
            audit.signature = release_manifest_test_signature(
                &auditor,
                &audit.signing_bytes().expect("encode synthetic audit"),
            );
            audit
        })
        .collect();
    manifest.audit_bundle_digest = manifest
        .computed_audit_bundle_digest()
        .expect("digest synthetic audit bundle");

    for binding in &mut manifest.protocols {
        binding.security_claim.audit_bundle_digest = manifest.audit_bundle_digest;
        binding.security_claim_digest = binding
            .security_claim
            .computed_digest()
            .expect("digest synthetic security claim");
    }
    for receipt in &mut manifest.stage_receipts {
        let protocol_index =
            usize::from(receipt.stage_ordinal) / PRIVACY_EXACT12_RELEASE_STAGES_PER_PROTOCOL_V1;
        receipt.security_claim_digest = manifest.protocols[protocol_index].security_claim_digest;
    }
    for artifact in &mut manifest.proof_artifacts {
        let protocol_index = PrivacyProtocolIdV1::ALL
            .iter()
            .position(|protocol_id| *protocol_id == artifact.protocol_id)
            .expect("closed protocol is present");
        artifact.security_claim_digest = manifest.protocols[protocol_index].security_claim_digest;
    }
    assert_eq!(
        manifest
            .computed_release_artifact_set_digest()
            .expect("redigest synthetic artifact set"),
        manifest.release_artifact_set_digest
    );

    manifest.manifest_digest = manifest
        .computed_manifest_digest()
        .expect("digest synthetic release manifest");
    manifest.release_signatures = PrivacyReleaseSignatureRoleV1::ALL
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            let signer = release_manifest_test_key(
                u8::try_from(index + 0x50).expect("small release signer index"),
            );
            let payload = PrivacyReleaseSignatureV1::signing_bytes(role, manifest.manifest_digest)
                .expect("encode synthetic release approval");
            PrivacyReleaseSignatureV1 {
                role,
                signer: signer.public_key().clone(),
                signature: release_manifest_test_signature(&signer, &payload),
            }
        })
        .collect();
    manifest
}

fn synthetic_valid_deployment(
    release_manifest_digest: PrivacyExact12ReleaseManifestDigestV1,
) -> PrivacyExact12DeploymentQualificationV1 {
    let network_id = network_id(41);
    let endpoint_version = "privacy-v1".to_owned();
    let converged_state_digest = PrivacyReleaseArtifactDigestV1::new(raw(220));
    let validator_keys = (0_u8..4)
        .map(|index| release_manifest_test_key(0x70 + index))
        .collect::<Vec<_>>();
    let mut deployment = PrivacyExact12DeploymentQualificationV1 {
        version: PRIVACY_EXACT12_DEPLOYMENT_QUALIFICATION_VERSION_V1,
        chain_id: iroha_model_base::chain::ChainId::from("synthetic-chain"),
        network_id,
        genesis_hash: *network_id.as_bytes(),
        release_manifest_digest,
        activation_transaction_digest: PrivacyReleaseArtifactDigestV1::new(raw(221)),
        activations: PrivacyProtocolIdV1::ALL
            .into_iter()
            .enumerate()
            .map(|(index, protocol_id)| PrivacyDeploymentActivationV1 {
                protocol_id,
                // Catalog order is identity order, not an activation chronology.
                activation_height: 21_u64
                    .checked_sub(u64::try_from(index).expect("small activation index"))
                    .expect("the twelve fixture heights remain positive"),
            })
            .collect(),
        validator_roster_digest: PrivacyReleaseArtifactDigestV1::new([0; 32]),
        endpoint_version: endpoint_version.clone(),
        convergence_height: 200,
        converged_state_digest,
        validator_canaries: validator_keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let pre_restart_height = 30 + u64::try_from(index).expect("small index") * 20;
                PrivacyDeploymentValidatorCanaryV1 {
                    validator_index: u16::try_from(index).expect("four validators fit u16"),
                    validator: key.public_key().clone(),
                    rollout_wave: u8::try_from(index + 1).expect("four waves fit u8"),
                    restart_count: 1,
                    pre_restart_height,
                    post_restart_height: pre_restart_height + 1,
                    canary_height: pre_restart_height + 10,
                    canary_digest: PrivacyReleaseArtifactDigestV1::new(raw(u8::try_from(
                        index + 230,
                    )
                    .expect("small canary index"))),
                    converged_state_digest,
                    endpoint_version: endpoint_version.clone(),
                }
            })
            .collect(),
        validator_signatures: Vec::new(),
        qualification_digest: PrivacyExact12DeploymentQualificationDigestV1::new([0; 32]),
    };
    deployment.validator_roster_digest = deployment
        .computed_validator_roster_digest()
        .expect("digest synthetic validator roster");
    deployment.qualification_digest = deployment
        .computed_qualification_digest()
        .expect("digest synthetic deployment qualification");
    deployment.validator_signatures = validator_keys
        .iter()
        .take(PRIVACY_EXACT12_DEPLOYMENT_SIGNATURES_V1)
        .enumerate()
        .map(|(index, key)| {
            let validator_index = u16::try_from(index).expect("three signatures fit u16");
            let payload = PrivacyDeploymentValidatorSignatureV1::signing_bytes(
                validator_index,
                deployment.qualification_digest,
            )
            .expect("encode synthetic deployment approval");
            PrivacyDeploymentValidatorSignatureV1 {
                validator_index,
                signature: release_manifest_test_signature(key, &payload),
            }
        })
        .collect();
    deployment
}

fn synthetic_qualified_capability_rows(
    release: &PrivacyExact12ReleaseManifestV1,
    deployment: &PrivacyExact12DeploymentQualificationV1,
) -> Vec<PrivacyCapabilityRowV1> {
    release
        .protocols
        .iter()
        .zip(&deployment.activations)
        .map(|(binding, deployed)| {
            let protocol_limits = protocol_limits(binding.protocol_id);
            let profile = PrivacyCompiledProfileSnapshotV1 {
                protocol_id: binding.protocol_id,
                proof_system_id: binding.proof_system_id,
                engine_id: binding.engine_id,
                parameter_id: binding.parameter_id,
                parameter_digest: binding.parameter_digest,
                verifier_digest: binding.verifier_digest,
                statement_schema_digest: binding.statement_schema_digest,
                engine_manifest_digest: binding.engine_manifest_digest,
                protocol_limits,
            };
            PrivacyCapabilityRowV1 {
                protocol_id: binding.protocol_id,
                compiled_profile: PrivacyCompiledProfileResultV1::Available(profile),
                activation: Some(PrivacyProtocolActivationRecordV1 {
                    protocol_id: binding.protocol_id,
                    proof_system_id: binding.proof_system_id,
                    engine_id: binding.engine_id,
                    parameter_id: binding.parameter_id,
                    parameter_digest: binding.parameter_digest,
                    verifier_digest: binding.verifier_digest,
                    statement_schema_digest: binding.statement_schema_digest,
                    engine_manifest_digest: binding.engine_manifest_digest,
                    lifecycle: PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                        proposed_at_height: 1,
                        activated_at_height: deployed.activation_height,
                        state_since_height: deployed.activation_height,
                    }),
                    protocol_limits,
                    pending_protocol_limits_tightening: None,
                }),
            }
        })
        .collect()
}

#[test]
fn release_artifact_digest_is_an_exact_fixed_width_type() {
    let digest = PrivacyReleaseArtifactDigestV1::new(raw(30));
    assert_eq!(digest.as_bytes(), &raw(30));
    assert!(!digest.is_zero());
    assert!(PrivacyReleaseArtifactDigestV1::new([0; 32]).is_zero());
    assert_fixed_width_norito(&digest, &raw(30));
}

#[test]
fn proof_artifact_distribution_is_the_frozen_fifty_four() {
    let mut count = 0_usize;
    for protocol_id in PrivacyProtocolIdV1::ALL {
        for stage in PrivacyReleaseStageV1::ALL {
            count += usize::from(privacy_exact12_release_proof_artifact_count_v1(
                protocol_id,
                stage,
            ));
        }
    }
    assert_eq!(count, PRIVACY_EXACT12_RELEASE_PROOF_ARTIFACTS_V1);
    assert_eq!(
        privacy_exact12_release_proof_artifact_count_v1(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            PrivacyReleaseStageV1::PositiveCanonicalEndToEnd,
        ),
        2
    );
    assert_eq!(
        privacy_exact12_release_proof_artifact_count_v1(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            PrivacyReleaseStageV1::PublicStatementBindingMutation,
        ),
        1
    );
    for stage in PrivacyReleaseStageV1::ALL {
        assert_eq!(
            privacy_exact12_release_proof_artifact_count_v1(
                PrivacyProtocolIdV1::IrohaZkAmsV1,
                stage,
            ),
            2
        );
    }
}

#[test]
fn synthetic_release_and_deployment_validate_and_roundtrip() {
    let release = synthetic_valid_release_manifest();
    assert_eq!(release.protocols.len(), 12);
    assert_eq!(release.stage_receipts.len(), 48);
    assert_eq!(release.proof_artifacts.len(), 54);
    assert_eq!(release.validate(), Ok(()));
    let encoded = norito::encode_canonical(&release).expect("encode synthetic release manifest");
    let decoded: PrivacyExact12ReleaseManifestV1 =
        norito::decode_canonical(&encoded).expect("decode synthetic release manifest");
    assert_eq!(decoded, release);

    let deployment = synthetic_valid_deployment(release.manifest_digest);
    assert_eq!(deployment.validator_canaries.len(), 4);
    assert_eq!(deployment.validator_signatures.len(), 3);
    assert_eq!(deployment.validate(), Ok(()));
    let encoded =
        norito::encode_canonical(&deployment).expect("encode synthetic deployment qualification");
    let decoded: PrivacyExact12DeploymentQualificationV1 =
        norito::decode_canonical(&encoded).expect("decode synthetic deployment qualification");
    assert_eq!(decoded, deployment);
}

#[test]
fn exact12_qualification_links_full_manifests_and_all_twelve_activations() {
    let release = synthetic_valid_release_manifest();
    let deployment = synthetic_valid_deployment(release.manifest_digest);
    let qualification = PrivacyExact12QualificationRecordV1 {
        release_manifest: release.clone(),
        deployment_qualification: deployment.clone(),
    };
    let rows = synthetic_qualified_capability_rows(&release, &deployment);
    assert_eq!(qualification.validate(), Ok(()));
    assert_eq!(qualification.validate_against_snapshot(200, &rows), Ok(()));
    assert_eq!(
        qualification.validate_protocol_at_snapshot(200, &rows[0]),
        Ok(())
    );

    let encoded = norito::encode_canonical(&qualification)
        .expect("encode complete Exact12 qualification record");
    let decoded: PrivacyExact12QualificationRecordV1 =
        norito::decode_canonical(&encoded).expect("decode complete Exact12 qualification record");
    assert_eq!(decoded, qualification);
    let mut trailing = encoded;
    trailing.push(0);
    assert!(norito::decode_canonical::<PrivacyExact12QualificationRecordV1>(&trailing).is_err());

    let mismatched = PrivacyExact12QualificationRecordV1 {
        release_manifest: release.clone(),
        deployment_qualification: synthetic_valid_deployment(
            PrivacyExact12ReleaseManifestDigestV1::new(raw(199)),
        ),
    };
    assert_eq!(
        mismatched.validate(),
        Err(PrivacyExact12QualificationRecordValidationErrorV1::ReleaseManifestDigest)
    );

    let mut wrong_height_rows = rows;
    let Some(activation) = &mut wrong_height_rows[0].activation else {
        unreachable!("qualified fixture has every activation")
    };
    let PrivacyProtocolLifecycleV1::Active(lifecycle) = &mut activation.lifecycle else {
        unreachable!("qualified fixture uses active lifecycles")
    };
    lifecycle.activated_at_height += 1;
    lifecycle.state_since_height += 1;
    assert_eq!(
        qualification.validate_against_snapshot(200, &wrong_height_rows),
        Err(PrivacyExact12QualificationRecordValidationErrorV1::ProtocolBinding)
    );
}

/// Reuse the complete signed test evidence for the generated instruction fixture.
pub fn generated_instruction_qualification() -> PrivacyExact12QualificationRecordV1 {
    let release_manifest = synthetic_valid_release_manifest();
    let deployment_qualification = synthetic_valid_deployment(release_manifest.manifest_digest);
    let qualification = PrivacyExact12QualificationRecordV1 {
        release_manifest,
        deployment_qualification,
    };
    qualification
        .validate()
        .expect("complete synthetic qualification");
    qualification
}

#[test]
fn qualified_capability_archive_accepts_complete_signed_evidence() {
    let release = synthetic_valid_release_manifest();
    let deployment = synthetic_valid_deployment(release.manifest_digest);
    let mut snapshot = capability_snapshot();
    snapshot.committed_height = deployment.convergence_height;
    snapshot.protocols = synthetic_qualified_capability_rows(&release, &deployment);
    snapshot.qualification = Some(PrivacyExact12QualificationRecordV1 {
        release_manifest: release,
        deployment_qualification: deployment,
    });
    let manifest = snapshot
        .exact12_capability_manifest_v1()
        .expect("project complete synthetic signed qualification");
    assert!(
        manifest
            .protocols
            .iter()
            .all(crate::privacy::PrivacyExact12CapabilityRowV1::is_network_available)
    );
    let archive = manifest
        .canonical_bytes()
        .expect("encode qualified capabilities");
    assert!(archive.len() <= PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1);
    assert_eq!(
        validate_privacy_capability_archive_v1(&archive),
        PrivacyCapabilityArchiveValidationStatusV1::Valid,
        "the native SDK boundary must admit all 48 stage receipts and 54 artifacts"
    );
    let mut missing_evidence = manifest.clone();
    let release = &mut missing_evidence
        .qualification
        .as_mut()
        .expect("complete qualification")
        .release_manifest;
    release.stage_receipts.clear();
    release.proof_artifacts.clear();
    release.audits.clear();
    release.release_signatures.clear();
    missing_evidence.manifest_digest = missing_evidence
        .computed_manifest_digest()
        .expect("rebind the outer manifest to the missing evidence");
    let missing_archive =
        norito::encode_canonical(&missing_evidence).expect("encode missing release evidence");
    assert_eq!(
        validate_privacy_capability_archive_v1(&missing_archive),
        PrivacyCapabilityArchiveValidationStatusV1::InvalidManifest,
        "nonzero claim digests cannot replace signed release evidence"
    );
    let mut hostile = manifest;
    hostile
        .qualification
        .as_mut()
        .expect("complete qualification")
        .release_manifest
        .release_signatures[0]
        .signature = Signature::from_bytes(&vec![
        1;
        PRIVACY_CAPABILITY_ARCHIVE_MAX_SEQUENCE_ELEMENTS_V1
            + 1
    ]);
    let hostile_archive = norito::encode_canonical(&hostile).expect("encode oversized signature");
    assert!(hostile_archive.len() <= PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1);
    assert_eq!(
        validate_privacy_capability_archive_v1(&hostile_archive),
        PrivacyCapabilityArchiveValidationStatusV1::DecodeResourceLimit,
        "qualification support must not remove nested sequence limits"
    );
}

#[test]
fn release_rejects_abi_stage_artifact_and_signature_mutations() {
    let release = synthetic_valid_release_manifest();

    let mut bad_abi = release.clone();
    bad_abi.abi_version = 0;
    assert_eq!(
        bad_abi.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::AbiBinding)
    );
    let mut zero_abi_hash = release.clone();
    zero_abi_hash.abi_hash = PrivacyReleaseArtifactDigestV1::new([0; 32]);
    assert_eq!(
        zero_abi_hash.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::AbiBinding)
    );

    let mut bad_stage = release.clone();
    bad_stage.stage_receipts[0].stage_ordinal = 1;
    assert_eq!(
        bad_stage.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::StageReceipt)
    );
    let mut bad_artifact_ordinal = release.clone();
    bad_artifact_ordinal.proof_artifacts[0].stage_artifact_ordinal = 1;
    assert_eq!(
        bad_artifact_ordinal.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ProofArtifact)
    );
    let mut bad_distribution = release.clone();
    bad_distribution.proof_artifacts.swap(4, 5);
    assert_eq!(
        bad_distribution.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ProofArtifact)
    );
    let mut bad_cross_binding = release.clone();
    bad_cross_binding.proof_artifacts[0].stage_receipt_digest =
        release.stage_receipts[1].receipt_digest;
    assert_eq!(
        bad_cross_binding.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ProofArtifact)
    );
    let mut missing_artifact = release.clone();
    missing_artifact.proof_artifacts.pop();
    assert_eq!(
        missing_artifact.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ProofArtifactCount)
    );

    let mut missing_approval = release.clone();
    missing_approval.release_signatures.pop();
    assert_eq!(
        missing_approval.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ReleaseSignatureCount)
    );
    let mut forged_approval = release;
    forged_approval.release_signatures[0].signature = Signature::from_bytes(&[0xA5; 64]);
    assert_eq!(
        forged_approval.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ReleaseSignature)
    );
}

#[test]
fn deployment_rejects_chain_rollout_quorum_and_signature_mutations() {
    let release = synthetic_valid_release_manifest();
    let deployment = synthetic_valid_deployment(release.manifest_digest);

    let mut other_chain = deployment.clone();
    other_chain.chain_id = iroha_model_base::chain::ChainId::from("other-chain");
    assert_eq!(
        other_chain.validate(),
        Err(PrivacyExact12DeploymentQualificationValidationErrorV1::QualificationDigest)
    );
    let mut wrong_genesis = deployment.clone();
    wrong_genesis.genesis_hash[0] ^= 1;
    assert_eq!(
        wrong_genesis.validate(),
        Err(PrivacyExact12DeploymentQualificationValidationErrorV1::NetworkGenesis)
    );

    let mut out_of_order_wave = deployment.clone();
    out_of_order_wave.validator_canaries[1].pre_restart_height =
        out_of_order_wave.validator_canaries[0].canary_height - 1;
    assert_eq!(
        out_of_order_wave.validate(),
        Err(PrivacyExact12DeploymentQualificationValidationErrorV1::Canary)
    );

    let mut short_quorum = deployment.clone();
    short_quorum.validator_signatures.pop();
    assert_eq!(
        short_quorum.validate(),
        Err(PrivacyExact12DeploymentQualificationValidationErrorV1::SignatureCount)
    );
    let mut duplicated_signer = deployment.clone();
    duplicated_signer.validator_signatures[1].validator_index = 0;
    assert_eq!(
        duplicated_signer.validate(),
        Err(PrivacyExact12DeploymentQualificationValidationErrorV1::Signature)
    );
    let mut forged_signature = deployment;
    forged_signature.validator_signatures[0].signature = Signature::from_bytes(&[0x5A; 64]);
    assert_eq!(
        forged_signature.validate(),
        Err(PrivacyExact12DeploymentQualificationValidationErrorV1::Signature)
    );
}

#[test]
fn release_and_deployment_json_roundtrip_and_reject_unknown_fields() {
    let release = synthetic_valid_release_manifest();
    let release_json = norito::json::to_json(&release).expect("serialize release manifest JSON");
    let release_roundtrip: PrivacyExact12ReleaseManifestV1 =
        norito::json::from_json(&release_json).expect("decode canonical release JSON");
    assert_eq!(release_roundtrip, release);
    let hostile_release = release_json.replacen('{', "{\"unexpected\":0,", 1);
    assert!(norito::json::from_json::<PrivacyExact12ReleaseManifestV1>(&hostile_release).is_err());

    let deployment = synthetic_valid_deployment(release.manifest_digest);
    let deployment_json =
        norito::json::to_json(&deployment).expect("serialize deployment qualification JSON");
    let deployment_roundtrip: PrivacyExact12DeploymentQualificationV1 =
        norito::json::from_json(&deployment_json).expect("decode canonical deployment JSON");
    assert_eq!(deployment_roundtrip, deployment);
    let hostile_deployment = deployment_json.replacen('{', "{\"unexpected\":0,", 1);
    assert!(
        norito::json::from_json::<PrivacyExact12DeploymentQualificationV1>(&hostile_deployment)
            .is_err()
    );

    let qualification = PrivacyExact12QualificationRecordV1 {
        release_manifest: release,
        deployment_qualification: deployment,
    };
    let qualification_json =
        norito::json::to_json(&qualification).expect("serialize qualification record JSON");
    let qualification_roundtrip: PrivacyExact12QualificationRecordV1 =
        norito::json::from_json(&qualification_json).expect("decode qualification record JSON");
    assert_eq!(qualification_roundtrip, qualification);
    let hostile_qualification = qualification_json.replacen('{', "{\"unexpected\":0,", 1);
    assert!(
        norito::json::from_json::<PrivacyExact12QualificationRecordV1>(&hostile_qualification)
            .is_err()
    );
}

fn resize_release_inventory<T: Clone>(rows: &mut Vec<T>, excess: bool) {
    if excess {
        rows.push(
            rows.first()
                .expect("the exact inventory is nonempty")
                .clone(),
        );
    } else {
        rows.pop().expect("the exact inventory is nonempty");
    }
}

fn assert_release_inventory_count(
    release: &PrivacyExact12ReleaseManifestV1,
    excess: bool,
    resize: fn(&mut PrivacyExact12ReleaseManifestV1, bool),
    expected: PrivacyExact12ReleaseManifestValidationErrorV1,
) {
    let mut invalid = release.clone();
    invalid.protocols[0].parameter_id = PrivacyParameterIdV1::new([0; 32]);
    resize(&mut invalid, excess);
    assert_eq!(invalid.validate(), Err(expected));
}

#[test]
fn release_inventory_rejects_short_and_extra_rows_before_protocol_validation() {
    let release = synthetic_valid_release_manifest();
    assert_eq!(release.validate(), Ok(()));
    for excess in [false, true] {
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.protocols, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::ProtocolCount,
        );
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.stage_receipts, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::StageReceiptCount,
        );
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.proof_artifacts, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::ProofArtifactCount,
        );
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.sdk_packages, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackageCount,
        );
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.hardware_results, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::HardwareResultCount,
        );
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.audits, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::AuditCount,
        );
        assert_release_inventory_count(
            &release,
            excess,
            |manifest, extra| resize_release_inventory(&mut manifest.release_signatures, extra),
            PrivacyExact12ReleaseManifestValidationErrorV1::ReleaseSignatureCount,
        );
    }
}

#[test]
fn release_manifest_validation_preserves_phase_error_order() {
    let release = synthetic_valid_release_manifest();
    let mut invalid = release.clone();
    invalid.version = 0;
    invalid.source.source_tree_clean = false;
    invalid.abi_version = 0;
    invalid.protocols[0].parameter_id = PrivacyParameterIdV1::new([0; 32]);
    invalid.stage_receipts[0].stage_ordinal = 1;
    invalid.proof_artifacts[0].stage_artifact_ordinal = 1;
    invalid.release_artifact_set_digest = PrivacyReleaseArtifactDigestV1::new([0; 32]);
    invalid.manifest_digest = PrivacyExact12ReleaseManifestDigestV1::new([0; 32]);
    invalid.release_signatures[0].signature = Signature::from_bytes(&[0xA5; 64]);
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::Version)
    );
    invalid.version = release.version;
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::SourceIdentity)
    );
    invalid.source.source_tree_clean = true;
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::AbiBinding)
    );
    invalid.abi_version = release.abi_version;
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ProtocolBinding)
    );
    invalid.protocols[0] = release.protocols[0].clone();
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::StageReceipt)
    );
    invalid.stage_receipts[0] = release.stage_receipts[0];
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ProofArtifact)
    );
    invalid.proof_artifacts[0] = release.proof_artifacts[0];
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ArtifactSetDigest)
    );
    invalid.release_artifact_set_digest = release.release_artifact_set_digest;
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ManifestDigest)
    );
    invalid.manifest_digest = release.manifest_digest;
    assert_eq!(
        invalid.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::ReleaseSignature)
    );
    invalid.release_signatures[0] = release.release_signatures[0].clone();
    assert_eq!(invalid.validate(), Ok(()));
}

fn sign_release_approval(
    approval: &mut PrivacyReleaseSignatureV1,
    signer: &KeyPair,
    manifest_digest: PrivacyExact12ReleaseManifestDigestV1,
) {
    approval.signer = signer.public_key().clone();
    approval.signature = release_manifest_test_signature(
        signer,
        &PrivacyReleaseSignatureV1::signing_bytes(approval.role, manifest_digest)
            .expect("encode the role-bound release approval"),
    );
}

fn sign_release_audit(audit: &mut PrivacyReleaseAuditV1, signer: &KeyPair) {
    audit.auditor = signer.public_key().clone();
    for disposition in &mut audit.accepted_medium_dispositions {
        disposition.signature = release_manifest_test_signature(
            signer,
            &disposition
                .signing_bytes()
                .expect("encode the Medium disposition"),
        );
    }
    audit.signature = release_manifest_test_signature(
        signer,
        &audit
            .signing_bytes()
            .expect("encode the audit report binding"),
    );
}

fn rebind_synthetic_release_audit_bundle(manifest: &mut PrivacyExact12ReleaseManifestV1) {
    manifest.audit_bundle_digest = manifest
        .computed_audit_bundle_digest()
        .expect("digest the changed audit evidence");
    for binding in &mut manifest.protocols {
        binding.security_claim.audit_bundle_digest = manifest.audit_bundle_digest;
        binding.security_claim_digest = binding
            .security_claim
            .computed_digest()
            .expect("digest the rebound security claim");
    }
    for receipt in &mut manifest.stage_receipts {
        let protocol_index =
            usize::from(receipt.stage_ordinal) / PRIVACY_EXACT12_RELEASE_STAGES_PER_PROTOCOL_V1;
        receipt.security_claim_digest = manifest.protocols[protocol_index].security_claim_digest;
    }
    for artifact in &mut manifest.proof_artifacts {
        let protocol_index = PrivacyProtocolIdV1::ALL
            .iter()
            .position(|protocol_id| *protocol_id == artifact.protocol_id)
            .expect("the fixture uses a catalog protocol");
        artifact.security_claim_digest = manifest.protocols[protocol_index].security_claim_digest;
    }
    assert_eq!(
        manifest
            .computed_release_artifact_set_digest()
            .expect("redigest the artifact set"),
        manifest.release_artifact_set_digest,
        "audit changes do not change the normalized non-audit artifact set"
    );
    manifest.manifest_digest = manifest
        .computed_manifest_digest()
        .expect("digest the rebound release manifest");
    for (index, approval) in manifest.release_signatures.iter_mut().enumerate() {
        let signer = release_manifest_test_key(
            u8::try_from(index + 0x50).expect("the fixture has a small closed role inventory"),
        );
        sign_release_approval(approval, &signer, manifest.manifest_digest);
    }
}

fn assert_release_audit_signatures(audit: &PrivacyReleaseAuditV1) {
    assert_eq!(
        audit.signature.verify(
            &audit.auditor,
            &audit.signing_bytes().expect("encode the signed audit")
        ),
        Ok(())
    );
    for disposition in &audit.accepted_medium_dispositions {
        assert_eq!(
            disposition.signature.verify(
                &audit.auditor,
                &disposition
                    .signing_bytes()
                    .expect("encode the signed disposition")
            ),
            Ok(())
        );
    }
}

#[test]
fn release_audits_require_independent_auditors_and_reports_with_valid_signatures() {
    let release = synthetic_valid_release_manifest();
    let mut duplicate_auditor = release.clone();
    let shared_authority = release_manifest_test_key(0x40);
    sign_release_audit(&mut duplicate_auditor.audits[1], &shared_authority);
    rebind_synthetic_release_audit_bundle(&mut duplicate_auditor);
    assert_release_audit_signatures(&duplicate_auditor.audits[1]);
    assert_eq!(
        duplicate_auditor.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::Audit)
    );

    let mut duplicate_report = release.clone();
    duplicate_report.audits[1].report_digest = duplicate_report.audits[0].report_digest;
    sign_release_audit(
        &mut duplicate_report.audits[1],
        &release_manifest_test_key(0x41),
    );
    rebind_synthetic_release_audit_bundle(&mut duplicate_report);
    assert_release_audit_signatures(&duplicate_report.audits[1]);
    assert_eq!(
        duplicate_report.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::Audit)
    );

    let mut independent = release;
    sign_release_audit(&mut independent.audits[1], &release_manifest_test_key(0x60));
    rebind_synthetic_release_audit_bundle(&mut independent);
    assert_release_audit_signatures(&independent.audits[1]);
    assert_eq!(independent.validate(), Ok(()));
}

#[test]
fn release_approvals_require_independent_signers_with_valid_signatures() {
    let release = synthetic_valid_release_manifest();
    for (seed, expected) in [
        (
            0x40,
            Err(PrivacyExact12ReleaseManifestValidationErrorV1::ReleaseSignature),
        ),
        (
            0x51,
            Err(PrivacyExact12ReleaseManifestValidationErrorV1::ReleaseSignature),
        ),
        (0x60, Ok(())),
    ] {
        let mut candidate = release.clone();
        sign_release_approval(
            &mut candidate.release_signatures[0],
            &release_manifest_test_key(seed),
            candidate.manifest_digest,
        );
        let approval = &candidate.release_signatures[0];
        let bytes =
            PrivacyReleaseSignatureV1::signing_bytes(approval.role, candidate.manifest_digest)
                .expect("encode the role-bound approval");
        assert_eq!(approval.signature.verify(&approval.signer, &bytes), Ok(()));
        assert_eq!(candidate.validate(), expected);
    }
}
#[test]
fn release_sdk_consumers_preserve_ten_exact_json_and_binary_identities() {
    use norito::codec::DecodeAll as _;
    let expected = [
        (PrivacyReleaseSdkConsumerV1::KotlinJvm, "kotlin_jvm", 0_u32),
        (
            PrivacyReleaseSdkConsumerV1::KotlinAndroid,
            "kotlin_android",
            1,
        ),
        (
            PrivacyReleaseSdkConsumerV1::JavaSourceKotlin,
            "java_source_kotlin",
            10,
        ),
        (
            PrivacyReleaseSdkConsumerV1::SwiftCBridge,
            "swift_c_bridge",
            3,
        ),
        (
            PrivacyReleaseSdkConsumerV1::JavascriptNapi,
            "javascript_napi",
            4,
        ),
        (PrivacyReleaseSdkConsumerV1::PythonPyo3, "python_pyo3", 5),
        (PrivacyReleaseSdkConsumerV1::CSharp, "csharp", 6),
        (PrivacyReleaseSdkConsumerV1::Cli, "cli", 7),
        (PrivacyReleaseSdkConsumerV1::OpenApi, "openapi", 8),
        (
            PrivacyReleaseSdkConsumerV1::GenesisTooling,
            "genesis_tooling",
            9,
        ),
    ];
    assert_eq!(PrivacyReleaseSdkConsumerV1::ALL.len(), 10);
    let schema = <PrivacyReleaseSdkConsumerV1 as iroha_schema::IntoSchema>::schema();
    let iroha_schema::Metadata::Enum(metadata) = schema
        .get::<PrivacyReleaseSdkConsumerV1>()
        .expect("consumer schema")
    else {
        panic!("SDK consumers must retain their closed enum schema");
    };
    assert_eq!(metadata.variants.len(), expected.len());
    for (index, (consumer, tag, discriminant)) in expected.into_iter().enumerate() {
        assert_eq!(PrivacyReleaseSdkConsumerV1::ALL[index], consumer);
        let bytes = consumer.encode();
        assert_eq!(bytes, discriminant.to_le_bytes(), "{tag}");
        assert_eq!(
            PrivacyReleaseSdkConsumerV1::decode_all(&mut bytes.as_slice())
                .expect("decode exact consumer index"),
            consumer,
        );
        let framed = norito::encode_canonical(&consumer).expect("frame consumer");
        assert_eq!(
            norito::decode_canonical::<PrivacyReleaseSdkConsumerV1>(&framed)
                .expect("decode framed consumer"),
            consumer,
        );
        let json = norito::json::to_json(&consumer).expect("encode consumer JSON");
        let value: norito::json::Value = norito::json::from_json(&json).unwrap();
        assert_eq!(value, norito::json!({"consumer": tag, "value": null}));
        assert_eq!(
            norito::json::from_json::<PrivacyReleaseSdkConsumerV1>(&json)
                .expect("decode exact consumer JSON"),
            consumer,
        );
        assert_eq!(metadata.variants[index].tag, tag);
        assert_eq!(metadata.variants[index].discriminant, discriminant);
        assert_eq!(metadata.variants[index].ty, None);
    }
}

#[test]
fn release_sdk_consumer_rejects_retired_java_json_and_binary_index() {
    use norito::codec::DecodeAll as _;
    // A test-only producer preserves the exact old payload and unchanged root identity.
    // No production decoder or compatibility alias is supplied for this retired tag.
    #[derive(norito::Encode, norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::privacy::release_manifest::PrivacyReleaseSdkConsumerV1"
    )]
    enum RetiredSdkConsumerWireFixture {
        #[codec(index = 2)]
        Retired,
    }
    for tag in ["java_android", "JavaAndroid", "JavaSourceKotlin"] {
        let json = format!(r#"{{"consumer":"{tag}","value":null}}"#);
        assert!(norito::json::from_json::<PrivacyReleaseSdkConsumerV1>(&json).is_err());
    }
    let old = RetiredSdkConsumerWireFixture::Retired;
    assert_eq!(old.encode(), 2_u32.to_le_bytes());
    let error = PrivacyReleaseSdkConsumerV1::decode_all(&mut old.encode().as_slice())
        .expect_err("retired binary consumer must not acquire new qualification meaning");
    assert!(matches!(
        error,
        norito::Error::Message(message) if message == "invalid enum discriminant"
    ));
    let framed = norito::encode_canonical(&old).expect("frame the exact retired consumer");
    let error = norito::decode_canonical::<PrivacyReleaseSdkConsumerV1>(&framed)
        .expect_err("matching frame identity must not admit a retired payload tag");
    assert!(matches!(
        error,
        norito::Error::Message(message) if message == "invalid enum discriminant"
    ));
}

#[test]
fn release_sdk_inventory_requires_separate_java_source_kotlin_evidence() {
    let release = synthetic_valid_release_manifest();
    assert_eq!(release.validate(), Ok(()));
    assert_eq!(release.sdk_packages.len(), 10);
    assert_eq!(
        release.sdk_packages[2].consumer,
        PrivacyReleaseSdkConsumerV1::JavaSourceKotlin
    );
    let mut missing = release.clone();
    missing.sdk_packages.remove(2);
    assert_eq!(
        missing.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackageCount)
    );
    let mut extra = release.clone();
    extra.sdk_packages.push(release.sdk_packages[2].clone());
    assert_eq!(
        extra.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackageCount)
    );
    for substitute in [
        PrivacyReleaseSdkConsumerV1::KotlinJvm,
        PrivacyReleaseSdkConsumerV1::KotlinAndroid,
    ] {
        let mut substituted = release.clone();
        substituted.sdk_packages[2].consumer = substitute;
        assert_eq!(
            substituted.validate(),
            Err(PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackage)
        );
    }
    let mut reordered = release.clone();
    reordered.sdk_packages.swap(1, 2);
    assert_eq!(
        reordered.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackage)
    );
    let mut reused_package = release.clone();
    reused_package.sdk_packages[2].package_digest = release.sdk_packages[1].package_digest;
    assert_eq!(
        reused_package.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackage)
    );
    let mut different_corpus = release.clone();
    different_corpus.sdk_packages[2].fixture_corpus_digest =
        PrivacyReleaseArtifactDigestV1::new(raw(158));
    assert_eq!(
        different_corpus.validate(),
        Err(PrivacyExact12ReleaseManifestValidationErrorV1::SdkPackage)
    );
}

#[test]
fn release_manifest_carrying_another_catalog_commitment_fails_to_decode() {
    let release = synthetic_valid_release_manifest();
    assert_eq!(release.validate(), Ok(()));
    let encoded = release.encode();
    let commitment = *PrivacyExact12CatalogCommitmentV1::canonical().as_bytes();
    let offset = encoded
        .windows(commitment.len())
        .position(|window| window == commitment)
        .expect("the manifest carries the canonical catalog commitment");
    assert_eq!(
        PrivacyExact12ReleaseManifestV1::decode(&mut encoded.as_slice())
            .expect("the unchanged bytes decode"),
        release
    );
    // The bare codec has no checksum: a one-bit change of the commitment is
    // refused by the commitment type itself, which decodes only the compiled value.
    for bit in [0_u8, 7] {
        let mut substituted = encoded.clone();
        substituted[offset] ^= 1 << bit;
        assert!(
            PrivacyExact12ReleaseManifestV1::decode(&mut substituted.as_slice()).is_err(),
            "a release manifest with another catalog commitment must not decode"
        );
    }
}
