#[test]
fn namespaces_root_roles_and_publications_are_closed_and_typed() {
    for statement in sample_statements() {
        let namespace = PrivacyNamespaceV1::from_statement(&statement);
        namespace.validate().expect("derived namespace");
        assert_eq!(namespace.protocol_id(), statement.protocol_id());
    }
    let incompatible = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: PrivacyPoolIdV1::new(raw(1)),
        }),
    );
    assert!(matches!(
        incompatible.validate(),
        Err(PrivacyNamespaceValidationError::IncompatibleScope { .. })
    ));
    let zero = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyNamespaceScopeV1::Policy(PrivacyPolicyNamespaceV1 {
            policy_id: PrivacyPolicyIdV1::new([0; 32]),
        }),
    );
    assert!(matches!(
        zero.validate(),
        Err(PrivacyNamespaceValidationError::ZeroComponent { .. })
    ));
    let x509_trust_anchor_namespace = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyNamespaceScopeV1::TrustAnchor(PrivacyTrustAnchorNamespaceV1 {
            trust_anchor_id: PrivacyIssuerIdV1::new(raw(61)),
        }),
    );
    x509_trust_anchor_namespace
        .validate()
        .expect("X.509 trust-anchor namespace");
    let encoded =
        norito::to_bytes(&x509_trust_anchor_namespace).expect("encode trust-anchor namespace");
    let decoded: PrivacyNamespaceV1 =
        norito::decode_from_bytes(&encoded).expect("decode trust-anchor namespace");
    assert_eq!(decoded, x509_trust_anchor_namespace);
    let json = norito::json::to_json(&x509_trust_anchor_namespace)
        .expect("encode trust-anchor namespace JSON");
    let decoded_json: PrivacyNamespaceV1 =
        norito::json::from_json(&json).expect("decode trust-anchor namespace JSON");
    assert_eq!(decoded_json, x509_trust_anchor_namespace);
    let x509_statement = statement_for(PrivacyProtocolIdV1::IrohaZkX509StarkP256V1);
    let x509_policy_namespace = PrivacyNamespaceV1::from_statement(&x509_statement);
    assert!(matches!(
        x509_policy_namespace.scope(),
        PrivacyNamespaceScopeV1::TrustAnchorPolicy(_)
    ));
    let ca_publication = PrivacyRootPublicationV1::new(
        x509_trust_anchor_namespace,
        PrivacyRootRoleV1::CertificateAuthorityMembership,
        1,
        PrivacyRootV1::new(raw(170)),
    )
    .expect("CA root uses the trust-anchor-wide namespace");
    ca_publication
        .validate()
        .expect("canonical CA root publication");
    assert!(matches!(
        PrivacyRootPublicationV1::new(
            x509_policy_namespace,
            PrivacyRootRoleV1::CertificateAuthorityMembership,
            1,
            PrivacyRootV1::new(raw(172)),
        ),
        Err(
            PrivacyRootPublicationValidationError::IncompatibleNamespaceScope {
                role: PrivacyRootRoleV1::CertificateAuthorityMembership,
                ..
            }
        )
    ));
    assert!(matches!(
        PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
            PrivacyNamespaceScopeV1::TrustAnchor(PrivacyTrustAnchorNamespaceV1 {
                trust_anchor_id: PrivacyIssuerIdV1::new(raw(61)),
            }),
        )
        .validate(),
        Err(PrivacyNamespaceValidationError::IncompatibleScope {
            protocol_id: PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        })
    ));
    assert_eq!(
        PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            PrivacyNamespaceScopeV1::TrustAnchor(PrivacyTrustAnchorNamespaceV1 {
                trust_anchor_id: PrivacyIssuerIdV1::new([0; 32]),
            }),
        )
        .validate(),
        Err(PrivacyNamespaceValidationError::ZeroComponent {
            component: PrivacyNamespaceComponentV1::Issuer,
        })
    );
    for role in [
        PrivacyRootRoleV1::PgcAccountState,
        PrivacyRootRoleV1::AccountRegistry,
        PrivacyRootRoleV1::NoteCommitmentAnchor,
        PrivacyRootRoleV1::OutputSet,
        PrivacyRootRoleV1::ProgramState,
    ] {
        assert_eq!(role.management(), PrivacyRootManagementV1::ProofManaged);
    }
    for role in [
        PrivacyRootRoleV1::Revocation,
        PrivacyRootRoleV1::CertificateAuthorityMembership,
    ] {
        assert_eq!(
            role.management(),
            PrivacyRootManagementV1::GovernanceManaged
        );
    }
    let pgc = statement_for(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1);
    let namespace = PrivacyNamespaceV1::from_statement(&pgc);
    let publication = PrivacyRootPublicationV1::new(
        namespace,
        PrivacyRootRoleV1::PgcAccountState,
        1,
        PrivacyRootV1::new(raw(200)),
    )
    .expect("valid root publication");
    publication.validate().expect("valid publication");
    let bytes = norito::to_bytes(&publication).expect("frame publication");
    let decoded: PrivacyRootPublicationV1 =
        norito::decode_from_bytes(&bytes).expect("decode publication");
    assert_eq!(decoded, publication);
    assert!(!publication.digest().expect("publication digest").is_zero());
    assert_privacy_digest_layout_invariant(|| publication.digest().expect("publication digest"));
    let mut invalid = publication;
    invalid.epoch = 0;
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyRootPublicationValidationError::ZeroEpoch)
    ));
    invalid = publication;
    invalid.root = PrivacyRootV1::new([0; 32]);
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyRootPublicationValidationError::ZeroRoot)
    ));
    invalid = publication;
    invalid.role = PrivacyRootRoleV1::Revocation;
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyRootPublicationValidationError::IncompatibleRole { .. })
    ));
}
#[test]
fn pgc_bootstrap_is_canonical_bounded_and_has_distinct_provenance() {
    let bootstrap = pgc_bootstrap();
    bootstrap.validate().expect("valid PGC bootstrap");
    let bytes = norito::to_bytes(&bootstrap).expect("frame bootstrap");
    let decoded: PrivacyPgcAccountBootstrapV1 =
        norito::decode_from_bytes(&bytes).expect("decode bootstrap");
    assert_eq!(decoded, bootstrap);
    let digest = bootstrap.digest().expect("bootstrap digest");
    assert_privacy_digest_layout_invariant(|| bootstrap.digest().expect("bootstrap digest"));
    assert!(!digest.is_zero());
    let publication = PrivacyRootPublicationV1::new(
        bootstrap.namespace,
        PrivacyRootRoleV1::PgcAccountState,
        bootstrap.initial_epoch,
        bootstrap.initial_root,
    )
    .expect("bootstrap publication");
    assert_ne!(
        digest.as_bytes(),
        publication.digest().expect("publication digest").as_bytes(),
        "bootstrap and root-publication provenance domains must differ"
    );
    let mut invalid = bootstrap.clone();
    invalid.initial_root = PrivacyRootV1::new([0; 32]);
    assert!(invalid.validate().is_err());
    for epoch in [0, 2, u64::MAX] {
        invalid = bootstrap.clone();
        invalid.initial_epoch = epoch;
        assert!(matches!(
            invalid.validate(),
            Err(
                PrivacyPgcAccountBootstrapValidationError::NonCanonicalInitialEpoch {
                    epoch: rejected,
                }
            ) if rejected == epoch
        ));
    }
    invalid = bootstrap.clone();
    invalid.total_supply = 0;
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyPgcAccountBootstrapValidationError::ZeroTotalSupply)
    ));
    invalid = bootstrap.clone();
    invalid.total_supply = u32::MAX;
    invalid
        .validate()
        .expect("the inclusive u32 supply boundary is canonical");
    invalid = bootstrap.clone();
    invalid.accounts.pop();
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyPgcAccountBootstrapValidationError::InvalidAccountCount { count: 15 })
    ));
    invalid = bootstrap.clone();
    invalid.accounts.swap(0, 1);
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyPgcAccountBootstrapValidationError::KeysNotStrictlyIncreasing)
    ));
    invalid = bootstrap.clone();
    invalid.accounts[1].public_key = invalid.accounts[0].public_key;
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyPgcAccountBootstrapValidationError::KeysNotStrictlyIncreasing)
    ));
    invalid = bootstrap.clone();
    invalid.accounts[0].encrypted_balance.right = PrivacyP256PointV1::new([0; 33]);
    assert!(matches!(
        invalid.validate(),
        Err(PrivacyPgcAccountBootstrapValidationError::ZeroPoint {
            point: PrivacyPgcAccountPointV1::EncryptedBalanceRight,
            ..
        })
    ));
}
#[test]
fn orchard_pool_bootstrap_has_one_node_derived_origin_and_distinct_provenance() {
    let bootstrap = PrivacyOrchardPoolBootstrapV1::new(
        PrivacyPoolIdV1::new(raw(210)),
        asset_definition_id(),
        AssetBalanceScope::Global,
        account(211),
    )
    .expect("canonical Orchard pool bootstrap");
    bootstrap.validate().expect("valid Orchard pool bootstrap");
    assert_eq!(
        bootstrap.namespace().protocol_id(),
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1
    );
    let encoded = norito::to_bytes(&bootstrap).expect("frame Orchard bootstrap");
    let decoded: PrivacyOrchardPoolBootstrapV1 =
        norito::decode_from_bytes(&encoded).expect("decode Orchard bootstrap");
    assert_eq!(decoded, bootstrap);
    let digest = bootstrap.digest().expect("digest Orchard bootstrap");
    assert_privacy_digest_layout_invariant(|| {
        bootstrap.digest().expect("digest Orchard bootstrap")
    });
    assert!(!digest.is_zero());
    let mut changed_asset = bootstrap.clone();
    changed_asset.asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("privacy", "universal").expect("domain"),
        Name::from_str("other").expect("asset name"),
    );
    assert_ne!(
        changed_asset.digest().expect("digest changed asset"),
        digest,
        "the immutable public bridge asset must be provenance-bound"
    );
    let mut changed_reserve = bootstrap.clone();
    changed_reserve.reserve_account = account(212);
    assert_ne!(
        changed_reserve.digest().expect("digest changed reserve"),
        digest,
        "the immutable reserve account must be provenance-bound"
    );
    assert_eq!(
        PrivacyOrchardPoolBootstrapV1::new(
            PrivacyPoolIdV1::new([0; 32]),
            asset_definition_id(),
            AssetBalanceScope::Global,
            account(211),
        ),
        Err(PrivacyOrchardPoolBootstrapValidationErrorV1::ZeroPoolId)
    );
    assert_eq!(
        PrivacyOrchardPoolBootstrapV1::new(
            PrivacyPoolIdV1::new(raw(210)),
            asset_definition_id(),
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
            account(211),
        ),
        Err(PrivacyOrchardPoolBootstrapValidationErrorV1::UniversalPublicBalanceScope)
    );
}
#[test]
fn proof_managed_pool_bootstraps_are_closed_bounded_and_self_authenticating() {
    let variants = [
        PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(PrivacyFcmpPoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(raw(213)),
            asset_definition_id: asset_definition_id(),
            initial_outputs: sorted_fcmp_outputs(&[1, 2]),
        }),
        PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
            PrivacyIvmPrivateNotePoolBootstrapV1 {
                pool_id: PrivacyPoolIdV1::new(raw(214)),
                asset_definition_id: asset_definition_id(),
                public_balance_scope: AssetBalanceScope::Global,
                reserve_account: account(215),
                program_id: PrivacyProgramIdV1::new(raw(216)),
                initial_note_commitments: vec![commitment(3), commitment(4)],
            },
        ),
        PrivacyProofManagedPoolBootstrapV1::PqMaspStarkV1(PrivacyPqMaspPoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(raw(217)),
            asset_definition_id: asset_definition_id(),
            initial_note_commitments: vec![commitment(5), commitment(6)],
        }),
    ];
    for bootstrap in variants {
        bootstrap
            .validate()
            .expect("canonical typed pool bootstrap");
        assert_eq!(bootstrap.namespace().protocol_id(), bootstrap.protocol_id());
        assert!(
            bootstrap
                .root_role()
                .is_compatible_with_namespace(bootstrap.namespace())
        );
        let digest = bootstrap.digest().expect("digest typed pool bootstrap");
        assert_privacy_digest_layout_invariant(|| {
            bootstrap.digest().expect("digest typed pool bootstrap")
        });
        assert!(!digest.is_zero());
        let encoded = norito::to_bytes(&bootstrap).expect("encode typed pool bootstrap");
        let decoded: PrivacyProofManagedPoolBootstrapV1 =
            norito::decode_from_bytes(&encoded).expect("decode typed pool bootstrap");
        assert_eq!(decoded, bootstrap);
        let json = norito::json::to_json(&bootstrap).expect("encode pool-bootstrap JSON");
        let decoded_json: PrivacyProofManagedPoolBootstrapV1 =
            norito::json::from_json(&json).expect("decode pool-bootstrap JSON");
        assert_eq!(decoded_json, bootstrap);
        let nested_prefix = json
            .strip_suffix("}}")
            .expect("tagged bootstrap ends with nested and outer objects");
        assert!(
            norito::json::from_json::<PrivacyProofManagedPoolBootstrapV1>(&format!(
                "{nested_prefix},\"legacy_root\":true}}}}"
            ))
            .is_err()
        );
    }
    let mut invalid =
        PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(PrivacyFcmpPoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(raw(218)),
            asset_definition_id: asset_definition_id(),
            initial_outputs: Vec::new(),
        });
    assert_eq!(
        invalid.validate(),
        Err(PrivacyProofManagedPoolBootstrapValidationErrorV1::EmptyInitialFcmpOutputs)
    );
    let PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(fcmp) = &mut invalid else {
        unreachable!()
    };
    fcmp.initial_outputs = vec![fcmp_output(7), fcmp_output(7)];
    assert!(matches!(
            invalid.validate(),
            Err(
                PrivacyProofManagedPoolBootstrapValidationErrorV1::InitialFcmpOutputIdsNotStrictlyIncreasing {
                    index: 1
                }
            )
        ));
    let PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(fcmp) = &mut invalid else {
        unreachable!()
    };
    fcmp.initial_outputs = vec![
        PrivacyFcmpOutputTupleV1 {
            output_key: [0; 32],
            linking_tag_generator: raw(8),
            amount_commitment: raw(9),
        },
        fcmp_output(10),
    ];
    assert!(matches!(
        invalid.validate(),
        Err(
            PrivacyProofManagedPoolBootstrapValidationErrorV1::InvalidInitialFcmpOutput {
                index: 0,
                source: PrivacyFcmpOutputTupleValidationErrorV1::ZeroComponent {
                    component: PrivacyFcmpOutputComponentV1::OutputKey
                }
            }
        )
    ));
    let PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(fcmp) = &mut invalid else {
        unreachable!()
    };
    fcmp.initial_outputs = vec![fcmp_output(9); PRIVACY_MAX_INITIAL_POOL_COMMITMENTS_V1 + 1];
    assert!(matches!(
        invalid.validate(),
        Err(
            PrivacyProofManagedPoolBootstrapValidationErrorV1::TooManyInitialFcmpOutputs {
                count,
                max: PRIVACY_MAX_INITIAL_POOL_COMMITMENTS_V1
            }
        ) if count == PRIVACY_MAX_INITIAL_POOL_COMMITMENTS_V1 + 1
    ));
    let invalid_program = PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
        PrivacyIvmPrivateNotePoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(raw(219)),
            asset_definition_id: asset_definition_id(),
            public_balance_scope: AssetBalanceScope::Global,
            reserve_account: account(220),
            program_id: PrivacyProgramIdV1::new([0; 32]),
            initial_note_commitments: vec![commitment(10)],
        },
    );
    assert_eq!(
        invalid_program.validate(),
        Err(PrivacyProofManagedPoolBootstrapValidationErrorV1::ZeroProgramId)
    );
    let universal_scope = PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
        PrivacyIvmPrivateNotePoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(raw(219)),
            asset_definition_id: asset_definition_id(),
            public_balance_scope: AssetBalanceScope::Dataspace(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            ),
            reserve_account: account(220),
            program_id: PrivacyProgramIdV1::new(raw(216)),
            initial_note_commitments: vec![commitment(10)],
        },
    );
    assert_eq!(
        universal_scope.validate(),
        Err(PrivacyProofManagedPoolBootstrapValidationErrorV1::UniversalPublicBalanceScope)
    );
}
#[test]
fn fcmp_output_and_typed_root_domains_match_known_answers() {
    let output = PrivacyFcmpOutputTupleV1 {
        output_key: raw(1),
        linking_tag_generator: raw(2),
        amount_commitment: raw(3),
    };
    assert_eq!(
        output.output_id().into_bytes(),
        hex!("5a67b729f611b60999fabfdb9028dc2e6aec85c1e63422e82ceb0d48bef6d824")
    );
    let root = PrivacyFcmpTreeRootV1 {
        layers: 1,
        point: raw(4),
    };
    assert_eq!(
        root.history_commitment().into_bytes(),
        hex!("d78fe90fc23fc58cf72a5eeaa6c9b145a47319c1ca5ef32eba9d30d359734906")
    );
    assert_ne!(
        PrivacyFcmpTreeRootV1 {
            layers: 2,
            point: raw(4),
        }
        .history_commitment(),
        root.history_commitment(),
        "layer parity is part of the shared root-history commitment"
    );
}
#[test]
fn pgc_bootstrap_proof_bytes_enforce_exact_cap_and_distinct_digest() {
    let max = usize::try_from(TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1)
        .expect("compiled proof cap fits usize");
    let at_cap = PrivacyPgcBootstrapProofBytesV1::new(vec![0xA5; max]);
    at_cap.validate().expect("exact byte cap is admitted");
    let digest = at_cap.digest().expect("digest proof at exact cap");
    assert!(!digest.is_zero());
    let mut changed = at_cap.clone();
    changed.bytes[max - 1] ^= 1;
    assert_ne!(
        changed.digest().expect("digest changed proof"),
        digest,
        "proof provenance must distinguish a one-byte mutation"
    );
    assert!(matches!(
        PrivacyPgcBootstrapProofBytesV1::new(Vec::new()).validate(),
        Err(PrivacyPgcBootstrapProofValidationError::Empty)
    ));
    assert!(matches!(
        PrivacyPgcBootstrapProofBytesV1::new(vec![0; 32]).validate(),
        Err(PrivacyPgcBootstrapProofValidationError::AllZero)
    ));
    assert!(matches!(
        PrivacyPgcBootstrapProofBytesV1::new(vec![1; max + 1]).validate(),
        Err(PrivacyPgcBootstrapProofValidationError::TooLarge {
            bytes,
            max: TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1,
        }) if bytes == u64::from(TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1) + 1
    ));
}
#[test]
fn every_caller_declared_root_transition_requires_a_distinct_exact_successor() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let protocols = [
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
    ];
    for protocol in protocols {
        for corruption in [
            RootCorruption::ZeroSuccessor,
            RootCorruption::Unchanged,
            RootCorruption::SkippedEpoch,
            RootCorruption::EpochOverflow,
        ] {
            let mut statement = statement_for(protocol);
            corrupt_root_transition(&mut statement, corruption);
            assert!(
                statement.validate(&limits).is_err(),
                "{protocol:?} accepted a malformed root transition"
            );
        }
    }
}
#[test]
fn pgc_public_memo_rejects_noncanonical_sizes_order_and_ciphertexts() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let base = statement_for(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1);
    let mutate = |f: fn(&mut AnonymousPgcKOutOfNStatementV1)| {
        let mut value = base.clone();
        let PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) = &mut value else {
            unreachable!()
        };
        f(statement);
        value.validate(&limits)
    };
    assert!(matches!(
        mutate(|statement| {
            statement.anonymity_set_public_keys.pop();
            statement.transfer_ciphertexts.pop();
        }),
        Err(PrivacyStatementValidationError::InvalidPgcAnonymitySetSize { size: 15 })
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.transfer_ciphertexts.pop();
        }),
        Err(
            PrivacyStatementValidationError::PgcPublicMemoCountMismatch {
                public_keys: 16,
                ciphertexts: 15
            }
        )
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.anonymity_set_public_keys[1] = statement.anonymity_set_public_keys[0];
        }),
        Err(PrivacyStatementValidationError::PgcAnonymitySetNotStrictlyIncreasing)
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.anonymity_set_public_keys.swap(0, 1);
        }),
        Err(PrivacyStatementValidationError::PgcAnonymitySetNotStrictlyIncreasing)
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.anonymity_set_public_keys[0] = PrivacyP256PointV1::new([0; 33]);
        }),
        Err(PrivacyStatementValidationError::ZeroP256Point { index: 0 })
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.transfer_ciphertexts[0].left = PrivacyP256PointV1::new([0; 33]);
        }),
        Err(PrivacyStatementValidationError::ZeroP256CiphertextPoint {
            index: 0,
            component: PrivacyP256CiphertextComponentV1::Left
        })
    ));
    assert!(matches!(
        mutate(|statement| statement.recipient_count = 0),
        Err(PrivacyStatementValidationError::InvalidPgcRecipientCount { count: 0, .. })
    ));
    assert!(matches!(
        mutate(|statement| statement.recipient_count = 9),
        Err(PrivacyStatementValidationError::InvalidPgcRecipientCount {
            count: 9,
            max: 8,
            ..
        })
    ));
    let mut thirty_two = base;
    let PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) = &mut thirty_two else {
        unreachable!()
    };
    statement.anonymity_set_public_keys = (1..=32).map(p256_point).collect();
    statement.transfer_ciphertexts = (1..=32).map(p256_ciphertext).collect();
    thirty_two.validate(&limits).expect("closed n=32 profile");
    let governed =
        PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(AnonymousPgcActivationLimitsV1 {
            max_anonymity_set_size: 16,
            max_recipient_count: 8,
        });
    assert!(matches!(
        governed.validate_statement(&thirty_two),
        Err(PrivacyActivationStatementLimitsError::CountExceeds {
            field: PrivacyActivationLimitFieldV1::AnonymousPgcAnonymitySetSize,
            count: 32,
            max: 16
        })
    ));
}
#[test]
fn verange_uses_only_closed_unsigned_ranges_and_effective_taira_cap() {
    assert_eq!(
        VERANGE_TAIRA_MAX_AGGREGATION_COUNT_V1,
        TAIRA_PRIVACY_MAX_COMMITMENTS_PER_ACTION_V1
    );
    assert_eq!(PrivacyVeRangeBitLengthV1::Bits32.bits(), 32);
    assert_eq!(PrivacyVeRangeBitLengthV1::Bits64.bits(), 64);
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let base = statement_for(PrivacyProtocolIdV1::VeRangeTransparentRangeV1);
    let mutate = |f: fn(&mut VeRangeTransparentRangeStatementV1)| {
        let mut value = base.clone();
        let PrivacyStatementV1::VeRangeTransparentRangeV1(statement) = &mut value else {
            unreachable!()
        };
        f(statement);
        value.validate(&limits)
    };
    assert!(matches!(
        mutate(|statement| {
            statement.value_commitments.clear();
            statement.aggregation_count = 0;
        }),
        Err(PrivacyStatementValidationError::InvalidAggregationCount { count: 0, max: 8 })
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.value_commitments = (1..=9).map(p256_point).collect();
            statement.aggregation_count = 9;
        }),
        Err(PrivacyStatementValidationError::InvalidAggregationCount { count: 9, max: 8 })
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.value_commitments[1] = statement.value_commitments[0];
        }),
        Err(PrivacyStatementValidationError::DuplicateCommitment)
    ));
    assert!(matches!(
        mutate(|statement| {
            statement.value_commitments[0] = PrivacyP256PointV1::new([0; 33]);
        }),
        Err(PrivacyStatementValidationError::ZeroP256Point { index: 0 })
    ));
    let invalid_activation =
        PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(VeRangeActivationLimitsV1 {
            max_aggregation_count: 9,
        });
    assert!(matches!(
        invalid_activation.validate(),
        Err(
            PrivacyProtocolActivationLimitsValidationError::ExceedsHardMaximum {
                field: PrivacyActivationLimitFieldV1::VeRangeAggregationCount,
                value: 9,
                hard_max: 8
            }
        )
    ));
}
#[test]
fn protocol_activation_profiles_reject_zero_and_over_ceiling_values() {
    for protocol in PrivacyProtocolIdV1::ALL {
        protocol_limits(protocol)
            .validate()
            .expect("default protocol profile");
    }
    let invalid = [
        PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(AnonymousPgcActivationLimitsV1 {
            max_anonymity_set_size: 15,
            max_recipient_count: 8,
        }),
        PrivacyProtocolActivationLimitsV1::IrohaZkAmsV1(ZkAmsActivationLimitsV1 {
            max_batch_size: 0,
            max_ring_size: ZK_AMS_MAX_RING_SIZE_V1,
        }),
        PrivacyProtocolActivationLimitsV1::IrohaZkAmsV1(ZkAmsActivationLimitsV1 {
            max_batch_size: ZK_AMS_MAX_BATCH_SIZE_V1,
            max_ring_size: 15,
        }),
        PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
            JindoActivationLimitsV1 {
                max_polynomial_count: IROHA_JINDO_MAX_POLYNOMIALS_V1 + 1,
            },
        ),
        PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(OrchardActivationLimitsV1 {
            max_action_count: 0,
        }),
        PrivacyProtocolActivationLimitsV1::MoneroFcmpPlusPlusV1(FcmpActivationLimitsV1 {
            max_input_count: FCMP_MAX_INPUTS_V1 + 1,
            max_output_count: FCMP_MAX_OUTPUTS_V1,
        }),
        PrivacyProtocolActivationLimitsV1::IrohaIvmPrivateNoteStarkV1(
            IvmPrivateNoteActivationLimitsV1 {
                max_input_count: IVM_PRIVATE_NOTE_MAX_INPUTS_V1,
                max_output_count: 0,
            },
        ),
        PrivacyProtocolActivationLimitsV1::PqMaspStarkV1(PqMaspActivationLimitsV1 {
            max_input_count: PQ_MASP_MAX_INPUTS_V1,
            max_output_count: PQ_MASP_MAX_OUTPUTS_V1 + 1,
        }),
    ];
    for value in invalid {
        assert!(value.validate().is_err(), "invalid activation: {value:?}");
    }
}
#[test]
fn zk_ams_batch_rejects_malformed_or_duplicate_anchors() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let base = statement_for(PrivacyProtocolIdV1::IrohaZkAmsV1);
    let mutate = |f: fn(&mut PrivacyZkAmsBatchAdmissionV1)| {
        let mut value = base.clone();
        let PrivacyStatementV1::IrohaZkAmsV1(statement) = &mut value else {
            unreachable!()
        };
        let PrivacyZkAmsActionV1::BatchAdmission(batch) = &mut statement.action else {
            unreachable!()
        };
        f(batch);
        value.validate(&limits)
    };
    assert!(matches!(
        mutate(|batch| batch.anchors = (1..=9).map(zk_ams_anchor).collect()),
        Err(PrivacyStatementValidationError::InvalidBatchSize { count: 9, max: 8 })
    ));
    assert!(matches!(
        mutate(|batch| batch.anchors.clear()),
        Err(PrivacyStatementValidationError::InvalidBatchSize { count: 0, max: 8 })
    ));
    assert!(matches!(
        mutate(|batch| batch.anchors[0].phc_hash = PrivacyZkAmsPhcHashV1::new([0; 32])),
        Err(PrivacyStatementValidationError::ZeroZkAmsPhcHash { index: 0 })
    ));
    assert!(matches!(
        mutate(|batch| {
            batch.anchors[1].phc_hash = batch.anchors[0].phc_hash;
        }),
        Err(PrivacyStatementValidationError::DuplicateZkAmsPhcHash)
    ));
    assert!(matches!(
        mutate(|batch| {
            batch.anchors[1].seed_public_key = batch.anchors[0].seed_public_key;
        }),
        Err(PrivacyStatementValidationError::DuplicateZkAmsSeedPublicKey)
    ));
}
#[test]
fn zk_ams_provisioning_enforces_closed_canonical_ring_and_key_image() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    for size in [16, 32, 64] {
        zk_ams_provision_statement(size)
            .validate(&limits)
            .expect("closed ZK-AMS ring size");
    }
    let mutate = |f: fn(&mut PrivacyZkAmsProvisionAccountV1)| {
        let mut value = zk_ams_provision_statement(16);
        let PrivacyStatementV1::IrohaZkAmsV1(statement) = &mut value else {
            unreachable!()
        };
        let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &mut statement.action else {
            unreachable!()
        };
        f(provision);
        value.validate(&limits)
    };
    assert!(matches!(
        mutate(|provision| {
            provision.admitted_seed_key_ring.pop();
        }),
        Err(PrivacyStatementValidationError::InvalidZkAmsRingSize { size: 15 })
    ));
    assert!(matches!(
        mutate(|provision| provision.admitted_seed_key_ring.swap(0, 1)),
        Err(PrivacyStatementValidationError::ZkAmsSeedKeyRingNotStrictlyIncreasing)
    ));
    assert!(matches!(
        mutate(|provision| {
            provision.admitted_seed_key_ring[1] = provision.admitted_seed_key_ring[0];
        }),
        Err(PrivacyStatementValidationError::ZkAmsSeedKeyRingNotStrictlyIncreasing)
    ));
    assert!(matches!(
        mutate(|provision| {
            provision.admitted_seed_key_ring[0] = PrivacyZkAmsSeedPublicKeyV1::new([0; 32]);
        }),
        Err(PrivacyStatementValidationError::ZeroZkAmsSeedPublicKey { index: 0 })
    ));
    assert!(matches!(
        mutate(|provision| provision.key_image = PrivacyZkAmsKeyImageV1::new([0; 32])),
        Err(PrivacyStatementValidationError::ZeroZkAmsKeyImage)
    ));
    let governed = PrivacyProtocolActivationLimitsV1::IrohaZkAmsV1(ZkAmsActivationLimitsV1 {
        max_batch_size: ZK_AMS_MAX_BATCH_SIZE_V1,
        max_ring_size: 16,
    });
    assert!(matches!(
        governed.validate_statement(&zk_ams_provision_statement(32)),
        Err(PrivacyActivationStatementLimitsError::CountExceeds {
            field: PrivacyActivationLimitFieldV1::ZkAmsRingSize,
            count: 32,
            max: 16
        })
    ));
}
fn mutate_jindo_statement(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
    mutate: impl FnOnce(&mut IrohaJindoPolynomialCommitmentStatementV1),
) -> Result<(), PrivacyStatementValidationError> {
    let mut value = base.clone();
    let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) = &mut value else {
        unreachable!()
    };
    mutate(statement);
    value.validate(limits)
}
fn assert_jindo_field_and_batch_validation(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) {
    mutate_jindo_statement(base, limits, |statement| {
        statement.evaluation_point = PrivacyJindoFieldElementV1::new([0; 32]);
        statement.claimed_evaluations[0] = PrivacyJindoFieldElementV1::new([0; 32]);
    })
    .expect("zero is a canonical Jindo field element");
    mutate_jindo_statement(base, limits, |statement| {
        let mut value = IROHA_JINDO_FIELD_MODULUS_LE_V1;
        value[0] -= 1;
        statement.evaluation_point = PrivacyJindoFieldElementV1::new(value);
    })
    .expect("p - 1 is the largest canonical Jindo field element");
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.evaluation_point =
                PrivacyJindoFieldElementV1::new(IROHA_JINDO_FIELD_MODULUS_LE_V1);
        }),
        Err(PrivacyStatementValidationError::NonCanonicalJindoEvaluationPoint)
    ));
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            let mut modulus_plus_one = IROHA_JINDO_FIELD_MODULUS_LE_V1;
            modulus_plus_one[0] += 1;
            statement.claimed_evaluations[1] = PrivacyJindoFieldElementV1::new(modulus_plus_one);
        }),
        Err(PrivacyStatementValidationError::NonCanonicalJindoClaimedEvaluation { index: 1 })
    ));
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.evaluation_point = PrivacyJindoFieldElementV1::new([u8::MAX; 32]);
        }),
        Err(PrivacyStatementValidationError::NonCanonicalJindoEvaluationPoint)
    ));
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.claimed_evaluations.pop();
        }),
        Err(PrivacyStatementValidationError::DeclaredCountMismatch {
            field: PrivacyCountFieldV1::JindoClaimedEvaluations,
            declared: 4,
            actual: 3
        })
    ));
    for count in [0_u8, 1, 3, 5] {
        assert!(matches!(
            mutate_jindo_statement(base, limits, move |statement| {
                statement.polynomial_commitments =
                    (1..=count).map(jindo_commitment).collect();
                statement.claimed_evaluations = (1..=count).map(jindo_field).collect();
            }),
            Err(PrivacyStatementValidationError::InvalidJindoPolynomialCount {
                count: observed,
                expected: 4
            }) if observed == u32::from(count)
        ));
    }
}
fn assert_jindo_commitment_encoding_validation(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) {
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.polynomial_commitments[0].encoding.pop();
        }),
        Err(
            PrivacyStatementValidationError::InvalidJindoLatticeCommitmentSize {
                index: 0,
                bytes,
                expected
            }
        ) if bytes == u32::try_from(IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1 - 1).unwrap()
            && expected == u32::try_from(IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1).unwrap()
    ));
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.polynomial_commitments[0].encoding.push(0)
        }),
        Err(
            PrivacyStatementValidationError::InvalidJindoLatticeCommitmentSize {
                index: 0,
                bytes,
                expected
            }
        ) if bytes == u32::try_from(IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1 + 1).unwrap()
            && expected == u32::try_from(IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1).unwrap()
    ));
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.polynomial_commitments[0].encoding.fill(0)
        }),
        Err(PrivacyStatementValidationError::AllZeroJindoLatticeCommitment { index: 0 })
    ));
    assert!(matches!(
        mutate_jindo_statement(base, limits, |statement| {
            statement.polynomial_commitments[1] = statement.polynomial_commitments[0].clone();
        }),
        Err(PrivacyStatementValidationError::DuplicateJindoLatticeCommitment)
    ));
}
fn assert_jindo_coefficient_boundaries(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) {
    for boundary in [
        IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1,
        IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1,
    ] {
        let mut value = base.clone();
        let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) = &mut value else {
            unreachable!()
        };
        statement.polynomial_commitments[0].encoding[..4].copy_from_slice(&boundary.to_le_bytes());
        value
            .validate(limits)
            .expect("inclusive Jindo rounded-coefficient boundary");
    }
    for outside in [
        i64::from(IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1) + 1,
        i64::from(IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1) - 1,
    ] {
        let mut value = base.clone();
        let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) = &mut value else {
            unreachable!()
        };
        statement.polynomial_commitments[0].encoding[..4].copy_from_slice(
            &i32::try_from(outside)
                .expect("adversarial Jindo coefficient fits i32")
                .to_le_bytes(),
        );
        assert!(matches!(
            value.validate(limits),
            Err(
                PrivacyStatementValidationError::JindoCommitmentCoefficientOutOfRange {
                    commitment_index: 0,
                    coefficient_index: 0,
                    value: observed,
                    min: IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1,
                    max: IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1
                }
            ) if i64::from(observed) == outside
        ));
    }
}
#[test]
fn jindo_univariate_profile_rejects_noncanonical_and_out_of_bound_values() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let base = statement_for(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1);
    assert_jindo_field_and_batch_validation(&base, &limits);
    assert_jindo_commitment_encoding_validation(&base, &limits);
    assert_jindo_coefficient_boundaries(&base, &limits);
    let governed = PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
        JindoActivationLimitsV1 {
            max_polynomial_count: 1,
        },
    );
    assert!(matches!(
        governed.validate_statement(&base),
        Err(PrivacyActivationStatementLimitsError::CountExceeds {
            field: PrivacyActivationLimitFieldV1::JindoPolynomialCount,
            count: 4,
            max: 1
        })
    ));
}
#[test]
fn vega_figure9_public_inputs_are_closed_and_non_degenerate() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let vega = statement_for(PrivacyProtocolIdV1::VegaExistingCredentialZkV1);
    let mutate_vega = |f: fn(&mut VegaExistingCredentialStatementV1)| {
        let mut value = vega.clone();
        let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) = &mut value else {
            unreachable!()
        };
        f(statement);
        value.validate(&limits)
    };
    assert!(matches!(
        mutate_vega(|statement| statement.issuer_id = PrivacyIssuerIdV1::new([0; 32])),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::IssuerId
        })
    ));
    assert!(matches!(
        mutate_vega(|statement| statement.issuer_record_epoch = 0),
        Err(PrivacyStatementValidationError::ZeroEpoch {
            field: PrivacyEpochFieldV1::VegaIssuerRecord
        })
    ));
    assert!(matches!(
        mutate_vega(|statement| {
            statement.issuer_record_digest = PrivacyVegaIssuerRecordDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::VegaIssuerRecordDigest
        })
    ));
    assert!(matches!(
        mutate_vega(|statement| statement.issuer_public_key = PrivacyP256PointV1::new([0; 33])),
        Err(PrivacyStatementValidationError::ZeroP256Point { index: 0 })
    ));
    assert!(matches!(
        mutate_vega(|statement| {
            statement.device_authentication_digest =
                PrivacyVegaDeviceAuthenticationDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::VegaDeviceAuthenticationDigest
        })
    ));
    assert!(matches!(
        mutate_vega(|statement| { statement.reader_challenge = PrivacyChallengeV1::new([0; 32]) }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::ReaderChallenge
        })
    ));
    assert!(matches!(
        mutate_vega(|statement| {
            statement.session_transcript_digest = PrivacySessionTranscriptDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::SessionTranscriptDigest
        })
    ));
    for years in [0, VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1.saturating_add(1)] {
        let mut value = vega.clone();
        let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) = &mut value else {
            unreachable!()
        };
        statement.minimum_age_years = years;
        assert!(matches!(
            value.validate(&limits),
            Err(PrivacyStatementValidationError::InvalidVegaAgeThreshold { .. })
        ));
    }
    assert_eq!(
        PrivacyNamespaceV1::from_statement(&vega).scope(),
        PrivacyNamespaceScopeV1::Parameter(PrivacyParameterNamespaceV1 {
            parameter_id: context().parameter_id
        })
    );
}
#[test]
fn vega_issuer_records_are_self_digested_forward_only_and_policy_closed() {
    let issuer_id = PrivacyIssuerIdV1::new(raw(0x91));
    let origin = PrivacyVegaIssuerRecordV1::new(
        issuer_id,
        1,
        p256_point(0x92),
        PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
        PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
        PrivacyVegaMdlDigestAlgorithmV1::Sha256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        None,
        PrivacyVegaIssuerRecordLifecycleV1::Active,
    )
    .expect("canonical Vega issuer origin");
    origin.validate_initial().expect("valid issuer origin");
    let mut tampered = origin;
    tampered.issuer_public_key = p256_point(0x93);
    assert_eq!(
        tampered.validate(),
        Err(PrivacyVegaIssuerRecordValidationErrorV1::RecordDigestMismatch)
    );
    let rotation = PrivacyVegaIssuerRecordV1::new(
        issuer_id,
        2,
        p256_point(0x93),
        origin.document_type,
        origin.namespace,
        origin.digest_algorithm,
        origin.issuer_authentication_algorithm,
        origin.device_authentication_algorithm,
        Some(origin.record_digest),
        PrivacyVegaIssuerRecordLifecycleV1::Active,
    )
    .expect("canonical issuer rotation");
    validate_vega_issuer_rotation_v1(&origin, &rotation).expect("one-step key rotation is valid");
    let no_op = PrivacyVegaIssuerRecordV1::new(
        issuer_id,
        2,
        origin.issuer_public_key,
        origin.document_type,
        origin.namespace,
        origin.digest_algorithm,
        origin.issuer_authentication_algorithm,
        origin.device_authentication_algorithm,
        Some(origin.record_digest),
        PrivacyVegaIssuerRecordLifecycleV1::Active,
    )
    .expect("intrinsically valid no-op successor");
    assert_eq!(
        validate_vega_issuer_rotation_v1(&origin, &no_op),
        Err(PrivacyVegaIssuerTransitionValidationErrorV1::RotationContentsUnchanged)
    );
    let wrong_predecessor = PrivacyVegaIssuerRecordV1::new(
        issuer_id,
        2,
        p256_point(0x93),
        origin.document_type,
        origin.namespace,
        origin.digest_algorithm,
        origin.issuer_authentication_algorithm,
        origin.device_authentication_algorithm,
        Some(PrivacyVegaIssuerRecordDigestV1::new(raw(0x94))),
        PrivacyVegaIssuerRecordLifecycleV1::Active,
    )
    .expect("intrinsically valid predecessor substitution");
    assert_eq!(
        validate_vega_issuer_rotation_v1(&origin, &wrong_predecessor),
        Err(PrivacyVegaIssuerTransitionValidationErrorV1::PredecessorDigestMismatch)
    );
    let revocation = PrivacyVegaIssuerRecordV1::new(
        issuer_id,
        3,
        rotation.issuer_public_key,
        rotation.document_type,
        rotation.namespace,
        rotation.digest_algorithm,
        rotation.issuer_authentication_algorithm,
        rotation.device_authentication_algorithm,
        Some(rotation.record_digest),
        PrivacyVegaIssuerRecordLifecycleV1::Revoked,
    )
    .expect("canonical issuer revocation");
    validate_vega_issuer_revocation_v1(&rotation, &revocation).expect("exact terminal successor");
    assert_eq!(
        validate_vega_issuer_rotation_v1(&revocation, &rotation),
        Err(PrivacyVegaIssuerTransitionValidationErrorV1::CurrentNotActive)
    );
    let encoded = norito::json::to_json(&origin).expect("encode Vega issuer record");
    let unknown_algorithm = encoded.replacen("Sha256", "Sha512", 1);
    assert_ne!(
        unknown_algorithm, encoded,
        "fixture contains digest algorithm"
    );
    assert!(
        norito::json::from_json::<PrivacyVegaIssuerRecordV1>(&unknown_algorithm).is_err(),
        "unreleased algorithm-policy variants must reject"
    );
    let legacy_field = encoded.replacen(
        "\"record_epoch\":1",
        "\"record_epoch\":1,\"legacy_key_id\":\"forbidden\"",
        1,
    );
    assert_ne!(legacy_field, encoded, "fixture contains record epoch");
    assert!(
        norito::json::from_json::<PrivacyVegaIssuerRecordV1>(&legacy_field).is_err(),
        "unknown legacy fields must reject"
    );
}
#[test]
fn vega_presentation_date_is_strict_proleptic_gregorian() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let vega = statement_for(PrivacyProtocolIdV1::VegaExistingCredentialZkV1);
    let mutate_date = |date: PrivacyVegaMdlDateV1| {
        let mut value = vega.clone();
        let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) = &mut value else {
            unreachable!()
        };
        statement.presentation_date = date;
        value.validate(&limits)
    };
    for year in [
        VEGA_MDL_MIN_PRESENTATION_YEAR_V1 - 1,
        VEGA_MDL_MAX_PRESENTATION_YEAR_V1 + 1,
    ] {
        assert!(matches!(
            mutate_date(PrivacyVegaMdlDateV1 {
                year,
                month: 1,
                day: 1
            }),
            Err(PrivacyStatementValidationError::InvalidVegaPresentationYear { .. })
        ));
    }
    for date in [
        PrivacyVegaMdlDateV1 {
            year: 2_026,
            month: 0,
            day: 1,
        },
        PrivacyVegaMdlDateV1 {
            year: 2_026,
            month: 13,
            day: 1,
        },
        PrivacyVegaMdlDateV1 {
            year: 2_026,
            month: 4,
            day: 31,
        },
        PrivacyVegaMdlDateV1 {
            year: 2_026,
            month: 2,
            day: 29,
        },
        PrivacyVegaMdlDateV1 {
            year: 2_000,
            month: 2,
            day: 30,
        },
        PrivacyVegaMdlDateV1 {
            year: 2_026,
            month: 1,
            day: 0,
        },
    ] {
        assert!(matches!(
            mutate_date(date),
            Err(PrivacyStatementValidationError::InvalidVegaPresentationDate { .. })
        ));
    }
    assert!(
        mutate_date(PrivacyVegaMdlDateV1 {
            year: 2_000,
            month: 2,
            day: 29,
        })
        .is_ok()
    );
    assert!(
        mutate_date(PrivacyVegaMdlDateV1 {
            year: VEGA_MDL_MAX_PRESENTATION_YEAR_V1,
            month: 12,
            day: 31,
        })
        .is_ok(),
        "the maximum presentation date has a possible later four-digit expiry"
    );
}
#[test]
fn vega_release_constants_match_the_one_compiled_figure9_shape() {
    assert_eq!(VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1, 368);
    assert_eq!(VEGA_MDL_MSO_PAYLOAD_BYTES_V1, 348);
    assert_eq!(VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1, 92);
    assert_eq!(VEGA_MDL_BIRTH_RANDOM_BYTES_V1, 16);
    assert_eq!(VEGA_MDL_FULL_DATE_TEXT_BYTES_V1, 10);
    assert_eq!(VEGA_MDL_RFC3339_UTC_SECONDS_TEXT_BYTES_V1, 20);
    assert_eq!(VEGA_MDL_MIN_PRESENTATION_YEAR_V1, 1_970);
    assert_eq!(VEGA_MDL_MAX_PRESENTATION_YEAR_V1, 9_998);
    assert_eq!(VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1, 1);
    assert_eq!(VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1, 150);
}
#[test]
fn x509_key_usage_requirement_is_wire_and_json_transparent() {
    for required in [false, true] {
        let requirement = PrivacyX509KeyUsageRequirementV1::new(required);
        assert_eq!(Encode::encode(&requirement), Encode::encode(&required));
        let json = norito::json::to_json(&requirement).expect("encode key-usage requirement JSON");
        assert_eq!(json, required.to_string());
        let decoded: PrivacyX509KeyUsageRequirementV1 =
            norito::json::from_json(&json).expect("decode key-usage requirement JSON");
        assert_eq!(decoded, requirement);
    }
}
fn validate_mutated_x509(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
    mutate: fn(&mut IrohaZkX509StarkP256StatementV1),
) -> Result<(), PrivacyStatementValidationError> {
    let mut value = base.clone();
    let PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) = &mut value else {
        unreachable!()
    };
    mutate(statement);
    value.validate(limits)
}
fn assert_x509_governance_and_usage_rejections(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) {
    assert!(
        validate_mutated_x509(base, limits, |statement| {
            statement.ca_membership_root_epoch = 0;
        })
        .is_err()
    );
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.trust_anchor_record_epoch = 0;
        }),
        Err(PrivacyStatementValidationError::ZeroEpoch {
            field: PrivacyEpochFieldV1::X509TrustAnchorRecord
        })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.trust_anchor_record_digest =
                PrivacyZkX509TrustAnchorRecordDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::X509TrustAnchorRecordDigest
        })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.certificate_policy_record_epoch = 0;
        }),
        Err(PrivacyStatementValidationError::ZeroEpoch {
            field: PrivacyEpochFieldV1::X509CertificatePolicyRecord
        })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.certificate_policy_record_digest =
                PrivacyZkX509CertificatePolicyRecordDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::X509CertificatePolicyRecordDigest
        })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.crl_record_epoch = 0;
        }),
        Err(PrivacyStatementValidationError::ZeroEpoch {
            field: PrivacyEpochFieldV1::X509CrlRecord
        })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.crl_record_digest = PrivacyZkX509CrlRecordDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroTypedField {
            field: PrivacyTypedFieldV1::X509CrlRecordDigest
        })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.key_usage.digital_signature = PrivacyX509KeyUsageRequirementV1::new(false);
        }),
        Err(PrivacyStatementValidationError::InvalidX509KeyUsage)
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.extended_key_usages.clear();
        }),
        Err(PrivacyStatementValidationError::MissingX509ExtendedKeyUsage)
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.extended_key_usages = vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::DocumentSigning,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ]
        }),
        Err(
            PrivacyStatementValidationError::TooManyX509ExtendedKeyUsages {
                actual: 4,
                max: ZK_X509_MAX_EXTENDED_KEY_USAGES_V1
            }
        )
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.extended_key_usages = vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
            ]
        }),
        Err(PrivacyStatementValidationError::X509ExtendedKeyUsagesNotStrictlyIncreasing)
    ));
}
fn assert_x509_disclosure_and_presentation_rejections(
    base: &PrivacyStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) {
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.disclosed_attributes[1].index = statement.disclosed_attributes[0].index
        }),
        Err(PrivacyStatementValidationError::X509DisclosedAttributesNotStrictlyIncreasing)
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.disclosed_attributes[1].index = 4;
        }),
        Err(PrivacyStatementValidationError::UnsupportedX509DisclosedAttributeIndex { index: 4 })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.disclosed_attributes[0].attribute_digest =
                PrivacyAttributeDigestV1::new([0; 32])
        }),
        Err(PrivacyStatementValidationError::ZeroX509DisclosedAttributeDigest { index: 0 })
    ));
    assert!(matches!(
        validate_mutated_x509(base, limits, |statement| {
            statement.disclosed_attributes = (0_u8..5)
                .map(|index| PrivacyZkX509DisclosedAttributeV1 {
                    index,
                    attribute_digest: PrivacyAttributeDigestV1::new(raw(index + 1)),
                })
                .collect()
        }),
        Err(
            PrivacyStatementValidationError::TooManyX509DisclosedAttributes {
                actual: 5,
                max: ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1
            }
        )
    ));
    validate_mutated_x509(base, limits, |statement| {
        statement.presentation_not_after_unix_seconds = statement
            .presentation_not_before_unix_seconds
            + ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1;
    })
    .expect("the exact presentation-window ceiling is admitted");
    let window_mutations: [fn(&mut IrohaZkX509StarkP256StatementV1); 3] = [
        |statement: &mut IrohaZkX509StarkP256StatementV1| {
            statement.presentation_not_after_unix_seconds =
                statement.presentation_not_before_unix_seconds;
        },
        |statement: &mut IrohaZkX509StarkP256StatementV1| {
            statement.presentation_not_after_unix_seconds =
                statement.presentation_not_before_unix_seconds - 1;
        },
        |statement: &mut IrohaZkX509StarkP256StatementV1| {
            statement.presentation_not_after_unix_seconds = statement
                .presentation_not_before_unix_seconds
                + ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1
                + 1;
        },
    ];
    for mutation in window_mutations {
        assert!(matches!(
            validate_mutated_x509(base, limits, mutation),
            Err(PrivacyStatementValidationError::InvalidX509PresentationWindow { .. })
        ));
    }
}
#[test]
fn zk_x509_governance_sha256_frames_match_known_answers() {
    // A small, canonical DER SEQUENCE containing INTEGER 42 and NULL.
    let exact_crl_der = hex!("300502012a0500");
    // RFC 5480 id-ecPublicKey/P-256 SPKI for the SEC 2 generator.
    let exact_issuer_spki_der = hex!(
        "3059301306072a8648ce3d020106082a8648ce3d03010703420004\
             6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );
    let crl_der_digest = PrivacyX509CrlDerDigestV1::digest_exact_der(&exact_crl_der);
    let issuer_spki_digest =
        PrivacyX509CrlIssuerSpkiDigestV1::digest_exact_der(&exact_issuer_spki_der);
    assert_eq!(
        crl_der_digest.as_bytes(),
        &hex!("bfa3e6225fbdc178b8595c06d8fb7ac8c48bcbf22370733501284b73fbba7e98")
    );
    assert_eq!(
        issuer_spki_digest.as_bytes(),
        &hex!("f7e1ecd75dd0aee92a81c2e8cfbb22cdee73ba8700b64349f6331d989d2b4400")
    );
    assert_ne!(
        crl_der_digest.as_bytes(),
        PrivacyX509CrlDerDigestV1::digest_exact_der(&exact_issuer_spki_der).as_bytes(),
        "the exact byte sequence must remain bound to its digest input"
    );
    assert_ne!(
        crl_der_digest.as_bytes(),
        PrivacyX509CrlIssuerSpkiDigestV1::digest_exact_der(&exact_crl_der).as_bytes(),
        "identical bytes under distinct digest domains must not collide"
    );
    let record = PrivacyZkX509CrlRecordV1::new(
        PrivacyIssuerIdV1::new([0x11; 32]),
        PrivacyPolicyIdV1::new([0x22; 32]),
        1,
        42,
        crl_der_digest,
        issuer_spki_digest,
        1_700_000_000,
        1_700_000_300,
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    )
    .expect("known-answer CRL record is canonical");
    assert_eq!(
        record.record_digest.as_bytes(),
        &hex!("d9cc3938a2fb3b8407f17c9e71ce926c627c144c1bf6c6a89a5fa2b73176c64d")
    );
    let trust_anchor = PrivacyZkX509TrustAnchorRecordV1::new(
        PrivacyIssuerIdV1::new([0x11; 32]),
        1,
        PrivacyX509TrustStoreDigestV1::new([0x22; 32]),
        PrivacyRootV1::new([0x33; 32]),
        1,
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    )
    .expect("known-answer trust-anchor record is canonical");
    assert_eq!(
        trust_anchor.record_digest.as_bytes(),
        &hex!("e4a0cf77fc1f0acefeeb98e62c74f718a2aa44e6471f7d1ee4d8b9022743e429")
    );
    let policy = PrivacyZkX509CertificatePolicyRecordV1::new(
        PrivacyIssuerIdV1::new([0x11; 32]),
        PrivacyPolicyIdV1::new([0x22; 32]),
        1,
        PrivacyPolicyDigestV1::new([0x33; 32]),
        PrivacyX509KeyUsageV1 {
            digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
            content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
            key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
            key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
        },
        vec![
            PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
            PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
        ],
        vec![0, 3],
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    )
    .expect("known-answer certificate-policy record is canonical");
    assert_eq!(
        policy.record_digest.as_bytes(),
        &hex!("9a1b485c0566abe3130bf29cacb9e2108adb6372174f8578021019a2f58c8ab0")
    );
}
#[test]
fn x509_rejects_stale_roots_invalid_usage_and_invalid_presentation_windows() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let x509 = statement_for(PrivacyProtocolIdV1::IrohaZkX509StarkP256V1);
    assert_x509_governance_and_usage_rejections(&x509, &limits);
    assert_x509_disclosure_and_presentation_rejections(&x509, &limits);
}
fn assert_zk_x509_trust_anchor_record_roundtrip(trust_anchor: PrivacyZkX509TrustAnchorRecordV1) {
    trust_anchor
        .validate_initial()
        .expect("canonical trust-anchor origin");
    assert_eq!(
        trust_anchor
            .compute_record_digest()
            .expect("recompute trust-anchor digest"),
        trust_anchor.record_digest
    );
    let encoded = norito::to_bytes(&trust_anchor).expect("encode trust-anchor");
    let decoded: PrivacyZkX509TrustAnchorRecordV1 =
        norito::decode_from_bytes(&encoded).expect("decode trust-anchor");
    assert_eq!(decoded, trust_anchor);
    decoded
        .validate_initial()
        .expect("decoded trust-anchor validates");
    let json = norito::json::to_json(&trust_anchor).expect("encode trust-anchor JSON");
    let decoded_json: PrivacyZkX509TrustAnchorRecordV1 =
        norito::json::from_json(&json).expect("decode trust-anchor JSON");
    assert_eq!(decoded_json, trust_anchor);
    let object_prefix = json
        .strip_suffix('}')
        .expect("trust-anchor JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyZkX509TrustAnchorRecordV1>(&format!(
            "{object_prefix},\"legacy_anchor\":true}}"
        ))
        .is_err()
    );
}
fn assert_zk_x509_certificate_policy_record_roundtrip(
    certificate_policy: &PrivacyZkX509CertificatePolicyRecordV1,
) {
    certificate_policy
        .validate_initial()
        .expect("canonical certificate-policy origin");
    assert_eq!(
        certificate_policy
            .compute_record_digest()
            .expect("recompute certificate-policy digest"),
        certificate_policy.record_digest
    );
    let encoded = norito::to_bytes(certificate_policy).expect("encode certificate policy");
    let decoded: PrivacyZkX509CertificatePolicyRecordV1 =
        norito::decode_from_bytes(&encoded).expect("decode certificate policy");
    assert_eq!(&decoded, certificate_policy);
    decoded
        .validate_initial()
        .expect("decoded certificate policy validates");
    let json = norito::json::to_json(certificate_policy).expect("encode certificate-policy JSON");
    let decoded_json: PrivacyZkX509CertificatePolicyRecordV1 =
        norito::json::from_json(&json).expect("decode certificate-policy JSON");
    assert_eq!(&decoded_json, certificate_policy);
    let object_prefix = json
        .strip_suffix('}')
        .expect("certificate-policy JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyZkX509CertificatePolicyRecordV1>(&format!(
            "{object_prefix},\"legacy_policy\":true}}"
        ))
        .is_err()
    );
}
fn assert_zk_x509_record_tampering_rejected(
    trust_anchor: PrivacyZkX509TrustAnchorRecordV1,
    certificate_policy: &PrivacyZkX509CertificatePolicyRecordV1,
) {
    let mut anchor_tamperings = Vec::new();
    let mut tampered = trust_anchor;
    tampered.trust_anchor_id = PrivacyIssuerIdV1::new(raw(82));
    anchor_tamperings.push(tampered);
    let mut tampered = trust_anchor;
    tampered.trust_store_digest = PrivacyX509TrustStoreDigestV1::new(raw(83));
    anchor_tamperings.push(tampered);
    let mut tampered = trust_anchor;
    tampered.ca_membership_root = PrivacyRootV1::new(raw(84));
    anchor_tamperings.push(tampered);
    for tampered in anchor_tamperings {
        assert_eq!(
            tampered.validate(),
            Err(PrivacyZkX509RecordValidationErrorV1::RecordDigestMismatch)
        );
    }
    let mut terminal_origin = trust_anchor;
    terminal_origin.lifecycle = PrivacyZkX509RecordLifecycleV1::Revoked;
    assert_eq!(
        terminal_origin.validate(),
        Err(
            PrivacyZkX509RecordValidationErrorV1::RevokedCaMembershipRootEpochNotHistorical {
                record_epoch: 1,
                root_epoch: 1,
            }
        )
    );
    let mut mismatched_root_epoch = trust_anchor;
    mismatched_root_epoch.ca_membership_root_epoch = trust_anchor.record_epoch + 1;
    assert_eq!(
        mismatched_root_epoch.validate(),
        Err(
            PrivacyZkX509RecordValidationErrorV1::CaMembershipRootEpochMismatch {
                record_epoch: trust_anchor.record_epoch,
                root_epoch: trust_anchor.record_epoch + 1,
            }
        )
    );
    let mut zero_digest = trust_anchor;
    zero_digest.record_digest = PrivacyZkX509TrustAnchorRecordDigestV1::new([0; 32]);
    assert_eq!(
        zero_digest.validate(),
        Err(PrivacyZkX509RecordValidationErrorV1::ZeroRecordDigest)
    );
    assert_eq!(
        PrivacyZkX509TrustAnchorRecordV1::new(
            trust_anchor.trust_anchor_id,
            1,
            trust_anchor.trust_store_digest,
            PrivacyRootV1::new([0; 32]),
            1,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        ),
        Err(PrivacyZkX509RecordValidationErrorV1::ZeroCaMembershipRoot)
    );
    assert_eq!(
        PrivacyZkX509TrustAnchorRecordV1::new(
            trust_anchor.trust_anchor_id,
            1,
            trust_anchor.trust_store_digest,
            trust_anchor.ca_membership_root,
            0,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        ),
        Err(PrivacyZkX509RecordValidationErrorV1::ZeroCaMembershipRootEpoch)
    );
    assert_eq!(
        PrivacyZkX509TrustAnchorRecordV1::new(
            trust_anchor.trust_anchor_id,
            1,
            trust_anchor.trust_store_digest,
            trust_anchor.ca_membership_root,
            2,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        ),
        Err(
            PrivacyZkX509RecordValidationErrorV1::CaMembershipRootEpochMismatch {
                record_epoch: 1,
                root_epoch: 2,
            }
        )
    );
    assert_eq!(
        PrivacyZkX509TrustAnchorRecordV1::new(
            trust_anchor.trust_anchor_id,
            2,
            trust_anchor.trust_store_digest,
            trust_anchor.ca_membership_root,
            2,
            Some(trust_anchor.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        ),
        Err(
            PrivacyZkX509RecordValidationErrorV1::RevokedCaMembershipRootEpochNotHistorical {
                record_epoch: 2,
                root_epoch: 2,
            }
        )
    );
    let mut policy_tamperings = Vec::new();
    let mut tampered = certificate_policy.clone();
    tampered.policy_digest = PrivacyPolicyDigestV1::new(raw(84));
    policy_tamperings.push(tampered);
    let mut tampered = certificate_policy.clone();
    tampered.required_key_usage.key_agreement = PrivacyX509KeyUsageRequirementV1::new(true);
    policy_tamperings.push(tampered);
    let mut tampered = certificate_policy.clone();
    tampered.required_extended_key_usages.remove(0);
    policy_tamperings.push(tampered);
    let mut tampered = certificate_policy.clone();
    tampered.required_disclosed_attribute_indices = vec![0, 2];
    policy_tamperings.push(tampered);
    for tampered in policy_tamperings {
        assert_eq!(
            tampered.validate(),
            Err(PrivacyZkX509RecordValidationErrorV1::RecordDigestMismatch)
        );
    }
}
#[test]
fn zk_x509_governance_records_are_self_digested_strict_and_roundtrip() {
    let trust_anchor = zk_x509_trust_anchor(
        ZK_X509_INITIAL_RECORD_EPOCH_V1,
        80,
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    let certificate_policy = zk_x509_certificate_policy(
        ZK_X509_INITIAL_RECORD_EPOCH_V1,
        81,
        vec![0, 3],
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert_zk_x509_trust_anchor_record_roundtrip(trust_anchor);
    assert_zk_x509_certificate_policy_record_roundtrip(&certificate_policy);
    assert_zk_x509_record_tampering_rejected(trust_anchor, &certificate_policy);
}
#[test]
fn zk_x509_signed_crl_records_are_canonical_bound_and_fail_closed() {
    let origin = zk_x509_crl(
        ZK_X509_INITIAL_RECORD_EPOCH_V1,
        100,
        1_000,
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    origin
        .validate_initial()
        .expect("canonical signed-CRL origin");
    assert_eq!(
        origin
            .compute_record_digest()
            .expect("recompute signed-CRL digest"),
        origin.record_digest
    );
    let encoded = norito::to_bytes(&origin).expect("encode signed-CRL record");
    let decoded: PrivacyZkX509CrlRecordV1 =
        norito::decode_from_bytes(&encoded).expect("decode signed-CRL record");
    assert_eq!(decoded, origin);
    decoded
        .validate_initial()
        .expect("decoded signed-CRL record validates");
    let json = norito::json::to_json(&origin).expect("encode signed-CRL JSON");
    let decoded_json: PrivacyZkX509CrlRecordV1 =
        norito::json::from_json(&json).expect("decode signed-CRL JSON");
    assert_eq!(decoded_json, origin);
    let object_prefix = json
        .strip_suffix('}')
        .expect("signed-CRL JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyZkX509CrlRecordV1>(&format!(
            "{object_prefix},\"legacy_crl\":true}}"
        ))
        .is_err()
    );
    let construct = |trust_anchor_id,
                     certificate_policy_id,
                     record_epoch,
                     crl_number,
                     crl_der_digest,
                     issuer_spki_digest,
                     this_update,
                     next_update,
                     previous_record_digest,
                     lifecycle| {
        PrivacyZkX509CrlRecordV1::new(
            trust_anchor_id,
            certificate_policy_id,
            record_epoch,
            crl_number,
            crl_der_digest,
            issuer_spki_digest,
            this_update,
            next_update,
            previous_record_digest,
            lifecycle,
        )
    };
    assert_eq!(
        construct(
            origin.trust_anchor_id,
            origin.certificate_policy_id,
            1,
            1,
            PrivacyX509CrlDerDigestV1::new([0; 32]),
            origin.issuer_spki_digest,
            1_000,
            1_300,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        ),
        Err(PrivacyZkX509RecordValidationErrorV1::ZeroCrlDerDigest)
    );
    assert_eq!(
        construct(
            origin.trust_anchor_id,
            origin.certificate_policy_id,
            1,
            1,
            origin.crl_der_digest,
            PrivacyX509CrlIssuerSpkiDigestV1::new([0; 32]),
            1_000,
            1_300,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        ),
        Err(PrivacyZkX509RecordValidationErrorV1::ZeroCrlIssuerSpkiDigest)
    );
    for (this_update, next_update) in [(1_000, 1_000), (1_001, 1_000)] {
        assert_eq!(
            construct(
                origin.trust_anchor_id,
                origin.certificate_policy_id,
                1,
                1,
                origin.crl_der_digest,
                origin.issuer_spki_digest,
                this_update,
                next_update,
                None,
                PrivacyZkX509RecordLifecycleV1::Active,
            ),
            Err(PrivacyZkX509RecordValidationErrorV1::InvalidCrlValidityWindow)
        );
    }
    let mut tampered = origin;
    tampered.next_update_unix_seconds += 1;
    assert_eq!(
        tampered.validate(),
        Err(PrivacyZkX509RecordValidationErrorV1::RecordDigestMismatch)
    );
    let rotation = zk_x509_crl(
        2,
        102,
        1_200,
        Some(origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    validate_zk_x509_crl_rotation_v1(&origin, &rotation).expect("canonical signed-CRL rotation");
    let mut rotation_revocation = zk_x509_crl(
        3,
        102,
        1_200,
        Some(rotation.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    rotation_revocation.crl_number = rotation.crl_number;
    rotation_revocation.record_digest = rotation_revocation
        .compute_record_digest()
        .expect("canonical post-rotation CRL revocation digest");
    validate_zk_x509_crl_revocation_v1(&rotation, &rotation_revocation)
        .expect("revocation preserves the most recent complete signed CRL");
    let stale_update = zk_x509_crl(
        2,
        102,
        1_000,
        Some(origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert_eq!(
        validate_zk_x509_crl_rotation_v1(&origin, &stale_update),
        Err(PrivacyZkX509TransitionValidationErrorV1::CrlThisUpdateNotIncreasing)
    );
    let mut stale_number = rotation;
    stale_number.crl_number = origin.crl_number;
    stale_number.record_digest = stale_number
        .compute_record_digest()
        .expect("stale CRLNumber digest");
    assert_eq!(
        validate_zk_x509_crl_rotation_v1(&origin, &stale_number),
        Err(PrivacyZkX509TransitionValidationErrorV1::CrlNumberNotIncreasing)
    );
    let same_der = zk_x509_crl(
        2,
        100,
        1_200,
        Some(origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert_eq!(
        validate_zk_x509_crl_rotation_v1(&origin, &same_der),
        Err(PrivacyZkX509TransitionValidationErrorV1::RotationContentsUnchanged)
    );
    let mut issuer_substitution = rotation;
    issuer_substitution.issuer_spki_digest = PrivacyX509CrlIssuerSpkiDigestV1::new(raw(104));
    issuer_substitution.record_digest = issuer_substitution
        .compute_record_digest()
        .expect("issuer-substitution digest");
    assert_eq!(
        validate_zk_x509_crl_rotation_v1(&origin, &issuer_substitution),
        Err(PrivacyZkX509TransitionValidationErrorV1::CrlIssuerSpkiDigestMismatch)
    );
    let mut revoked = zk_x509_crl(
        2,
        100,
        1_000,
        Some(origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    revoked.crl_number = origin.crl_number;
    revoked.record_digest = revoked
        .compute_record_digest()
        .expect("canonical signed-CRL revocation digest");
    validate_zk_x509_crl_revocation_v1(&origin, &revoked)
        .expect("canonical signed-CRL lineage revocation");
    let after_terminal = zk_x509_crl(
        3,
        105,
        1_400,
        Some(revoked.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert_eq!(
        validate_zk_x509_crl_rotation_v1(&revoked, &after_terminal),
        Err(PrivacyZkX509TransitionValidationErrorV1::CurrentNotActive)
    );
    let mut mutated_revocation = zk_x509_crl(
        2,
        107,
        1_000,
        Some(origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    mutated_revocation.crl_number = origin.crl_number;
    mutated_revocation.record_digest = mutated_revocation
        .compute_record_digest()
        .expect("mutated signed-CRL revocation digest");
    assert_eq!(
        validate_zk_x509_crl_revocation_v1(&origin, &mutated_revocation),
        Err(PrivacyZkX509TransitionValidationErrorV1::RevocationContentsChanged)
    );
}
fn assert_zk_x509_policy_caps_and_ordering() {
    let key_usage = PrivacyX509KeyUsageV1 {
        digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
        content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
        key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
        key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
    };
    let construct_policy = |extended_key_usages, disclosures| {
        PrivacyZkX509CertificatePolicyRecordV1::new(
            PrivacyIssuerIdV1::new(raw(61)),
            PrivacyPolicyIdV1::new(raw(62)),
            1,
            PrivacyPolicyDigestV1::new(raw(90)),
            key_usage,
            extended_key_usages,
            disclosures,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        )
    };
    construct_policy(
        vec![
            PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
            PrivacyX509ExtendedKeyUsageV1::DocumentSigning,
            PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
        ],
        vec![0, 1, 2, 3],
    )
    .expect("exact EKU and disclosure caps are valid");
    assert!(matches!(
        construct_policy(
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::DocumentSigning,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            vec![]
        ),
        Err(
            PrivacyZkX509RecordValidationErrorV1::TooManyExtendedKeyUsages {
                actual: 4,
                max: ZK_X509_MAX_EXTENDED_KEY_USAGES_V1
            }
        )
    ));
    assert!(matches!(
        construct_policy(
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
            ],
            vec![]
        ),
        Err(PrivacyZkX509RecordValidationErrorV1::ExtendedKeyUsagesNotStrictlyIncreasing)
    ));
    assert!(matches!(
        construct_policy(
            vec![PrivacyX509ExtendedKeyUsageV1::ClientAuthentication],
            vec![0, 1, 2, 3, 4]
        ),
        Err(
            PrivacyZkX509RecordValidationErrorV1::TooManyDisclosedAttributes {
                actual: 5,
                max: ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1
            }
        )
    ));
    assert!(matches!(
        construct_policy(
            vec![PrivacyX509ExtendedKeyUsageV1::ClientAuthentication],
            vec![0, 2, 2]
        ),
        Err(PrivacyZkX509RecordValidationErrorV1::DisclosedAttributeIndicesNotStrictlyIncreasing)
    ));
}
fn assert_zk_x509_trust_anchor_transitions() {
    let anchor_origin = zk_x509_trust_anchor(1, 91, None, PrivacyZkX509RecordLifecycleV1::Active);
    let anchor_rotation = zk_x509_trust_anchor(
        2,
        92,
        Some(anchor_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    validate_zk_x509_trust_anchor_rotation_v1(&anchor_origin, &anchor_rotation)
        .expect("canonical trust-anchor rotation");
    let mut digest_only_rotation = anchor_rotation;
    digest_only_rotation.ca_membership_root = anchor_origin.ca_membership_root;
    digest_only_rotation.record_digest = digest_only_rotation
        .compute_record_digest()
        .expect("digest-only trust-anchor rotation digest");
    assert_eq!(
            validate_zk_x509_trust_anchor_rotation_v1(&anchor_origin, &digest_only_rotation),
            Err(
                PrivacyZkX509TransitionValidationErrorV1::TrustStoreDigestChangedWithoutCaMembershipRoot
            )
        );
    let mut root_only_rotation = anchor_rotation;
    root_only_rotation.trust_store_digest = anchor_origin.trust_store_digest;
    root_only_rotation.record_digest = root_only_rotation
        .compute_record_digest()
        .expect("root-only trust-anchor rotation digest");
    assert_eq!(
            validate_zk_x509_trust_anchor_rotation_v1(&anchor_origin, &root_only_rotation),
            Err(
                PrivacyZkX509TransitionValidationErrorV1::CaMembershipRootChangedWithoutTrustStoreDigest
            )
        );
    let rotation_revocation = zk_x509_trust_anchor(
        3,
        92,
        Some(anchor_rotation.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    validate_zk_x509_trust_anchor_revocation_v1(&anchor_rotation, &rotation_revocation)
        .expect("trust-anchor revocation preserves the latest active CA-root epoch");
    let mut substituted_historical_root_epoch = rotation_revocation;
    substituted_historical_root_epoch.ca_membership_root_epoch =
        anchor_origin.ca_membership_root_epoch;
    substituted_historical_root_epoch.record_digest = substituted_historical_root_epoch
        .compute_record_digest()
        .expect("historical CA-root epoch substitution digest");
    assert_eq!(
        validate_zk_x509_trust_anchor_revocation_v1(
            &anchor_rotation,
            &substituted_historical_root_epoch,
        ),
        Err(PrivacyZkX509TransitionValidationErrorV1::RevocationContentsChanged)
    );
    let anchor_noop = zk_x509_trust_anchor(
        2,
        91,
        Some(anchor_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert_eq!(
        validate_zk_x509_trust_anchor_rotation_v1(&anchor_origin, &anchor_noop),
        Err(PrivacyZkX509TransitionValidationErrorV1::RotationContentsUnchanged)
    );
    let anchor_skipped = zk_x509_trust_anchor(
        3,
        92,
        Some(anchor_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert!(matches!(
        validate_zk_x509_trust_anchor_rotation_v1(&anchor_origin, &anchor_skipped),
        Err(
            PrivacyZkX509TransitionValidationErrorV1::NonCanonicalSuccessorEpoch {
                expected: 2,
                actual: 3
            }
        )
    ));
    let anchor_revoked = zk_x509_trust_anchor(
        2,
        91,
        Some(anchor_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    validate_zk_x509_trust_anchor_revocation_v1(&anchor_origin, &anchor_revoked)
        .expect("canonical trust-anchor revocation");
    let after_terminal = zk_x509_trust_anchor(
        3,
        93,
        Some(anchor_revoked.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    assert_eq!(
        validate_zk_x509_trust_anchor_rotation_v1(&anchor_revoked, &after_terminal),
        Err(PrivacyZkX509TransitionValidationErrorV1::CurrentNotActive)
    );
}
fn assert_zk_x509_certificate_policy_transitions() {
    let policy_origin = zk_x509_certificate_policy(
        1,
        94,
        vec![0, 3],
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    let policy_rotation = zk_x509_certificate_policy(
        2,
        95,
        vec![0, 2, 3],
        Some(policy_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Active,
    );
    validate_zk_x509_certificate_policy_rotation_v1(&policy_origin, &policy_rotation)
        .expect("canonical policy rotation");
    let policy_revoked = zk_x509_certificate_policy(
        2,
        94,
        vec![0, 3],
        Some(policy_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    validate_zk_x509_certificate_policy_revocation_v1(&policy_origin, &policy_revoked)
        .expect("canonical policy revocation");
    let mutated_revocation = zk_x509_certificate_policy(
        2,
        96,
        vec![0, 3],
        Some(policy_origin.record_digest),
        PrivacyZkX509RecordLifecycleV1::Revoked,
    );
    assert_eq!(
        validate_zk_x509_certificate_policy_revocation_v1(&policy_origin, &mutated_revocation),
        Err(PrivacyZkX509TransitionValidationErrorV1::RevocationContentsChanged)
    );
}
