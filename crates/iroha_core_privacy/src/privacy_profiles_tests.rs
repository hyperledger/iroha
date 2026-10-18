#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::privacy::{
        AnonymousPgcActivationLimitsV1, PRIVACY_PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        PrivacyProposedLifecycleV1,
    };
    use iroha_schema::{Declaration, MetaMap, NamedFieldsMeta, TypeId};
    struct SchemaOrderAb;
    impl TypeId for SchemaOrderAb {
        fn id() -> String {
            "privacy-test::CanonicalSchema".to_owned()
        }
    }
    impl IntoSchema for SchemaOrderAb {
        fn type_name() -> String {
            "CanonicalSchema".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            u32::update_schema_map(map);
            u64::update_schema_map(map);
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "alpha".to_owned(),
                        ty: core::any::TypeId::of::<u32>(),
                    },
                    Declaration {
                        name: "beta".to_owned(),
                        ty: core::any::TypeId::of::<u64>(),
                    },
                ],
            }));
        }
    }
    struct SchemaOrderBa;
    impl TypeId for SchemaOrderBa {
        fn id() -> String {
            "privacy-test::CanonicalSchema".to_owned()
        }
    }
    impl IntoSchema for SchemaOrderBa {
        fn type_name() -> String {
            "CanonicalSchema".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            u32::update_schema_map(map);
            u64::update_schema_map(map);
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "beta".to_owned(),
                        ty: core::any::TypeId::of::<u64>(),
                    },
                    Declaration {
                        name: "alpha".to_owned(),
                        ty: core::any::TypeId::of::<u32>(),
                    },
                ],
            }));
        }
    }
    struct SchemaRetyped;
    impl TypeId for SchemaRetyped {
        fn id() -> String {
            "privacy-test::CanonicalSchema".to_owned()
        }
    }
    impl IntoSchema for SchemaRetyped {
        fn type_name() -> String {
            "CanonicalSchema".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            u64::update_schema_map(map);
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "alpha".to_owned(),
                        ty: core::any::TypeId::of::<u64>(),
                    },
                    Declaration {
                        name: "beta".to_owned(),
                        ty: core::any::TypeId::of::<u64>(),
                    },
                ],
            }));
        }
    }
    struct SchemaEquivalentAliases;
    impl TypeId for SchemaEquivalentAliases {
        fn id() -> String {
            "privacy-test::EquivalentAliases".to_owned()
        }
    }
    impl IntoSchema for SchemaEquivalentAliases {
        fn type_name() -> String {
            "EquivalentAliases".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            String::update_schema_map(map);
            Box::<str>::update_schema_map(map);
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "owned".to_owned(),
                        ty: core::any::TypeId::of::<String>(),
                    },
                    Declaration {
                        name: "boxed".to_owned(),
                        ty: core::any::TypeId::of::<Box<str>>(),
                    },
                ],
            }));
        }
    }
    struct SchemaConflictLeft;
    impl TypeId for SchemaConflictLeft {
        fn id() -> String {
            "privacy-test::ConflictingAlias".to_owned()
        }
    }
    impl IntoSchema for SchemaConflictLeft {
        fn type_name() -> String {
            "ConflictingAlias".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            map.insert::<Self>(Metadata::Int(IntMode::FixedWidth));
        }
    }
    struct SchemaConflictRight;
    impl TypeId for SchemaConflictRight {
        fn id() -> String {
            "privacy-test::ConflictingAlias".to_owned()
        }
    }
    impl IntoSchema for SchemaConflictRight {
        fn type_name() -> String {
            "ConflictingAlias".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            map.insert::<Self>(Metadata::Bool);
        }
    }
    struct SchemaConflictingAliases;
    impl TypeId for SchemaConflictingAliases {
        fn id() -> String {
            "privacy-test::ConflictingAliases".to_owned()
        }
    }
    impl IntoSchema for SchemaConflictingAliases {
        fn type_name() -> String {
            "ConflictingAliases".to_owned()
        }
        fn update_schema_map(map: &mut MetaMap) {
            SchemaConflictLeft::update_schema_map(map);
            SchemaConflictRight::update_schema_map(map);
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "left".to_owned(),
                        ty: core::any::TypeId::of::<SchemaConflictLeft>(),
                    },
                    Declaration {
                        name: "right".to_owned(),
                        ty: core::any::TypeId::of::<SchemaConflictRight>(),
                    },
                ],
            }));
        }
    }
    fn verange_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("fixed VeRange parameters derive")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn pgc_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            .expect("fixed Anonymous-PGC parameters derive")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn jindo_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
            .expect("fixed Jindo parameters derive")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn bootle_lantern_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_bootle_lantern_profile_material_v1()
            .expect("fixed Bootle/Lantern profile derives")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn orchard_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
            .expect("fixed Orchard profile derives")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn fcmp_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
            .expect("fixed FCMP++ profile derives")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn ivm_private_note_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)
            .expect("fixed IVM private-note profile derives")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    fn pq_masp_activation() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::PqMaspStarkV1)
            .expect("fixed PQ-MASP profile derives")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: 100,
                },
            ))
    }
    #[test]
    fn semantic_parameter_labels_and_framed_note_profiles_cannot_drift() {
        assert_eq!(
            IVM_PRIVATE_NOTE_PARAMETER_SET_LABEL_V1,
            b"goldilocks-sha3-384-proof-managed-note-stark+private-note-vm16x8-tree32-v1"
        );
        assert_eq!(
            PQ_MASP_PARAMETER_SET_LABEL_V1,
            b"goldilocks-sha3-384-proof-managed-note-stark+pq-masp+mldsa65+mlkem768-v1"
        );
        #[cfg(feature = "zk-stark")]
        assert_eq!(
            ZK_ACE_PARAMETER_SET_LABEL_V1,
            b"goldilocks-sha3-384-fp4-binary-fri8-q136+poseidon-x7-identity-zk-ace-v1"
        );
        for stale_geometry in [
            b"mask255".as_slice(),
            b"mask111".as_slice(),
            b"three-lane".as_slice(),
            b"blowup32".as_slice(),
        ] {
            assert!(
                !IVM_PRIVATE_NOTE_PARAMETER_SET_LABEL_V1
                    .windows(stale_geometry.len())
                    .any(|window| window == stale_geometry)
            );
            assert!(
                !PQ_MASP_PARAMETER_SET_LABEL_V1
                    .windows(stale_geometry.len())
                    .any(|window| window == stale_geometry)
            );
            #[cfg(feature = "zk-stark")]
            assert!(
                !ZK_ACE_PARAMETER_SET_LABEL_V1
                    .windows(stale_geometry.len())
                    .any(|window| window == stale_geometry)
            );
        }
        let private_geometry = proof_managed_note_stark_geometry_digest_v1(&PRIVATE_NOTE_DOMAINS_V1)
            .expect("private-note geometry digest");
        let masp_geometry = proof_managed_note_stark_geometry_digest_v1(&PQ_MASP_DOMAINS_V1)
            .expect("PQ-MASP geometry digest");
        assert_ne!(private_geometry, masp_geometry);
        assert_ne!(private_geometry, crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1::default());
        assert_ne!(masp_geometry, crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1::default());
        assert_ne!(
            proof_managed_note_stark_profile_digest_v1(
                &PRIVATE_NOTE_DOMAINS_V1,
                IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1,
            )
            .expect("private-note profile digest"),
            crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1::default(),
        );
        assert_ne!(
            proof_managed_note_stark_profile_digest_v1(
                &PQ_MASP_DOMAINS_V1,
                PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1,
            )
            .expect("PQ-MASP profile digest"),
            crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1::default(),
        );
        assert!(
            IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1
                < usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
                    .expect("global proof cap fits usize"),
            "the independent private-note proof cap must remain below the governed global cap"
        );
        assert_eq!(
            PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1,
            usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
                .expect("global proof cap fits usize"),
            "the complete PQ-MASP authorization wire consumes the governed global cap"
        );
    }
    #[test]
    fn pq_masp_profile_binds_the_exact_wallet_and_verified_effect_schemas() {
        assert_eq!(
            PQ_MASP_WALLET_CIPHERTEXT_SCHEMA_V1,
            b"typed-output:recipient-id32+encapsulation-digest32+output-commitment32+ciphertext[PQE1+mlkem768-ciphertext1088+nonce24+xchacha20poly1305[PQN1+value-u128be+authorization-key-digest32+recipient-id32+nullifier-key-digest32+rho32+blinding32+memo-digest32]+tag16]|mlkem768-domain-kdf|aad:domain+asset-definition-id-u64be-length+norito+pool-id32+output-commitment32+recipient-id32+encapsulation-digest32"
        );
        assert_eq!(
            PQ_MASP_VERIFIED_EFFECT_SCHEMA_V1,
            b"namespace:norito|bootstrap-digest:32|asset-definition-id:norito|current-root:32|current-epoch:u64|next-root:32|next-epoch:u64|transition:pq-masp{ordered-nullifiers[32]+ordered-output-commitments[32]+validator-derived-successor-frontier}|value-balance:none"
        );
        for stale_field in [
            b"value-u128le".as_slice(),
            b"rseed32".as_slice(),
            b"anchor-epoch".as_slice(),
            b"ordered-encrypted-outputs".as_slice(),
            b"expiry-height".as_slice(),
        ] {
            assert!(
                !PQ_MASP_WALLET_CIPHERTEXT_SCHEMA_V1
                    .windows(stale_field.len())
                    .any(|window| window == stale_field)
                    && !PQ_MASP_VERIFIED_EFFECT_SCHEMA_V1
                        .windows(stale_field.len())
                        .any(|window| window == stale_field),
                "stale PQ-MASP profile field survived: {}",
                String::from_utf8_lossy(stale_field)
            );
        }
        let exact = compiled_pq_masp_profile_v1().expect("compiled PQ-MASP profile");
        for changed in [
            compiled_pq_masp_profile_v1_with_schemas(
                b"substituted-wallet-schema",
                PQ_MASP_VERIFIED_EFFECT_SCHEMA_V1,
            )
            .expect("structurally valid wallet-schema substitution"),
            compiled_pq_masp_profile_v1_with_schemas(
                PQ_MASP_WALLET_CIPHERTEXT_SCHEMA_V1,
                b"substituted-verified-effect-schema",
            )
            .expect("structurally valid effect-schema substitution"),
        ] {
            assert_eq!(changed.parameter_id, exact.parameter_id);
            assert_eq!(changed.parameter_digest, exact.parameter_digest);
            assert_ne!(changed.verifier_digest, exact.verifier_digest);
            assert_eq!(
                changed.statement_schema_digest,
                exact.statement_schema_digest
            );
            assert_ne!(changed.engine_manifest_digest, exact.engine_manifest_digest);
        }
    }
    #[test]
    fn local_compiled_profile_catalog_is_exact12_and_contains_no_governance_state() {
        let catalog = compiled_privacy_profile_catalog_v1().expect("compiled profile catalog");
        assert_eq!(catalog.version, PRIVACY_COMPILED_PROFILE_CATALOG_VERSION_V1);
        assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::COUNT);
        assert!(
            catalog
                .protocols
                .iter()
                .map(|row| row.protocol_id)
                .eq(PrivacyProtocolIdV1::ALL)
        );
        let json = norito::json::to_json(&catalog).expect("catalog JSON");
        for forbidden in [
            "committed_height",
            "consensus_policy",
            "activation",
            "lifecycle",
        ] {
            assert!(
                !json.contains(forbidden),
                "local catalog must not expose governance field {forbidden}"
            );
        }
    }
    #[test]
    fn compiled_profile_catalog_cache_returns_owned_isolated_clones() {
        let canonical = compiled_privacy_profile_catalog_v1().expect("compiled profile catalog");
        canonical.validate().expect("canonical compiled catalog");
        assert_eq!(canonical.protocols.len(), PrivacyProtocolIdV1::COUNT);
        let canonical_archive =
            norito::encode_canonical(&canonical).expect("canonical compiled catalog archive");
        let mut caller_owned = canonical;
        caller_owned.protocols.rotate_left(1);
        assert!(
            caller_owned.validate().is_err(),
            "mutating one returned clone must make only that caller's copy noncanonical"
        );
        let subsequent =
            compiled_privacy_profile_catalog_v1().expect("subsequent compiled profile catalog");
        subsequent
            .validate()
            .expect("the cached canonical catalog must remain valid");
        assert_eq!(subsequent.protocols.len(), PrivacyProtocolIdV1::COUNT);
        assert!(
            subsequent
                .protocols
                .iter()
                .map(|row| row.protocol_id)
                .eq(PrivacyProtocolIdV1::ALL)
        );
        assert_eq!(
            norito::encode_canonical(&subsequent)
                .expect("subsequent canonical compiled catalog archive"),
            canonical_archive,
            "a caller mutation must not alias or modify the immutable cache"
        );
    }
    #[test]
    fn local_compiled_profile_catalog_archive_rejects_canonical_substitution() {
        use PrivacyCompiledProfileCatalogArchiveValidationStatusV1 as Status;
        let catalog = compiled_privacy_profile_catalog_v1().expect("compiled profile catalog");
        let archive = norito::encode_canonical(&catalog).expect("canonical catalog");
        assert_eq!(
            validate_local_privacy_compiled_profile_catalog_archive_v1(&archive),
            Status::Valid
        );
        let mut substituted = catalog;
        let profile = substituted
            .protocols
            .iter_mut()
            .find_map(|row| match &mut row.compiled_profile {
                PrivacyCompiledProfileResultV1::Available(profile) => Some(profile),
                PrivacyCompiledProfileResultV1::Unavailable(_) => None,
            })
            .expect("at least one compiled profile");
        let mut digest = *profile.parameter_digest.as_bytes();
        digest[0] ^= 0x80;
        profile.parameter_digest = PrivacyParameterDigestV1::new(digest);
        profile
            .validate()
            .expect("substituted profile remains structural");
        let substituted =
            norito::encode_canonical(&substituted).expect("canonical substituted catalog");
        assert_eq!(
            validate_privacy_compiled_profile_catalog_archive_v1(&substituted),
            Status::Valid,
            "the data-model validator establishes only canonical catalog structure"
        );
        assert_eq!(
            validate_local_privacy_compiled_profile_catalog_archive_v1(&substituted),
            Status::InvalidCatalog,
            "the local validator must reject a canonical profile substitution"
        );
    }
    #[test]
    fn only_governance_released_engines_have_compiled_profiles() {
        let available = PrivacyProtocolIdV1::ALL
            .into_iter()
            .filter(|protocol_id| compiled_privacy_profile_v1(*protocol_id).is_ok())
            .collect::<Vec<_>>();
        let mut expected = vec![
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
            PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
            PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            PrivacyProtocolIdV1::PqMaspStarkV1,
        ];
        if require_activation_readiness_v1(zk_x509_activation_readiness_v1()).is_ok() {
            expected.push(PrivacyProtocolIdV1::IrohaZkX509StarkP256V1);
        }
        assert_eq!(available, expected);
    }
    #[test]
    fn ivm_private_note_profile_binds_distinct_proof_and_wallet_randomness_policies() {
        let exact = compiled_ivm_private_note_profile_v1().expect("compiled IVM profile");
        assert_ne!(
            TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1,
            CURVE_PROVER_RANDOMNESS_POLICY_V1
        );
        assert!(
            IVM_PRIVATE_NOTE_ENGINE_DESCRIPTOR_V1
                .windows(CURVE_PROVER_RANDOMNESS_POLICY_V1.len())
                .any(|window| window == CURVE_PROVER_RANDOMNESS_POLICY_V1)
        );
        let mut changed_proof_policy = TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1.to_vec();
        changed_proof_policy[0] ^= 1;
        let mut changed_wallet_policy = CURVE_PROVER_RANDOMNESS_POLICY_V1.to_vec();
        changed_wallet_policy[0] ^= 1;
        for changed in [
            compiled_ivm_private_note_profile_v1_with_randomness_policies(
                &changed_proof_policy,
                CURVE_PROVER_RANDOMNESS_POLICY_V1,
            )
            .expect("structurally valid proof-policy mutation"),
            compiled_ivm_private_note_profile_v1_with_randomness_policies(
                TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1,
                &changed_wallet_policy,
            )
            .expect("structurally valid wallet-policy mutation"),
        ] {
            assert_eq!(changed.parameter_id, exact.parameter_id);
            assert_ne!(changed.parameter_digest, exact.parameter_digest);
            assert_ne!(changed.verifier_digest, exact.verifier_digest);
            assert_eq!(
                changed.statement_schema_digest,
                exact.statement_schema_digest
            );
            assert_ne!(changed.engine_manifest_digest, exact.engine_manifest_digest);
        }
    }
    #[test]
    fn ivm_private_note_and_pq_masp_profiles_are_exact_bounded_and_mutation_closed() {
        let cases = [
            (
                PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
                ivm_private_note_activation(),
                PrivacyProtocolActivationLimitsV1::IrohaIvmPrivateNoteStarkV1(
                    IvmPrivateNoteActivationLimitsV1 {
                        max_input_count: IVM_PRIVATE_NOTE_MAX_INPUTS_V1,
                        max_output_count: IVM_PRIVATE_NOTE_MAX_OUTPUTS_V1,
                    },
                ),
            ),
            (
                PrivacyProtocolIdV1::PqMaspStarkV1,
                pq_masp_activation(),
                PrivacyProtocolActivationLimitsV1::PqMaspStarkV1(PqMaspActivationLimitsV1 {
                    max_input_count: PQ_MASP_MAX_INPUTS_V1,
                    max_output_count: PQ_MASP_MAX_OUTPUTS_V1,
                }),
            ),
        ];
        for (protocol_id, valid, expected_limits) in cases {
            let first = compiled_privacy_profile_v1(protocol_id).expect("compiled native profile");
            let second = compiled_privacy_profile_v1(protocol_id).expect("deterministic profile");
            assert_eq!(first, second);
            assert_eq!(
                first.proof_system_id,
                PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks
            );
            assert_eq!(
                first.engine_id,
                PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri
            );
            assert_eq!(first.protocol_limits, expected_limits);
            for digest in [
                *first.parameter_id.as_bytes(),
                *first.parameter_digest.as_bytes(),
                *first.verifier_digest.as_bytes(),
                *first.statement_schema_digest.as_bytes(),
                *first.engine_manifest_digest.as_bytes(),
            ] {
                assert_ne!(digest, [0; 32]);
            }
            // Release pins bind the SHA3-384 outer protocol, opaque 48-byte roots,
            // and the corresponding exact native proof descriptors.
            let expected_bindings = match protocol_id {
                PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 => (
                    "b0c21b543f231dbf44462c66a59259bbcac43ad560d5c83b7bd0a138de5c1660".to_owned(),
                    "3f5cb64afd9758719b46a2a3b855dcb19384014cd50c213eff5335b1cfdddcf7".to_owned(),
                    "22fa8b0543dec76865723cbe079d510eb05d75e47e0a0e3dba2205166c9357c5".to_owned(),
                    "59aac0b35adf82940e87293f55f304ab52904896a19bc5a5989aca24eb9c4bc9".to_owned(),
                    "3a7a880faf2b32775c1d0db22fef3543fadeddc3db8bcad21e4e3df0f87ae09e".to_owned(),
                ),
                PrivacyProtocolIdV1::PqMaspStarkV1 => (
                    "42e04aa67d09764cd49fe28d60e4ca9d6fafbbda622478386241afc930814018".to_owned(),
                    "48c3e48e3bb822548a815c67996a1b94810e4cc41c73eb50d61af8e09f68bafe".to_owned(),
                    "62b1ccc68615391c90f4e375b4e61ccf5d4bbce4bd5ef3077a4707c6628b6d6b".to_owned(),
                    "a6314323ab707a3766599aed2d109b3ada63acec793ff2a729c749cd951a332d".to_owned(),
                    "aa2bcf7c8ffa58aeca8b1f84c96b75e405b10695e3b3084c70ec0c7e4ffee121".to_owned(),
                ),
                _ => unreachable!("the test covers only IVM private note and PQ-MASP"),
            };
            assert_eq!(
                (
                    hex::encode(first.parameter_id.as_bytes()),
                    hex::encode(first.parameter_digest.as_bytes()),
                    hex::encode(first.verifier_digest.as_bytes()),
                    hex::encode(first.statement_schema_digest.as_bytes()),
                    hex::encode(first.engine_manifest_digest.as_bytes()),
                ),
                expected_bindings,
                "every consensus-critical {} binding is a pinned KAT",
                protocol_id.canonical_label(),
            );
            validate_compiled_privacy_activation_v1(&valid)
                .expect("exact compiled activation is accepted");
            let mutations: [(
                CompiledPrivacyProfileValidationErrorV1,
                fn(&mut PrivacyProtocolActivationRecordV1),
            ); 8] = [
                (
                    CompiledPrivacyProfileValidationErrorV1::ProofSystemMismatch,
                    |record| record.proof_system_id = PrivacyProofSystemIdV1::Halo2IpaPasta,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::EngineMismatch,
                    |record| record.engine_id = PrivacyEngineIdV1::NativeHalo2Orchard,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::ParameterIdMismatch,
                    |record| record.parameter_id.0[0] ^= 1,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::ParameterDigestMismatch,
                    |record| record.parameter_digest.0[0] ^= 1,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch,
                    |record| record.verifier_digest.0[0] ^= 1,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::StatementSchemaDigestMismatch,
                    |record| record.statement_schema_digest.0[0] ^= 1,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::EngineManifestDigestMismatch,
                    |record| record.engine_manifest_digest.0[0] ^= 1,
                ),
                (
                    CompiledPrivacyProfileValidationErrorV1::ProtocolLimitsMismatch,
                    |record| match &mut record.protocol_limits {
                        PrivacyProtocolActivationLimitsV1::IrohaIvmPrivateNoteStarkV1(limits) => {
                            limits.max_input_count += 1;
                        }
                        PrivacyProtocolActivationLimitsV1::PqMaspStarkV1(limits) => {
                            limits.max_output_count += 1;
                        }
                        _ => unreachable!("test covers only IVM private note and PQ-MASP"),
                    },
                ),
            ];
            for (expected, mutate) in mutations {
                let mut changed = valid;
                mutate(&mut changed);
                assert_eq!(
                    validate_compiled_privacy_activation_v1(&changed),
                    Err(expected)
                );
            }
        }
    }
    #[test]
    fn compiling_ivm_private_note_and_pq_masp_does_not_activate_their_lifecycles() {
        let snapshot = committed_privacy_capability_snapshot_v1(
            42,
            PrivacyConsensusPolicyV1::taira_default(),
            None,
            |_| None,
        )
        .expect("empty committed lifecycle state is valid");
        for protocol_id in [
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            PrivacyProtocolIdV1::PqMaspStarkV1,
        ] {
            let row = snapshot
                .protocols
                .iter()
                .find(|row| row.protocol_id == protocol_id)
                .expect("exact12 row");
            assert!(matches!(
                row.compiled_profile,
                PrivacyCompiledProfileResultV1::Available(_)
            ));
            assert_eq!(row.activation, None);
        }
    }
    #[test]
    fn fcmp_profile_is_deterministic_exact_bounded_and_mutation_closed() {
        let first = compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
            .expect("compiled FCMP++");
        let second = compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
            .expect("compiled FCMP++");
        assert_eq!(first, second);
        assert_eq!(
            first.proof_system_id,
            PrivacyProofSystemIdV1::FcmpPlusPlusCurveTreeBulletproofs
        );
        assert_eq!(first.engine_id, PrivacyEngineIdV1::NativeFcmpPlusPlus);
        assert_eq!(
            first.protocol_limits,
            PrivacyProtocolActivationLimitsV1::MoneroFcmpPlusPlusV1(FcmpActivationLimitsV1 {
                max_input_count: FCMP_MAX_INPUTS_V1,
                max_output_count: FCMP_MAX_OUTPUTS_V1,
            })
        );
        assert_eq!(
            fcmp_plus_plus_wire_size_v1(
                FCMP_MAX_INPUTS_NATIVE_V1,
                FCMP_MAX_TREE_LAYERS_V1,
                FCMP_MAX_OUTPUTS_NATIVE_V1,
            )
            .expect("maximum FCMP++ wire"),
            FCMP_MAX_PROOF_WIRE_BYTES_V1
        );
        assert!(
            FCMP_MAX_PROOF_WIRE_BYTES_V1
                <= usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
                    .expect("global proof cap fits usize")
        );
        for digest in [
            fcmp_compiled_profile_digest_v1(),
            *first.parameter_id.as_bytes(),
            *first.parameter_digest.as_bytes(),
            *first.verifier_digest.as_bytes(),
            *first.statement_schema_digest.as_bytes(),
            *first.engine_manifest_digest.as_bytes(),
        ] {
            assert_ne!(digest, [0; 32]);
        }
        assert_eq!(
            (
                hex::encode(first.parameter_id.as_bytes()),
                hex::encode(first.parameter_digest.as_bytes()),
                hex::encode(first.verifier_digest.as_bytes()),
                hex::encode(first.statement_schema_digest.as_bytes()),
                hex::encode(first.engine_manifest_digest.as_bytes()),
            ),
            (
                "8a24198f13ce0dbe0f4747874def956dc15ca98f9308c29ed678afddbe989a04".to_owned(),
                "92ee53970444330e37716b98a9eb1c04d8e52eb1ffe08103fb2745cc1abc9a89".to_owned(),
                "e03cf36db71869cc30ddffc00c9cbf32b84424693018415824e4e6553347f23e".to_owned(),
                "6071bb6f845eed0a13df34ca6e2b28c2b6a9af1c98b6b08957d9838a5c6101c7".to_owned(),
                "8e182847eb0ff635485572aaf234693beec0970bd6fac3a6bc7ee9fe525864d4".to_owned(),
            ),
            "every consensus-critical FCMP++ binding is a pinned KAT",
        );
        let mut mutated_randomness_policy = CURVE_PROVER_RANDOMNESS_POLICY_V1.to_vec();
        mutated_randomness_policy[0] ^= 1;
        let policy_mutation =
            compiled_fcmp_profile_v1_with_randomness_policy(&mutated_randomness_policy)
                .expect("structurally valid FCMP++ policy mutation");
        assert_eq!(policy_mutation.parameter_id, first.parameter_id);
        assert_ne!(policy_mutation.parameter_digest, first.parameter_digest);
        assert_ne!(policy_mutation.verifier_digest, first.verifier_digest);
        assert_eq!(
            policy_mutation.statement_schema_digest,
            first.statement_schema_digest
        );
        assert_ne!(
            policy_mutation.engine_manifest_digest,
            first.engine_manifest_digest
        );
        let valid = fcmp_activation();
        validate_compiled_privacy_activation_v1(&valid).expect("exact FCMP++ activation");
        let mutations: [(
            CompiledPrivacyProfileValidationErrorV1,
            fn(&mut PrivacyProtocolActivationRecordV1),
        ); 8] = [
            (
                CompiledPrivacyProfileValidationErrorV1::ProofSystemMismatch,
                |record| record.proof_system_id = PrivacyProofSystemIdV1::Halo2IpaPasta,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineMismatch,
                |record| record.engine_id = PrivacyEngineIdV1::NativeHalo2Orchard,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterIdMismatch,
                |record| record.parameter_id.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterDigestMismatch,
                |record| record.parameter_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch,
                |record| record.verifier_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::StatementSchemaDigestMismatch,
                |record| record.statement_schema_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineManifestDigestMismatch,
                |record| record.engine_manifest_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ProtocolLimitsMismatch,
                |record| {
                    record.protocol_limits =
                        PrivacyProtocolActivationLimitsV1::MoneroFcmpPlusPlusV1(
                            FcmpActivationLimitsV1 {
                                max_input_count: FCMP_MAX_INPUTS_V1 + 1,
                                max_output_count: FCMP_MAX_OUTPUTS_V1,
                            },
                        );
                },
            ),
        ];
        for (expected, mutate) in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert_eq!(
                validate_compiled_privacy_activation_v1(&changed),
                Err(expected)
            );
        }
    }
    #[test]
    fn bootle_lantern_profile_is_deterministic_complete_bounded_and_mutation_closed() {
        let first = compiled_bootle_lantern_profile_material_v1().expect("profile material");
        let second = compiled_bootle_lantern_profile_material_v1().expect("profile material");
        assert_eq!(first, second);
        assert_eq!(
            first.proof_system_id,
            PrivacyProofSystemIdV1::LanternLnp22ModuleLinearNorm
        );
        assert_eq!(first.engine_id, PrivacyEngineIdV1::NativeLanternLnp22);
        assert_eq!(
            first.protocol_limits,
            PrivacyProtocolActivationLimitsV1::IrohaBootleLanternAnoncredV1
        );
        assert_eq!(APPLICATION_RING_DEGREE_V1, 64);
        assert_eq!(
            APPLICATION_RING_DEGREE_V1,
            BOOTLE_LANTERN_MODEL_RING_DEGREE_V1
        );
        assert_eq!(
            BOOTLE_LANTERN_APPLICATION_MODULUS_V1,
            BOOTLE_LANTERN_MODEL_APPLICATION_MODULUS_V1
        );
        assert_eq!(APPLICATION_ROWS_V1, 8);
        assert_eq!(APPLICATION_ROWS_V1, BOOTLE_LANTERN_MODEL_ATTRIBUTE_COUNT_V1);
        assert_eq!(APPLICATION_WITNESS_POLYNOMIALS_V1, 48);
        assert_eq!(
            BOOTLE_LANTERN_PARAMETER_SET_LABEL_V1,
            b"falcon512-ntru-r512-as-r64-rank8-interleaved"
        );
        for required in [
            &b"BLNS-specialization-no-main-construction-reduction"[..],
            &b"rust-fn-dsa-workspace-0.3-daf14859b5aa3f8d75c42966ba7de83e6eb59997"[..],
        ] {
            assert!(
                BOOTLE_LANTERN_IMPLEMENTATION_PROVENANCE_V1
                    .windows(required.len())
                    .any(|window| window == required),
                "implementation provenance omitted {}",
                String::from_utf8_lossy(required)
            );
        }
        for (descriptor, required) in [
            (
                BOOTLE_LANTERN_ISSUER_PARAMETER_SCHEMA_V1,
                &b"H_i[j]=h[8*j+i]"[..],
            ),
            (
                BOOTLE_LANTERN_RELATION_SCHEMA_V1,
                &b"A_r*r+A_tau*tau+A_m*m+scope-s1-H*s2=0"[..],
            ),
            (
                BOOTLE_LANTERN_CREDENTIAL_SCOPE_SCHEMA_V1,
                &b"excluded:action-index+transaction-intent-digest"[..],
            ),
            (
                BOOTLE_LANTERN_BLIND_ISSUANCE_SCHEMA_V1,
                &b"atomic-height-aware-Fresh-to-Processing-before-one-master64"[..],
            ),
            (
                BOOTLE_LANTERN_NATIVE_PRODUCER_SCHEMA_V1,
                &b"cached-completed-replay-does-not-touch-rng"[..],
            ),
            (
                BOOTLE_LANTERN_TRANSCRIPT_SCHEMA_V1,
                &b"issuer-generated-one-shot-issuance-authorization-digest"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUANCE_WIRE_DESCRIPTOR_V1,
                &b"ILA1:fixed320"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUANCE_WIRE_DESCRIPTOR_V1,
                &b"ILR1:fixed3176"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUANCE_WIRE_DESCRIPTOR_V1,
                &b"ILQ1:fixed71576"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUANCE_WIRE_SCHEMA_V1,
                &b"caller-cap-before-exact-length-before-allocation"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1,
                &b"authorization-state:Fresh-Processing-Completed-or-Failed"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUANCE_RANDOMNESS_DESCRIPTOR_V1,
                &b"closed-purpose-enum:no-caller-selected-labels"[..],
            ),
            (
                BOOTLE_LANTERN_ISSUANCE_STORE_PROFILE_DESCRIPTOR_V1,
                &b"canonical-process-lease+unix-nonblocking-exclusive-flock-held-for-lifetime"[..],
            ),
            (
                BOOTLE_LANTERN_FALCON512_MAPPING_DESCRIPTOR_V1,
                &b"H_i[j]=h[8*j+i]"[..],
            ),
            (
                BOOTLE_LANTERN_FALCON512_IMPLEMENTATION_PROVENANCE_V1,
                &b"arbitrary-R512-target"[..],
            ),
            (
                BOOTLE_CREDENTIAL_RANDOMNESS_PROFILE_DESCRIPTOR_V1,
                &b"sign-cache:issuance-local-persistent"[..],
            ),
        ] {
            assert!(
                descriptor
                    .windows(required.len())
                    .any(|window| window == required),
                "compiled descriptor omitted {}",
                String::from_utf8_lossy(required)
            );
        }
        assert_eq!(
            BOOTLE_LANTERN_SCOPE_APPLICATION_ACCEPTANCE_LIMIT_V1,
            BOOTLE_LANTERN_APPLICATION_MODULUS_V1 * 5
        );
        assert_eq!(BOOTLE_LANTERN_SCOPE_MAX_COEFFICIENT_ATTEMPTS_V1, 4_096);
        assert_eq!(CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1, 16);
        assert_eq!(
            CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1,
            RANDOMNESS_NORM_SQUARED_BOUND_V1
        );
        assert_eq!(MAX_CREDENTIAL_RANDOMNESS_VECTOR_ATTEMPTS_V1, 64);
        assert_eq!(MAX_CREDENTIAL_RANDOMNESS_COEFFICIENT_PROPOSALS_V1, 256);
        assert_eq!(
            MAX_BOOTLE_LANTERN_ISSUER_KEYGEN_CANDIDATES_V1,
            BOOTLE_LANTERN_FALCON512_DEFAULT_KEYGEN_CANDIDATES_V1
        );
        assert_eq!(MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1, 4);
        assert_eq!(MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1, 4_096);
        assert_eq!(MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1, 64);
        assert_eq!(BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1, 3_310);
        assert_eq!(BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RECORDS_V1, 1_000_000);
        assert_eq!(
            BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_TOTAL_BYTES_V1,
            3_310_000_000
        );
        assert_eq!(BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_RECORDS_V1, 4_096);
        assert_eq!(
            BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_TOTAL_BYTES_V1,
            13_557_760
        );
        assert_eq!(
            BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_RETENTION_BLOCKS_V1,
            4_096
        );
        assert_eq!(BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1, 320);
        assert_eq!(BLIND_ISSUANCE_REQUEST_BYTES_V1, 71_576);
        assert_eq!(BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1, 16);
        assert_eq!(BLIND_ISSUANCE_REQUEST_MAGIC_V1, *b"ILQ1");
        assert_eq!(BLIND_ISSUANCE_REQUEST_VERSION_V1, 1);
        assert_eq!(BLIND_ISSUANCE_REQUEST_PURPOSE_TAG_V1, 1);
        assert_eq!(BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1, 8);
        assert_eq!(BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1, 64);
        assert_eq!(BLIND_ISSUANCE_RESPONSE_BYTES_V1, 3_176);
        assert_eq!(BLIND_ISSUANCE_REQUEST_PROOF_MAGIC_V1, *b"ILB1");
        assert_eq!(BLIND_ISSUANCE_REQUEST_PROOF_PURPOSE_TAG_V1, 1);
        assert_eq!(
            BOOTLE_LANTERN_CREDENTIAL_SCOPE_DIGEST_DOMAIN_V1,
            b"iroha.privacy.bootle-lantern.credential-scope-digest.v1"
        );
        assert_ne!(bootle_lantern_issuer_profile_digest_v1(), [0; 32]);
        assert_eq!(BOOTLE_LANTERN_PROOF_BYTES_V1, 70_344);
        assert!(
            u64::try_from(BOOTLE_LANTERN_PROOF_BYTES_V1).expect("proof size fits u64")
                <= u64::from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
        );
        assert_ne!(public_parameter_seed_v1(), [0; 32]);
        for digest in [
            *first.parameter_id.as_bytes(),
            *first.parameter_digest.as_bytes(),
            *first.verifier_digest.as_bytes(),
            *first.statement_schema_digest.as_bytes(),
            *first.engine_manifest_digest.as_bytes(),
        ] {
            assert_ne!(digest, [0; 32]);
        }
        assert_eq!(
            (
                hex::encode(first.parameter_id.as_bytes()),
                hex::encode(first.parameter_digest.as_bytes()),
                hex::encode(first.verifier_digest.as_bytes()),
                hex::encode(first.statement_schema_digest.as_bytes()),
                hex::encode(first.engine_manifest_digest.as_bytes()),
            ),
            (
                "5858a2e4d1be81b06da5a153e8ec103515939fbe78106d7c4e3aa865c2d347cd".to_owned(),
                "c0bbfcdc6d612eef0e8a5ef549f7dab1f832b217566445b7881fb9d71d1f300a".to_owned(),
                "3a6e0f4fdaeeab4947f68b44ee6f1eb0434f32326289210d3faab15038ab9cff".to_owned(),
                "cd5aeafd932dbf75f3cf1d59671480b377f12188aac553700864f0619812fa78".to_owned(),
                "7d9e4422510f202eb46891b6830923622d396833c32691bda883710eb72b5b2a".to_owned(),
            ),
            "every consensus-critical Bootle/Lantern binding is a pinned KAT"
        );
        if !BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1 {
            return;
        }
        let valid = bootle_lantern_activation();
        validate_compiled_privacy_activation_v1(&valid).expect("exact profile");
        let mutations: [(
            CompiledPrivacyProfileValidationErrorV1,
            fn(&mut PrivacyProtocolActivationRecordV1),
        ); 8] = [
            (
                CompiledPrivacyProfileValidationErrorV1::ProofSystemMismatch,
                |record| {
                    record.proof_system_id =
                        PrivacyProofSystemIdV1::FcmpPlusPlusCurveTreeBulletproofs;
                },
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineMismatch,
                |record| record.engine_id = PrivacyEngineIdV1::NativeFcmpPlusPlus,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterIdMismatch,
                |record| record.parameter_id.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterDigestMismatch,
                |record| record.parameter_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch,
                |record| record.verifier_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::StatementSchemaDigestMismatch,
                |record| record.statement_schema_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineManifestDigestMismatch,
                |record| record.engine_manifest_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ProtocolLimitsMismatch,
                |record| {
                    record.protocol_limits =
                        PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                            JindoActivationLimitsV1 {
                                max_polynomial_count: 1,
                            },
                        );
                },
            ),
        ];
        for (expected, mutate) in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert_eq!(
                validate_compiled_privacy_activation_v1(&changed),
                Err(expected)
            );
        }
    }
    #[test]
    fn bootle_lantern_complete_sampling_profile_is_parameter_bound_and_kat_pinned() {
        assert!(
            BOOTLE_LANTERN_TRANSCRIPT_SCHEMA_V1
                .windows(b"max-rejected-uniform-draws-per-coefficient=4096".len())
                .any(|window| { window == b"max-rejected-uniform-draws-per-coefficient=4096" })
        );
        let public_parameter_seed = public_parameter_seed_v1();
        let sampling_profile_digest = bootle_sampling_profile_digest_v1();
        assert_eq!(
            hex::encode(sampling_profile_digest),
            "6e037c7342b327b75df5621f999506799174254ca7a7846d7549a6526f6ef897"
        );
        let governed =
            bootle_lantern_parameter_digest_v1(&public_parameter_seed, &sampling_profile_digest);
        assert_eq!(
            hex::encode(governed),
            "c0bbfcdc6d612eef0e8a5ef549f7dab1f832b217566445b7881fb9d71d1f300a"
        );
        for index in 0..sampling_profile_digest.len() {
            let mut mutated_sampling_profile_digest = sampling_profile_digest;
            mutated_sampling_profile_digest[index] ^= 1;
            assert_ne!(
                governed,
                bootle_lantern_parameter_digest_v1(
                    &public_parameter_seed,
                    &mutated_sampling_profile_digest
                ),
                "sampling-profile digest byte {index} was not parameter-bound"
            );
        }
    }
    #[test]
    fn orchard_profile_is_deterministic_complete_bounded_and_mutation_closed() {
        let first = compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
            .expect("profile");
        let second = compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
            .expect("profile");
        assert_eq!(first, second);
        assert_eq!(first.proof_system_id, PrivacyProofSystemIdV1::Halo2IpaPasta);
        assert_eq!(first.engine_id, PrivacyEngineIdV1::NativeHalo2Orchard);
        assert_eq!(
            first.protocol_limits,
            PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(OrchardActivationLimitsV1 {
                max_action_count: ORCHARD_MODEL_MAX_ACTIONS_V1,
            })
        );
        assert_eq!(ORCHARD_ENGINE_MAX_ACTIONS_V1, 2);
        assert_eq!(ORCHARD_MODEL_MAX_ACTIONS_V1, 2);
        assert!(
            orchard_authorization_wire_size_v1(2).expect("wire size")
                <= usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
                    .expect("global proof cap fits usize")
        );
        assert_ne!(orchard_empty_root_v1(), [0; 32]);
        for digest in [
            *first.parameter_id.as_bytes(),
            *first.parameter_digest.as_bytes(),
            *first.verifier_digest.as_bytes(),
            *first.statement_schema_digest.as_bytes(),
            *first.engine_manifest_digest.as_bytes(),
        ] {
            assert_ne!(digest, [0; 32]);
        }
        let mut mutated_source_policy = TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1.to_vec();
        mutated_source_policy[0] ^= 1;
        let mut mutated_bridge_policy = ORCHARD_PROVER_RANDOMNESS_POLICY_V1.to_vec();
        mutated_bridge_policy[0] ^= 1;
        for (label, source_policy, bridge_policy) in [
            (
                "source",
                mutated_source_policy.as_slice(),
                ORCHARD_PROVER_RANDOMNESS_POLICY_V1,
            ),
            (
                "bridge",
                TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1,
                mutated_bridge_policy.as_slice(),
            ),
        ] {
            let policy_mutation =
                compiled_orchard_profile_v1_with_randomness_policies(source_policy, bridge_policy)
                    .expect("structurally valid Orchard policy mutation");
            assert_eq!(
                policy_mutation.parameter_id, first.parameter_id,
                "{label} policy changed the parameter family"
            );
            assert_ne!(
                policy_mutation.parameter_digest, first.parameter_digest,
                "{label} policy was not parameter-bound"
            );
            assert_ne!(
                policy_mutation.verifier_digest, first.verifier_digest,
                "{label} policy was not verifier-bound"
            );
            assert_eq!(
                policy_mutation.statement_schema_digest, first.statement_schema_digest,
                "{label} policy changed the statement schema"
            );
            assert_ne!(
                policy_mutation.engine_manifest_digest, first.engine_manifest_digest,
                "{label} policy was not engine-manifest-bound"
            );
        }
        assert_eq!(
            (
                hex::encode(first.parameter_id.as_bytes()),
                hex::encode(first.parameter_digest.as_bytes()),
                hex::encode(first.verifier_digest.as_bytes()),
                hex::encode(first.statement_schema_digest.as_bytes()),
                hex::encode(first.engine_manifest_digest.as_bytes()),
            ),
            (
                "8d5a2946c58314ac12d2968ffe9e8e0c672e3bbceefaaefad6a87420ea7dd212".to_owned(),
                "b27b73d59151415e21b158c75ed9371cccd795655b604e4a6b53db621660b66e".to_owned(),
                "5f44e8a6a901ef33bc3c99d5400592f420f006877ae9904b758ee49a3226718f".to_owned(),
                "2141dd88d579b2460cfb0f79f230bfb2f71663364d8700c8e7e6b3e8f57c5a2a".to_owned(),
                "c294d7ddc1be131d273410ce3f191328ed589b7db37283b49b138658250f060c".to_owned(),
            ),
            "every consensus-critical Orchard profile binding is a pinned KAT"
        );
        let valid = orchard_activation();
        validate_compiled_privacy_activation_v1(&valid).expect("exact profile");
        let mutations: [fn(&mut PrivacyProtocolActivationRecordV1); 7] = [
            |record| record.parameter_id.0[0] ^= 1,
            |record| record.parameter_digest.0[0] ^= 1,
            |record| record.verifier_digest.0[0] ^= 1,
            |record| record.statement_schema_digest.0[0] ^= 1,
            |record| record.engine_manifest_digest.0[0] ^= 1,
            |record| {
                record.proof_system_id = PrivacyProofSystemIdV1::FcmpPlusPlusCurveTreeBulletproofs
            },
            |record| record.engine_id = PrivacyEngineIdV1::NativeFcmpPlusPlus,
        ];
        for mutate in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert!(validate_compiled_privacy_activation_v1(&changed).is_err());
        }
    }
    #[test]
    #[cfg(feature = "zk-stark")]
    fn zk_ace_sha3_outer_profile_stays_unavailable_without_qrom_certification() {
        let protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(CompiledPrivacyProfileErrorV1::EngineUnavailable { protocol_id })
        );
        const { assert!(!ZK_ACE_FULL_ENGINE_AVAILABLE_V1) };
        assert!(!ZK_ACE_QROM_CERTIFICATION_BLOCKER_V1.is_empty());
        assert_eq!(ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1, 2_131_222);
    }
    #[test]
    fn zk_ams_profile_is_unavailable_until_every_mkhe_gate_closes() {
        let expected = CompiledPrivacyProfileErrorV1::EngineUnavailable {
            protocol_id: PrivacyProtocolIdV1::IrohaZkAmsV1,
        };
        assert_eq!(
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1),
            Err(expected)
        );
        assert_eq!(
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1),
            Err(expected),
            "the unavailable result must be deterministic"
        );
        let readiness =
            iroha_zkp_halo2::vega::zk_ams_mkhe_readiness_v1().expect("readiness derives");
        assert!(readiness.parameter_gate);
        assert!(readiness.noise_gate);
        assert!(readiness.security_gate);
        assert!(!readiness.resource_gate);
        assert!(!readiness.wire_gate);
        assert!(!readiness.malicious_party_gate);
        assert!(!readiness.decryption_share_gate);
        assert!(readiness.packing_gate);
        assert!(!readiness.phase23_gate);
        assert!(!readiness.release_kat_gate);
        assert!(!readiness.is_ready());
    }
    #[test]
    fn structural_schema_digest_detects_reordering_and_retyping() {
        let original = canonical_schema_digest_v1::<SchemaOrderAb>().expect("schema");
        let reordered = canonical_schema_digest_v1::<SchemaOrderBa>().expect("schema");
        let retyped = canonical_schema_digest_v1::<SchemaRetyped>().expect("schema");
        assert_ne!(original, reordered);
        assert_ne!(original, retyped);
        assert_ne!(reordered, retyped);
        assert_eq!(
            original,
            canonical_schema_digest_v1::<SchemaOrderAb>().expect("schema")
        );
    }
    #[test]
    fn structural_schema_digest_deduplicates_only_equivalent_aliases() {
        let equivalent =
            canonical_schema_digest_v1::<SchemaEquivalentAliases>().expect("equivalent aliases");
        assert_ne!(equivalent, [0; 32]);
        assert_eq!(
            canonical_schema_digest_v1::<SchemaEquivalentAliases>().expect("equivalent aliases"),
            equivalent
        );
        assert_eq!(
            canonical_schema_digest_v1::<SchemaConflictingAliases>(),
            Err(CanonicalSchemaDigestErrorV1::ConflictingStableTypeId)
        );
    }
    #[test]
    fn verange_profile_is_deterministic_and_uses_effective_global_cap() {
        let first = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("profile");
        let second = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("profile");
        assert_eq!(first, second);
        assert_eq!(
            first.protocol_limits,
            PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
                VeRangeActivationLimitsV1 {
                    max_aggregation_count: 8,
                }
            )
        );
        for digest in [
            *first.parameter_id.as_bytes(),
            *first.parameter_digest.as_bytes(),
            *first.verifier_digest.as_bytes(),
            *first.statement_schema_digest.as_bytes(),
            *first.engine_manifest_digest.as_bytes(),
        ] {
            assert_ne!(digest, [0; 32]);
        }
        assert_eq!(
            (
                hex::encode(first.parameter_id.as_bytes()),
                hex::encode(first.parameter_digest.as_bytes()),
                hex::encode(first.verifier_digest.as_bytes()),
                hex::encode(first.statement_schema_digest.as_bytes()),
                hex::encode(first.engine_manifest_digest.as_bytes()),
            ),
            (
                "97e8be40e495bb6723db0ca73c04d2441ff166cf2163ddd2662c7e6a083f2c32".to_owned(),
                "3d79fe744741f956cb589f45774f922b849cf93833e6a9ebdedf1f815f1b7b44".to_owned(),
                "9b1a285d43ddc306b4d9ca6eac525b49b073f7d281ecf94299730613f683aa13".to_owned(),
                "e98c04cd9cdf69539d24858400c02d1021207b6377bfbe63a734e189ff5b4327".to_owned(),
                "b3fd69b5fcf8ba2f14f529a8edfac9725338124ac24d612da65eb0fb8364c0d5".to_owned(),
            )
        );
    }
    #[test]
    fn anonymous_pgc_profile_is_deterministic_complete_and_bounded() {
        let first = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            .expect("profile");
        let second = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            .expect("profile");
        assert_eq!(first, second);
        assert_eq!(
            PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
            PRIVACY_PGC_BOOTSTRAP_INITIAL_EPOCH_V1
        );
        assert_eq!(
            first.protocol_limits,
            PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
                AnonymousPgcActivationLimitsV1 {
                    max_anonymity_set_size: 64,
                    max_recipient_count: 8,
                }
            )
        );
        assert_eq!(
            (
                hex::encode(first.parameter_id.as_bytes()),
                hex::encode(first.parameter_digest.as_bytes()),
                hex::encode(first.verifier_digest.as_bytes()),
                hex::encode(first.statement_schema_digest.as_bytes()),
                hex::encode(first.engine_manifest_digest.as_bytes()),
            ),
            (
                "58c1a93d39f23727ae8b5bbb661414f3dcadf2479575282cd7e3b9ebbb5589fc".to_owned(),
                "ca09d19ed5f3bb56ba7432a67b7ad14697c4874ab7870ea53441e4df0624bd7b".to_owned(),
                "f744892c6f1a855b2dc24586ff5701f45ff2dad4d94bca6f8342e500df899a02".to_owned(),
                "68641f65f768489617b1105cf3918b4f0b0499800af18a1f92b5471fa7836ebb".to_owned(),
                "041fd6b68d1a2e8b78749f58d013239e317d010ecdc7e37d1299ab9835c3b887".to_owned(),
            )
        );
    }
    #[test]
    fn jindo_profile_is_deterministic_complete_and_bounded() {
        let first =
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
                .expect("profile");
        let second =
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
                .expect("profile");
        assert_eq!(first, second);
        assert_eq!(
            first.proof_system_id,
            PrivacyProofSystemIdV1::JindoPolynomialCommitment
        );
        assert_eq!(first.engine_id, PrivacyEngineIdV1::NativeJindo);
        assert_eq!(JINDO_NATIVE_PROOF_BYTES_V1, 7_159_944);
        assert_ne!(jindo_crs_digest_v1(), [0; 32]);
        assert_eq!(
            crate::privacy_engines::jindo::jindo_unit_difference_certificate_v1()
                .expect("compiled Jindo unit theorem")
                .digest(),
            crate::privacy_engines::jindo::JINDO_UNIT_DIFFERENCE_CERTIFICATE_DIGEST_V1,
        );
        assert_eq!(
            crate::privacy_engines::jindo::jindo_security_certificate_v1(),
            Err(
                crate::privacy_engines::jindo::JindoSecurityCertificateErrorV1::MissingQromParallelFiatShamirExtractorLoss {
                    repetitions: 32,
                    terminal_challenge_bits: 352,
                    required_security_bits: 128,
                },
            ),
        );
        let activation = first.activation_record(PrivacyProtocolLifecycleV1::Proposed(
            PrivacyProposedLifecycleV1 {
                proposed_at_height: 1,
            },
        ));
        assert_eq!(activation.protocol_id, first.protocol_id);
        assert_eq!(activation.parameter_digest, first.parameter_digest);
        let provenance = core::str::from_utf8(JINDO_SOURCE_PROVENANCE_V1)
            .expect("Jindo source provenance is ASCII");
        assert!(provenance.contains("revision-2026-06-02"));
        assert!(provenance.contains("ringo-snark@805eab27"));
        let wire = core::str::from_utf8(JINDO_PROOF_WIRE_LABEL_V1)
            .expect("Jindo proof wire label is ASCII");
        for required in [
            "IJP3",
            "32-parallel",
            "224-outer-packed5",
            "384-inner-packed6",
            "4612-field",
            "7159944-bytes",
            "no-IJP1",
            "no-IJP2",
        ] {
            assert!(
                wire.contains(required),
                "Jindo wire descriptor lost {required}"
            );
        }
        assert_eq!(
            first.protocol_limits,
            PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                JindoActivationLimitsV1 {
                    max_polynomial_count: u32::try_from(JINDO_MAX_BATCH_SIZE_V1)
                        .expect("fixed Jindo batch size fits u32"),
                }
            )
        );
        assert_eq!(
            (
                hex::encode(first.parameter_id.as_bytes()),
                hex::encode(first.parameter_digest.as_bytes()),
                hex::encode(first.verifier_digest.as_bytes()),
                hex::encode(first.statement_schema_digest.as_bytes()),
                hex::encode(first.engine_manifest_digest.as_bytes()),
                hex::encode(jindo_crs_digest_v1()),
            ),
            (
                "c4a5f4e1dc7ec790302538f77d0a76c9ca1442f3d23a2517c5f577714bd94500".to_owned(),
                "e5989a51a3121672e02ff827bd9850587233e1ba77eab3dc5401e914ab2ade84".to_owned(),
                "e32deea2258a2dfa34f5394f78001051a10945a9b9a9ac51ab3fedd1cdb25289".to_owned(),
                "cc09c3ae81e41158eb533d828aea52c27a1769cc8e89bbd2adb42eeaf84cbd61".to_owned(),
                "9c94a7482d68cc10d6d062bc6cdd40e25aa319f27bad56c8109b79fee500f000".to_owned(),
                "adc8dc7954268627d30b85d6a79df579b3a933af487248a4cba79af08f217dda".to_owned(),
            )
        );
    }
    #[test]
    fn vega_engine_remains_unavailable_until_exact12_qualification() {
        let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(CompiledPrivacyProfileErrorV1::EngineUnavailable { protocol_id })
        );
        assert_ne!(vega_mdl_canonical_relation_digest_v1(), [0; 32]);
        assert_ne!(vega_mdl_compiled_profile_digest_v1(), [0; 32]);
        assert_eq!(
            vega_mdl_verifier_digest_v1().expect("canonical Vega-MC verifier digest"),
            VEGA_MDL_CANONICAL_VERIFIER_DIGEST_V1,
        );
    }
    #[test]
    #[ignore = "operator-only KAT regeneration after an intentional compiled-profile change"]
    fn print_available_profile_tuples() {
        for protocol_id in PrivacyProtocolIdV1::ALL {
            let profile = match compiled_privacy_profile_v1(protocol_id) {
                Ok(profile) => profile,
                Err(error) => {
                    eprintln!("{}=unavailable|{error}", protocol_id.canonical_label());
                    continue;
                }
            };
            eprintln!(
                "{}={}|{}|{}|{}|{}",
                protocol_id.canonical_label(),
                hex::encode(profile.parameter_id.as_bytes()),
                hex::encode(profile.parameter_digest.as_bytes()),
                hex::encode(profile.verifier_digest.as_bytes()),
                hex::encode(profile.statement_schema_digest.as_bytes()),
                hex::encode(profile.engine_manifest_digest.as_bytes()),
            );
        }
    }
    #[test]
    fn jindo_compiled_profile_rejects_every_binding_and_policy_mismatch() {
        let valid = jindo_activation();
        validate_compiled_privacy_activation_v1(&valid).expect("exact profile");
        let mutations: [(
            CompiledPrivacyProfileValidationErrorV1,
            fn(&mut PrivacyProtocolActivationRecordV1),
        ); 8] = [
            (
                CompiledPrivacyProfileValidationErrorV1::ProofSystemMismatch,
                |record| {
                    record.proof_system_id = PrivacyProofSystemIdV1::IrohaVeRangeP256;
                },
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineMismatch,
                |record| record.engine_id = PrivacyEngineIdV1::NativeVeRangeP256,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterIdMismatch,
                |record| record.parameter_id.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterDigestMismatch,
                |record| record.parameter_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch,
                |record| record.verifier_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::StatementSchemaDigestMismatch,
                |record| record.statement_schema_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineManifestDigestMismatch,
                |record| record.engine_manifest_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ProtocolLimitsMismatch,
                |record| {
                    record.protocol_limits =
                        PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                            JindoActivationLimitsV1 {
                                max_polynomial_count: 5,
                            },
                        );
                },
            ),
        ];
        for (expected, mutate) in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert_eq!(
                validate_compiled_privacy_activation_v1(&changed),
                Err(expected)
            );
        }
    }
    #[test]
    fn every_compiled_cryptographic_binding_is_immutable() {
        let valid = verange_activation();
        validate_compiled_privacy_activation_v1(&valid).expect("exact profile");
        let mutations: [(
            CompiledPrivacyProfileValidationErrorV1,
            fn(&mut PrivacyProtocolActivationRecordV1),
        ); 7] = [
            (
                CompiledPrivacyProfileValidationErrorV1::ProofSystemMismatch,
                |record| {
                    record.proof_system_id = PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks
                },
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineMismatch,
                |record| record.engine_id = PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterIdMismatch,
                |record| record.parameter_id.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterDigestMismatch,
                |record| record.parameter_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch,
                |record| record.verifier_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::StatementSchemaDigestMismatch,
                |record| record.statement_schema_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineManifestDigestMismatch,
                |record| record.engine_manifest_digest.0[0] ^= 1,
            ),
        ];
        for (expected, mutate) in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert_eq!(
                validate_compiled_privacy_activation_v1(&changed),
                Err(expected)
            );
        }
    }
    #[test]
    fn compiled_validation_accepts_lower_protocol_policy_without_changing_digests() {
        let verange_compiled =
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
                .expect("VeRange profile");
        let mut verange = verange_activation();
        verange.protocol_limits = PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
            VeRangeActivationLimitsV1 {
                max_aggregation_count: 1,
            },
        );
        validate_compiled_privacy_activation_v1(&verange).expect("lower VeRange policy");
        assert_eq!(verange.parameter_id, verange_compiled.parameter_id);
        assert_eq!(verange.parameter_digest, verange_compiled.parameter_digest);
        assert_eq!(verange.verifier_digest, verange_compiled.verifier_digest);
        assert_eq!(
            verange.statement_schema_digest,
            verange_compiled.statement_schema_digest
        );
        assert_eq!(
            verange.engine_manifest_digest,
            verange_compiled.engine_manifest_digest
        );
        let pgc_compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            .expect("PGC profile");
        let mut pgc = pgc_activation();
        pgc.protocol_limits = PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
            AnonymousPgcActivationLimitsV1 {
                max_anonymity_set_size: 16,
                max_recipient_count: 1,
            },
        );
        validate_compiled_privacy_activation_v1(&pgc).expect("lower PGC policy");
        assert_eq!(pgc.parameter_id, pgc_compiled.parameter_id);
        assert_eq!(pgc.parameter_digest, pgc_compiled.parameter_digest);
        assert_eq!(pgc.verifier_digest, pgc_compiled.verifier_digest);
        assert_eq!(
            pgc.statement_schema_digest,
            pgc_compiled.statement_schema_digest
        );
        assert_eq!(
            pgc.engine_manifest_digest,
            pgc_compiled.engine_manifest_digest
        );
        let jindo_compiled =
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
                .expect("Jindo profile");
        let mut jindo = jindo_activation();
        jindo.protocol_limits = PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
            JindoActivationLimitsV1 {
                max_polynomial_count: 1,
            },
        );
        validate_compiled_privacy_activation_v1(&jindo).expect("lower Jindo policy");
        assert_eq!(jindo.parameter_id, jindo_compiled.parameter_id);
        assert_eq!(jindo.parameter_digest, jindo_compiled.parameter_digest);
        assert_eq!(jindo.verifier_digest, jindo_compiled.verifier_digest);
        assert_eq!(
            jindo.statement_schema_digest,
            jindo_compiled.statement_schema_digest
        );
        assert_eq!(
            jindo.engine_manifest_digest,
            jindo_compiled.engine_manifest_digest
        );
        let orchard_compiled =
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
                .expect("Orchard profile");
        let mut orchard = orchard_activation();
        orchard.protocol_limits =
            PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(OrchardActivationLimitsV1 {
                max_action_count: 1,
            });
        validate_compiled_privacy_activation_v1(&orchard).expect("lower Orchard policy");
        assert_eq!(orchard.parameter_id, orchard_compiled.parameter_id);
        assert_eq!(orchard.parameter_digest, orchard_compiled.parameter_digest);
        assert_eq!(orchard.verifier_digest, orchard_compiled.verifier_digest);
        assert_eq!(
            orchard.statement_schema_digest,
            orchard_compiled.statement_schema_digest
        );
        assert_eq!(
            orchard.engine_manifest_digest,
            orchard_compiled.engine_manifest_digest
        );
    }
    #[test]
    fn compiled_validation_rejects_protocol_limit_overflow_mismatch_and_invalid_lowering() {
        let mut invalid = Vec::new();
        let mut verange_over = verange_activation();
        verange_over.protocol_limits = PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
            VeRangeActivationLimitsV1 {
                max_aggregation_count: 9,
            },
        );
        invalid.push(verange_over);
        let mut pgc_n_over = pgc_activation();
        pgc_n_over.protocol_limits = PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
            AnonymousPgcActivationLimitsV1 {
                max_anonymity_set_size: 65,
                max_recipient_count: 8,
            },
        );
        invalid.push(pgc_n_over);
        let mut pgc_k_over = pgc_activation();
        pgc_k_over.protocol_limits = PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
            AnonymousPgcActivationLimitsV1 {
                max_anonymity_set_size: 64,
                max_recipient_count: 9,
            },
        );
        invalid.push(pgc_k_over);
        let mut pgc_bad_closed_set = pgc_activation();
        pgc_bad_closed_set.protocol_limits =
            PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
                AnonymousPgcActivationLimitsV1 {
                    max_anonymity_set_size: 17,
                    max_recipient_count: 1,
                },
            );
        invalid.push(pgc_bad_closed_set);
        let mut zero_verange = verange_activation();
        zero_verange.protocol_limits = PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
            VeRangeActivationLimitsV1 {
                max_aggregation_count: 0,
            },
        );
        invalid.push(zero_verange);
        let mut jindo_over = jindo_activation();
        jindo_over.protocol_limits =
            PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                JindoActivationLimitsV1 {
                    max_polynomial_count: 5,
                },
            );
        invalid.push(jindo_over);
        let mut zero_jindo = jindo_activation();
        zero_jindo.protocol_limits =
            PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                JindoActivationLimitsV1 {
                    max_polynomial_count: 0,
                },
            );
        invalid.push(zero_jindo);
        let mut orchard_over = orchard_activation();
        orchard_over.protocol_limits =
            PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(OrchardActivationLimitsV1 {
                max_action_count: ORCHARD_MODEL_MAX_ACTIONS_V1 + 1,
            });
        invalid.push(orchard_over);
        let mut zero_orchard = orchard_activation();
        zero_orchard.protocol_limits =
            PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(OrchardActivationLimitsV1 {
                max_action_count: 0,
            });
        invalid.push(zero_orchard);
        let mut wrong_variant = verange_activation();
        wrong_variant.protocol_limits = PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
            AnonymousPgcActivationLimitsV1 {
                max_anonymity_set_size: 16,
                max_recipient_count: 1,
            },
        );
        invalid.push(wrong_variant);
        for activation in invalid {
            assert_eq!(
                validate_compiled_privacy_activation_v1(&activation),
                Err(CompiledPrivacyProfileValidationErrorV1::ProtocolLimitsMismatch)
            );
        }
    }
    #[test]
    fn zk_x509_compiled_activation_is_fail_closed_or_complete_and_immutable() {
        let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
        let profile = match compiled_privacy_profile_v1(protocol_id) {
            Ok(profile) => profile,
            Err(CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id: unavailable,
            }) if unavailable == protocol_id => return,
            Err(error) => panic!("unexpected ZK-X509 profile error: {error}"),
        };
        for digest in [
            *profile.parameter_id.as_bytes(),
            *profile.parameter_digest.as_bytes(),
            *profile.verifier_digest.as_bytes(),
            *profile.statement_schema_digest.as_bytes(),
            *profile.engine_manifest_digest.as_bytes(),
        ] {
            assert_ne!(digest, [0; 32]);
        }
        assert_eq!(
            profile.proof_system_id,
            PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks
        );
        assert_eq!(
            profile.engine_id,
            PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri
        );
        assert_eq!(
            profile.protocol_limits,
            PrivacyProtocolActivationLimitsV1::IrohaZkX509StarkP256V1
        );
        let valid = profile.activation_record(PrivacyProtocolLifecycleV1::Proposed(
            PrivacyProposedLifecycleV1 {
                proposed_at_height: 100,
            },
        ));
        validate_compiled_privacy_activation_v1(&valid).expect("exact compiled profile");
        let mutations: [(
            CompiledPrivacyProfileValidationErrorV1,
            fn(&mut PrivacyProtocolActivationRecordV1),
        ); 8] = [
            (
                CompiledPrivacyProfileValidationErrorV1::ProofSystemMismatch,
                |record| {
                    record.proof_system_id =
                        PrivacyProtocolIdV1::VeRangeTransparentRangeV1.expected_proof_system();
                },
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineMismatch,
                |record| {
                    record.engine_id =
                        PrivacyProtocolIdV1::VeRangeTransparentRangeV1.expected_engine();
                },
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterIdMismatch,
                |record| record.parameter_id.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ParameterDigestMismatch,
                |record| record.parameter_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch,
                |record| record.verifier_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::StatementSchemaDigestMismatch,
                |record| record.statement_schema_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::EngineManifestDigestMismatch,
                |record| record.engine_manifest_digest.0[0] ^= 1,
            ),
            (
                CompiledPrivacyProfileValidationErrorV1::ProtocolLimitsMismatch,
                |record| {
                    record.protocol_limits =
                        PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
                            VeRangeActivationLimitsV1 {
                                max_aggregation_count: 1,
                            },
                        );
                },
            ),
        ];
        for (expected, mutate) in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert_eq!(
                validate_compiled_privacy_activation_v1(&changed),
                Err(expected)
            );
        }
        let mut wrong_protocol = valid;
        wrong_protocol.protocol_id = PrivacyProtocolIdV1::VeRangeTransparentRangeV1;
        assert_eq!(
            validate_compiled_privacy_activation_v1(&wrong_protocol),
            Err(CompiledPrivacyProfileValidationErrorV1::ProtocolMismatch)
        );
    }
    #[test]
    fn anonymous_pgc_compiled_bindings_are_immutable() {
        let valid = pgc_activation();
        validate_compiled_privacy_activation_v1(&valid).expect("exact profile");
        let mutations: [fn(&mut PrivacyProtocolActivationRecordV1); 5] = [
            |record| {
                record.parameter_digest.0[0] ^= 1;
            },
            |record| record.verifier_digest.0[0] ^= 1,
            |record| record.statement_schema_digest.0[0] ^= 1,
            |record| record.engine_manifest_digest.0[0] ^= 1,
            |record| {
                let PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(ref mut limits) =
                    record.protocol_limits
                else {
                    unreachable!("fixture is Anonymous PGC");
                };
                limits.max_recipient_count += 1;
            },
        ];
        for mutate in mutations {
            let mut changed = valid;
            mutate(&mut changed);
            assert!(validate_compiled_privacy_activation_v1(&changed).is_err());
        }
    }
}
