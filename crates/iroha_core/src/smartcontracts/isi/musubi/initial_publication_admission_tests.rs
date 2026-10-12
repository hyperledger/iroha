// Actual signed Initial admission and positive Nexus fees. Uncompleted provider evidence is a
// refusal specimen, never a fabricated native completion, inventory or successful publication.
mod initial_publication_admission {
    use super::*;
    use crate::{
        executor::{Executor, quote_nexus_fee_admission_draft},
        smartcontracts::isi::{
            InitialNativeInstructionAdmission, registered_native_instruction_initial_admission,
        },
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_config::parameters::actual::Nexus;
    use iroha_data_model::nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig};
    use iroha_data_model::{
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
        domain::Domain,
        isi::{Log, Mint, Register, Transfer, sorafs::InitializeSorafsProviderAdmissionV1},
        sorafs::{
            capacity::ProviderId,
            pin_registry::{
                ManifestDigest, ProviderIngestCompletionAuthorityV1,
                ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
                ReplicationOrderId,
            },
            provider_admission::governance::{
                InitialProviderAdmissionCouncilV1, InitialProviderAdmissionV1,
            },
        },
        transaction::{
            FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
            error::TransactionRejectionReason,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::LaneId;
    use iroha_primitives::{numeric::Quantity, time::TimeSource};
    use sorafs_manifest::{
        ProviderAdmissionEnvelopeV1, provider_admission::ProviderAdmissionGenesisMaterialV1,
    };
    use std::time::Duration;

    const NOW: u64 = 1_700_000_000;
    const PUBLISHER: u8 = 0x34;
    const BROKER: u8 = 0x35;
    const STRANGER: u8 = 0x90;
    const SINK: u8 = 0x91;
    fn key(seed: u8) -> KeyPair {
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
    }

    fn namespace_domain() -> DomainId {
        DomainId::parse_fully_qualified("native.universal").unwrap()
    }
    struct Fixture {
        chain: CertifiedTestChain,
        archive: MusubiArchiveRecordV1,
        manifest: MusubiReleaseManifestV1,
        lock: MusubiVerificationLockV1,
        asset: AssetDefinitionId,
        provider: ProviderId,
    }
    impl Fixture {
        fn new() -> Self {
            let envelope: ProviderAdmissionEnvelopeV1 =
                norito::decode_from_bytes(include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/sorafs_manifest/provider_admission/envelope_v1.to"
                )))
                .unwrap();
            let material = ProviderAdmissionGenesisMaterialV1 {
                proposal: envelope.proposal,
                advert_body: envelope.advert_body,
                issued_at: NOW,
                retention_epoch: NOW + 3_600,
            };
            material.validate().unwrap();
            let provider = ProviderId::new(material.proposal.provider_id);
            let council = key(0x45);
            let initialize = InitializeSorafsProviderAdmissionV1 {
                council: InitialProviderAdmissionCouncilV1 {
                    policy_id: [0xC1; 32],
                    trusted_signers: vec![council.public_key().to_bytes().1.try_into().unwrap()],
                    signature_threshold: 1,
                },
                providers: vec![InitialProviderAdmissionV1 {
                    owner: account(BROKER),
                    material: norito::encode_canonical(&material).unwrap(),
                }],
            };
            let world = World::with(
                [],
                [PUBLISHER, BROKER, STRANGER, SINK].map(|seed| {
                    let account = account(seed);
                    Account::new(account.clone()).build(&account)
                }),
                [],
            );
            let asset = AssetDefinitionId::parse_address_literal(
                &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
            )
            .unwrap();
            let mut config = TestChainConfig::new(world, NOW * 1_000);
            let mut nexus = Nexus::default();
            nexus.fees.base_fee = 1_u32.into();
            nexus.fees.per_instruction_fee = 1_u32.into();
            nexus.fees.per_byte_fee = Quantity::zero();
            nexus.fees.per_gas_unit_fee = Quantity::zero();
            nexus.fees.fee_asset_id = asset.to_string();
            nexus.fees.fee_sink_account_id = account(SINK).to_string();
            // Declare both routing targets so the wrong-home binding reaches the native
            // namespace check instead of failing because its dataspace is unknown.
            nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: DataSpaceId::new(7),
                    alias: "fixture-other".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .unwrap();
            nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
            nexus.lane_catalog = LaneCatalog::new(
                std::num::NonZeroU32::new(2).unwrap(),
                vec![
                    LaneConfig::default(),
                    LaneConfig {
                        id: LaneId::new(1),
                        dataspace_id: DataSpaceId::new(7),
                        alias: "fixture-other".to_owned(),
                        ..Default::default()
                    },
                ],
            )
            .unwrap();
            nexus.configured_lane_catalog = nexus.lane_catalog.clone();
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
            config.nexus = Some(nexus);
            config.genesis_instructions = vec![
                initialize.into(),
                Register::domain(Domain::new(namespace_domain())).into(),
                Transfer::domain(
                    AccountId::new(config.genesis_key.public_key().clone()),
                    namespace_domain(),
                    account(PUBLISHER),
                )
                .into(),
                Register::asset_definition(AssetDefinition::numeric(
                    asset.clone(),
                    "Publication fee",
                    AssetBalancePolicy::Global,
                    None,
                ))
                .into(),
                Mint::asset_quantity(1_000_u32, AssetId::new(asset.clone(), account(PUBLISHER)))
                    .into(),
                Mint::asset_quantity(1_000_u32, AssetId::new(asset.clone(), account(STRANGER)))
                    .into(),
            ];
            let chain = CertifiedTestChain::start(config).unwrap();
            let mut archive = retention_archive(PUBLISHER);
            let package = MusubiPackageIdV1::new(
                DataSpaceId::UNIVERSAL,
                MusubiPackageScopeV1::Domain("native".parse().unwrap()),
                "native-initial".parse().unwrap(),
            );
            let release = MusubiReleaseIdV1::new(package, "1.0.0".parse().unwrap());
            let lock = MusubiVerificationLockV1 {
                schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
                version: MUSUBI_REGISTRY_VERSION_V1,
                root: release.clone(),
                root_dependencies: Vec::new(),
                nodes: Vec::new(),
            };
            let manifest = MusubiReleaseManifestV1 {
                release,
                edition: MusubiKotodamaEditionV1::V1,
                abi: MusubiAbiBindingV1::new([0xA1; 32]).unwrap(),
                dependencies: Vec::new(),
                exports: Vec::new(),
                interface_digest: MusubiContentDigestV1::new([0xA2; 32]),
                metadata: MusubiReleaseMetadataV1::default(),
                archive_id: archive.archive_id,
                verification_lock_digest: lock.digest(),
            };
            archive.staging_receipt.payload.binding.network_id = chain.network_id();
            archive.staging_receipt.payload.binding.seed_provider = provider;
            archive
                .staging_receipt
                .payload
                .binding
                .semantic_release_manifest_digest = manifest.semantic_digest();
            archive.staging_receipt.payload.issued_at_ms = NOW * 1_000;
            archive.staging_receipt.payload.expires_at_ms = (NOW + 600) * 1_000;
            archive.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
                key(BROKER).private_key(),
                archive.staging_receipt.payload.signing_hash(),
            )
            .unwrap();
            let mut f = Self {
                chain,
                archive,
                manifest,
                lock,
                asset,
                provider,
            };
            assert!(matches!(
                f.chain.state().view().world().executor(),
                Executor::Initial
            ));
            for seed in [PUBLISHER, STRANGER] {
                assert!(
                    f.chain
                        .state()
                        .view()
                        .world()
                        .account_permissions()
                        .get(&account(seed))
                        .is_none_or(|permissions| permissions.is_empty())
                );
            }
            f.applied(
                PUBLISHER,
                Log::new(
                    iroha_logger::Level::INFO,
                    "native publication admission".into(),
                )
                .into(),
            );
            assert!(
                crate::query::provider_admission::read_finalized_provider_admission_v1(
                    &f.chain.state().view(),
                    provider,
                    NOW,
                )
                .unwrap()
                .unwrap()
                .is_genesis_material()
            );
            let register = RegisterMusubiArchiveV1::new(
                f.archive.commitment.clone(),
                f.archive.staging_receipt.clone(),
                1,
            );
            f.applied(PUBLISHER, register.into());
            f.archive = f
                .chain
                .state()
                .view()
                .world()
                .musubi_archives()
                .get(&f.archive.archive_id)
                .unwrap()
                .clone();
            assert_eq!(f.archive.registered_at_height, 3);
            assert_eq!(f.archive.registered_by, account(PUBLISHER));
            f
        }
        fn balance(&self, seed: u8) -> Quantity {
            self.chain
                .state()
                .view()
                .world()
                .assets()
                .get(&AssetId::new(self.asset.clone(), account(seed)))
                .map_or_else(Quantity::zero, |value| value.as_ref().clone())
        }
        fn submit(&mut self, seed: u8, instruction: InstructionBox) -> Option<String> {
            let time = self.chain.committed(self.chain.height()).block_time_ms() + 1;
            let builder = TransactionBuilder::new_with_time_source(
                self.chain.network_id(),
                account(seed),
                &TimeSource::new_fixed(Duration::from_millis(time)),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([instruction]);
            let view = self.chain.state().view();
            let quote = quote_nexus_fee_admission_draft(
                view.world(),
                view.nexus(),
                view.pipeline(),
                builder.payload(),
                view.authenticated_query_ledger_time_ms().unwrap(),
                crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                    .expect("original committed fixture time"),
                self.chain.height() + 1,
                Some(DataSpaceId::UNIVERSAL),
            )
            .unwrap();
            drop(view);
            let signed: SignedTransaction = builder
                .with_fee_payment_intent(quote.recommended_intent)
                .sign(key(seed).private_key());
            let before = self.balance(seed);
            let sink = self.balance(SINK);
            let supply = self
                .chain
                .state()
                .view()
                .world()
                .asset_total_amount(&self.asset)
                .unwrap();
            let applied = self.chain.commit_at(time, vec![signed.clone()])[0];
            let block = self.chain.committed(self.chain.height());
            assert_eq!(block.block().network_entrypoint_count(), 1);
            assert_eq!(
                block.block().network_entrypoint_at(0).unwrap(),
                &TransactionEntrypoint::External(signed)
            );
            let result = &block.block().network_output_at(0).unwrap().1.result;
            assert_eq!(result.is_ok(), applied);
            let fee = before.checked_sub(&self.balance(seed)).unwrap();
            assert!(fee <= Quantity::from(2_u32));
            assert_eq!(
                self.balance(SINK),
                sink,
                "native Nexus fees burn the payer asset without crediting the configured sink"
            );
            assert_eq!(
                self.chain
                    .state()
                    .view()
                    .world()
                    .asset_total_amount(&self.asset)
                    .unwrap(),
                supply.checked_sub(&fee).unwrap(),
                "the actual charged fee is removed from the original asset supply"
            );
            if applied {
                assert_eq!(
                    fee,
                    Quantity::from(2_u32),
                    "successful ordinary work pays original positive fees"
                );
                None
            } else {
                let TransactionRejectionReason::Validation(
                    iroha_data_model::executor::ValidationFail::InstructionFailed(error),
                ) = result.as_ref().unwrap_err()
                else {
                    panic!("must reach the unchanged native handler: {result:?}");
                };
                let mut reason = error.to_string();
                let mut source = std::error::Error::source(error);
                while let Some(cause) = source {
                    reason.push_str(": ");
                    reason.push_str(&cause.to_string());
                    source = cause.source();
                }
                Some(reason)
            }
        }
        fn applied(&mut self, seed: u8, instruction: InstructionBox) {
            assert_eq!(self.submit(seed, instruction), None);
        }
        fn refused(&mut self, seed: u8, instruction: InstructionBox, reason: &str) {
            let result = self.submit(seed, instruction).expect("native refusal");
            assert!(result.contains(reason), "{result}");
            let view = self.chain.state().view();
            assert_eq!(
                view.world().musubi_archives().get(&self.archive.archive_id),
                Some(&self.archive)
            );
            assert_eq!(
                view.world()
                    .musubi_provider_bundle_attestations()
                    .iter()
                    .count(),
                0
            );
            assert_eq!(view.world().musubi_archive_locations().iter().count(), 0);
            assert_eq!(view.world().musubi_packages().iter().count(), 0);
            assert_eq!(view.world().musubi_releases().iter().count(), 0);
        }
        fn attestation(&self, revision: u64) -> RegisterMusubiProviderBundleAttestationV1 {
            let signing = key(0xA3);
            let completion = AccountId::new(signing.public_key().clone());
            let tip = self.chain.committed(self.chain.height());
            // A signed claim for a nonexistent completion; never inserted as native state.
            let payload = MusubiProviderBundleVerificationPayloadV1 {
                version: 1,
                binding: MusubiProviderBundleVerificationBindingV1 {
                    network_id: self.chain.network_id(),
                    provider_id: self.provider,
                    completed_by: completion.clone(),
                    completion_authority: ProviderIngestCompletionAuthorityV1::new(
                        account(BROKER),
                        completion,
                        ProviderIngestCompletionSignerPolicyV1 {
                            policy_id: [0xA4; 32],
                            revision: 1,
                            predecessor_digest: None,
                            policy_digest: [0xA5; 32],
                        },
                    ),
                    replication_order: ReplicationOrderId::new([0xA6; 32]),
                    assignment_revision: 1,
                    completion_epoch: NOW,
                    finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                        height: tip.height(),
                        block_hash: *tip.block_hash().as_ref(),
                    },
                    archive_id: self.archive.archive_id,
                    bundle_digest: self.archive.commitment.bundle_digest,
                    descriptor_digest: self.archive.commitment.descriptor_digest,
                    semantic_release_manifest_digest: self.manifest.semantic_digest(),
                    verification_lock_digest: self.lock.digest(),
                    source_tree_digest: self.archive.commitment.source_tree_digest,
                },
            };
            let signature =
                SignatureOf::try_from_hash(signing.private_key(), payload.signing_hash()).unwrap();
            let value = MusubiProviderBundleVerificationAttestationV1 {
                payload,
                approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                    public_key: signing.public_key().clone(),
                    signature,
                }],
            };
            value.verify(&value.payload.binding).unwrap();
            RegisterMusubiProviderBundleAttestationV1::new(value, revision)
        }
        fn location(&self, revision: u64) -> AddMusubiArchiveLocationV1 {
            AddMusubiArchiveLocationV1 {
                archive_id: self.archive.archive_id,
                location_id: MusubiArchiveLocationIdV1::new([0xA7; 32]),
                pin_manifest: ManifestDigest::new([0xA8; 32]),
                replication_order: ReplicationOrderId::new([0xA6; 32]),
                provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1::new(
                    [0xA9; 32],
                ),
                renew_after_epoch: NOW + 60,
                expires_at_epoch: NOW + 600,
                expected_location_revision: revision,
            }
        }
        fn publication(&self, revision: u64) -> PublishMusubiReleaseV1 {
            let view = self.chain.state().view();
            let tip = self.chain.committed(self.chain.height());
            PublishMusubiReleaseV1::new(
                "native.universal".parse().unwrap(),
                MusubiPublicationV1 {
                    manifest: self.manifest.clone(),
                    resolution: MusubiResolutionProofV1 {
                        snapshot: MusubiRegistrySnapshotV1 {
                            finalized_height: tip.height(),
                            finalized_block_hash: *tip.block_hash().as_ref(),
                            index_revision: view.world().musubi_resolver_index_revision(),
                        },
                        lock: self.lock.clone(),
                    },
                },
                None,
                revision,
                None,
            )
        }
    }
    #[test]
    fn signed_initial_attestation_and_location_keep_manager_cas_and_native_source_refusals() {
        let mut f = Fixture::new();
        for instruction in [f.attestation(1).into(), f.location(1).into()] {
            f.refused(
                STRANGER,
                instruction,
                "authority cannot manage this Musubi archive",
            );
        }
        for instruction in [f.attestation(2).into(), f.location(2).into()] {
            f.refused(
                PUBLISHER,
                instruction,
                "stale Musubi archive location revision",
            );
        }
        let missing = f.attestation(1);
        f.refused(PUBLISHER, missing.into(), "replication order");
    }
    #[test]
    fn signed_initial_release_preserves_policy_and_three_provider_availability_gates() {
        let mut f = Fixture::new();
        let stale = f.publication(2);
        f.refused(
            PUBLISHER,
            stale.into(),
            "stale Musubi registry policy revision",
        );
        for seed in [PUBLISHER, STRANGER] {
            let unavailable = f.publication(1);
            f.refused(
                seed,
                unavailable.into(),
                "has not reached finalized replication quorum",
            );
        }
    }
    #[test]
    fn signed_initial_namespace_binding_tracks_real_domain_owner_and_retains_immutable_generation()
    {
        let mut f = Fixture::new();
        let binding = MusubiNamespaceBindingV1 {
            namespace: "native.universal".parse().unwrap(),
            home_dataspace: DataSpaceId::UNIVERSAL,
            scope: MusubiPackageScopeV1::Domain("native".parse().unwrap()),
            generation: f
                .chain
                .state()
                .view()
                .world()
                .musubi_domain_ownership_generation(&namespace_domain()),
        };
        let instruction =
            |binding: MusubiNamespaceBindingV1| RegisterMusubiNamespaceBindingV1::new(binding, 1);
        f.refused(
            STRANGER,
            instruction(binding.clone()).into(),
            "does not own Musubi namespace",
        );
        let mut changed = binding.clone();
        changed.generation += 1;
        f.refused(
            PUBLISHER,
            instruction(changed).into(),
            "ownership generation is stale",
        );
        let mut cross_scope = binding.clone();
        cross_scope.home_dataspace = DataSpaceId::new(7);
        f.refused(
            PUBLISHER,
            instruction(cross_scope).into(),
            "not declared home dataspace",
        );
        assert!(
            f.chain
                .state()
                .view()
                .world()
                .musubi_namespace_bindings()
                .get(&binding.namespace)
                .is_none()
        );
        f.applied(PUBLISHER, instruction(binding.clone()).into());
        assert_eq!(
            f.chain
                .state()
                .view()
                .world()
                .musubi_namespace_bindings()
                .get(&binding.namespace),
            Some(&binding)
        );
        f.applied(PUBLISHER, instruction(binding.clone()).into());
        f.applied(
            PUBLISHER,
            Transfer::domain(account(PUBLISHER), namespace_domain(), account(STRANGER)).into(),
        );
        assert_eq!(
            f.chain
                .state()
                .view()
                .world()
                .musubi_domain_ownership_generation(&namespace_domain()),
            binding.generation + 1
        );
        f.refused(
            PUBLISHER,
            instruction(binding.clone()).into(),
            "does not own Musubi namespace",
        );
        // Replay is authorized by the actual successor, without rewriting original generation.
        f.applied(STRANGER, instruction(binding.clone()).into());
        let mut replacement = binding.clone();
        replacement.generation += 1;
        f.refused(STRANGER, instruction(replacement).into(), "already bound");
        assert_eq!(
            f.chain
                .state()
                .view()
                .world()
                .musubi_namespace_bindings()
                .get(&binding.namespace),
            Some(&binding)
        );
    }
    #[test]
    fn initial_publication_classifies_only_the_four_reviewed_native_owners() {
        let f = Fixture::new();
        for instruction in [
            f.attestation(1).into(),
            f.location(1).into(),
            f.publication(1).into(),
            RegisterMusubiNamespaceBindingV1::new(
                MusubiNamespaceBindingV1 {
                    namespace: "native.universal".parse().unwrap(),
                    home_dataspace: DataSpaceId::UNIVERSAL,
                    scope: MusubiPackageScopeV1::Domain("native".parse().unwrap()),
                    generation: 1,
                },
                1,
            )
            .into(),
        ] {
            assert_eq!(
                registered_native_instruction_initial_admission(&instruction),
                Some(InitialNativeInstructionAdmission::CoreAuthorized)
            );
        }
        let unreviewed: InstructionBox = SetMusubiReleaseYankV1::new(
            f.manifest.release.clone(),
            true,
            MusubiReasonV1::new("not part of this admission").unwrap(),
            1,
        )
        .into();
        assert_eq!(
            registered_native_instruction_initial_admission(&unreviewed),
            None
        );
    }
}
