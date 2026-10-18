// Shared signed and persisted-state fixtures for the current privacy regressions.
fn nonzero(byte: u8) -> [u8; 32] {
    [byte; 32]
}
fn network_id(byte: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(nonzero(byte)),
    ))
}
fn p256_point(multiple: u64) -> PrivacyP256PointV1 {
    let compressed = crate::privacy_engines::p256::CompressedPointV1::from_projective(
        ProjectivePoint::generator() * Scalar::from(multiple),
    )
    .expect("non-zero generator multiple");
    PrivacyP256PointV1::new(*compressed.as_bytes())
}
fn vega_issuer_record(
    issuer_id: PrivacyIssuerIdV1,
    epoch: u64,
    key_multiple: u64,
    previous_record_digest: Option<PrivacyVegaIssuerRecordDigestV1>,
    lifecycle: PrivacyVegaIssuerRecordLifecycleV1,
) -> PrivacyVegaIssuerRecordV1 {
    PrivacyVegaIssuerRecordV1::new(
        issuer_id,
        epoch,
        p256_point(key_multiple),
        iroha_data_model::privacy::PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
        PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
        PrivacyVegaMdlDigestAlgorithmV1::Sha256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        previous_record_digest,
        lifecycle,
    )
    .expect("canonical Vega issuer record")
}
fn account(seed: u8) -> AccountId {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("fixture seed derives Ed25519 keypair");
    AccountId::new(key_pair.public_key().clone())
}
fn zk_ace_policy_id(index: u64) -> PrivacyPolicyIdV1 {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&index.to_le_bytes());
    bytes[8] = 1;
    PrivacyPolicyIdV1::new(bytes)
}
fn zk_ace_policy_record(policy_id: PrivacyPolicyIdV1) -> PrivacyZkAcePolicyRecordV1 {
    let mut allowlist = vec![account(11), account(12)];
    allowlist.sort_unstable();
    PrivacyZkAcePolicyRecordV1::new(
        policy_id,
        PrivacyZkAceIdentityCommitmentV1::new([13; 6]).expect("small fixture words are canonical"),
        PrivacyPolicyDigestV1::new(nonzero(14)),
        1,
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("domain"),
            Name::from_str("asset").expect("asset name"),
        ),
        allowlist,
        PrivacyZkAcePolicyLifecycleV1::Active,
    )
    .expect("canonical ZK-ACE policy")
}
fn bootle_lantern_issuer_policy(
    issuer_byte: u8,
    policy_byte: u8,
    epoch: u64,
    lifecycle: BootleLanternIssuerPolicyLifecycleV1,
) -> BootleLanternIssuerPolicyV1 {
    let fixture_seed = usize::from(issuer_byte) + usize::from(policy_byte);
    let first_column = core::array::from_fn(|block| BootleLanternPolynomialV1 {
        coefficients: (0..BOOTLE_LANTERN_RING_DEGREE_V1)
            .map(|coefficient| {
                u16::try_from(
                    (fixture_seed + block * BOOTLE_LANTERN_RING_DEGREE_V1 + coefficient) % 12_288
                        + 1,
                )
                .expect("fixture residue fits u16")
            })
            .collect(),
    });
    let issuer_public_matrix =
        BootleLanternIssuerPublicMatrixV1::from_r512_first_column_blocks_v1(&first_column)
            .expect("canonical degree-512 multiplication matrix");
    let mut policy = BootleLanternIssuerPolicyV1 {
        issuer_id: PrivacyIssuerIdV1::new(nonzero(issuer_byte)),
        policy_id: PrivacyPolicyIdV1::new(nonzero(policy_byte)),
        epoch,
        lifecycle,
        issuer_parameter_id: PrivacyParameterIdV1::new(nonzero(0xB3)),
        issuer_parameter_digest: PrivacyParameterDigestV1::new([0; 32]),
        issuer_public_matrix,
        required_disclosure_bitmap: 0,
        allowed_values: vec![
            BootleLanternAllowedAttributeValuesV1 { values: Vec::new() };
            BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1
        ],
        record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]),
    };
    policy.issuer_parameter_digest = policy
        .computed_issuer_parameter_digest()
        .expect("canonical Bootle/Lantern issuer matrix encoding");
    policy.record_digest = policy
        .computed_record_digest()
        .expect("canonical Bootle/Lantern policy encoding");
    policy
        .validate()
        .expect("canonical Bootle/Lantern issuer policy");
    policy
}
fn validate_persisted_commitments(
    commitments: &Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
) -> Result<(), String> {
    let activations = Storage::<PrivacyActivationKeyV1, PrivacyProtocolActivationRecordV1>::new();
    let pgc_accounts = Storage::<PrivacyPgcAccountKeyV1, PrivacyPgcAccountStateV1>::new();
    let pgc_pool_invariants =
        Storage::<PrivacyPgcPoolInvariantKeyV1, PrivacyPgcPoolInvariantV1>::new();
    let nullifiers = Storage::<PrivacyNullifierKeyV1, PrivacyStateItemRecordV1>::new();
    let roots = Storage::<PrivacyRootKeyV1, PrivacyRootProvenanceV1>::new();
    let root_heads = Storage::<PrivacyRootHeadKeyV1, PrivacyRootHeadRecordV1>::new();
    validate_privacy_persisted_state_v1(
        &PrivacyConsensusPolicyV1::taira_default(),
        &activations.view(),
        PrivacyPgcStateReadV1 {
            accounts: &pgc_accounts.view(),
            pool_invariants: &pgc_pool_invariants.view(),
        },
        &nullifiers.view(),
        &commitments.view(),
        &roots.view(),
        &root_heads.view(),
    )
}
fn pgc_namespace(pool_byte: u8) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: PrivacyPoolIdV1::new(nonzero(pool_byte)),
        }),
    )
}
fn vega_namespace() -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        PrivacyNamespaceScopeV1::Parameter(PrivacyParameterNamespaceV1 {
            parameter_id: PrivacyParameterIdV1::new(nonzero(40)),
        }),
    )
}
fn zk_ams_namespace(registry_byte: u8) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        PrivacyNamespaceScopeV1::IssuerRegistryPolicy(PrivacyIssuerRegistryPolicyNamespaceV1 {
            issuer_id: PrivacyIssuerIdV1::new(nonzero(0x91)),
            registry_id: PrivacyZkAmsRegistryIdV1::new(nonzero(registry_byte)),
            policy_id: PrivacyPolicyIdV1::new(nonzero(0x92)),
        }),
    )
}
fn orchard_namespace(pool_byte: u8) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: PrivacyPoolIdV1::new(nonzero(pool_byte)),
        }),
    )
}
fn fcmp_namespace(pool_byte: u8) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: PrivacyPoolIdV1::new(nonzero(pool_byte)),
        }),
    )
}
fn fcmp_output_tuple(seed: u64) -> PrivacyFcmpOutputTupleV1 {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    let point = |multiple| {
        (ED25519_BASEPOINT_POINT * Scalar::from(multiple))
            .compress()
            .to_bytes()
    };
    PrivacyFcmpOutputTupleV1 {
        output_key: point(seed),
        linking_tag_generator: point(seed.checked_add(1).expect("test scalar")),
        amount_commitment: point(seed.checked_add(2).expect("test scalar")),
    }
}
fn sorted_fcmp_output_tuples(seeds: &[u64]) -> Vec<PrivacyFcmpOutputTupleV1> {
    let mut outputs = seeds
        .iter()
        .copied()
        .map(fcmp_output_tuple)
        .collect::<Vec<_>>();
    outputs.sort_unstable_by_key(|output| output.output_id());
    outputs
}
fn ivm_private_note_namespace(pool_byte: u8, program_byte: u8) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyNamespaceScopeV1::PoolProgram(
            iroha_data_model::privacy::PrivacyPoolProgramNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new(nonzero(pool_byte)),
                program_id: iroha_data_model::privacy::PrivacyProgramIdV1::new(nonzero(
                    program_byte,
                )),
            },
        ),
    )
}
fn pq_masp_namespace(pool_byte: u8) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::PqMaspStarkV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: PrivacyPoolIdV1::new(nonzero(pool_byte)),
        }),
    )
}
fn x509_namespace() -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyNamespaceScopeV1::TrustAnchorPolicy(PrivacyTrustAnchorPolicyNamespaceV1 {
            trust_anchor_id: PrivacyIssuerIdV1::new(nonzero(41)),
            policy_id: PrivacyPolicyIdV1::new(nonzero(42)),
        }),
    )
}
fn x509_ca_namespace() -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyNamespaceScopeV1::TrustAnchor(PrivacyTrustAnchorNamespaceV1 {
            trust_anchor_id: PrivacyIssuerIdV1::new(nonzero(41)),
        }),
    )
}
fn x509_root_key(role: PrivacyRootRoleV1, epoch: u64, root_byte: u8) -> PrivacyRootKeyV1 {
    assert_eq!(role, PrivacyRootRoleV1::CertificateAuthorityMembership);
    let namespace = x509_ca_namespace();
    PrivacyRootKeyV1::new(
        namespace,
        role,
        epoch,
        PrivacyRootV1::new(nonzero(root_byte)),
    )
    .expect("valid root key")
}
fn indexed_nonzero(domain: u8, index: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = domain;
    bytes[1..9].copy_from_slice(&index.to_le_bytes());
    bytes
}
fn x509_trust_anchor_record(
    trust_anchor_id: PrivacyIssuerIdV1,
    epoch: u64,
    trust_store_byte: u8,
    previous_record_digest: Option<PrivacyZkX509TrustAnchorRecordDigestV1>,
    lifecycle: PrivacyZkX509RecordLifecycleV1,
) -> PrivacyZkX509TrustAnchorRecordV1 {
    let ca_membership_root_epoch = match lifecycle {
        PrivacyZkX509RecordLifecycleV1::Active => epoch,
        PrivacyZkX509RecordLifecycleV1::Revoked => epoch.saturating_sub(1),
    };
    PrivacyZkX509TrustAnchorRecordV1::new(
        trust_anchor_id,
        epoch,
        PrivacyX509TrustStoreDigestV1::new(nonzero(trust_store_byte)),
        PrivacyRootV1::new(nonzero(trust_store_byte.wrapping_add(1))),
        ca_membership_root_epoch,
        previous_record_digest,
        lifecycle,
    )
    .expect("canonical X.509 trust-anchor record")
}
fn x509_certificate_policy_record(
    trust_anchor_id: PrivacyIssuerIdV1,
    policy_id: PrivacyPolicyIdV1,
    epoch: u64,
    policy_byte: u8,
    disclosures: Vec<u8>,
    previous_record_digest: Option<PrivacyZkX509CertificatePolicyRecordDigestV1>,
    lifecycle: PrivacyZkX509RecordLifecycleV1,
) -> PrivacyZkX509CertificatePolicyRecordV1 {
    PrivacyZkX509CertificatePolicyRecordV1::new(
        trust_anchor_id,
        policy_id,
        epoch,
        PrivacyPolicyDigestV1::new(nonzero(policy_byte)),
        PrivacyX509KeyUsageV1 {
            digital_signature: true.into(),
            content_commitment: false.into(),
            key_encipherment: false.into(),
            key_agreement: false.into(),
        },
        vec![
            PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
            PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
        ],
        disclosures,
        previous_record_digest,
        lifecycle,
    )
    .expect("canonical X.509 certificate-policy record")
}
fn x509_crl_record(
    trust_anchor_id: PrivacyIssuerIdV1,
    policy_id: PrivacyPolicyIdV1,
    epoch: u64,
    crl_number: u64,
    _root_byte: u8,
    previous_record_digest: Option<PrivacyZkX509CrlRecordDigestV1>,
    lifecycle: PrivacyZkX509RecordLifecycleV1,
) -> PrivacyZkX509CrlRecordV1 {
    PrivacyZkX509CrlRecordV1::new(
        trust_anchor_id,
        policy_id,
        epoch,
        crl_number,
        PrivacyX509CrlDerDigestV1::new(indexed_nonzero(0xC1, epoch)),
        PrivacyX509CrlIssuerSpkiDigestV1::new(nonzero(0xC2)),
        1_749_999_900 + epoch,
        1_750_000_600 + epoch,
        previous_record_digest,
        lifecycle,
    )
    .expect("canonical X.509 signed-CRL record")
}
fn insert_x509_trust_anchor(
    commitments: &mut Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    record: PrivacyZkX509TrustAnchorRecordV1,
    admitted_at_height: u64,
) {
    let key = PrivacyCommitmentKeyV1::zk_x509_trust_anchor_revision(
        record.trust_anchor_id,
        record.record_epoch,
    )
    .expect("trust-anchor revision key");
    let value =
        PrivacyStateItemRecordV1::zk_x509_trust_anchor_governance(record, admitted_at_height)
            .expect("trust-anchor state record");
    commitments.insert(key, value);
}
fn insert_x509_certificate_policy(
    commitments: &mut Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    record: PrivacyZkX509CertificatePolicyRecordV1,
    admitted_at_height: u64,
) {
    let key = PrivacyCommitmentKeyV1::zk_x509_certificate_policy_revision(
        record.trust_anchor_id,
        record.policy_id,
        record.record_epoch,
    )
    .expect("certificate-policy revision key");
    let value =
        PrivacyStateItemRecordV1::zk_x509_certificate_policy_governance(record, admitted_at_height)
            .expect("certificate-policy state record");
    commitments.insert(key, value);
}
fn insert_x509_crl(
    commitments: &mut Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    record: PrivacyZkX509CrlRecordV1,
    admitted_at_height: u64,
) {
    let key = PrivacyCommitmentKeyV1::zk_x509_crl_current(
        record.trust_anchor_id,
        record.certificate_policy_id,
    )
    .expect("current signed-CRL key");
    let value = PrivacyStateItemRecordV1::zk_x509_crl_governance(record, admitted_at_height)
        .expect("signed-CRL state record");
    commitments.insert(key, value);
}
fn x509_root_provenance(
    key: PrivacyRootKeyV1,
    trust_anchor: PrivacyZkX509TrustAnchorRecordV1,
    admitted_at_height: u64,
) -> PrivacyRootProvenanceV1 {
    let publication = PrivacyRootPublicationV1 {
        namespace: key.namespace(),
        role: key.role(),
        epoch: key.epoch(),
        root: key.root(),
    };
    match publication.role {
        PrivacyRootRoleV1::CertificateAuthorityMembership => {
            PrivacyRootProvenanceV1::zk_x509_ca_governance(
                publication.digest().expect("root publication digest"),
                publication.namespace,
                publication.epoch,
                publication.root,
                trust_anchor,
                admitted_at_height,
            )
            .expect("X.509 CA-root provenance")
        }
        _ => panic!("X.509 root fixture requires a closed X.509 role"),
    }
}
fn root_provenance() -> PrivacyRootProvenanceV1 {
    PrivacyRootProvenanceV1::verified_proof(
        PrivacyStatementDigestV1::new(nonzero(50)),
        1,
        0,
        1,
        PrivacyRootV1::new(nonzero(49)),
    )
    .expect("valid root provenance")
}
fn pgc_accounts(count: u8) -> Vec<PrivacyPgcAccountV1> {
    let point = |multiple: u64| {
        let compressed = crate::privacy_engines::p256::CompressedPointV1::from_projective(
            ProjectivePoint::generator() * Scalar::from(multiple),
        )
        .expect("non-zero generator multiple");
        PrivacyP256PointV1::new(*compressed.as_bytes())
    };
    let mut public_keys = (1..=u64::from(count)).map(point).collect::<Vec<_>>();
    public_keys.sort_unstable();
    public_keys
        .into_iter()
        .enumerate()
        .map(|(index, public_key)| {
            let multiple = u64::try_from(index).expect("small fixture index") + 100;
            PrivacyPgcAccountV1 {
                public_key,
                encrypted_balance: PrivacyP256CiphertextV1 {
                    left: point(multiple),
                    right: point(multiple + 100),
                },
            }
        })
        .collect()
}
fn activation_proposal() -> PrivacyProtocolActivationRecordV1 {
    crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
    )
    .expect("compiled VeRange profile")
    .activation_record(PrivacyProtocolLifecycleV1::Proposed(
        PrivacyProposedLifecycleV1 {
            proposed_at_height: 1_000,
        },
    ))
}
struct PgcPersistedFixture {
    activations: Storage<PrivacyActivationKeyV1, PrivacyProtocolActivationRecordV1>,
    pgc_accounts: Storage<PrivacyPgcAccountKeyV1, PrivacyPgcAccountStateV1>,
    pgc_pool_invariants: Storage<PrivacyPgcPoolInvariantKeyV1, PrivacyPgcPoolInvariantV1>,
    nullifiers: Storage<PrivacyNullifierKeyV1, PrivacyStateItemRecordV1>,
    commitments: Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    roots: Storage<PrivacyRootKeyV1, PrivacyRootProvenanceV1>,
    root_heads: Storage<PrivacyRootHeadKeyV1, PrivacyRootHeadRecordV1>,
    namespace: PrivacyNamespaceV1,
    invariant_key: PrivacyPgcPoolInvariantKeyV1,
    account_keys: Vec<PrivacyPgcAccountKeyV1>,
    root_key: PrivacyRootKeyV1,
    head_key: PrivacyRootHeadKeyV1,
    root: PrivacyRootV1,
    bootstrap_digest: PrivacyPgcAccountBootstrapDigestV1,
    bootstrap_proof_digest: PrivacyPgcBootstrapProofDigestV1,
    provenance: PrivacyRootProvenanceV1,
}
impl PgcPersistedFixture {
    fn validate(&self) -> Result<(), String> {
        validate_privacy_persisted_state_v1(
            &PrivacyConsensusPolicyV1::taira_default(),
            &self.activations.view(),
            PrivacyPgcStateReadV1 {
                accounts: &self.pgc_accounts.view(),
                pool_invariants: &self.pgc_pool_invariants.view(),
            },
            &self.nullifiers.view(),
            &self.commitments.view(),
            &self.roots.view(),
            &self.root_heads.view(),
        )
    }
    fn replace_root_and_head(
        &mut self,
        epoch: u64,
        root: PrivacyRootV1,
        provenance: PrivacyRootProvenanceV1,
    ) {
        self.root_key = PrivacyRootKeyV1::new(
            self.namespace,
            PrivacyRootRoleV1::PgcAccountState,
            epoch,
            root,
        )
        .expect("replacement root key");
        self.roots = Storage::new();
        self.roots.insert(self.root_key, provenance.clone());
        self.root_heads = Storage::new();
        self.root_heads.insert(
            self.head_key,
            PrivacyRootHeadRecordV1::new(epoch, root, provenance, None)
                .expect("replacement root head"),
        );
    }
    fn invariant(&self) -> PrivacyPgcPoolInvariantV1 {
        *self
            .pgc_pool_invariants
            .view()
            .get(&self.invariant_key)
            .expect("fixture pool invariant")
    }
    fn account_table(&self) -> Vec<PrivacyPgcAccountV1> {
        self.pgc_accounts
            .view()
            .iter()
            .map(|(key, state)| PrivacyPgcAccountV1 {
                public_key: key.public_key(),
                encrypted_balance: state.encrypted_balance(),
            })
            .collect()
    }
    fn advance_with_retention(&mut self, retained_root_count: u32) {
        let head = self
            .root_heads
            .view()
            .get(&self.head_key)
            .expect("fixture current head").clone();
        let next_epoch = head.epoch().checked_add(1).expect("fixture epoch advance");
        let mut statement_bytes = [0xD0; 32];
        statement_bytes[..8].copy_from_slice(&next_epoch.to_be_bytes());
        let statement_digest = PrivacyStatementDigestV1::new(statement_bytes);
        let account_provenance =
            PrivacyPgcAccountProvenanceV1::verified_proof(statement_digest, next_epoch + 10, 0)
                .expect("successor account provenance");
        let invariant = self.invariant();
        let account_table = self.account_table();
        let next_root = compute_privacy_pgc_account_state_root_v1(
            self.namespace,
            next_epoch,
            invariant.total_supply(),
            &account_table,
        )
        .expect("successor account root");
        let root_provenance = PrivacyRootProvenanceV1::verified_pgc_successor(
            statement_digest,
            next_epoch + 10,
            0,
            head.epoch(),
            head.root(),
            invariant
                .digest(self.namespace)
                .expect("pool invariant digest"),
        )
        .expect("successor root provenance");
        let next_key = PrivacyRootKeyV1::new(
            self.namespace,
            PrivacyRootRoleV1::PgcAccountState,
            next_epoch,
            next_root,
        )
        .expect("successor root key");
        let removals = plan_privacy_root_history_update_v1(
            &self.roots.view(),
            &[next_key],
            retained_root_count,
        )
        .expect("successor history plan");
        let retention_anchor = removals
            .last()
            .map(|key| {
                PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root())
                    .expect("pruned root anchor")
            })
            .or(head.retention_anchor());
        let retained_roots = self
            .roots
            .view()
            .iter()
            .filter(|(key, _)| !removals.contains(key))
            .map(|(key, provenance)| (*key, provenance.clone()))
            .collect::<Vec<_>>();
        self.roots = retained_roots.into_iter().collect();
        for key in &self.account_keys {
            let encrypted_balance = self
                .pgc_accounts
                .view()
                .get(key)
                .expect("fixture account")
                .encrypted_balance();
            self.pgc_accounts.insert(
                *key,
                PrivacyPgcAccountStateV1::new(encrypted_balance, next_epoch, account_provenance)
                    .expect("successor account state"),
            );
        }
        self.roots.insert(next_key, root_provenance.clone());
        self.root_heads.insert(
            self.head_key,
            PrivacyRootHeadRecordV1::new(next_epoch, next_root, root_provenance.clone(), retention_anchor)
                .expect("successor head"),
        );
        self.root_key = next_key;
        self.root = next_root;
        self.provenance = root_provenance;
    }
    fn tighten_retention(&mut self, retained_root_count: u32) {
        let head = self
            .root_heads
            .view()
            .get(&self.head_key)
            .expect("fixture current head").clone();
        let plans = plan_privacy_root_retention_reduction_v1(
            &self.roots.view(),
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            retained_root_count,
        )
        .expect("retention reduction plan");
        if plans.is_empty() {
            return;
        }
        assert_eq!(plans.len(), 1);
        let plan = &plans[0];
        assert_eq!(plan.head_key, self.head_key);
        let retained_roots = self
            .roots
            .view()
            .iter()
            .filter(|(key, _)| !plan.removal_keys.contains(key))
            .map(|(key, provenance)| (*key, provenance.clone()))
            .collect::<Vec<_>>();
        self.roots = retained_roots.into_iter().collect();
        self.root_heads.insert(
            self.head_key,
            PrivacyRootHeadRecordV1::new(
                head.epoch(),
                head.root(),
                head.provenance().clone(),
                Some(plan.new_anchor),
            )
            .expect("retention-tightened head"),
        );
    }
    fn load_with_retention(
        &self,
        retained_root_count: u32,
    ) -> Result<PrivacyPgcPoolSnapshotV1, String> {
        load_privacy_pgc_pool_snapshot_v1(
            self.namespace,
            retained_root_count,
            &self.pgc_accounts.view(),
            &self.pgc_pool_invariants.view(),
            &self.roots.view(),
            &self.root_heads.view(),
        )
    }
}
fn pgc_persisted_fixture() -> PgcPersistedFixture {
    let namespace = pgc_namespace(20);
    let bootstrap_digest = PrivacyPgcAccountBootstrapDigestV1::new(nonzero(0xB1));
    let bootstrap_proof_digest = PrivacyPgcBootstrapProofDigestV1::new(nonzero(0xB2));
    let total_supply = 160;
    let epoch = PRIVACY_PGC_BOOTSTRAP_INITIAL_EPOCH_V1;
    let account_table = pgc_accounts(16);
    let root =
        compute_privacy_pgc_account_state_root_v1(namespace, epoch, total_supply, &account_table)
            .expect("canonical fixture root");
    let account_provenance =
        PrivacyPgcAccountProvenanceV1::bootstrap(bootstrap_digest, bootstrap_proof_digest, 9)
            .expect("bootstrap account provenance");
    let provenance =
        PrivacyRootProvenanceV1::verified_bootstrap(bootstrap_digest, bootstrap_proof_digest, 9)
            .expect("bootstrap root provenance");
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
    )
    .expect("compiled Anonymous PGC profile");
    let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height: 1,
            activated_at_height: 2,
            state_since_height: 2,
        },
    ));
    let mut activations = Storage::new();
    activations.insert(
        PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1),
        activation,
    );
    let mut pgc_accounts = Storage::new();
    let mut account_keys = Vec::with_capacity(account_table.len());
    for account in account_table {
        let key = PrivacyPgcAccountKeyV1::new(namespace, account.public_key).expect("account key");
        pgc_accounts.insert(
            key,
            PrivacyPgcAccountStateV1::new(account.encrypted_balance, epoch, account_provenance)
                .expect("account state"),
        );
        account_keys.push(key);
    }
    let invariant_key = PrivacyPgcPoolInvariantKeyV1::new(namespace).expect("pool invariant key");
    let mut pgc_pool_invariants = Storage::new();
    pgc_pool_invariants.insert(
        invariant_key,
        PrivacyPgcPoolInvariantV1::new(
            total_supply,
            root,
            bootstrap_digest,
            bootstrap_proof_digest,
        )
        .expect("pool invariant"),
    );
    let root_key =
        PrivacyRootKeyV1::new(namespace, PrivacyRootRoleV1::PgcAccountState, epoch, root)
            .expect("root key");
    let head_key =
        PrivacyRootHeadKeyV1::new(namespace, PrivacyRootRoleV1::PgcAccountState).expect("head key");
    let mut roots = Storage::new();
    roots.insert(root_key, provenance.clone());
    let mut root_heads = Storage::new();
    root_heads.insert(
        head_key,
        PrivacyRootHeadRecordV1::new(epoch, root, provenance.clone(), None).expect("root head"),
    );
    PgcPersistedFixture {
        activations,
        pgc_accounts,
        pgc_pool_invariants,
        nullifiers: Storage::new(),
        commitments: Storage::new(),
        roots,
        root_heads,
        namespace,
        invariant_key,
        account_keys,
        root_key,
        head_key,
        root,
        bootstrap_digest,
        bootstrap_proof_digest,
        provenance,
    }
}
fn expect_pgc_persisted_error(mutate: impl FnOnce(&mut PgcPersistedFixture), expected: &str) {
    let mut fixture = pgc_persisted_fixture();
    mutate(&mut fixture);
    let error = fixture
        .validate()
        .expect_err("adversarial persisted state must reject");
    assert!(
        error.contains(expected),
        "expected `{expected}` in persisted-state rejection, got `{error}`"
    );
}
struct OrchardPersistedFixture {
    activations: Storage<PrivacyActivationKeyV1, PrivacyProtocolActivationRecordV1>,
    pgc_accounts: Storage<PrivacyPgcAccountKeyV1, PrivacyPgcAccountStateV1>,
    pgc_pool_invariants: Storage<PrivacyPgcPoolInvariantKeyV1, PrivacyPgcPoolInvariantV1>,
    nullifiers: Storage<PrivacyNullifierKeyV1, PrivacyStateItemRecordV1>,
    commitments: Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    roots: Storage<PrivacyRootKeyV1, PrivacyRootProvenanceV1>,
    root_heads: Storage<PrivacyRootHeadKeyV1, PrivacyRootHeadRecordV1>,
    namespace: PrivacyNamespaceV1,
    bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1,
    state_key: PrivacyCommitmentKeyV1,
    head_key: PrivacyRootHeadKeyV1,
}
impl OrchardPersistedFixture {
    fn validate(&self) -> Result<(), String> {
        validate_privacy_persisted_state_v1(
            &PrivacyConsensusPolicyV1::taira_default(),
            &self.activations.view(),
            PrivacyPgcStateReadV1 {
                accounts: &self.pgc_accounts.view(),
                pool_invariants: &self.pgc_pool_invariants.view(),
            },
            &self.nullifiers.view(),
            &self.commitments.view(),
            &self.roots.view(),
            &self.root_heads.view(),
        )
    }
    fn load_with_retention(
        &self,
        retained_root_count: u32,
    ) -> Result<PrivacyOrchardPoolSnapshotV1, String> {
        load_privacy_orchard_pool_snapshot_v1(
            self.namespace,
            retained_root_count,
            &self.commitments.view(),
            &self.roots.view(),
            &self.root_heads.view(),
        )
    }
    fn state(&self) -> PrivacyOrchardPoolStateV1 {
        self.commitments
            .view()
            .get(&self.state_key)
            .and_then(PrivacyStateItemRecordV1::orchard_pool_state_ref)
            .expect("fixture Orchard pool state")
            .clone()
    }
    fn set_state(&mut self, state: PrivacyOrchardPoolStateV1) {
        self.commitments.insert(
            self.state_key,
            PrivacyStateItemRecordV1::orchard_pool_state(state)
                .expect("canonical Orchard pool state record"),
        );
    }
    fn advance_with_retention(&mut self, retained_root_count: u32, note_commitments: &[[u8; 32]]) {
        let snapshot = self
            .load_with_retention(retained_root_count)
            .expect("coherent Orchard predecessor");
        let successor = snapshot
            .derive_successor(note_commitments)
            .expect("canonical Orchard commitments");
        let next_epoch = successor.epoch();
        let mut statement_bytes = [0xC0; 32];
        statement_bytes[..8].copy_from_slice(&next_epoch.to_be_bytes());
        let statement_digest = PrivacyStatementDigestV1::new(statement_bytes);
        let root_provenance = PrivacyRootProvenanceV1::orchard_pool_successor(
            self.bootstrap_digest,
            statement_digest,
            next_epoch + 10,
            0,
            snapshot.current_epoch(),
            snapshot.current_root(),
        )
        .expect("successor root provenance");
        let next_key = PrivacyRootKeyV1::new(
            self.namespace,
            PrivacyRootRoleV1::NoteCommitmentAnchor,
            next_epoch,
            successor.root(),
        )
        .expect("successor root key");
        let removals = plan_privacy_root_history_update_v1(
            &self.roots.view(),
            &[next_key],
            retained_root_count,
        )
        .expect("successor history plan");
        let predecessor_anchor = self
            .root_heads
            .view()
            .get(&self.head_key)
            .expect("fixture predecessor head").retention_anchor();
        let retention_anchor = removals
            .last()
            .map(|key| {
                PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root())
                    .expect("pruned Orchard root anchor")
            })
            .or(predecessor_anchor);
        let retained = self
            .roots
            .view()
            .iter()
            .filter(|(key, _)| !removals.contains(key))
            .map(|(key, provenance)| (*key, provenance.clone()))
            .collect::<Vec<_>>();
        self.roots = retained.into_iter().collect();
        self.roots.insert(next_key, root_provenance.clone());
        self.root_heads.insert(
            self.head_key,
            PrivacyRootHeadRecordV1::new(
                next_epoch,
                successor.root(),
                root_provenance,
                retention_anchor,
            )
            .expect("successor root head"),
        );
        self.set_state(successor);
    }
}
fn orchard_persisted_fixture() -> OrchardPersistedFixture {
    let namespace = orchard_namespace(0xA7);
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("privacy", "universal").expect("domain"),
        Name::from_str("orchard_asset").expect("asset name"),
    );
    let reserve_account = account(0xA9);
    let PrivacyNamespaceScopeV1::Pool(pool) = namespace.scope() else {
        unreachable!("Orchard fixture uses a pool namespace")
    };
    let bootstrap = PrivacyOrchardPoolBootstrapV1::new(
        pool.pool_id,
        asset_definition_id,
        AssetBalanceScope::Global,
        reserve_account,
    )
    .expect("canonical Orchard bootstrap");
    let bootstrap_digest = bootstrap.digest().expect("Orchard bootstrap digest");
    let state =
        PrivacyOrchardPoolStateV1::bootstrap(bootstrap).expect("canonical Orchard empty state");
    let root = state.root();
    let provenance = PrivacyRootProvenanceV1::orchard_pool_bootstrap(bootstrap_digest, 9)
        .expect("Orchard bootstrap provenance");
    let root_key = PrivacyRootKeyV1::new(
        namespace,
        PrivacyRootRoleV1::NoteCommitmentAnchor,
        PRIVACY_ORCHARD_POOL_INITIAL_EPOCH_V1,
        root,
    )
    .expect("Orchard bootstrap root key");
    let head_key = PrivacyRootHeadKeyV1::new(namespace, PrivacyRootRoleV1::NoteCommitmentAnchor)
        .expect("Orchard head key");
    let state_key =
        PrivacyCommitmentKeyV1::orchard_pool_state(namespace).expect("Orchard state key");
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
    )
    .expect("compiled Orchard profile");
    let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height: 1,
            activated_at_height: 2,
            state_since_height: 2,
        },
    ));
    let mut activations = Storage::new();
    activations.insert(
        PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::OrchardHalo2ActionsV1),
        activation,
    );
    let mut commitments = Storage::new();
    let reserve_asset = AssetId::with_scope(
        state.asset_definition_id().clone(),
        state.reserve_account().clone(),
        state.public_balance_scope(),
    );
    let reserve_owner = PrivacyPublicReserveOwnerV1::Orchard {
        namespace,
        bootstrap_digest,
    };
    commitments.insert(
        PrivacyCommitmentKeyV1::public_reserve_custody(reserve_owner.protocol_id(), &reserve_asset)
            .expect("Orchard reserve key"),
        PrivacyStateItemRecordV1::public_reserve_custody(reserve_asset, reserve_owner)
            .expect("Orchard reserve custody"),
    );
    commitments.insert(
        state_key,
        PrivacyStateItemRecordV1::orchard_pool_state(state).expect("Orchard state record"),
    );
    let mut roots = Storage::new();
    roots.insert(root_key, provenance.clone());
    let mut root_heads = Storage::new();
    root_heads.insert(
        head_key,
        PrivacyRootHeadRecordV1::new(
            PRIVACY_ORCHARD_POOL_INITIAL_EPOCH_V1,
            root,
            provenance,
            None,
        )
        .expect("Orchard bootstrap head"),
    );
    OrchardPersistedFixture {
        activations,
        pgc_accounts: Storage::new(),
        pgc_pool_invariants: Storage::new(),
        nullifiers: Storage::new(),
        commitments,
        roots,
        root_heads,
        namespace,
        bootstrap_digest,
        state_key,
        head_key,
    }
}
fn expect_orchard_persisted_error(
    mutate: impl FnOnce(&mut OrchardPersistedFixture),
    expected: &str,
) {
    let mut fixture = orchard_persisted_fixture();
    mutate(&mut fixture);
    let error = fixture
        .validate()
        .expect_err("adversarial Orchard state must reject");
    assert!(
        error.contains(expected),
        "expected `{expected}` in Orchard persisted-state rejection, got `{error}`"
    );
}
struct ProofManagedPersistedFixture {
    commitments: Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    roots: Storage<PrivacyRootKeyV1, PrivacyRootProvenanceV1>,
    root_heads: Storage<PrivacyRootHeadKeyV1, PrivacyRootHeadRecordV1>,
    bootstrap: PrivacyProofManagedPoolBootstrapV1,
    bootstrap_digest: PrivacyProofManagedPoolBootstrapDigestV1,
    namespace: PrivacyNamespaceV1,
    config_key: PrivacyCommitmentKeyV1,
    head_key: PrivacyRootHeadKeyV1,
    initial_root: PrivacyRootV1,
}
impl ProofManagedPersistedFixture {
    fn load(&self) -> Result<PrivacyProofManagedPoolSnapshotV1, String> {
        load_privacy_proof_managed_pool_snapshot_v1(
            self.namespace,
            PrivacyConsensusPolicyV1::taira_default().admission_retained_root_count(),
            &self.commitments.view(),
            &self.roots.view(),
            &self.root_heads.view(),
        )
    }
    fn remove_commitment(&mut self, key: PrivacyCommitmentKeyV1) {
        self.commitments = self
            .commitments
            .view()
            .iter()
            .filter(|(candidate, _)| **candidate != key)
            .map(|(candidate, record)| (*candidate, record.clone()))
            .collect();
    }
    fn advance(&mut self, outputs: &[PrivacyCommitmentV1]) {
        let snapshot = self.load().expect("coherent proof-managed predecessor");
        let successor = snapshot
            .derive_note_successor(outputs)
            .expect("canonical proof-managed append");
        let mut statement_bytes = [0xD0; 32];
        statement_bytes[..8].copy_from_slice(&successor.epoch().to_be_bytes());
        let statement_digest = PrivacyStatementDigestV1::new(statement_bytes);
        let output_count = u32::try_from(outputs.len()).expect("output count");
        for (output_index, commitment) in outputs.iter().enumerate() {
            let key =
                PrivacyCommitmentKeyV1::proof_managed_pool_commitment(self.namespace, *commitment)
                    .expect("output key");
            let output_index = u32::try_from(output_index).expect("output index");
            let append_position = snapshot
                .output_count()
                .checked_add(u64::from(output_index))
                .expect("append position");
            let item = PrivacyStateItemRecordV1::proof_managed_pool_verified_commitment(
                self.bootstrap_digest,
                statement_digest,
                successor.epoch(),
                output_index,
                append_position,
                1,
                output_count,
                10 + successor.epoch(),
                0,
            )
            .expect("verified commitment");
            self.commitments.insert(key, item);
        }
        self.commitments.insert(
            self.config_key,
            PrivacyStateItemRecordV1::proof_managed_pool_state(
                self.bootstrap.clone(),
                self.bootstrap_digest,
                self.initial_root,
                PrivacyProofManagedPoolAccumulatorStateV1::PrivateNote(successor.clone()),
                7,
            )
            .expect("successor config"),
        );
        let provenance = PrivacyRootProvenanceV1::proof_managed_pool_successor(
            self.bootstrap_digest,
            self.namespace.protocol_id(),
            statement_digest,
            1,
            output_count,
            10 + successor.epoch(),
            0,
            snapshot.current_epoch(),
            snapshot.current_root(),
        )
        .expect("successor provenance");
        let root_key = PrivacyRootKeyV1::new(
            self.namespace,
            self.bootstrap.root_role(),
            successor.epoch(),
            successor.root(),
        )
        .expect("successor root key");
        self.roots.insert(root_key, provenance.clone());
        self.root_heads.insert(
            self.head_key,
            PrivacyRootHeadRecordV1::new(successor.epoch(), successor.root(), provenance, None)
                .expect("successor head"),
        );
    }
}
fn proof_managed_note_persisted_fixture(
    protocol_id: PrivacyProtocolIdV1,
) -> ProofManagedPersistedFixture {
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("privacy", "universal").expect("domain"),
        Name::from_str("private_note_state").expect("asset name"),
    );
    let initial_note_commitments = vec![
        PrivacyCommitmentV1::new(nonzero(0xB4)),
        PrivacyCommitmentV1::new(nonzero(0xB5)),
    ];
    let bootstrap = match protocol_id {
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 => {
            PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
                iroha_data_model::privacy::PrivacyIvmPrivateNotePoolBootstrapV1 {
                    pool_id: PrivacyPoolIdV1::new(nonzero(0xB1)),
                    asset_definition_id,
                    public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
                    reserve_account: account(0xB2),
                    program_id: iroha_data_model::privacy::PrivacyProgramIdV1::new(nonzero(0xB3)),
                    initial_note_commitments,
                },
            )
        }
        PrivacyProtocolIdV1::PqMaspStarkV1 => PrivacyProofManagedPoolBootstrapV1::PqMaspStarkV1(
            iroha_data_model::privacy::PrivacyPqMaspPoolBootstrapV1 {
                pool_id: PrivacyPoolIdV1::new(nonzero(0xB1)),
                asset_definition_id,
                initial_note_commitments,
            },
        ),
        _ => panic!("note fixture accepts only private-IVM or PQ-MASP"),
    };
    let namespace = bootstrap.namespace();
    let bootstrap_digest = bootstrap.digest().expect("bootstrap digest");
    let initial_root = crate::privacy_engines::proof_managed_pool_initial_root_v1(&bootstrap)
        .expect("native initial root");
    let config_key =
        PrivacyCommitmentKeyV1::proof_managed_pool_config(namespace).expect("config key");
    let mut commitments = Storage::new();
    commitments.insert(
        config_key,
        PrivacyStateItemRecordV1::proof_managed_pool_bootstrap(
            bootstrap.clone(),
            bootstrap_digest,
            initial_root,
            7,
        )
        .expect("bootstrap config"),
    );
    if let PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(config) = &bootstrap {
        let reserve_asset = AssetId::with_scope(
            config.asset_definition_id.clone(),
            config.reserve_account.clone(),
            config.public_balance_scope,
        );
        let reserve_owner = PrivacyPublicReserveOwnerV1::PrivateIvm {
            namespace,
            bootstrap_digest,
        };
        commitments.insert(
            PrivacyCommitmentKeyV1::public_reserve_custody(
                reserve_owner.protocol_id(),
                &reserve_asset,
            )
            .expect("private-IVM reserve key"),
            PrivacyStateItemRecordV1::public_reserve_custody(reserve_asset, reserve_owner)
                .expect("private-IVM reserve custody"),
        );
    }
    for (position, commitment) in bootstrap
        .initial_note_commitments()
        .expect("private-note bootstrap commitments")
        .iter()
        .enumerate()
    {
        let genesis_item = PrivacyStateItemRecordV1::proof_managed_pool_bootstrap_commitment(
            bootstrap_digest,
            u64::try_from(position).expect("genesis position"),
            7,
        )
        .expect("genesis item");
        commitments.insert(
            PrivacyCommitmentKeyV1::proof_managed_pool_commitment(namespace, *commitment)
                .expect("genesis key"),
            genesis_item,
        );
    }
    let provenance = PrivacyRootProvenanceV1::proof_managed_pool_bootstrap(
        bootstrap_digest,
        namespace.protocol_id(),
        7,
    )
    .expect("bootstrap provenance");
    let root_key = PrivacyRootKeyV1::new(namespace, bootstrap.root_role(), 1, initial_root)
        .expect("bootstrap root key");
    let head_key = PrivacyRootHeadKeyV1::new(namespace, bootstrap.root_role()).expect("head key");
    let mut roots = Storage::new();
    roots.insert(root_key, provenance.clone());
    let mut root_heads = Storage::new();
    root_heads.insert(
        head_key,
        PrivacyRootHeadRecordV1::new(1, initial_root, provenance, None).expect("bootstrap head"),
    );
    ProofManagedPersistedFixture {
        commitments,
        roots,
        root_heads,
        bootstrap,
        bootstrap_digest,
        namespace,
        config_key,
        head_key,
        initial_root,
    }
}
fn proof_managed_persisted_fixture() -> ProofManagedPersistedFixture {
    proof_managed_note_persisted_fixture(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)
}
fn pq_masp_persisted_fixture() -> ProofManagedPersistedFixture {
    proof_managed_note_persisted_fixture(PrivacyProtocolIdV1::PqMaspStarkV1)
}
struct FcmpPersistedFixture {
    commitments: Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    roots: Storage<PrivacyRootKeyV1, PrivacyRootProvenanceV1>,
    root_heads: Storage<PrivacyRootHeadKeyV1, PrivacyRootHeadRecordV1>,
    bootstrap: PrivacyProofManagedPoolBootstrapV1,
    bootstrap_digest: PrivacyProofManagedPoolBootstrapDigestV1,
    namespace: PrivacyNamespaceV1,
    config_key: PrivacyCommitmentKeyV1,
    head_key: PrivacyRootHeadKeyV1,
    initial_root: PrivacyRootV1,
}
impl FcmpPersistedFixture {
    fn load(&self) -> Result<PrivacyProofManagedPoolSnapshotV1, String> {
        load_privacy_proof_managed_pool_snapshot_v1(
            self.namespace,
            PrivacyConsensusPolicyV1::taira_default().admission_retained_root_count(),
            &self.commitments.view(),
            &self.roots.view(),
            &self.root_heads.view(),
        )
    }
    fn remove_output(&mut self, output: PrivacyFcmpOutputTupleV1) {
        let key = PrivacyCommitmentKeyV1::fcmp_output(self.namespace, output.output_id())
            .expect("typed FCMP++ output key");
        self.commitments = self
            .commitments
            .view()
            .iter()
            .filter(|(candidate, _)| **candidate != key)
            .map(|(candidate, record)| (*candidate, record.clone()))
            .collect();
    }
    fn advance(&mut self, outputs: &[PrivacyFcmpOutputTupleV1]) {
        let snapshot = self.load().expect("coherent FCMP++ predecessor");
        let successor = snapshot
            .derive_fcmp_successor(outputs)
            .expect("canonical FCMP++ append");
        let mut statement_bytes = [0xE0; 32];
        statement_bytes[..8].copy_from_slice(&successor.epoch().to_be_bytes());
        let statement_digest = PrivacyStatementDigestV1::new(statement_bytes);
        let output_count = u32::try_from(outputs.len()).expect("output count");
        for (output_index, output) in outputs.iter().copied().enumerate() {
            let key = PrivacyCommitmentKeyV1::fcmp_output(self.namespace, output.output_id())
                .expect("typed output key");
            let output_index = u32::try_from(output_index).expect("output index");
            let append_position = snapshot
                .output_count()
                .checked_add(u64::from(output_index))
                .expect("append position");
            let record = PrivacyStateItemRecordV1::fcmp_verified_output(
                self.bootstrap_digest,
                output,
                statement_digest,
                successor.epoch(),
                output_index,
                append_position,
                1,
                output_count,
                20 + successor.epoch(),
                0,
            )
            .expect("verified FCMP++ output");
            self.commitments.insert(key, record);
        }
        self.commitments.insert(
            self.config_key,
            PrivacyStateItemRecordV1::proof_managed_pool_state(
                self.bootstrap.clone(),
                self.bootstrap_digest,
                self.initial_root,
                PrivacyProofManagedPoolAccumulatorStateV1::Fcmp(successor.clone()),
                7,
            )
            .expect("FCMP++ successor config"),
        );
        let provenance = PrivacyRootProvenanceV1::proof_managed_pool_successor(
            self.bootstrap_digest,
            self.namespace.protocol_id(),
            statement_digest,
            1,
            output_count,
            20 + successor.epoch(),
            0,
            snapshot.current_epoch(),
            snapshot.current_root(),
        )
        .expect("FCMP++ successor provenance");
        let root = successor.root().history_commitment();
        let root_key = PrivacyRootKeyV1::new(
            self.namespace,
            PrivacyRootRoleV1::OutputSet,
            successor.epoch(),
            root,
        )
        .expect("FCMP++ successor root key");
        self.roots.insert(root_key, provenance.clone());
        self.root_heads.insert(
            self.head_key,
            PrivacyRootHeadRecordV1::new(successor.epoch(), root, provenance, None)
                .expect("FCMP++ successor head"),
        );
    }
}
fn fcmp_persisted_fixture() -> FcmpPersistedFixture {
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("privacy", "universal").expect("domain"),
        Name::from_str("fcmp_state").expect("asset name"),
    );
    let bootstrap = PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(
        iroha_data_model::privacy::PrivacyFcmpPoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(nonzero(0xD1)),
            asset_definition_id,
            initial_outputs: sorted_fcmp_output_tuples(&[11, 21]),
        },
    );
    bootstrap.validate().expect("canonical FCMP++ bootstrap");
    let namespace = bootstrap.namespace();
    let bootstrap_digest = bootstrap.digest().expect("FCMP++ bootstrap digest");
    let initial_root = crate::privacy_engines::proof_managed_pool_initial_root_v1(&bootstrap)
        .expect("native FCMP++ initial root");
    let config_key =
        PrivacyCommitmentKeyV1::proof_managed_pool_config(namespace).expect("config key");
    let mut commitments = Storage::new();
    commitments.insert(
        config_key,
        PrivacyStateItemRecordV1::proof_managed_pool_bootstrap(
            bootstrap.clone(),
            bootstrap_digest,
            initial_root,
            7,
        )
        .expect("FCMP++ bootstrap config"),
    );
    for (position, output) in bootstrap
        .initial_fcmp_outputs()
        .expect("FCMP++ genesis outputs")
        .iter()
        .copied()
        .enumerate()
    {
        let record = PrivacyStateItemRecordV1::fcmp_bootstrap_output(
            bootstrap_digest,
            output,
            u64::try_from(position).expect("genesis position"),
            7,
        )
        .expect("FCMP++ genesis provenance");
        commitments.insert(
            PrivacyCommitmentKeyV1::fcmp_output(namespace, output.output_id())
                .expect("FCMP++ genesis key"),
            record,
        );
    }
    let provenance = PrivacyRootProvenanceV1::proof_managed_pool_bootstrap(
        bootstrap_digest,
        namespace.protocol_id(),
        7,
    )
    .expect("FCMP++ bootstrap provenance");
    let root_key = PrivacyRootKeyV1::new(namespace, PrivacyRootRoleV1::OutputSet, 1, initial_root)
        .expect("FCMP++ bootstrap root key");
    let head_key = PrivacyRootHeadKeyV1::new(namespace, PrivacyRootRoleV1::OutputSet)
        .expect("FCMP++ head key");
    let mut roots = Storage::new();
    roots.insert(root_key, provenance.clone());
    let mut root_heads = Storage::new();
    root_heads.insert(
        head_key,
        PrivacyRootHeadRecordV1::new(1, initial_root, provenance, None)
            .expect("FCMP++ bootstrap head"),
    );
    FcmpPersistedFixture {
        commitments,
        roots,
        root_heads,
        bootstrap,
        bootstrap_digest,
        namespace,
        config_key,
        head_key,
        initial_root,
    }
}
fn validate_proof_managed_fixture_maps(
    protocol_id: PrivacyProtocolIdV1,
    nullifiers: &Storage<PrivacyNullifierKeyV1, PrivacyStateItemRecordV1>,
    commitments: &Storage<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
    roots: &Storage<PrivacyRootKeyV1, PrivacyRootProvenanceV1>,
    root_heads: &Storage<PrivacyRootHeadKeyV1, PrivacyRootHeadRecordV1>,
) -> Result<(), String> {
    let activation = crate::privacy_profiles::compiled_privacy_profile_v1(protocol_id)
        .expect("compiled proof-managed profile")
        .activation_record(PrivacyProtocolLifecycleV1::Active(
            PrivacyActiveLifecycleV1 {
                proposed_at_height: 1,
                activated_at_height: 2,
                state_since_height: 2,
            },
        ));
    let mut activations = Storage::new();
    activations.insert(PrivacyActivationKeyV1::new(protocol_id), activation);
    validate_privacy_persisted_state_v1(
        &PrivacyConsensusPolicyV1::taira_default(),
        &activations.view(),
        PrivacyPgcStateReadV1 {
            accounts: &Storage::<PrivacyPgcAccountKeyV1, PrivacyPgcAccountStateV1>::new().view(),
            pool_invariants: &Storage::<PrivacyPgcPoolInvariantKeyV1, PrivacyPgcPoolInvariantV1>::new().view(),
        },
        &nullifiers.view(),
        &commitments.view(),
        &roots.view(),
        &root_heads.view(),
    )
}
