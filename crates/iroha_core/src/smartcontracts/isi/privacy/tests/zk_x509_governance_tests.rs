//! X.509 governance lifecycle and atomic root-state regression coverage.

use super::*;

struct X509GovernanceRecords {
    anchor_origin: PrivacyZkX509TrustAnchorRecordV1,
    policy_origin: PrivacyZkX509CertificatePolicyRecordV1,
    crl_origin: PrivacyZkX509CrlRecordV1,
    anchor_rotation: PrivacyZkX509TrustAnchorRecordV1,
    policy_rotation: PrivacyZkX509CertificatePolicyRecordV1,
    crl_rotation: PrivacyZkX509CrlRecordV1,
    anchor_revoked: PrivacyZkX509TrustAnchorRecordV1,
    policy_revoked: PrivacyZkX509CertificatePolicyRecordV1,
    crl_revoked: PrivacyZkX509CrlRecordV1,
}

impl X509GovernanceRecords {
    fn new() -> Self {
        let anchor_origin =
            x509_trust_anchor(1, 0xD1, None, PrivacyZkX509RecordLifecycleV1::Active);
        let policy_origin = x509_policy(
            1,
            0xD2,
            vec![0, 3],
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        );
        let crl_origin = x509_crl(
            1,
            1,
            0xE2,
            1_799_999_900,
            1_800_000_300,
            0xD4,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        );
        let anchor_rotation = x509_trust_anchor(
            2,
            0xD5,
            Some(anchor_origin.record_digest),
            PrivacyZkX509RecordLifecycleV1::Active,
        );
        let policy_rotation = x509_policy(
            2,
            0xD6,
            vec![0, 2, 3],
            Some(policy_origin.record_digest),
            PrivacyZkX509RecordLifecycleV1::Active,
        );
        let crl_rotation = x509_crl(
            2,
            2,
            0xE3,
            1_799_999_950,
            1_800_000_300,
            0xD8,
            Some(crl_origin.record_digest),
            PrivacyZkX509RecordLifecycleV1::Active,
        );
        let anchor_revoked = x509_trust_anchor(
            3,
            0xD5,
            Some(anchor_rotation.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        );
        let policy_revoked = x509_policy(
            3,
            0xD6,
            vec![0, 2, 3],
            Some(policy_rotation.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        );
        let crl_revoked = x509_crl(
            3,
            2,
            0xE3,
            1_799_999_950,
            1_800_000_300,
            0xD8,
            Some(crl_rotation.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        );
        Self {
            anchor_origin,
            policy_origin,
            crl_origin,
            anchor_rotation,
            policy_rotation,
            crl_rotation,
            anchor_revoked,
            policy_revoked,
            crl_revoked,
        }
    }

    // Each lifecycle stage owns one block. Separate calls bound the live stack
    // frame: putting every block/transaction overlay in one test function also
    // reserves all of their debug-build stack slots during state construction.
    #[inline(never)]
    fn register_anchor_and_policy(&self, state: &State, height: u64) {
        let mut block = state.block(test_header_at(height));
        let anchor_origin = self.anchor_origin;
        let policy_origin = self.policy_origin.clone();
        {
            let mut transaction = block.transaction();
            let error = RegisterPrivacyZkX509TrustAnchorV1::new(anchor_origin)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("X.509 governance permission is mandatory");
            assert!(error.to_string().contains("CanEnactGovernance"), "{error}");
            assert_eq!(transaction.world.privacy_commitments.iter().count(), 0);
            assert_empty_and_unbudgeted(&transaction);
        }
        {
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            RegisterPrivacyZkX509TrustAnchorV1::new(anchor_origin)
                .execute(&ALICE_ID, &mut transaction)
                .expect("trust-anchor and CA root register atomically before activation");
            assert_eq!(transaction.world.privacy_roots.iter().count(), 1);
            assert_eq!(transaction.world.privacy_root_heads.iter().count(), 1);
            let ca_head = transaction
                .world
                .privacy_root_heads
                .get(
                    &PrivacyRootHeadKeyV1::new(
                        x509_ca_namespace(),
                        PrivacyRootRoleV1::CertificateAuthorityMembership,
                    )
                    .expect("CA root-head key"),
                )
                .expect("atomic CA root head");
            assert_eq!(ca_head.epoch(), 1);
            assert_eq!(ca_head.root(), anchor_origin.ca_membership_root);
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            RegisterPrivacyZkX509CertificatePolicyV1::new(policy_origin.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect("certificate-policy registration does not require premature activation");
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            transaction.apply();
        }
        block
            .commit_world_overlay_for_testing()
            .expect("commit X.509 anchor and policy block");
    }

    #[inline(never)]
    fn register_crl_and_rotate_anchor(&self, state: &State, height: u64) {
        let mut block = state.block(test_header_at(height));
        let anchor_origin = self.anchor_origin;
        let policy_origin = self.policy_origin.clone();
        let crl_origin = self.crl_origin;
        let anchor_rotation = self.anchor_rotation;
        {
            let mut transaction = block.transaction();
            RegisterPrivacyZkX509CrlV1::new(crl_origin)
                .execute(&ALICE_ID, &mut transaction)
                .expect("signed CRL record registers without a secondary revocation root");
            assert_eq!(
                privacy_zk_x509_governance_record_counts_v1(&transaction.world.privacy_commitments)
                    .expect("canonical X.509 origins"),
                (1, 1)
            );
            assert_eq!(transaction.world.privacy_commitments.iter().count(), 3);
            assert_eq!(transaction.world.privacy_roots.iter().count(), 1);
            assert_eq!(transaction.world.privacy_root_heads.iter().count(), 1);
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            let snapshot = load_privacy_zk_x509_authoritative_state_v1(
                x509_trust_anchor_id(),
                x509_policy_id(),
                8,
                &transaction.world.privacy_commitments,
                &transaction.world.privacy_roots,
                &transaction.world.privacy_root_heads,
            )
            .expect("complete typed origin authoritative state");
            assert_eq!(snapshot.trust_anchor(), anchor_origin);
            assert_eq!(snapshot.certificate_policy(), &policy_origin);
            assert_eq!(snapshot.crl_record(), crl_origin);
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let count_before = transaction.world.privacy_commitments.iter().count();
            let roots_before = transaction.world.privacy_roots.iter().count();
            let heads_before = transaction.world.privacy_root_heads.iter().count();
            let error = RegisterPrivacyZkX509TrustAnchorV1::new(anchor_origin)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("duplicate trust-anchor origin");
            assert!(
                smart_contract_parameter_message(&error).contains("already registered"),
                "{error:?}"
            );
            assert_eq!(
                transaction.world.privacy_commitments.iter().count(),
                count_before
            );
            assert_eq!(transaction.world.privacy_roots.iter().count(), roots_before);
            assert_eq!(
                transaction.world.privacy_root_heads.iter().count(),
                heads_before
            );
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
        {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let roots_before = transaction.world.privacy_roots.iter().count();
            let heads_before = transaction.world.privacy_root_heads.iter().count();
            let publication = PrivacyRootPublicationV1 {
                namespace: x509_namespace(),
                role: PrivacyRootRoleV1::CertificateAuthorityMembership,
                epoch: 2,
                root: PrivacyRootV1::new([0xA2; 32]),
            };
            let error = PublishPrivacyRootV1::new(publication)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("generic and cross-scope X.509 roots must fail closed");
            assert!(
                smart_contract_parameter_message(&error).contains("derived atomically")
                    || smart_contract_parameter_message(&error).contains("incompatible"),
                "{error:?}"
            );
            assert_eq!(transaction.world.privacy_roots.iter().count(), roots_before);
            assert_eq!(
                transaction.world.privacy_root_heads.iter().count(),
                heads_before
            );
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
        {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let commitment_count = transaction.world.privacy_commitments.iter().count();
            let root_count = transaction.world.privacy_roots.iter().count();
            let outdated = x509_crl(
                1,
                1,
                0xEA,
                1_799_999_699,
                1_800_000_300,
                0xEA,
                None,
                PrivacyZkX509RecordLifecycleV1::Active,
            );
            let error = RegisterPrivacyZkX509CrlV1::new(outdated)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("CRL older than the consensus freshness limit");
            assert!(
                smart_contract_parameter_message(&error).contains("freshness limit"),
                "{error:?}"
            );
            let future = x509_crl(
                1,
                1,
                0xEB,
                1_800_000_001,
                1_800_000_301,
                0xEB,
                None,
                PrivacyZkX509RecordLifecycleV1::Active,
            );
            let error = RegisterPrivacyZkX509CrlV1::new(future)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("future CRL must not be accepted");
            assert!(
                smart_contract_parameter_message(&error).contains("not current"),
                "{error:?}"
            );
            let mut digest_substitution = crl_origin;
            digest_substitution.crl_der_digest = PrivacyX509CrlDerDigestV1::new([0xEC; 32]);
            let error = RegisterPrivacyZkX509CrlV1::new(digest_substitution)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("record/root substitution must invalidate the self-digest");
            assert!(
                smart_contract_parameter_message(&error).contains("digest"),
                "{error:?}"
            );
            assert_eq!(
                transaction.world.privacy_commitments.iter().count(),
                commitment_count
            );
            assert_eq!(transaction.world.privacy_roots.iter().count(), root_count);
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
        {
            let mut transaction = block.transaction();
            let count_before = transaction.world.privacy_commitments.iter().count();
            let root_count_before = transaction.world.privacy_roots.iter().count();
            let budget_before = transaction.privacy_budget_for_testing();
            let error = RotatePrivacyZkX509TrustAnchorV1::new(
                PrivacyZkX509TrustAnchorRecordDigestV1::new([0xEF; 32]),
                anchor_rotation,
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("stale trust-anchor digest");
            assert!(
                smart_contract_parameter_message(&error).contains("stale or substituted"),
                "{error:?}"
            );
            assert_eq!(
                transaction.world.privacy_commitments.iter().count(),
                count_before
            );
            assert_eq!(
                transaction.world.privacy_roots.iter().count(),
                root_count_before
            );
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
        {
            let mut transaction = block.transaction();
            RotatePrivacyZkX509TrustAnchorV1::new(anchor_origin.record_digest, anchor_rotation)
                .execute(&ALICE_ID, &mut transaction)
                .expect("exact trust-anchor and CA-root rotation");
            assert_eq!(transaction.world.privacy_roots.iter().count(), 2);
            let ca_head = transaction
                .world
                .privacy_root_heads
                .get(
                    &PrivacyRootHeadKeyV1::new(
                        x509_ca_namespace(),
                        PrivacyRootRoleV1::CertificateAuthorityMembership,
                    )
                    .expect("CA head"),
                )
                .expect("rotated CA head");
            assert_eq!(ca_head.epoch(), 2);
            assert_eq!(ca_head.root(), anchor_rotation.ca_membership_root);
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            transaction.apply();
        }
        block
            .commit_world_overlay_for_testing()
            .expect("commit X.509 CRL and anchor-rotation block");
    }

    #[inline(never)]
    fn rotate_policy_and_crl(&self, state: &State, height: u64) {
        let mut block = state.block(test_header_at(height));
        let policy_origin = self.policy_origin.clone();
        let crl_origin = self.crl_origin;
        let anchor_rotation = self.anchor_rotation;
        let policy_rotation = self.policy_rotation.clone();
        let crl_rotation = self.crl_rotation;
        {
            let mut transaction = block.transaction();
            RotatePrivacyZkX509CertificatePolicyV1::new(
                policy_origin.record_digest,
                policy_rotation.clone(),
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect("exact one-epoch certificate-policy rotation");
            assert_eq!(transaction.world.privacy_roots.iter().count(), 2);
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let commitment_count = transaction.world.privacy_commitments.iter().count();
            let root_count = transaction.world.privacy_roots.iter().count();
            let error = RotatePrivacyZkX509CrlV1::new(
                PrivacyZkX509CrlRecordDigestV1::new([0xEE; 32]),
                crl_rotation,
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("stale CRL compare-and-swap digest");
            assert!(
                smart_contract_parameter_message(&error).contains("stale or substituted"),
                "{error:?}"
            );
            let mut record_substitution = crl_rotation;
            record_substitution.next_update_unix_seconds += 1;
            let error =
                RotatePrivacyZkX509CrlV1::new(crl_origin.record_digest, record_substitution)
                    .execute(&ALICE_ID, &mut transaction)
                    .expect_err("tampered CRL record must fail its self-digest");
            assert!(
                smart_contract_parameter_message(&error).contains("digest"),
                "{error:?}"
            );
            assert_eq!(
                transaction.world.privacy_commitments.iter().count(),
                commitment_count
            );
            assert_eq!(transaction.world.privacy_roots.iter().count(), root_count);
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
        {
            let mut transaction = block.transaction();
            RotatePrivacyZkX509CrlV1::new(crl_origin.record_digest, crl_rotation)
                .execute(&ALICE_ID, &mut transaction)
                .expect("complete signed CRL rotates atomically");
            assert_eq!(transaction.world.privacy_roots.iter().count(), 2);
            assert_eq!(transaction.world.privacy_root_heads.iter().count(), 1);
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            let snapshot = load_privacy_zk_x509_authoritative_state_v1(
                x509_trust_anchor_id(),
                x509_policy_id(),
                8,
                &transaction.world.privacy_commitments,
                &transaction.world.privacy_roots,
                &transaction.world.privacy_root_heads,
            )
            .expect("fully rotated authoritative X.509 state");
            assert_eq!(snapshot.trust_anchor(), anchor_rotation);
            assert_eq!(snapshot.certificate_policy(), &policy_rotation);
            assert_eq!(snapshot.crl_record(), crl_rotation);
            transaction.apply();
        }
        block
            .commit_world_overlay_for_testing()
            .expect("commit X.509 policy and CRL-rotation block");
    }

    #[inline(never)]
    fn revoke_crl_and_policy(&self, state: &State, height: u64) {
        let mut block = state.block(test_header_at(height));
        let anchor_rotation = self.anchor_rotation;
        let policy_rotation = self.policy_rotation.clone();
        let crl_rotation = self.crl_rotation;
        let anchor_revoked = self.anchor_revoked;
        let policy_revoked = self.policy_revoked.clone();
        let crl_revoked = self.crl_revoked;
        {
            let mut transaction = block.transaction();
            let commitment_count = transaction.world.privacy_commitments.iter().count();
            let root_count = transaction.world.privacy_roots.iter().count();
            let error = RevokePrivacyZkX509TrustAnchorV1::new(
                anchor_rotation.record_digest,
                anchor_revoked,
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("active policy must block parent-anchor revocation");
            assert!(
                smart_contract_parameter_message(&error).contains("active certificate policy"),
                "{error:?}"
            );
            let error = RevokePrivacyZkX509CertificatePolicyV1::new(
                policy_rotation.record_digest,
                policy_revoked.clone(),
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("active CRL must block parent-policy revocation");
            assert!(
                smart_contract_parameter_message(&error).contains("active signed CRL"),
                "{error:?}"
            );
            assert_eq!(
                transaction.world.privacy_commitments.iter().count(),
                commitment_count
            );
            assert_eq!(transaction.world.privacy_roots.iter().count(), root_count);
            assert_eq!(transaction.privacy_budget_for_testing(), (0, 0, 0, 0));
        }
        {
            let mut transaction = block.transaction();
            RevokePrivacyZkX509CrlV1::new(crl_rotation.record_digest, crl_revoked)
                .execute(&ALICE_ID, &mut transaction)
                .expect("leaf CRL lineage revokes first");
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            RevokePrivacyZkX509CertificatePolicyV1::new(
                policy_rotation.record_digest,
                policy_revoked.clone(),
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect("policy revokes only after its CRL");
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            transaction.apply();
        }
        block
            .commit_world_overlay_for_testing()
            .expect("commit X.509 CRL and policy-revocation block");
    }

    #[inline(never)]
    fn revoke_anchor_and_reject_terminal_rotation(&self, state: &State, height: u64) {
        let mut block = state.block(test_header_at(height));
        let anchor_rotation = self.anchor_rotation;
        let anchor_revoked = self.anchor_revoked;
        let policy_revoked = self.policy_revoked.clone();
        let crl_revoked = self.crl_revoked;
        {
            let mut transaction = block.transaction();
            RevokePrivacyZkX509TrustAnchorV1::new(anchor_rotation.record_digest, anchor_revoked)
                .execute(&ALICE_ID, &mut transaction)
                .expect("trust anchor revokes only after every child");
            assert_eq!(transaction.privacy_budget_for_testing().0, 1);
            assert_eq!(transaction.world.privacy_roots.iter().count(), 2);
            assert_eq!(transaction.world.privacy_root_heads.iter().count(), 1);
            let current_crl = crate::privacy_state::load_privacy_zk_x509_crl_v1(
                x509_trust_anchor_id(),
                x509_policy_id(),
                &transaction.world.privacy_commitments,
            )
            .expect("terminal CRL remains authoritative");
            assert_eq!(current_crl, crl_revoked);
            assert_eq!(
                load_privacy_zk_x509_certificate_policy_v1(
                    x509_trust_anchor_id(),
                    x509_policy_id(),
                    &transaction.world.privacy_commitments,
                )
                .expect("terminal certificate policy remains authoritative"),
                policy_revoked
            );
            assert_eq!(
                load_privacy_zk_x509_trust_anchor_v1(
                    x509_trust_anchor_id(),
                    &transaction.world.privacy_commitments,
                )
                .expect("terminal trust anchor remains authoritative"),
                anchor_revoked
            );
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let roots_before = transaction.world.privacy_roots.iter().count();
            let commitment_count = transaction.world.privacy_commitments.iter().count();
            let error = RotatePrivacyZkX509CertificatePolicyV1::new(
                policy_revoked.record_digest,
                x509_policy(
                    4,
                    0xDB,
                    vec![0, 2, 3],
                    Some(policy_revoked.record_digest),
                    PrivacyZkX509RecordLifecycleV1::Active,
                ),
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("terminal policy cannot rotate");
            assert!(
                smart_contract_parameter_message(&error).contains("active trust anchor")
                    || smart_contract_parameter_message(&error).contains("not active"),
                "{error:?}"
            );
            let after_terminal = x509_crl(
                4,
                3,
                0xE4,
                1_799_999_975,
                1_800_000_300,
                0xD9,
                Some(crl_revoked.record_digest),
                PrivacyZkX509RecordLifecycleV1::Active,
            );
            let error = RotatePrivacyZkX509CrlV1::new(crl_revoked.record_digest, after_terminal)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("terminal CRL cannot rotate");
            assert!(
                smart_contract_parameter_message(&error).contains("active")
                    || smart_contract_parameter_message(&error).contains("revoked"),
                "{error:?}"
            );
            assert_eq!(
                transaction.world.privacy_commitments.iter().count(),
                commitment_count
            );
            assert_eq!(transaction.world.privacy_roots.iter().count(), roots_before);
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
    }
}

#[test]
fn zk_x509_governance_and_roots_are_exact_failure_atomic_and_preactivation() {
    let state = state_with_activation(active_lifecycle());
    let records = X509GovernanceRecords::new();
    records.register_anchor_and_policy(&state, TEST_BLOCK_HEIGHT);
    records.register_crl_and_rotate_anchor(&state, TEST_BLOCK_HEIGHT + 1);
    records.rotate_policy_and_crl(&state, TEST_BLOCK_HEIGHT + 2);
    records.revoke_crl_and_policy(&state, TEST_BLOCK_HEIGHT + 3);
    records.revoke_anchor_and_reject_terminal_rotation(&state, TEST_BLOCK_HEIGHT + 4);
}
