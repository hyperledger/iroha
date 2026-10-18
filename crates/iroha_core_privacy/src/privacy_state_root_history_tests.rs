#[test]
fn compiled_limits_keep_bounded_root_history() {
    assert_eq!(
        PrivacyConsensusLimitsV1::taira_default().retained_root_count,
        2_048
    );
}
#[test]
fn root_history_prunes_independently_per_namespace() {
    let mut roots = Storage::new();
    let record = root_provenance();
    let independent_namespace = pgc_namespace(0xE1);
    for epoch in 1..=2_048 {
        let root_byte = (epoch % 251 + 1) as u8;
        roots.insert(
            x509_root_key(
                PrivacyRootRoleV1::CertificateAuthorityMembership,
                epoch,
                root_byte,
            ),
            record.clone(),
        );
        roots.insert(
            PrivacyRootKeyV1::new(
                independent_namespace,
                PrivacyRootRoleV1::PgcAccountState,
                epoch,
                PrivacyRootV1::new(nonzero(root_byte)),
            )
            .expect("independent root key"),
            record.clone(),
        );
    }
    let added = x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 2_049, 43);
    let removals =
        plan_privacy_root_history_update_v1(&roots.view(), &[added], 2_048).expect("valid plan");
    assert_eq!(
        removals,
        vec![x509_root_key(
            PrivacyRootRoleV1::CertificateAuthorityMembership,
            1,
            2
        )]
    );
    assert!(
        roots
            .view()
            .get(
                &PrivacyRootKeyV1::new(
                    independent_namespace,
                    PrivacyRootRoleV1::PgcAccountState,
                    1,
                    PrivacyRootV1::new(nonzero(2)),
                )
                .expect("independent root key")
            )
            .is_some(),
        "planning one namespace must not prune another namespace"
    );
}
#[test]
fn root_history_rejects_replays_epoch_conflicts_and_stale_epochs() {
    let mut roots = Storage::new();
    roots.insert(
        x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 7, 70),
        root_provenance(),
    );
    let exact_replay = x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 7, 70);
    assert!(matches!(
        plan_privacy_root_history_update_v1(&roots.view(), &[exact_replay], 8),
        Err(PrivacyRootHistoryErrorV1::ExistingRoot { key }) if *key == exact_replay
    ));
    assert!(matches!(
        plan_privacy_root_history_update_v1(
            &roots.view(),
            &[x509_root_key(
                PrivacyRootRoleV1::CertificateAuthorityMembership,
                7,
                71,
            )],
            8,
        ),
        Err(PrivacyRootHistoryErrorV1::EpochConflict { epoch: 7, .. })
    ));
    assert!(matches!(
        plan_privacy_root_history_update_v1(
            &roots.view(),
            &[x509_root_key(
                PrivacyRootRoleV1::CertificateAuthorityMembership,
                6,
                60,
            )],
            8,
        ),
        Err(PrivacyRootHistoryErrorV1::NonMonotonicEpoch {
            latest_epoch: 7,
            added_epoch: 6,
            ..
        })
    ));
}
#[test]
fn root_history_rejects_duplicate_and_over_capacity_effects() {
    let roots = Storage::new();
    let duplicate = x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 1, 10);
    assert!(matches!(
        plan_privacy_root_history_update_v1(&roots.view(), &[duplicate, duplicate], 8),
        Err(PrivacyRootHistoryErrorV1::DuplicateAddedRoot { key }) if *key == duplicate
    ));
    let additions = [
        x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 1, 10),
        x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 2, 20),
        x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 3, 30),
    ];
    assert!(matches!(
        plan_privacy_root_history_update_v1(&roots.view(), &additions, 2),
        Err(PrivacyRootHistoryErrorV1::AddedRootsExceedRetention { count: 3, max: 2 })
    ));
}

#[test]
fn root_history_refusal_retains_exact_owned_key_after_inputs_drop() {
    let exact_key = x509_root_key(PrivacyRootRoleV1::CertificateAuthorityMembership, 7, 70);
    let refusal = {
        let mut roots = Storage::new();
        roots.insert(exact_key, root_provenance());
        plan_privacy_root_history_update_v1(&roots.view(), &[exact_key], 8)
            .expect_err("existing root refuses without changing its identity")
    };
    assert_eq!(
        refusal.to_string(),
        format!("privacy root is already retained: {exact_key:?}")
    );
    let cloned = refusal.clone();
    assert_eq!(cloned, refusal);
    match (refusal, cloned) {
        (
            PrivacyRootHistoryErrorV1::ExistingRoot { key: original },
            PrivacyRootHistoryErrorV1::ExistingRoot { key: copied },
        ) => {
            assert_eq!(*original, exact_key);
            assert_eq!(*copied, exact_key);
        }
        unexpected => panic!("unexpected root-history refusals: {unexpected:?}"),
    }
}
