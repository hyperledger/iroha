#[test]
fn concurrent_pending_invitations_rebase_and_accept_independently() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(21);
    let first_account = account(22);
    let second_account = account(23);
    let package = package("concurrent-invites");
    let first_id = MusubiInviteIdV1::new([0x21; 32]);
    let second_id = MusubiInviteIdV1::new([0x22; 32]);
    seed_package_owner(&package, &owner, 1, &mut transaction);
    InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: first_id,
        invited_account: first_account.clone(),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 1,
    }
    .execute(&owner, &mut transaction)
    .expect("first invitation advances package governance");
    InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: second_id,
        invited_account: second_account.clone(),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 2,
    }
    .execute(&owner, &mut transaction)
    .expect("second invitation rebases the first invitation");
    for invite_id in [first_id, second_id] {
        let invitation = transaction
            .world
            .musubi_package_invitations
            .get(&invite_id)
            .expect("pending invitation remains authoritative");
        assert_eq!(invitation.state, MusubiInvitationStateV1::Pending);
        assert_eq!(invitation.expected_governance_revision, 3);
    }
    AcceptMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: first_id,
        expected_governance_revision: 3,
    }
    .execute(&first_account, &mut transaction)
    .expect("the rebased first invitation remains acceptable");
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&first_id)
            .expect("accepted invitation remains in history")
            .state,
        MusubiInvitationStateV1::Accepted
    );
    let second = transaction
        .world
        .musubi_package_invitations
        .get(&second_id)
        .expect("second invitation remains pending");
    assert_eq!(second.state, MusubiInvitationStateV1::Pending);
    assert_eq!(second.expected_governance_revision, 4);
    AcceptMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: second_id,
        expected_governance_revision: 4,
    }
    .execute(&second_account, &mut transaction)
    .expect("the second invitation remains independently acceptable");
    let package = transaction
        .world
        .musubi_packages
        .get(&package)
        .expect("package remains after both acceptances");
    assert_eq!(package.revisions.governance, 5);
    assert!(package.owners.binary_search(&first_account).is_ok());
    assert!(package.owners.binary_search(&second_account).is_ok());
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&second_id)
            .expect("second invitation remains in history")
            .state,
        MusubiInvitationStateV1::Accepted
    );
}
#[test]
fn stale_accept_retries_after_an_invitation_race_rebases_the_cas_revision() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(24);
    let first_account = account(25);
    let package = package("stale-invite-race");
    let first_id = MusubiInviteIdV1::new([0x24; 32]);
    seed_package_owner(&package, &owner, 1, &mut transaction);
    InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: first_id,
        invited_account: first_account.clone(),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 1,
    }
    .execute(&owner, &mut transaction)
    .expect("first invitation succeeds");
    InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: MusubiInviteIdV1::new([0x25; 32]),
        invited_account: account(26),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 2,
    }
    .execute(&owner, &mut transaction)
    .expect("racing invitation advances and rebases governance");
    let _ = take_musubi_events(&mut transaction);
    let outdated = AcceptMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: first_id,
        expected_governance_revision: 2,
    }
    .execute(&first_account, &mut transaction)
    .expect_err("the pre-race CAS revision must remain stale");
    assert!(
        outdated
            .to_string()
            .contains("stale Musubi package governance")
    );
    let invitation = transaction
        .world
        .musubi_package_invitations
        .get(&first_id)
        .expect("stale acceptance leaves the invitation pending");
    assert_eq!(invitation.state, MusubiInvitationStateV1::Pending);
    assert_eq!(invitation.expected_governance_revision, 3);
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("stale acceptance leaves the package unchanged")
            .revisions
            .governance,
        3
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
    AcceptMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: first_id,
        expected_governance_revision: 3,
    }
    .execute(&first_account, &mut transaction)
    .expect("acceptance retries successfully at the rebased revision");
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("retried acceptance advances governance")
            .revisions
            .governance,
        4
    );
}
#[test]
fn invalid_invitation_is_rejected_before_pending_invitations_are_rebased() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(27);
    let pending_account = account(28);
    let package = package("invalid-invite-atomicity");
    let pending = MusubiMaintainerInvitationV1 {
        invite_id: MusubiInviteIdV1::new([0x28; 32]),
        package: package.clone(),
        invited_by: owner.clone(),
        invited_account: pending_account.clone(),
        role: MusubiPackageRoleV1::Owner,
        expected_governance_revision: 1,
        expires_at_height: 100,
        state: MusubiInvitationStateV1::Pending,
    };
    let pending_directory_key = MusubiMaintainerDirectoryKeyV1::pending(
        package.clone(),
        pending_account,
        pending.invite_id,
    );
    seed_package_owner(&package, &owner, 1, &mut transaction);
    seed_pending_invitation(pending.clone(), &mut transaction);
    let directory_before = transaction
        .world
        .musubi_maintainer_directory
        .iter()
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect::<Vec<_>>();
    let error = InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: MusubiInviteIdV1::new([0; 32]),
        invited_account: account(29),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 1,
    }
    .execute(&owner, &mut transaction)
    .expect_err("a zero invitation identity must fail before governance advances");
    assert!(
        matches!(&error, Error::InvalidParameter(
            iroha_data_model::isi::error::InvalidParameterError::SmartContract(message)
        ) if message.contains("invitation is invalid")),
        "unexpected invalid invitation rejection: {error:?}"
    );
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("package remains")
            .revisions
            .governance,
        1
    );
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&pending.invite_id),
        Some(&pending)
    );
    assert_eq!(
        transaction
            .world
            .musubi_maintainer_directory
            .get(&pending_directory_key),
        Some(&MusubiMaintainerDirectoryEntryV1::PendingInvitation(
            pending
        ))
    );
    assert_eq!(
        transaction
            .world
            .musubi_maintainer_directory
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect::<Vec<_>>(),
        directory_before
    );
    assert!(
        transaction
            .world
            .musubi_package_invitations
            .get(&MusubiInviteIdV1::new([0; 32]))
            .is_none()
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn publication_index_overflow_drops_the_unapplied_invitation_plan() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(30);
    let invited = account(31);
    let package = package("publication-plan-overflow");
    let pending = MusubiMaintainerInvitationV1 {
        invite_id: MusubiInviteIdV1::new([0x30; 32]),
        package: package.clone(),
        invited_by: owner.clone(),
        invited_account: invited,
        role: MusubiPackageRoleV1::Owner,
        expected_governance_revision: 1,
        expires_at_height: 100,
        state: MusubiInvitationStateV1::Pending,
    };
    seed_package_owner(&package, &owner, 1, &mut transaction);
    seed_pending_invitation(pending.clone(), &mut transaction);
    *transaction.world.musubi_resolver_index_revision.get_mut() =
        crate::state::MusubiResolverIndexRevisionV1::new(u64::MAX)
            .expect("maximum resolver revision remains nonzero");
    let directory_before = transaction
        .world
        .musubi_maintainer_directory
        .iter()
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect::<Vec<_>>();
    let error = (|| -> Result<(), Error> {
        let mut candidate = transaction
            .world
            .musubi_packages
            .get(&package)
            .cloned()
            .expect("seeded package remains");
        let advance = plan_package_governance_advance(
            &mut candidate,
            execution_height(&transaction),
            None,
            transaction.world(),
        )?;
        let planned_index_revision = plan_resolver_index_revision(&transaction)?;
        *transaction.world.musubi_resolver_index_revision.get_mut() = planned_index_revision;
        transaction
            .world
            .musubi_packages
            .insert(package.clone(), candidate);
        advance.apply_invitation_updates(&mut transaction);
        Ok(())
    })()
    .expect_err("publication must fail when the resolver revision cannot advance");
    assert!(
        error
            .to_string()
            .contains("resolver-index revision overflow")
    );
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("package remains")
            .revisions
            .governance,
        1
    );
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&pending.invite_id),
        Some(&pending)
    );
    assert_eq!(
        transaction
            .world
            .musubi_maintainer_directory
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect::<Vec<_>>(),
        directory_before
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        u64::MAX
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn publication_reverse_reference_failure_drops_the_unapplied_invitation_plan() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(32);
    let package = package("publication-reverse-bound");
    let pending = MusubiMaintainerInvitationV1 {
        invite_id: MusubiInviteIdV1::new([0x32; 32]),
        package: package.clone(),
        invited_by: owner.clone(),
        invited_account: account(33),
        role: MusubiPackageRoleV1::Owner,
        expected_governance_revision: 1,
        expires_at_height: 100,
        state: MusubiInvitationStateV1::Pending,
    };
    seed_package_owner(&package, &owner, 1, &mut transaction);
    seed_pending_invitation(pending.clone(), &mut transaction);
    let archive_id = ArchiveId::new([0x34; 32]);
    let releases = (0..MUSUBI_MAX_RESOLUTION_NODES_V1)
        .map(|patch| {
            MusubiReleaseIdV1::new(
                package.clone(),
                MusubiVersionV1::new(
                    1,
                    0,
                    u64::try_from(patch).expect("bounded patch fits u64"),
                    Vec::new(),
                )
                .expect("bounded release version is valid"),
            )
        })
        .collect::<Vec<_>>();
    let references = MusubiArchiveReverseReferencesV1 {
        archive_id,
        releases,
    };
    references
        .validate()
        .expect("maximum-size reverse-reference fixture is valid");
    transaction
        .world
        .musubi_archive_reverse_references
        .insert(archive_id, references.clone());
    let directory_before = transaction
        .world
        .musubi_maintainer_directory
        .iter()
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect::<Vec<_>>();
    let new_release = MusubiReleaseIdV1::new(
        package.clone(),
        MusubiVersionV1::new(
            1,
            0,
            u64::try_from(MUSUBI_MAX_RESOLUTION_NODES_V1).expect("bounded patch fits u64"),
            Vec::new(),
        )
        .expect("successor release version is valid"),
    );
    let error = (|| -> Result<(), Error> {
        let mut candidate = transaction
            .world
            .musubi_packages
            .get(&package)
            .cloned()
            .expect("seeded package remains");
        let advance = plan_package_governance_advance(
            &mut candidate,
            execution_height(&transaction),
            None,
            transaction.world(),
        )?;
        let planned_references =
            plan_archive_reverse_reference(archive_id, new_release.clone(), transaction.world())?;
        transaction
            .world
            .musubi_packages
            .insert(package.clone(), candidate);
        transaction
            .world
            .musubi_archive_reverse_references
            .insert(archive_id, planned_references);
        advance.apply_invitation_updates(&mut transaction);
        Ok(())
    })()
    .expect_err("publication must fail when an archive reference bound is exhausted");
    assert!(error.to_string().contains("reverse references"));
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("package remains")
            .revisions
            .governance,
        1
    );
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&pending.invite_id),
        Some(&pending)
    );
    assert_eq!(
        transaction
            .world
            .musubi_maintainer_directory
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect::<Vec<_>>(),
        directory_before
    );
    assert_eq!(
        transaction
            .world
            .musubi_archive_reverse_references
            .get(&archive_id),
        Some(&references)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn package_pending_invitation_bound_is_enforced_before_mutation() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(31);
    let package = MusubiPackageIdV1::new(
        iroha_model_base::topology::DataSpaceId::new(7),
        MusubiPackageScopeV1::DataspaceRoot,
        "bounded-invites".parse().expect("package name"),
    );
    transaction.world.musubi_packages.insert(
        package.clone(),
        MusubiPackageRecordV1 {
            package: package.clone(),
            claimed_namespace: "sora".parse().expect("namespace"),
            claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([1; 32]),
            owners: vec![owner.clone()],
            member_accounts: vec![owner.clone()],
            claimed_at_height: 1,
            revisions: MusubiPackageRevisionsV1 {
                governance: 1,
                metadata: 1,
                archive_locations: 1,
            },
        },
    );
    let owner_member = MusubiPackageMemberV1 {
        package: package.clone(),
        account: owner.clone(),
        role: MusubiPackageRoleV1::Owner,
        accepted_at_height: 1,
        governance_revision: 1,
    };
    transaction
        .world
        .musubi_package_members
        .insert(owner_member.key(), owner_member.clone());
    upsert_maintainer_directory(
        MusubiMaintainerDirectoryEntryV1::Accepted(owner_member),
        &mut transaction,
    );
    for index in 0..MUSUBI_MAX_PENDING_INVITATIONS_V1 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(
            &u64::try_from(index + 1)
                .expect("bounded fixture index fits u64")
                .to_le_bytes(),
        );
        let invitation = MusubiMaintainerInvitationV1 {
            invite_id: MusubiInviteIdV1::new(bytes),
            package: package.clone(),
            invited_by: owner.clone(),
            invited_account: account(u8::try_from(index % 200 + 32).expect("account seed")),
            role: MusubiPackageRoleV1::Owner,
            expected_governance_revision: 1,
            expires_at_height: 100,
            state: MusubiInvitationStateV1::Pending,
        };
        upsert_maintainer_directory(
            MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation),
            &mut transaction,
        );
    }
    assert_eq!(
        pending_invitation_count(&package, transaction.world()),
        MUSUBI_MAX_PENDING_INVITATIONS_V1
    );
    let instruction = InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: MusubiInviteIdV1::new([0xFE; 32]),
        invited_account: account(232),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 1,
    };
    let error = instruction
        .execute(&owner, &mut transaction)
        .expect_err("the 257th pending invitation must fail closed");
    assert!(error.to_string().contains("pending-invitation bound"));
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("package remains")
            .revisions
            .governance,
        1
    );
}
#[test]
fn expired_pending_invitations_reclaim_bound_and_emit_bounded_events() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(10).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(31);
    let package = package("expiry-reclaim");
    seed_package_owner(&package, &owner, 1, &mut transaction);
    for index in 0..MUSUBI_MAX_PENDING_INVITATIONS_V1 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(
            &u64::try_from(index + 1)
                .expect("bounded fixture index fits u64")
                .to_le_bytes(),
        );
        seed_pending_invitation(
            MusubiMaintainerInvitationV1 {
                invite_id: MusubiInviteIdV1::new(bytes),
                package: package.clone(),
                invited_by: owner.clone(),
                invited_account: account(u8::try_from(index % 200 + 40).expect("account seed")),
                role: MusubiPackageRoleV1::Owner,
                expected_governance_revision: 1,
                expires_at_height: 5,
                state: MusubiInvitationStateV1::Pending,
            },
            &mut transaction,
        );
    }
    assert_eq!(
        pending_invitation_count(&package, transaction.world()),
        MUSUBI_MAX_PENDING_INVITATIONS_V1
    );
    let replacement_id = MusubiInviteIdV1::new([0xFE; 32]);
    InviteMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id: replacement_id,
        invited_account: account(250),
        role: MusubiPackageRoleV1::Owner,
        expires_at_height: 100,
        expected_governance_revision: 1,
    }
    .execute(&owner, &mut transaction)
    .expect("expired invitations reclaim capacity before the bound check");
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("package remains")
            .revisions
            .governance,
        2
    );
    assert_eq!(pending_invitation_count(&package, transaction.world()), 1);
    let (expired, pending) = transaction.world.musubi_package_invitations.iter().fold(
        (0_usize, 0_usize),
        |(expired, pending), (_, invitation)| match invitation.state {
            MusubiInvitationStateV1::Expired => (expired + 1, pending),
            MusubiInvitationStateV1::Pending => (expired, pending + 1),
            MusubiInvitationStateV1::Accepted | MusubiInvitationStateV1::Revoked => {
                (expired, pending)
            }
        },
    );
    assert_eq!(expired, MUSUBI_MAX_PENDING_INVITATIONS_V1);
    assert_eq!(pending, 1);
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&replacement_id)
            .expect("replacement invitation")
            .state,
        MusubiInvitationStateV1::Pending
    );
    let events = take_musubi_events(&mut transaction);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, MusubiEvent::MaintainerInvitationExpired(_)))
            .count(),
        MUSUBI_MAX_PENDING_INVITATIONS_V1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, MusubiEvent::MaintainerInvited(_)))
            .count(),
        1
    );
    assert_eq!(events.len(), MUSUBI_MAX_PENDING_INVITATIONS_V1 + 1);
}
#[test]
fn invitation_revoke_is_owner_only_cas_and_replay_safe() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(5).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(51);
    let stranger = account(52);
    let invited = account(53);
    let package = package("revoke-invite");
    let invite_id = MusubiInviteIdV1::new([0x53; 32]);
    seed_package_owner(&package, &owner, 1, &mut transaction);
    seed_pending_invitation(
        MusubiMaintainerInvitationV1 {
            invite_id,
            package: package.clone(),
            invited_by: owner.clone(),
            invited_account: invited.clone(),
            role: MusubiPackageRoleV1::Owner,
            expected_governance_revision: 1,
            expires_at_height: 100,
            state: MusubiInvitationStateV1::Pending,
        },
        &mut transaction,
    );
    let revoke = |expected_governance_revision| RevokeMusubiPackageMaintainerInvitationV1 {
        package: package.clone(),
        invite_id,
        expected_governance_revision,
    };
    let unauthorized = revoke(1)
        .execute(&stranger, &mut transaction)
        .expect_err("a non-owner cannot revoke an invitation");
    assert!(unauthorized.to_string().contains("not an owner"));
    let outdated = revoke(2)
        .execute(&owner, &mut transaction)
        .expect_err("a stale governance revision fails closed");
    assert!(
        outdated
            .to_string()
            .contains("stale Musubi package governance")
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
    revoke(1)
        .execute(&owner, &mut transaction)
        .expect("the current owner may revoke the pending invitation");
    assert_eq!(
        transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("package remains")
            .revisions
            .governance,
        2
    );
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&invite_id)
            .expect("historical invitation remains")
            .state,
        MusubiInvitationStateV1::Revoked
    );
    assert!(
        transaction
            .world
            .musubi_maintainer_directory
            .get(&MusubiMaintainerDirectoryKeyV1::pending(
                package.clone(),
                invited,
                invite_id,
            ))
            .is_none()
    );
    assert!(matches!(
        take_musubi_events(&mut transaction).as_slice(),
        [MusubiEvent::MaintainerInvitationRevoked(_)]
    ));
    let replay = revoke(2)
        .execute(&owner, &mut transaction)
        .expect_err("a terminal invitation cannot be revoked twice");
    assert!(replay.to_string().contains("not pending"));
    let old_revision_replay = revoke(1)
        .execute(&owner, &mut transaction)
        .expect_err("the original compare-and-set revision cannot be replayed");
    assert!(
        old_revision_replay
            .to_string()
            .contains("stale Musubi package governance")
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn accepting_an_expired_invitation_fails_without_mutating_it() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(10).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(61);
    let invited = account(62);
    let package = package("expired-accept");
    let invite_id = MusubiInviteIdV1::new([0x62; 32]);
    seed_package_owner(&package, &owner, 1, &mut transaction);
    seed_pending_invitation(
        MusubiMaintainerInvitationV1 {
            invite_id,
            package: package.clone(),
            invited_by: owner,
            invited_account: invited.clone(),
            role: MusubiPackageRoleV1::Owner,
            expected_governance_revision: 1,
            expires_at_height: 9,
            state: MusubiInvitationStateV1::Pending,
        },
        &mut transaction,
    );
    let error = AcceptMusubiPackageMaintainerV1 {
        package: package.clone(),
        invite_id,
        expected_governance_revision: 1,
    }
    .execute(&invited, &mut transaction)
    .expect_err("height-expired invitations are never accepted");
    assert!(
        error
            .to_string()
            .contains("next successful package governance mutation")
    );
    assert_eq!(
        transaction
            .world
            .musubi_package_invitations
            .get(&invite_id)
            .expect("pending record remains until governance cleanup")
            .state,
        MusubiInvitationStateV1::Pending
    );
    assert_eq!(pending_invitation_count(&package, transaction.world()), 1);
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn maintainer_query_visibility_excludes_only_height_expired_invitations() {
    let package = package("query-expiry");
    let owner = account(71);
    let accepted = MusubiMaintainerDirectoryEntryV1::Accepted(MusubiPackageMemberV1 {
        package: package.clone(),
        account: owner.clone(),
        role: MusubiPackageRoleV1::Owner,
        accepted_at_height: 1,
        governance_revision: 1,
    });
    let mut invitation = MusubiMaintainerInvitationV1 {
        invite_id: MusubiInviteIdV1::new([0x71; 32]),
        package,
        invited_by: owner,
        invited_account: account(72),
        role: MusubiPackageRoleV1::Owner,
        expected_governance_revision: 1,
        expires_at_height: 9,
        state: MusubiInvitationStateV1::Pending,
    };
    assert!(maintainer_directory_entry_visible_at_height(&accepted, 10));
    assert!(!maintainer_directory_entry_visible_at_height(
        &MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation.clone()),
        10,
    ));
    invitation.expires_at_height = 10;
    assert!(maintainer_directory_entry_visible_at_height(
        &MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation),
        10,
    ));
}
#[test]
fn identical_alias_replay_requires_current_package_owner_authorization() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(81);
    let stranger = account(82);
    let package = package("alias-target");
    let alias: MusubiAliasNameV1 = "repeat".parse().expect("alias");
    seed_package_owner(&package, &owner, 1, &mut transaction);
    transaction.world.musubi_aliases.insert(
        alias.clone(),
        MusubiAliasRecordV1 {
            alias: alias.clone(),
            target: package.clone(),
            registered_by: owner.clone(),
            pricing_revision: 1,
            paid_xor: 1,
            registered_at_height: 1,
            history_revision: 1,
        },
    );
    let mut closed_policy = MusubiRegistryPolicyV1 {
        revision: 2,
        mode: MusubiRegistryAdmissionModeV1::Closed,
        ..Default::default()
    };
    closed_policy.alias_pricing.revision = 2;
    closed_policy.alias_pricing.length_5_to_32_xor = 2;
    *transaction.world.musubi_registry_policy.get_mut() = closed_policy;
    let error = RegisterMusubiAliasV1 {
        alias: alias.clone(),
        target: package.clone(),
        expected_pricing_revision: 1,
    }
    .execute(&stranger, &mut transaction)
    .expect_err("an arbitrary authority cannot obtain successful alias replay");
    assert!(error.to_string().contains("not an owner"));
    assert_eq!(
        transaction
            .world
            .musubi_aliases
            .get(&alias)
            .expect("alias remains")
            .history_revision,
        1
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
    RegisterMusubiAliasV1 {
        alias: alias.clone(),
        target: package,
        expected_pricing_revision: u64::MAX,
    }
    .execute(&owner, &mut transaction)
    .expect("the current owner may replay an identical alias under closed admission");
    assert_eq!(
        transaction
            .world
            .musubi_aliases
            .get(&alias)
            .expect("alias remains")
            .history_revision,
        1
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn location_reverse_indices_reject_reuse_and_retain_tombstones() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let pin = iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xA1; 32]);
    let order = iroha_data_model::sorafs::pin_registry::ReplicationOrderId::new([0x22; 32]);
    let first_archive = retention_archive(0xA3);
    let mut first = location_fixture(0xA3, pin, order);
    first.archive_id = first_archive.archive_id;
    transaction
        .world
        .musubi_locations_by_replication_order
        .insert(
            order,
            MusubiReplicationOrderLocationReferenceV1 {
                binding: MusubiReplicationOrderArchiveBindingV1::new(
                    order,
                    first_archive.archive_id,
                    first_archive.commitment.clone(),
                ),
                lifecycle: MusubiReplicationOrderLocationLifecycleV1::PreLocation,
            },
        );
    transaction
        .world
        .musubi_archives
        .insert(first_archive.archive_id, first_archive);
    bind_location_reverse_indices(None, &first, &mut transaction)
        .expect("first exact location binding succeeds");
    assert!(
        transaction
            .world
            .musubi_locations_by_pin
            .get(&pin)
            .is_some_and(|reference| reference.active && reference.location == first.key())
    );
    let conflicting_archive = retention_archive(0xA4);
    let conflicting_order =
        iroha_data_model::sorafs::pin_registry::ReplicationOrderId::new([0x25; 32]);
    let mut conflicting = location_fixture(0xA4, pin, conflicting_order);
    conflicting.archive_id = conflicting_archive.archive_id;
    transaction
        .world
        .musubi_locations_by_replication_order
        .insert(
            conflicting_order,
            MusubiReplicationOrderLocationReferenceV1 {
                binding: MusubiReplicationOrderArchiveBindingV1::new(
                    conflicting_order,
                    conflicting_archive.archive_id,
                    conflicting_archive.commitment.clone(),
                ),
                lifecycle: MusubiReplicationOrderLocationLifecycleV1::PreLocation,
            },
        );
    transaction
        .world
        .musubi_archives
        .insert(conflicting_archive.archive_id, conflicting_archive);
    let error = bind_location_reverse_indices(None, &conflicting, &mut transaction)
        .expect_err("one pin manifest cannot be rebound to another location");
    assert!(matches!(error, Error::InvariantViolation(message)
        if message.contains("pin manifests cannot be reused")));
    retire_location_reverse_indices(&first, &mut transaction)
        .expect("retirement atomically leaves reuse tombstones");
    assert!(
        transaction
            .world
            .musubi_locations_by_pin
            .get(&pin)
            .is_some_and(|reference| !reference.active && reference.location == first.key())
    );
    let error = bind_location_reverse_indices(None, &conflicting, &mut transaction)
        .expect_err("retired pin tombstones permanently reject reuse");
    assert!(matches!(error, Error::InvariantViolation(message)
        if message.contains("pin manifests cannot be reused")));
}
#[test]
fn namespace_binding_sns_refusal_retains_original_owner_before_replay_and_retries() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(1);
    let selector =
        crate::sns::selector_for_dataspace_alias("sora").expect("dataspace alias selector");
    let address = iroha_data_model::account::AccountAddress::from_account_id(&owner)
        .expect("account address");
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        crate::sns::SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        iroha_primitives::json::Json::new(7_u64),
    );
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        10,
        20,
        30,
        metadata,
    );
    transaction
        .world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), record.encode());
    let binding = MusubiNamespaceBindingV1 {
        namespace: "sora".parse().expect("namespace"),
        home_dataspace: iroha_model_base::topology::DataSpaceId::new(7),
        scope: MusubiPackageScopeV1::DataspaceRoot,
        generation: 1,
    };
    transaction
        .world
        .musubi_namespace_bindings
        .insert(binding.namespace.clone(), binding.clone());
    let closed_policy = MusubiRegistryPolicyV1 {
        revision: 2,
        mode: MusubiRegistryAdmissionModeV1::Closed,
        ..Default::default()
    };
    *transaction.world.musubi_registry_policy.get_mut() = closed_policy;
    let key = crate::sns::record_storage_key(&selector);
    let original = transaction
        .world
        .smart_contract_state
        .get(&key)
        .unwrap()
        .clone();
    transaction.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let mut retry_block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        None,
        None,
        1,
        0,
    ));
    let command = RegisterMusubiNamespaceBindingV1::new(binding.clone(), u64::MAX);
    {
        let mut tx = retry_block.transaction();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let original_attempt = command.clone();
        let result =
            norito::with_decode_limits_scope(limits, || original_attempt.execute(&owner, &mut tx));
        assert!(result.is_err());
        assert!(tx.is_execution_deferred());
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&original));
        assert_eq!(
            tx.world.musubi_namespace_bindings.get(&binding.namespace),
            Some(&binding)
        );
        assert!(tx.world.take_external_events().is_empty());
    }
    let mut retry = retry_block.transaction();
    command.clone().execute(&owner, &mut retry).unwrap();
    assert!(!retry.is_execution_deferred());
    assert!(retry.world.take_external_events().is_empty());
    retry.world.smart_contract_state.insert(key, vec![0xff]);
    assert!(command.execute(&owner, &mut retry).is_err());
    assert!(!retry.is_execution_deferred());
    assert!(retry.world.take_external_events().is_empty());
}
#[test]
fn namespace_binding_replay_requires_current_owner_authorization() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let owner = account(1);
    let stranger = account(2);
    let selector =
        crate::sns::selector_for_dataspace_alias("sora").expect("dataspace alias selector");
    let address = iroha_data_model::account::AccountAddress::from_account_id(&owner)
        .expect("account address");
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        crate::sns::SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        iroha_primitives::json::Json::new(7_u64),
    );
    let mut record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        10,
        20,
        30,
        metadata,
    );
    transaction
        .world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), record.encode());
    let binding = MusubiNamespaceBindingV1 {
        namespace: "sora".parse().expect("namespace"),
        home_dataspace: iroha_model_base::topology::DataSpaceId::new(7),
        scope: MusubiPackageScopeV1::DataspaceRoot,
        generation: 1,
    };
    transaction
        .world
        .musubi_namespace_bindings
        .insert(binding.namespace.clone(), binding.clone());
    let closed_policy = MusubiRegistryPolicyV1 {
        revision: 2,
        mode: MusubiRegistryAdmissionModeV1::Closed,
        ..Default::default()
    };
    *transaction.world.musubi_registry_policy.get_mut() = closed_policy;
    let unauthorized = RegisterMusubiNamespaceBindingV1::new(binding.clone(), 1)
        .execute(&stranger, &mut transaction)
        .expect_err("an arbitrary authority cannot obtain a successful namespace replay");
    assert!(unauthorized.to_string().contains("does not own"));
    assert!(transaction.world.take_external_events().is_empty());
    RegisterMusubiNamespaceBindingV1::new(binding.clone(), u64::MAX)
        .execute(&owner, &mut transaction)
        .expect("the current owner may replay an identical binding under closed admission");
    assert!(transaction.world.take_external_events().is_empty());
    record.owner = stranger.clone();
    record.ownership_generation = 2;
    transaction
        .world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), record.encode());
    let former_owner = RegisterMusubiNamespaceBindingV1::new(binding.clone(), u64::MAX)
        .execute(&owner, &mut transaction)
        .expect_err("the former namespace owner cannot replay after ownership changes");
    assert!(former_owner.to_string().contains("does not own"));
    RegisterMusubiNamespaceBindingV1::new(binding.clone(), u64::MAX)
        .execute(&stranger, &mut transaction)
        .expect("the live owner may replay an immutable older-generation binding");
    assert!(transaction.world.take_external_events().is_empty());
    let conflicting = MusubiNamespaceBindingV1 {
        home_dataspace: iroha_model_base::topology::DataSpaceId::new(8),
        ..binding
    };
    RegisterMusubiNamespaceBindingV1::new(conflicting, 1)
        .execute(&stranger, &mut transaction)
        .expect_err("conflicting immutable namespace binding is rejected");
    assert!(transaction.world.take_external_events().is_empty());
}
#[test]
fn namespace_claim_uses_live_owner_generation_after_immutable_binding_registration() {
    let owner_keypair =
        KeyPair::try_from_seed(vec![41; 32], Algorithm::Ed25519).expect("owner fixture keypair");
    let owner = AccountId::new(owner_keypair.public_key().clone());
    let delegate = account(42);
    let binding = MusubiNamespaceBindingV1 {
        namespace: "dex.universal".parse().expect("namespace"),
        home_dataspace: iroha_model_base::topology::DataSpaceId::new(7),
        scope: MusubiPackageScopeV1::Domain("dex".parse().expect("domain")),
        generation: 1,
    };
    let sign_delegation = |owner_generation| {
        let payload = MusubiNamespaceDelegationPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            namespace_binding: binding.digest(),
            owner_generation,
            owner: owner.clone(),
            delegate: delegate.clone(),
            expires_at_height: 100,
        };
        MusubiNamespaceDelegationV1 {
            approvals: vec![MusubiNamespaceDelegationApprovalV1 {
                public_key: owner_keypair.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    owner_keypair.private_key(),
                    payload.signing_hash(),
                )
                .expect("sign namespace delegation"),
            }],
            payload,
        }
    };
    validate_namespace_claim_authority(&binding, None, &owner, &owner, 2, 50)
        .expect("the live owner may claim after ownership generation advances");
    validate_namespace_claim_authority(
        &binding,
        Some(&sign_delegation(2)),
        &delegate,
        &owner,
        2,
        50,
    )
    .expect("a delegation signed by the live owner generation may claim");
    validate_namespace_claim_authority(
        &binding,
        Some(&sign_delegation(1)),
        &delegate,
        &owner,
        2,
        50,
    )
    .expect_err("a delegation from the immutable binding generation is stale");
    validate_namespace_claim_authority(&binding, None, &owner, &owner, 0, 50)
        .expect_err("a zero live ownership generation must fail closed");
}
#[test]
fn namespace_home_dataspace_matches_catalog_for_root_and_domain_scopes() {
    let world = World::default();
    let catalog = iroha_data_model::nexus::DataSpaceCatalog::default();
    let bindings = [
        MusubiNamespaceBindingV1 {
            namespace: "universal".parse().expect("root namespace"),
            home_dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            scope: MusubiPackageScopeV1::DataspaceRoot,
            generation: 1,
        },
        MusubiNamespaceBindingV1 {
            namespace: "dex.universal".parse().expect("domain namespace"),
            home_dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            scope: MusubiPackageScopeV1::Domain("dex".parse().expect("domain")),
            generation: 1,
        },
    ];
    for binding in &bindings {
        validate_namespace_home_dataspace(binding, &world.view(), &catalog, 50)
            .expect("namespace alias and structural dataspace agree");
        let mismatched = MusubiNamespaceBindingV1 {
            home_dataspace: iroha_model_base::topology::DataSpaceId::new(7),
            ..binding.clone()
        };
        validate_namespace_home_dataspace(&mismatched, &world.view(), &catalog, 50)
            .expect_err("cross-dataspace namespace binding must fail closed");
    }
}
#[test]
fn namespace_home_dataspace_rejects_static_dynamic_alias_conflicts_for_all_scopes() {
    let catalog = iroha_data_model::nexus::DataSpaceCatalog::default();
    let selector =
        crate::sns::selector_for_dataspace_alias("universal").expect("dataspace selector");
    let owner = account(43);
    let address = iroha_data_model::account::AccountAddress::from_account_id(&owner)
        .expect("account address");
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        crate::sns::SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        iroha_primitives::json::Json::new(7_u64),
    );
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner,
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        metadata,
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), record.encode());
    let bindings = [
        MusubiNamespaceBindingV1 {
            namespace: "universal".parse().expect("root namespace"),
            home_dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            scope: MusubiPackageScopeV1::DataspaceRoot,
            generation: 1,
        },
        MusubiNamespaceBindingV1 {
            namespace: "dex.universal".parse().expect("domain namespace"),
            home_dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            scope: MusubiPackageScopeV1::Domain("dex".parse().expect("domain")),
            generation: 1,
        },
    ];
    for binding in &bindings {
        let error = validate_namespace_home_dataspace(binding, &world.view(), &catalog, 50)
            .expect_err("conflicting static and dynamic dataspace mappings must fail closed");
        assert!(
            error
                .to_string()
                .contains(crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE),
            "unexpected namespace mapping error: {error}"
        );
    }
}
#[test]
fn release_yank_rejects_decoded_empty_reason_before_state_lookup() {
    let release = MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            iroha_model_base::topology::DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "validation".parse().expect("package name"),
        ),
        "1.0.0".parse().expect("release version"),
    );
    let canonical = SetMusubiReleaseYankV1::new(
        release,
        true,
        MusubiReasonV1::new("valid reason").expect("reason"),
        1,
    );
    let json = norito::json::to_json(&canonical).expect("serialize yank request");
    let hostile = json.replacen("valid reason", "", 1);
    assert_ne!(hostile, json, "reason fixture must be replaced");
    let decoded: SetMusubiReleaseYankV1 =
        norito::json::from_json(&hostile).expect("decode structurally valid hostile request");
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let error = decoded
        .execute(&account(44), &mut transaction)
        .expect_err("decoded empty reason must fail before the missing-release lookup");
    assert!(
        matches!(error, Error::InvalidParameter(_)),
        "unexpected decoded-yank rejection: {error}"
    );
}
#[test]
fn parliament_consumption_records_server_execution_height() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(GOVERNANCE_EXECUTION_HEIGHT)
            .expect("nonzero governance fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let minimum_enactment_delay = transaction.gov.min_enactment_delay;
    let decision = MusubiGovernanceDecisionV1 {
        decision_id: [0x91; 32],
        action_digest: MusubiGovernanceActionDigestV1::new([0x92; 32]),
        enacted_at_height: GOVERNANCE_EXECUTION_HEIGHT
            .checked_sub(minimum_enactment_delay.max(1))
            .expect("governance fixture height exceeds its minimum delay"),
        execute_after_height: GOVERNANCE_EXECUTION_HEIGHT,
    };
    consume_parliament_decision(decision, &mut transaction)
        .expect("valid decision is consumed at the server block height");
    let consumed = transaction
        .world
        .musubi_governance_decisions
        .get(&decision.decision_id)
        .expect("decision consumption retained");
    assert_eq!(consumed.decision, decision);
    assert_eq!(consumed.minimum_enactment_delay, minimum_enactment_delay);
    assert_eq!(consumed.consumed_at_height, GOVERNANCE_EXECUTION_HEIGHT);
}
#[test]
fn proposal_fingerprint_mismatch_is_rejected_before_recovery_mutation() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(GOVERNANCE_EXECUTION_HEIGHT)
            .expect("nonzero governance fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let package = package("fingerprint-guard");
    let old_owner = account(81);
    let replacement = account(82);
    seed_package_owner(&package, &old_owner, 1, &mut transaction);
    let action = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
        package: package.clone(),
        owners: vec![replacement.clone()],
        expected_revision: 1,
    });
    let wrong_id = [0xA5; 32];
    let kind = ProposalKind::MusubiRegistryGovernance(action.clone());
    assert_ne!(wrong_id, kind.fingerprint());
    let decision = decision_for_current_block(wrong_id, &action, &transaction);
    insert_enacted_proposal(wrong_id, kind, decision.enacted_at_height, &mut transaction);
    let error = RecoverMusubiPackageV1 {
        decision,
        package: package.clone(),
        owners: vec![replacement.clone()],
        expected_governance_revision: 1,
    }
    .execute(&account(83), &mut transaction)
    .expect_err("a proposal stored under a non-fingerprint key must fail closed");
    assert!(error.to_string().contains("fingerprint"), "{error}");
    let persisted = transaction
        .world
        .musubi_packages
        .get(&package)
        .expect("seeded package remains");
    assert_eq!(persisted.owners, vec![old_owner]);
    assert_eq!(persisted.revisions.governance, 1);
    assert!(
        transaction
            .world
            .musubi_package_members
            .get(&MusubiPackageMemberKeyV1::new(package, replacement))
            .is_none()
    );
    assert!(
        transaction
            .world
            .musubi_governance_decisions
            .get(&wrong_id)
            .is_none()
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn owner_recovery_binds_consumption_state_event_and_rejects_replay() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(GOVERNANCE_EXECUTION_HEIGHT)
            .expect("nonzero governance fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let package = package("recovery-proof");
    let old_owner = account(84);
    seed_package_owner(&package, &old_owner, 1, &mut transaction);
    let mut replacement_owners = vec![account(86), account(85)];
    replacement_owners.sort();
    replacement_owners.dedup();
    let action = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
        package: package.clone(),
        owners: replacement_owners.clone(),
        expected_revision: 1,
    });
    let decision = seed_enacted_decision(&action, &mut transaction);
    RecoverMusubiPackageV1 {
        decision,
        package: package.clone(),
        owners: replacement_owners.clone(),
        expected_governance_revision: 1,
    }
    .execute(&account(87), &mut transaction)
    .expect("canonical owner recovery executes");
    let consumption = *transaction
        .world
        .musubi_governance_decisions
        .get(&decision.decision_id)
        .expect("decision consumption retained");
    assert_eq!(consumption.decision, decision);
    assert_eq!(consumption.consumed_at_height, GOVERNANCE_EXECUTION_HEIGHT);
    let persisted = transaction
        .world
        .musubi_packages
        .get(&package)
        .cloned()
        .expect("recovered package retained");
    assert_eq!(persisted.owners, replacement_owners);
    assert_eq!(persisted.member_accounts, replacement_owners);
    assert_eq!(persisted.revisions.governance, 2);
    for owner in &replacement_owners {
        let member = transaction
            .world
            .musubi_package_members
            .get(&MusubiPackageMemberKeyV1::new(
                package.clone(),
                owner.clone(),
            ))
            .expect("recovered owner member retained");
        assert_eq!(member.role, MusubiPackageRoleV1::Owner);
        assert_eq!(member.governance_revision, 2);
        assert_eq!(member.accepted_at_height, consumption.consumed_at_height);
    }
    assert!(
        transaction
            .world
            .musubi_package_members
            .get(&MusubiPackageMemberKeyV1::new(package.clone(), old_owner))
            .is_none()
    );
    let events = take_musubi_events(&mut transaction);
    let [MusubiEvent::PackageRecovered(event)] = events.as_slice() else {
        panic!("expected exactly one package-recovery event: {events:?}");
    };
    assert_eq!(event.package, package);
    assert_eq!(event.action_digest, consumption.decision.action_digest);
    assert_eq!(event.finalized_height, consumption.consumed_at_height);
    assert_eq!(event.governance_revision, persisted.revisions.governance);
    assert_eq!(usize::from(event.owner_count), persisted.owners.len());
    let replay_error = RecoverMusubiPackageV1 {
        decision,
        package: package.clone(),
        owners: replacement_owners,
        expected_governance_revision: 1,
    }
    .execute(&account(87), &mut transaction)
    .expect_err("the same Parliament decision cannot be replayed");
    assert!(replay_error.to_string().contains("already consumed"));
    assert_eq!(
        transaction.world.musubi_packages.get(&package),
        Some(&persisted)
    );
    assert_eq!(
        transaction
            .world
            .musubi_governance_decisions
            .get(&decision.decision_id),
        Some(&consumption)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn artifact_takedown_binds_state_resolver_directory_consumption_event_and_rejects_replay() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(GOVERNANCE_EXECUTION_HEIGHT)
            .expect("nonzero governance fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let archive = retention_archive(91);
    let archive_id = archive.archive_id;
    let source_digest = archive.commitment.source_tree_digest;
    let initial_release = retention_release(
        archive_id,
        "1.0.0",
        false,
        MusubiArtifactGovernanceStateV1::Available,
    );
    initial_release
        .validate()
        .expect("initial release fixture is valid");
    let release_id = initial_release.manifest.release.clone();
    let package = release_id.package.clone();
    seed_package_owner(&package, &account(92), 1, &mut transaction);
    let initial_index_revision = transaction.world.musubi_resolver_index_revision.get().get();
    let expected_index_revision = initial_index_revision
        .checked_add(1)
        .expect("fixture resolver revision has a successor");
    let initial_row = MusubiResolverReleaseRowV1 {
        release: release_id.clone(),
        release_digest: initial_release.release_digest,
        archive_id,
        source_digest,
        interface_digest: initial_release.manifest.interface_digest,
        abi: initial_release.manifest.abi,
        dependencies: initial_release.manifest.dependencies.clone(),
        selection: MusubiReleaseSelectionStateV1 {
            yank: initial_release.yank.clone(),
            storage: MusubiArchiveAvailabilityV1 {
                archive_id,
                availability: MusubiStorageAvailabilityV1::Selectable,
                healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                active_locations: 1,
                finalized_height: 1,
                finalized_block_hash: [0xB1; 32],
                index_revision: initial_index_revision,
            },
            governance: MusubiArtifactGovernanceStateV1::Available,
        },
        index_revision: initial_index_revision,
    };
    initial_row
        .validate()
        .expect("initial resolver row is fresh-selectable");
    transaction
        .world
        .musubi_releases
        .insert(release_id.clone(), initial_release.clone());
    transaction
        .world
        .musubi_resolver_index
        .insert(release_id.clone(), initial_row.clone());
    let (namespace, metadata_revision) = {
        let package_record = transaction
            .world
            .musubi_packages
            .get(&package)
            .expect("seeded package remains available");
        (
            package_record.claimed_namespace.clone(),
            package_record.revisions.metadata,
        )
    };
    let selector = MusubiPackageSelectorV1 {
        namespace,
        name: package.name.clone(),
    };
    let initial_directory = MusubiOrderedPackageEntryV1 {
        selector: selector.clone(),
        package: package.clone(),
        latest_selectable: Some(release_id.version.clone()),
        metadata_revision,
        index_revision: initial_index_revision,
    };
    initial_directory
        .validate()
        .expect("initial directory fixture is valid");
    transaction
        .world
        .musubi_public_directory
        .insert(selector.clone(), initial_directory);
    let reason: MusubiReasonV1 = "governed security response"
        .parse()
        .expect("bounded takedown reason");
    let action = MusubiParliamentActionV1::TakedownArtifact(MusubiTakedownArtifactActionV1 {
        release: release_id.clone(),
        reason: reason.clone(),
        expected_artifact_governance_revision: 1,
    });
    let decision = seed_enacted_decision(&action, &mut transaction);
    let minimum_enactment_delay = transaction.gov.min_enactment_delay;
    SetMusubiArtifactTakedownV1 {
        decision,
        release: release_id.clone(),
        reason: reason.clone(),
        expected_artifact_governance_revision: 1,
    }
    .execute(&account(93), &mut transaction)
    .expect("canonical artifact takedown executes");
    let expected_governance =
        MusubiArtifactGovernanceStateV1::TakenDown(MusubiArtifactTakedownV1 {
            action_digest: decision.action_digest,
            reason: reason.clone(),
            applied_at_height: GOVERNANCE_EXECUTION_HEIGHT,
        });
    let mut expected_release = initial_release;
    expected_release.artifact_governance = expected_governance.clone();
    expected_release.revisions.artifact_governance = 2;
    let mut expected_row = initial_row;
    expected_row.selection.governance = expected_governance;
    expected_row.index_revision = expected_index_revision;
    let expected_directory = MusubiOrderedPackageEntryV1 {
        selector: selector.clone(),
        package: package.clone(),
        latest_selectable: None,
        metadata_revision,
        index_revision: expected_index_revision,
    };
    let expected_consumption = MusubiGovernanceDecisionConsumptionV1 {
        decision,
        minimum_enactment_delay,
        consumed_at_height: GOVERNANCE_EXECUTION_HEIGHT,
    };
    assert!(decision.enacted_at_height < decision.execute_after_height);
    assert!(decision.execute_after_height <= expected_consumption.consumed_at_height);
    assert_eq!(
        transaction.world.musubi_releases.get(&release_id),
        Some(&expected_release)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index.get(&release_id),
        Some(&expected_row)
    );
    assert_eq!(
        transaction.world.musubi_public_directory.get(&selector),
        Some(&expected_directory)
    );
    assert_eq!(
        transaction
            .world
            .musubi_governance_decisions
            .get(&decision.decision_id),
        Some(&expected_consumption)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        expected_index_revision
    );
    assert_eq!(
        take_musubi_events(&mut transaction),
        vec![MusubiEvent::ArtifactTakenDown(
            MusubiArtifactTakedownEventV1 {
                release: release_id.clone(),
                archive_id,
                action_digest: decision.action_digest,
                governance_revision: 2,
                finalized_height: GOVERNANCE_EXECUTION_HEIGHT,
            }
        )]
    );
    let replay_error = SetMusubiArtifactTakedownV1 {
        decision,
        release: release_id.clone(),
        reason,
        expected_artifact_governance_revision: 1,
    }
    .execute(&account(93), &mut transaction)
    .expect_err("the same artifact takedown decision cannot be replayed");
    assert!(replay_error.to_string().contains("already consumed"));
    assert_eq!(
        transaction.world.musubi_releases.get(&release_id),
        Some(&expected_release)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index.get(&release_id),
        Some(&expected_row)
    );
    assert_eq!(
        transaction.world.musubi_public_directory.get(&selector),
        Some(&expected_directory)
    );
    assert_eq!(
        transaction
            .world
            .musubi_governance_decisions
            .get(&decision.decision_id),
        Some(&expected_consumption)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        expected_index_revision
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn empty_maintainer_role_and_revision_overflow_fail_closed() {
    let empty = MusubiMaintainerPermissionsV1 {
        publish: false,
        yank: false,
        metadata: false,
        archive_locations: false,
    };
    assert!(validate_role(MusubiPackageRoleV1::Maintainer(empty)).is_err());
    assert!(next_revision(u64::MAX, "test").is_err());
}
