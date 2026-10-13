//! Exact Musubi secondary-index checks across both retained World cuts.

use super::*;

fn invalid(cut: &str, field: &str, reason: &str) -> json::Error {
    invalid_musubi_state(field, format!("{cut} World cut: {reason}"))
}

fn validate_maintainer_cut(
    members: &impl StorageReadOnly<MusubiPackageMemberKeyV1, MusubiPackageMemberV1>,
    invitations: &impl StorageReadOnly<MusubiInviteIdV1, MusubiMaintainerInvitationV1>,
    directory: &impl StorageReadOnly<MusubiMaintainerDirectoryKeyV1, MusubiMaintainerDirectoryEntryV1>,
    cut: &str,
) -> Result<(), json::Error> {
    const FIELD: &str = "musubi_maintainer_directory";
    for (key, member) in members.iter() {
        if key != &member.key() {
            return Err(invalid(cut, FIELD, "member key disagrees with its record"));
        }
        let directory_key = MusubiMaintainerDirectoryKeyV1::accepted(
            member.package.clone(),
            member.account.clone(),
        );
        if !matches!(
            directory.get(&directory_key),
            Some(MusubiMaintainerDirectoryEntryV1::Accepted(indexed)) if indexed == member
        ) {
            return Err(invalid(
                cut,
                FIELD,
                "member lacks its exact accepted directory row",
            ));
        }
    }
    for (id, invitation) in invitations.iter() {
        if id != &invitation.invite_id {
            return Err(invalid(
                cut,
                FIELD,
                "invitation key disagrees with its record",
            ));
        }
        let directory_key = MusubiMaintainerDirectoryKeyV1::pending(
            invitation.package.clone(),
            invitation.invited_account.clone(),
            invitation.invite_id,
        );
        let indexed = directory.get(&directory_key);
        if invitation.state == iroha_data_model::musubi::MusubiInvitationStateV1::Pending {
            if !matches!(
                indexed,
                Some(MusubiMaintainerDirectoryEntryV1::PendingInvitation(stored))
                    if stored == invitation
            ) {
                return Err(invalid(
                    cut,
                    FIELD,
                    "pending invitation lacks its exact directory row",
                ));
            }
        } else if indexed.is_some() {
            return Err(invalid(
                cut,
                FIELD,
                "non-pending invitation remains in the directory",
            ));
        }
    }
    // The canonical key sorts by package first, so one counter covers the
    // pending-invitation bound without allocating a second directory.
    let mut current_package = None;
    let mut pending_count = 0_usize;
    for (key, entry) in directory.iter() {
        if current_package != Some(&key.package) {
            current_package = Some(&key.package);
            pending_count = 0;
        }
        if key != &entry.key() {
            return Err(invalid(
                cut,
                FIELD,
                "directory key disagrees with its entry",
            ));
        }
        entry
            .validate()
            .map_err(|_| invalid(cut, FIELD, "invalid directory entry"))?;
        let exact_source = match entry {
            MusubiMaintainerDirectoryEntryV1::Accepted(member) => members
                .get(&member.key())
                .is_some_and(|source| source == member),
            MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation) => {
                pending_count += 1;
                if pending_count > MUSUBI_MAX_PENDING_INVITATIONS_V1 {
                    return Err(invalid(cut, FIELD, "pending-invitation bound exceeded"));
                }
                invitations
                    .get(&invitation.invite_id)
                    .is_some_and(|source| source == invitation)
            }
        };
        if !exact_source {
            return Err(invalid(
                cut,
                FIELD,
                "directory entry has no exact source row",
            ));
        }
    }
    Ok(())
}

fn validate_archive_cut(
    archives: &impl StorageReadOnly<ArchiveId, MusubiArchiveRecordV1>,
    releases: &impl StorageReadOnly<MusubiReleaseIdV1, MusubiReleaseRecordV1>,
    availability: &impl StorageReadOnly<ArchiveId, MusubiArchiveAvailabilityV1>,
    references: &impl StorageReadOnly<ArchiveId, MusubiArchiveReverseReferencesV1>,
    shortfall_releases: u64,
    cut: &str,
) -> Result<(), json::Error> {
    const REFERENCES: &str = "musubi_archive_reverse_references";
    const SHORTFALL: &str = "musubi_replication_shortfall_releases";
    for (archive_id, row) in references.iter() {
        if archive_id != &row.archive_id || archives.get(archive_id).is_none() {
            return Err(invalid(
                cut,
                REFERENCES,
                "reverse-reference row has no exact archive",
            ));
        }
        row.validate()
            .map_err(|_| invalid(cut, REFERENCES, "invalid reverse-reference row"))?;
        for release_id in &row.releases {
            if releases
                .get(release_id)
                .is_none_or(|release| release.manifest.archive_id != *archive_id)
            {
                return Err(invalid(
                    cut,
                    REFERENCES,
                    "reverse reference has no exact release",
                ));
            }
        }
    }
    for (archive_id, _) in archives.iter() {
        if references.get(archive_id).is_none() {
            return Err(invalid(
                cut,
                REFERENCES,
                "archive lacks its reverse-reference row",
            ));
        }
        if availability.get(archive_id).is_none() {
            return Err(invalid(
                cut,
                SHORTFALL,
                "archive lacks its availability row",
            ));
        }
    }
    for (archive_id, row) in availability.iter() {
        if archive_id != &row.archive_id || archives.get(archive_id).is_none() {
            return Err(invalid(
                cut,
                SHORTFALL,
                "availability row has no exact archive",
            ));
        }
    }
    let mut expected_shortfall = 0_u64;
    for (release_id, release) in releases.iter() {
        let archive_id = &release.manifest.archive_id;
        let reverse = references.get(archive_id).ok_or_else(|| {
            invalid(
                cut,
                REFERENCES,
                "release lacks its archive reverse-reference row",
            )
        })?;
        if reverse.releases.binary_search(release_id).is_err() {
            return Err(invalid(
                cut,
                REFERENCES,
                "release lacks its exact reverse reference",
            ));
        }
        let status = availability
            .get(archive_id)
            .ok_or_else(|| invalid(cut, SHORTFALL, "release lacks its archive availability row"))?;
        if status.availability != MusubiStorageAvailabilityV1::Selectable {
            expected_shortfall = expected_shortfall
                .checked_add(1)
                .ok_or_else(|| invalid(cut, SHORTFALL, "shortfall count overflows u64"))?;
        }
    }
    if shortfall_releases != expected_shortfall {
        return Err(invalid(
            cut,
            SHORTFALL,
            "shortfall count disagrees with exact releases",
        ));
    }
    Ok(())
}

/// Verify three secondary projections on the current and rollback-visible cuts.
pub(super) fn validate_musubi_derived_cuts(world: &World) -> Result<(), json::Error> {
    validate_maintainer_cut(
        &world.musubi_package_members.view(),
        &world.musubi_package_invitations.view(),
        &world.musubi_maintainer_directory.view(),
        "current",
    )?;
    validate_archive_cut(
        &world.musubi_archives.view(),
        &world.musubi_releases.view(),
        &world.musubi_archive_availability.view(),
        &world.musubi_archive_reverse_references.view(),
        *world.musubi_replication_shortfall_releases.view().get(),
        "current",
    )?;
    // Read-only rollback views preserve the retained undo logs after dropping.
    validate_maintainer_cut(
        &world.musubi_package_members.block_and_revert(),
        &world.musubi_package_invitations.block_and_revert(),
        &world.musubi_maintainer_directory.block_and_revert(),
        "predecessor",
    )?;
    validate_archive_cut(
        &world.musubi_archives.block_and_revert(),
        &world.musubi_releases.block_and_revert(),
        &world.musubi_archive_availability.block_and_revert(),
        &world.musubi_archive_reverse_references.block_and_revert(),
        world
            .musubi_replication_shortfall_releases
            .predecessor_view()
            .get()
            .unwrap_or_else(|| *world.musubi_replication_shortfall_releases.view().get()),
        "predecessor",
    )
}
