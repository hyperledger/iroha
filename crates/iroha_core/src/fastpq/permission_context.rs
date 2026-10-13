//! Exact execution permission context using original-pool funded sort backing.
//!
//! The committed bytes equal the existing permission-table convention. This is
//! role/permission/epoch context only, never account membership or authorization.
//! Bare field encoding and the final digest stream without output-sized frames;
//! serializer-internal scratch remains its serializer's separate obligation.

use iroha_allocation::{AllocationBudget, AllocationReservation, ChargedBuffer};
use iroha_crypto::Hash;
use iroha_data_model::role::{Role, RoleId};

use super::{PERMISSION_TABLE_ROOT_DOMAIN, PermissionTableEntry};

/// Finite refusal before publishing a source-context commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermissionContextError {
    /// Checked size, original pool or exact physical backing admission failed.
    Capacity,
    /// Canonical field encoding failed; no partial digest is returned.
    Encoding,
}

/// Exact sort backing demand before any source capture allocation.
pub(crate) fn permission_table_backing_layout<'a, I>(
    roles: I,
) -> Result<std::alloc::Layout, PermissionContextError>
where
    I: IntoIterator<Item = (&'a RoleId, &'a Role)>,
{
    let count = roles.into_iter().try_fold(0usize, |count, (_, role)| {
        count
            .checked_add(role.permissions.len())
            .ok_or(PermissionContextError::Capacity)
    })?;
    std::alloc::Layout::array::<PermissionTableEntry>(count)
        .map_err(|_| PermissionContextError::Capacity)
}

/// Commit the exact original role table without uncharged sort/payload buffers.
///
/// `roles` must borrow the same immutable table for both passes. Count drift is
/// refused even for a caller that violates that contract using interior state.
/// The only new explicit allocation is the exact fixed sort backing, acquired
/// from `budget` before construction and released before this function returns.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: connect funded permission-context capture to finalized proof preparation; preserve exact original-pool sort admission"
    )
)]
pub(crate) fn funded_permission_table_root<'a, I>(
    roles: impl Fn() -> I,
    budget: &AllocationBudget,
) -> Result<[u8; 32], PermissionContextError>
where
    I: IntoIterator<Item = (&'a RoleId, &'a Role)>,
{
    let layout = permission_table_backing_layout(roles())?;
    let mut reservation = budget
        .try_reserve(layout)
        .map_err(|_| PermissionContextError::Capacity)?;
    let root = prepaid_permission_table_root(roles, &mut reservation)?;
    if reservation.remaining_bytes() != 0 {
        return Err(PermissionContextError::Encoding);
    }
    Ok(root)
}

/// Retain fixed internal identity for the original permission table traversal.
/// The public sorted root remains the existing canonical commitment. This local
/// seal adds no public input and creates no authority from supplied tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PermissionContextSeal {
    root: [u8; 32],
    traversal: [u8; 32],
    count: usize,
}
impl PermissionContextSeal {
    pub(crate) fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Re-read the same original canonical table iteration without sort storage.
    /// A different traversal is conservatively refused even if its sorted root
    /// could coincide; source callers always use the original State role map.
    pub(crate) fn matches<'a, I>(&self, roles: I) -> Result<bool, PermissionContextError>
    where
        I: IntoIterator<Item = (&'a RoleId, &'a Role)>,
    {
        let mut count = 0usize;
        let traversal = Hash::new_from_writer(|writer| {
            writer.write_all(b"iroha:fastpq:permission-context-retention:v1\0")?;
            for (role_id, role) in roles {
                let role_bytes = hash_bare(role_id).map_err(|_| std::io::ErrorKind::InvalidData)?;
                for permission in &role.permissions {
                    count = count
                        .checked_add(1)
                        .ok_or(std::io::ErrorKind::InvalidData)?;
                    writer.write_all(&role_bytes)?;
                    writer.write_all(
                        &hash_bare(permission).map_err(|_| std::io::ErrorKind::InvalidData)?,
                    )?;
                    writer.write_all(
                        &role
                            .permission_epoch(permission)
                            .unwrap_or_default()
                            .to_le_bytes(),
                    )?;
                }
            }
            writer.write_all(
                &u64::try_from(count)
                    .map_err(|_| std::io::ErrorKind::InvalidData)?
                    .to_le_bytes(),
            )
        })
        .map(<[u8; 32]>::from)
        .map_err(|_| PermissionContextError::Encoding)?;
        Ok(count == self.count && traversal == self.traversal)
    }
}

/// Consume exact original backing and return the unchanged public sorted root.
pub(crate) fn prepaid_permission_table_root<'a, I>(
    roles: impl Fn() -> I,
    reservation: &mut AllocationReservation,
) -> Result<[u8; 32], PermissionContextError>
where
    I: IntoIterator<Item = (&'a RoleId, &'a Role)>,
{
    prepaid_permission_table_seal(roles, reservation).map(|sealed| sealed.root())
}

/// Derive the public root and private traversal seal from the same original
/// admitted entries; fixed sort scratch is released before return.
pub(crate) fn prepaid_permission_table_seal<'a, I>(
    roles: impl Fn() -> I,
    reservation: &mut AllocationReservation,
) -> Result<PermissionContextSeal, PermissionContextError>
where
    I: IntoIterator<Item = (&'a RoleId, &'a Role)>,
{
    let count = roles().into_iter().try_fold(0usize, |count, (_, role)| {
        count
            .checked_add(role.permissions.len())
            .ok_or(PermissionContextError::Capacity)
    })?;
    let wire_count = u64::try_from(count).map_err(|_| PermissionContextError::Capacity)?;
    let mut entries = ChargedBuffer::from_reservation(count, reservation)
        .map_err(|_| PermissionContextError::Capacity)?;
    for (role_id, role) in roles() {
        let role_bytes = hash_bare(role_id)?;
        for permission in &role.permissions {
            entries
                .try_push(PermissionTableEntry {
                    role_bytes,
                    permission_bytes: hash_bare(permission)?,
                    epoch_bytes: role
                        .permission_epoch(permission)
                        .unwrap_or_default()
                        .to_le_bytes(),
                })
                .map_err(|_| PermissionContextError::Capacity)?;
        }
    }
    if entries.as_slice().len() != count {
        return Err(PermissionContextError::Encoding);
    }
    let traversal = Hash::new_from_writer(|writer| {
        writer.write_all(b"iroha:fastpq:permission-context-retention:v1\0")?;
        for entry in entries.as_slice() {
            writer.write_all(&entry.role_bytes)?;
            writer.write_all(&entry.permission_bytes)?;
            writer.write_all(&entry.epoch_bytes)?;
        }
        writer.write_all(&wire_count.to_le_bytes())
    })
    .map(<[u8; 32]>::from)
    .map_err(|_| PermissionContextError::Encoding)?;
    if count == 0 {
        return Ok(PermissionContextSeal {
            root: [0; 32],
            traversal,
            count,
        });
    }
    entries.as_mut_slice().sort_unstable_by_key(|entry| {
        (entry.role_bytes, entry.permission_bytes, entry.epoch_bytes)
    });
    let root = Hash::new_from_writer(|writer| {
        writer.write_all(PERMISSION_TABLE_ROOT_DOMAIN)?;
        writer.write_all(&wire_count.to_le_bytes())?;
        for entry in entries.as_slice() {
            writer.write_all(&entry.role_bytes)?;
            writer.write_all(&entry.permission_bytes)?;
            writer.write_all(&entry.epoch_bytes)?;
        }
        Ok(())
    })
    .map(Into::into)
    .map_err(|_| PermissionContextError::Encoding)?;
    Ok(PermissionContextSeal {
        root,
        traversal,
        count,
    })
}

fn hash_bare<T: norito::SerializePayload>(value: &T) -> Result<[u8; 32], PermissionContextError> {
    Hash::new_from_writer(|mut writer| {
        norito::codec::encode_adaptive_into(value, &mut writer)
            .map(|_| ())
            .map_err(|_| std::io::Error::other("permission context encoding failed"))
    })
    .map(Into::into)
    .map_err(|_| PermissionContextError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{Registrable, permission::Permission};
    use iroha_primitives::json::Json;
    use iroha_test_samples::ALICE_ID;
    use norito::codec::Encode;

    #[test]
    fn original_permission_bytes_order_epoch_and_exact_backing_are_preserved() {
        let permission = Permission::new("test_permission".to_owned(), Json::new(()));
        let make = |id: &str, epoch| {
            let id: RoleId = id.parse().unwrap();
            let role = Role::new(id.clone(), ALICE_ID.clone())
                .add_permission_with_epoch(permission.clone(), epoch)
                .build(&ALICE_ID);
            (id, role)
        };
        let roles = [make("first", 0), make("second", 7)];
        let required = std::alloc::Layout::array::<PermissionTableEntry>(roles.len())
            .unwrap()
            .size();
        let short = AllocationBudget::new(required - 1);
        assert_eq!(
            funded_permission_table_root(|| roles.iter().map(|(id, role)| (id, role)), &short),
            Err(PermissionContextError::Capacity)
        );
        assert_eq!(short.peak_reserved_bytes(), 0);
        let exact = AllocationBudget::new(required);
        let forward =
            funded_permission_table_root(|| roles.iter().map(|(id, role)| (id, role)), &exact)
                .unwrap();
        assert_eq!(exact.peak_reserved_bytes(), required);
        assert_eq!(exact.reserved_bytes(), 0);
        assert_eq!(
            funded_permission_table_root(
                || roles.iter().rev().map(|(id, role)| (id, role)),
                &exact
            )
            .unwrap(),
            forward
        );
        assert_eq!(
            super::super::permission_table_root(roles.iter().map(|(id, role)| (id, role))),
            forward
        );
        assert_eq!(roles[0].1.permission_epoch(&permission), None);
        assert_eq!(roles[1].1.permission_epoch(&permission), Some(7));
        let mut records: Vec<_> = roles
            .iter()
            .zip([0_u64, 7])
            .map(|((id, role), epoch)| {
                assert_eq!(
                    role.permission_epoch(&permission).unwrap_or_default(),
                    epoch
                );
                (
                    Hash::new(id.encode()),
                    Hash::new(permission.encode()),
                    epoch,
                )
            })
            .collect();
        records.sort_unstable_by_key(|(id, permission, epoch)| {
            (*id, *permission, epoch.to_le_bytes())
        });
        let mut original = PERMISSION_TABLE_ROOT_DOMAIN.to_vec();
        original.extend_from_slice(&2u64.to_le_bytes());
        for (id, permission, epoch) in records {
            original.extend_from_slice(id.as_ref());
            original.extend_from_slice(permission.as_ref());
            original.extend_from_slice(&epoch.to_le_bytes());
        }
        assert_eq!(forward, <[u8; 32]>::from(Hash::new(original)));
        assert_eq!(
            funded_permission_table_root(std::iter::empty, &AllocationBudget::new(0)).unwrap(),
            [0; 32]
        );
    }

    #[test]
    fn changed_role_source_count_refuses_without_leaking_original_credit() {
        let id: RoleId = "one".parse().unwrap();
        let role = Role::new(id.clone(), ALICE_ID.clone())
            .add_permission(Permission::new("one_permission".to_owned(), Json::new(())))
            .build(&ALICE_ID);
        for grow in [false, true] {
            let calls = std::cell::Cell::new(0usize);
            let budget = AllocationBudget::new(1024);
            let result = funded_permission_table_root(
                || {
                    let call = calls.get();
                    calls.set(call + 1);
                    std::iter::repeat_n((&id, &role), usize::from((call == 0) != grow))
                },
                &budget,
            );
            assert!(result.is_err());
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
    #[test]
    fn retained_permission_identity_rechecks_without_admission_or_sort_backing() {
        let permission = Permission::new("retained_permission".to_owned(), Json::new(()));
        let make = |name: &str, epoch| {
            let id: RoleId = name.parse().unwrap();
            let role = Role::new(id.clone(), ALICE_ID.clone())
                .add_permission_with_epoch(permission.clone(), epoch)
                .build(&ALICE_ID);
            (id, role)
        };
        let roles = [make("first", 0), make("second", 7)];
        let layout =
            permission_table_backing_layout(roles.iter().map(|(id, role)| (id, role))).unwrap();
        let budget = AllocationBudget::new(layout.size());
        let mut reserved = budget.try_reserve(layout).unwrap();
        let sealed = prepaid_permission_table_seal(
            || roles.iter().map(|(id, role)| (id, role)),
            &mut reserved,
        )
        .unwrap();
        assert_eq!(reserved.remaining_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            sealed.root(),
            super::super::permission_table_root(roles.iter().map(|(id, role)| (id, role)))
        );
        let occupied = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        assert!(
            sealed
                .matches(roles.iter().map(|(id, role)| (id, role)))
                .unwrap()
        );
        assert!(
            !sealed
                .matches(roles[..1].iter().map(|(id, role)| (id, role)))
                .unwrap()
        );
        assert!(
            !sealed
                .matches(roles.iter().rev().map(|(id, role)| (id, role)))
                .unwrap()
        );
        let changed = [make("first", 0), make("second", 8)];
        assert!(
            !sealed
                .matches(changed.iter().map(|(id, role)| (id, role)))
                .unwrap()
        );
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
