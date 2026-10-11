//! Fixed-field originals for an existing native ledger-wide reader at one certified cut.
//!
//! Only complete typed key sets and the requested account/fee values are exposed.
//! No projected query Account, synthetic rekey row, absent funding balance or
//! post-result value is substituted for a certified original. Returned references
//! stay under the locked World and original finite operation budget.

use super::*;
use iroha_data_model::{
    account::{
        AccountValue,
        rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
    },
    alias_setup::AccountAliasName,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetId, AssetValue},
    identifier::{IdentifierPolicy, IdentifierPolicyId},
    nexus::{
        FeeSponsorBudgetCounterKey, FeeSponsorEnrollment, FeeSponsorEnrollmentKey,
        FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramRevision,
        FeeSponsorProgramRevisionKey, FeeSponsorVault, FeeSponsorVaultKey,
    },
    ram_lfe::RamLfeProgramPolicy,
};
use iroha_model_base::topology::DataSpaceId;

const FEE_KEYS_LIMIT: usize = 16_384;
const ROW_BYTES_LIMIT: usize = 1024 * 1024;
// Three native Names are individually <=255 UTF-8 bytes. This explicit finite
// temporary bound covers canonical validation, their owned alias copies, the
// native literal roundtrip, selector and fixed 64-hex SNS key construction. It
// is admitted before any such temporary allocation and retained through callback.
const ACCOUNT_SELECTOR_TEMP_BYTES: usize = 16 * 1024;

type AccountOriginal<'a> = (
    &'a AccountId,
    &'a AccountRekeyRecord,
    &'a AccountValue,
    &'a [u8],
);

fn require_key(snapshot: &WorldStateSnapshotV1, field: &str, key: Hash) -> Result<(), String> {
    snapshot
        .entries
        .binary_search_by(|entry| {
            (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&(
                field,
                WorldStateElementKindV1::Table,
                Some(key),
            ))
        })
        .map(|_| ())
        .map_err(|_| {
            format!("World authority original {field} key differs from certified execution")
        })
}

fn complete_keys<'a, K: norito::codec::Encode + 'a>(
    snapshot: &WorldStateSnapshotV1,
    field: &str,
    count: usize,
    limit: usize,
    keys: impl Iterator<Item = &'a K>,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<&'a K>, String> {
    if count > limit {
        return Err(format!(
            "World authority original {field} key count exceeds its complete bound"
        ));
    }
    require_complete_table_count(snapshot, field, count)?;
    let mut originals = ChargedBuffer::new(count, budget).map_err(|error| error.to_string())?;
    for key in keys {
        if originals.as_slice().len() >= count {
            return Err("World authority original key count changed".into());
        }
        require_key(snapshot, field, hash_value(key)?)?;
        originals.push_reserved(key);
    }
    if originals.as_slice().len() != count {
        return Err("World authority original key set is incomplete".into());
    }
    Ok(originals)
}

fn require_row<K: norito::codec::Encode, V: norito::codec::Encode>(
    snapshot: &WorldStateSnapshotV1,
    field: &str,
    key: &K,
    value: &V,
) -> Result<(), String> {
    // Count the actual native payload without allocating another original buffer.
    let length = norito::codec::encode_adaptive_into(value, &mut std::io::sink())
        .map_err(|error| error.to_string())?;
    if length > ROW_BYTES_LIMIT {
        return Err(format!(
            "World authority original {field} row exceeds its bound"
        ));
    }
    require_target(
        snapshot,
        field,
        WorldStateElementKindV1::Table,
        Some(hash_value(key)?),
        hash_value(value)?,
    )
}

fn consume_account<T>(
    snapshot: &WorldStateSnapshotV1,
    world: &WorldBlock<'_>,
    name: &AccountAliasName,
    catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    budget: &AllocationBudget,
    consume: impl FnOnce(
        &WorldStateSnapshotV1,
        &AccountAlias,
        &[&AccountAlias],
        Option<AccountOriginal<'_>>,
    ) -> Result<T, String>,
) -> Result<T, String> {
    let _selector_charge = budget
        .try_reserve_bytes(ACCOUNT_SELECTOR_TEMP_BYTES)
        .map_err(|error| error.to_string())?;
    if !name.is_canonical() {
        return Err("World authority account alias is not canonical".into());
    }
    let entry = catalog
        .by_alias(name.dataspace.as_ref())
        .ok_or("World authority alias dataspace is not in the retained native catalog")?;
    if entry.id == DataSpaceId::UNIVERSAL {
        return Err("World authority account alias requires a native scoped dataspace".into());
    }
    let alias = AccountAlias::new(
        name.label.clone(),
        name.domain.clone().map(AccountAliasDomain::new),
        entry.id,
    );
    let literal = name.canonical_text();
    if alias
        .to_literal(catalog)
        .map_err(|error| error.to_string())?
        != literal
    {
        return Err("World authority account alias changed native catalog spelling".into());
    }
    let keys = complete_keys(
        snapshot,
        "world.account_aliases",
        world.account_aliases.iter().count(),
        MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
        world.account_aliases.iter().map(|(key, _)| key),
        budget,
    )?;
    let selected = match world.account_aliases.get(&alias) {
        None => None,
        Some(bound) => {
            require_row(snapshot, "world.account_aliases", &alias, bound)?;
            let rekey = world
                .account_rekey_records
                .get(&alias)
                .ok_or("World authority selected account rekey original is absent")?;
            if rekey.label != alias || &rekey.active_account_id != bound {
                return Err(
                    "World authority selected rekey original disagrees with native binding".into(),
                );
            }
            let account = world
                .accounts
                .get(bound)
                .ok_or("World authority selected bound account original is absent")?;
            let selector = crate::sns::selector_for_account_alias(&alias, catalog)
                .map_err(|error| error.to_string())?;
            let lease_key = crate::sns::record_storage_key(&selector);
            let lease = world
                .smart_contract_state
                .get(&lease_key)
                .ok_or("World authority selected account SNS original is absent")?;
            require_row(snapshot, "world.account_rekey_records", &alias, rekey)?;
            require_row(snapshot, "world.accounts", bound, account)?;
            require_row(snapshot, "world.smart_contract_state", &lease_key, lease)?;
            Some((bound, rekey, account, lease.as_slice()))
        }
    };
    consume(snapshot, &alias, keys.as_slice(), selected)
}

#[allow(clippy::too_many_arguments)]
fn consume_fee<T>(
    snapshot: &WorldStateSnapshotV1,
    world: &WorldBlock<'_>,
    program_id: &FeeSponsorProgramId,
    fee_asset: &AssetDefinitionId,
    budget: &AllocationBudget,
    consume: impl FnOnce(
        &WorldStateSnapshotV1,
        &[&AssetId],
        &[&FeeSponsorProgramId],
        &[&FeeSponsorProgramRevisionKey],
        &[&FeeSponsorEnrollmentKey],
        &[&FeeSponsorVaultKey],
        &[&FeeSponsorBudgetCounterKey],
        &AccountValue,
        &AssetDefinition,
        &AssetValue,
        Option<&FeeSponsorProgram>,
        &[&FeeSponsorProgramRevision],
        &[&FeeSponsorEnrollment],
        &[&FeeSponsorVault],
    ) -> Result<T, String>,
) -> Result<T, String> {
    let asset_keys = complete_keys(
        snapshot,
        "world.assets",
        world.assets.iter().count(),
        FEE_KEYS_LIMIT,
        world.assets.iter().map(|(key, _)| key),
        budget,
    )?;
    let program_keys = complete_keys(
        snapshot,
        "world.fee_sponsor_programs",
        world.fee_sponsor_programs.iter().count(),
        FEE_KEYS_LIMIT,
        world.fee_sponsor_programs.iter().map(|(key, _)| key),
        budget,
    )?;
    let revision_keys = complete_keys(
        snapshot,
        "world.fee_sponsor_program_revisions",
        world.fee_sponsor_program_revisions.iter().count(),
        FEE_KEYS_LIMIT,
        world
            .fee_sponsor_program_revisions
            .iter()
            .map(|(key, _)| key),
        budget,
    )?;
    let enrollment_keys = complete_keys(
        snapshot,
        "world.fee_sponsor_enrollments",
        world.fee_sponsor_enrollments.iter().count(),
        FEE_KEYS_LIMIT,
        world.fee_sponsor_enrollments.iter().map(|(key, _)| key),
        budget,
    )?;
    let vault_keys = complete_keys(
        snapshot,
        "world.fee_sponsor_vaults",
        world.fee_sponsor_vaults.iter().count(),
        FEE_KEYS_LIMIT,
        world.fee_sponsor_vaults.iter().map(|(key, _)| key),
        budget,
    )?;
    let counter_keys = complete_keys(
        snapshot,
        "world.fee_sponsor_budget_counters",
        world.fee_sponsor_budget_counters.iter().count(),
        FEE_KEYS_LIMIT,
        world.fee_sponsor_budget_counters.iter().map(|(key, _)| key),
        budget,
    )?;
    let sponsor = world
        .accounts
        .get(&program_id.sponsor)
        .ok_or("World authority funding sponsor account original is absent")?;
    let definition = world
        .asset_definitions
        .get(fee_asset)
        .ok_or("World authority funding definition original is absent")?;
    if definition.balance_scope_policy() != AssetBalancePolicy::Global {
        return Err("World authority funding definition must have exact Global policy".into());
    }
    // Borrow the actual stored key instead of manufacturing an AssetId or amount.
    let (source_key, source) = world
        .assets
        .iter()
        .find(|(key, _)| {
            key.account() == &program_id.sponsor
                && key.definition() == fee_asset
                && key.scope() == &AssetBalanceScope::Global
        })
        .ok_or("World authority funding Global bucket original is absent; absence is not zero")?;
    require_row(snapshot, "world.accounts", &program_id.sponsor, sponsor)?;
    require_row(snapshot, "world.asset_definitions", fee_asset, definition)?;
    require_row(snapshot, "world.assets", source_key, source)?;
    let program = world.fee_sponsor_programs.get(program_id);
    if let Some(program) = program {
        if &program.id != program_id {
            return Err("World authority selected program original identity differs".into());
        }
        require_row(snapshot, "world.fee_sponsor_programs", program_id, program)?;
    }
    let mut revisions = ChargedBuffer::new(
        revision_keys
            .as_slice()
            .iter()
            .filter(|key| &key.program_id == program_id)
            .count(),
        budget,
    )
    .map_err(|error| error.to_string())?;
    let mut enrollments = ChargedBuffer::new(
        enrollment_keys
            .as_slice()
            .iter()
            .filter(|key| &key.program_id == program_id)
            .count(),
        budget,
    )
    .map_err(|error| error.to_string())?;
    let mut vaults = ChargedBuffer::new(
        vault_keys
            .as_slice()
            .iter()
            .filter(|key| &key.program_id == program_id)
            .count(),
        budget,
    )
    .map_err(|error| error.to_string())?;
    for (key, value) in world
        .fee_sponsor_program_revisions
        .iter()
        .filter(|(key, _)| &key.program_id == program_id)
    {
        if value.program_id != key.program_id || value.revision != key.revision {
            return Err(
                "World authority revision original differs from its actual native key".into(),
            );
        }
        require_row(snapshot, "world.fee_sponsor_program_revisions", key, value)?;
        revisions.push_reserved(value);
    }
    for (key, value) in world
        .fee_sponsor_enrollments
        .iter()
        .filter(|(key, _)| &key.program_id == program_id)
    {
        if &value.key != key {
            return Err(
                "World authority enrollment original differs from its actual native key".into(),
            );
        }
        require_row(snapshot, "world.fee_sponsor_enrollments", key, value)?;
        enrollments.push_reserved(value);
    }
    for (key, value) in world
        .fee_sponsor_vaults
        .iter()
        .filter(|(key, _)| &key.program_id == program_id)
    {
        if &value.key != key {
            return Err("World authority vault original differs from its actual native key".into());
        }
        require_row(snapshot, "world.fee_sponsor_vaults", key, value)?;
        vaults.push_reserved(value);
    }
    consume(
        snapshot,
        asset_keys.as_slice(),
        program_keys.as_slice(),
        revision_keys.as_slice(),
        enrollment_keys.as_slice(),
        vault_keys.as_slice(),
        counter_keys.as_slice(),
        sponsor,
        definition,
        source,
        program,
        revisions.as_slice(),
        enrollments.as_slice(),
        vaults.as_slice(),
    )
}

fn consume_identifier<T>(
    snapshot: &WorldStateSnapshotV1,
    world: &WorldBlock<'_>,
    policy_id: &IdentifierPolicyId,
    budget: &AllocationBudget,
    consume: impl FnOnce(
        &WorldStateSnapshotV1,
        &IdentifierPolicy,
        &RamLfeProgramPolicy,
    ) -> Result<T, String>,
) -> Result<T, String> {
    // Two bounded native Names, their canonical literal and parse temporaries.
    // Keep this reservation through the borrowed callback/response encoding.
    let _selector_charge = budget.try_reserve_bytes(4096).map_err(|e| e.to_string())?;
    let parsed = policy_id
        .to_string()
        .parse::<IdentifierPolicyId>()
        .map_err(|e| e.to_string())?;
    if &parsed != policy_id {
        return Err("World authority identifier policy id is not canonical".into());
    }
    let policy = world
        .identifier_policies
        .get(policy_id)
        .ok_or("World authority selected identifier policy original is absent")?;
    if &policy.id != policy_id {
        return Err("World authority identifier policy differs from its actual key".into());
    }
    let program = world
        .ram_lfe_program_policies
        .get(&policy.program_id)
        .ok_or("World authority selected identifier program original is absent")?;
    if program.program_id != policy.program_id {
        return Err("World authority identifier program differs from its actual key".into());
    }
    require_row(snapshot, "world.identifier_policies", policy_id, policy)?;
    require_row(
        snapshot,
        "world.ram_lfe_program_policies",
        &policy.program_id,
        program,
    )?;
    consume(snapshot, policy, program)
}

impl State {
    /// Borrow only the exact identifier policy and its referenced program from
    /// the same certified World cut under the existing ledger-wide read root.
    /// Active-policy and program-use decisions remain with the native consumer.
    /// # Errors
    /// Missing/revoked read permission, changed cut, missing or substituted rows,
    /// noncanonical selector, oversized originals or exhausted finite budget.
    pub fn with_native_identifier_policy_originals_v1<T>(
        &self,
        tip: &CommittedBlock,
        authority: &AccountId,
        policy_id: &IdentifierPolicyId,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            &WorldStateSnapshotV1,
            &IdentifierPolicy,
            &RamLfeProgramPolicy,
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(
            tip,
            Some(authority),
            budget,
            |snapshot, world| consume_identifier(snapshot, world, policy_id, budget, consume),
        )
    }

    /// Borrow complete canonical account binding keys and only one alias's actual
    /// account/rekey/SNS originals at the retained native certified pre-tail cut.
    /// The signed HTTP corridor independently authenticates `authority`; this
    /// method requires its existing native ledger-wide read root under that cut.
    /// # Errors
    /// Missing/revoked native read permission, invalid selector, retired/changed
    /// cut, incomplete or post-tail originals, missing selected row or finite budget.
    pub fn with_native_account_alias_originals_v1<T>(
        &self,
        tip: &CommittedBlock,
        authority: &AccountId,
        name: &AccountAliasName,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            &WorldStateSnapshotV1,
            &AccountAlias,
            &[&AccountAlias],
            Option<AccountOriginal<'_>>,
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(tip, Some(authority), budget, |snapshot, world| {
            require_target(snapshot, "world.parameters", WorldStateElementKindV1::Cell, None,
                hash_value(world.parameters.get())?)?;
            let _parameter_identity_charge = budget.try_reserve_bytes(1024).map_err(|e| e.to_string())?;
            let parameter = world.parameters.get().custom().get(
                &iroha_data_model::nexus::NexusRuntimeCatalogV1::parameter_id()
            ).ok_or("World authority account alias requires the original committed runtime catalog; default or process-only catalog is not authority")?;
            // Native catalog JSON's own bounded decoder permits at most sixteen
            // times MAX_NEXUS_RUNTIME_CATALOG_BYTES of retained decode storage.
            // Reserve that documented ceiling before invoking the actual decoder.
            let decode_bytes = iroha_data_model::nexus::MAX_NEXUS_RUNTIME_CATALOG_BYTES
                .checked_mul(16).ok_or("World authority catalog decode bound overflows")?;
            let _decode_charge = budget.try_reserve_bytes(decode_bytes).map_err(|e| e.to_string())?;
            let runtime = iroha_data_model::nexus::NexusRuntimeCatalogV1::from_custom_parameter(parameter)
                .map_err(|e| e.to_string())?.ok_or("World authority protected catalog identity differs")?;
            let configured = self.nexus.read();
            let baseline = &configured.configured_dataspace_catalog;
            let count = baseline.entries().len().checked_add(runtime.dataspaces.len())
                .ok_or("World authority catalog count overflows")?;
            if count > 2 * iroha_data_model::nexus::MAX_NEXUS_RUNTIME_CATALOG_ENTRIES {
                return Err("World authority effective catalog exceeds native bounded baselines/additions".into());
            }
            // Two native descriptor vectors, every cloned description/alias and
            // the existing catalog constructor's transient uniqueness trees are
            // admitted before merge/hash/clone. A truthful per-entry tree ceiling
            // also covers the native baseline-hash Vec and bare codec backing.
            let descriptor_layout = Layout::array::<iroha_data_model::nexus::DataSpaceMetadata>(count)
                .map_err(|e| e.to_string())?.size();
            let payload_bytes = baseline.entries().iter()
                .chain(runtime.dataspaces.iter().map(|row| &row.descriptor))
                .try_fold(0usize, |bytes, entry| bytes.checked_add(entry.alias.len())
                    .and_then(|v| v.checked_add(entry.description.as_ref().map_or(0,String::len)))
                    .ok_or("World authority catalog payload length overflows"))?;
            let clone_bytes = descriptor_layout.checked_mul(2)
                .and_then(|v| v.checked_add(payload_bytes.checked_mul(4)?))
                .and_then(|v| v.checked_add(count.checked_mul(2048)?))
                .ok_or("World authority catalog original allocation bound overflows")?;
            let _catalog_charge = budget.try_reserve_bytes(clone_bytes).map_err(|e| e.to_string())?;
            let manifests = self.lane_manifests.read();
            if runtime.baseline_manifests_hash != Hash::prehashed(manifests.baseline_consensus_policy_digest()) {
                return Err("World authority committed catalog differs from immutable native manifest baseline".into());
            }
            let catalog = crate::state::runtime_catalog_dataspaces(baseline, Some(&runtime))
                .map_err(|e| e.to_string())?;
            consume_account(snapshot, world, name, &catalog, budget, consume)
        })
    }

    /// Borrow complete six-table fee keys, the exact program's native rows and
    /// mandatory present sponsor/definition/Global bucket funding originals.
    /// Counter values and all unrelated account/program values remain private.
    /// A missing source bucket is refused even at a requested pre-zero cut.
    /// # Errors
    /// Missing/revoked native read root, absent funding original, non-Global
    /// definition, incomplete/post-tail cut originals, count/row or finite budget.
    #[allow(clippy::too_many_arguments)]
    pub fn with_native_global_fee_originals_v1<T>(
        &self,
        tip: &CommittedBlock,
        authority: &AccountId,
        program_id: &FeeSponsorProgramId,
        fee_asset: &AssetDefinitionId,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            &WorldStateSnapshotV1,
            &[&AssetId],
            &[&FeeSponsorProgramId],
            &[&FeeSponsorProgramRevisionKey],
            &[&FeeSponsorEnrollmentKey],
            &[&FeeSponsorVaultKey],
            &[&FeeSponsorBudgetCounterKey],
            &AccountValue,
            &AssetDefinition,
            &AssetValue,
            Option<&FeeSponsorProgram>,
            &[&FeeSponsorProgramRevision],
            &[&FeeSponsorEnrollment],
            &[&FeeSponsorVault],
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(
            tip,
            Some(authority),
            budget,
            |snapshot, world| consume_fee(snapshot, world, program_id, fee_asset, budget, consume),
        )
    }
}

#[cfg(test)]
#[path = "authority_originals/tests.rs"]
mod tests;
