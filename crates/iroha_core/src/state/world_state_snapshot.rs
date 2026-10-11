//! Cold complete element publication at one original certified pre-tail World cut.
//!
//! Normal execution retains the accumulator and funded touched-hash journal. This
//! on-demand path borrows target values from the same locked World overlay and
//! funds every retained snapshot entry with the original finite operation pool.
//! Only private journal preimages can undo deterministic post-result writes. The
//! complete reconstructed root/count must match certified R; current typed targets
//! that changed in the tail are refused. Decoded restoration requires native replay.

#[path = "world_state_snapshot/reserve_account.rs"]
mod reserve_account;
#[path = "world_state_snapshot/reserve_policy.rs"]
mod reserve_policy;
use super::world_state_cut::CutCapsule;
use super::*;
use crate::{
    state::{
        AssetDefinitionAliasBindingRecord, State, StateReadOnly, StateView, StateViewError,
        WorldReadOnly, is_stable_state_view_generation,
    },
    sumeragi::certified_chain::CommittedBlock,
};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinition, AssetDefinitionId},
    sumeragi_finality::{
        MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
        WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
    },
};
use iroha_model_base::state_path::StatePath;
use std::alloc::Layout;

/// A complete World snapshot either retains the original local refusal or rejects its claim.
#[derive(Debug, thiserror::Error)]
pub enum WorldStateSnapshotError {
    /// The original State reader could not be acquired or its runtime was invalid.
    #[error("World snapshot State view: {0}")]
    View(#[from] StateViewError),
    /// The original World overlay retains its exact allocation or physical read refusal.
    #[error("World snapshot acquisition: {0}")]
    Acquisition(#[source] mv::storage::AdmittedStorageError),
    /// The certified cut, its typed originals or its bounded encoding was invalid.
    #[error("{0}")]
    Invalid(String),
}

impl From<String> for WorldStateSnapshotError {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}
impl From<&str> for WorldStateSnapshotError {
    fn from(reason: &str) -> Self {
        Self::Invalid(reason.into())
    }
}

/// Borrowed exact provider-admission originals from one certified pre-tail World.
/// The consumer still authenticates the complete snapshot and typed preimages.
#[derive(Clone, Copy, Debug)]
pub struct ProviderAdmissionSnapshotOriginalsV1<'a> {
    /// Complete canonical World hash preimages at the selected original decision.
    pub world: &'a WorldStateSnapshotV1,
    /// Original current council head bytes.
    pub council_head: &'a Vec<u8>,
    /// Original immediate council predecessor, absent only for revision one.
    pub council_predecessor: Option<&'a Vec<u8>>,
    /// Original current provider head bytes.
    pub provider_head: &'a Vec<u8>,
    /// Original immediate provider predecessor, absent only for revision one.
    pub provider_predecessor: Option<&'a Vec<u8>>,
    /// Original current native provider owner.
    pub owner: &'a iroha_data_model::account::AccountId,
    /// Original current token custody index and control, if configured on this provider.
    pub stream_token: Option<(&'a Vec<u8>, &'a Vec<u8>)>,
}

/// Private move-only snapshot owner; payload fields drop before their exact charges.
pub(super) struct SnapshotCollector<'a> {
    entries: Vec<WorldStateSnapshotEntryV1>,
    charges: ChargedBuffer<AllocationCharge>,
    budget: &'a AllocationBudget,
    expected: usize,
}

impl<'a> SnapshotCollector<'a> {
    fn new(budget: &'a AllocationBudget, expected: usize, fields: usize) -> Result<Self, String> {
        if expected > MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1 {
            return Err("World snapshot exceeds its complete-entry bound".into());
        }
        let mut charges = ChargedBuffer::new(
            expected
                .checked_add(3)
                .ok_or("World snapshot allocation ledger overflows")?,
            budget,
        )
        .map_err(|error| error.to_string())?;
        let layouts = [
            Layout::array::<WorldStateSnapshotEntryV1>(expected)
                .map_err(|error| error.to_string())?,
            Layout::array::<bool>(fields).map_err(|error| error.to_string())?,
            Layout::new::<[u16; LANES]>(),
        ];
        let mut reservation = budget
            .try_reserve_layouts(layouts.iter().copied())
            .map_err(|error| error.to_string())?;
        for layout in layouts {
            charges.push_reserved(
                reservation
                    .try_split(layout)
                    .map_err(|error| error.to_string())?,
            );
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(expected)
            .map_err(|error| format!("World snapshot original storage is unavailable: {error}"))?;
        Ok(Self {
            entries,
            charges,
            budget,
            expected,
        })
    }

    pub(super) fn push(
        &mut self,
        id: &str,
        kind: WorldStateElementKindV1,
        key_hash: Option<Hash>,
        value_hash: Hash,
    ) -> Result<(), String> {
        if self.entries.len() >= self.expected {
            return Err("World snapshot differs from the original stored entry count".into());
        }
        // Admit the exact field bytes before their sole owned allocation.
        let layout = Layout::array::<u8>(id.len()).map_err(|error| error.to_string())?;
        let charge = self
            .budget
            .try_reserve(layout)
            .map_err(|error| error.to_string())?
            .try_split(layout)
            .map_err(|error| error.to_string())?;
        let mut field_id = String::new();
        field_id.try_reserve_exact(id.len()).map_err(|error| {
            format!("World snapshot original field storage is unavailable: {error}")
        })?;
        field_id.push_str(id);
        self.charges.push_reserved(charge);
        self.entries.push(WorldStateSnapshotEntryV1 {
            field_id,
            kind,
            key_hash,
            value_hash,
        });
        Ok(())
    }

    fn finish(mut self, schema_hash: Hash) -> Result<CapturedSnapshot, String> {
        if self.entries.len() != self.expected {
            return Err("World snapshot omits original canonical entries".into());
        }
        self.entries.sort_unstable_by(|a, b| {
            (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash))
        });
        if self.entries.windows(2).any(|rows| {
            (&rows[0].field_id, rows[0].kind, rows[0].key_hash)
                == (&rows[1].field_id, rows[1].kind, rows[1].key_hash)
        }) {
            return Err("World snapshot repeats a canonical element identity".into());
        }
        let snapshot = WorldStateSnapshotV1 {
            schema_hash,
            entries: self.entries,
        };
        if norito::canonical_frame_len(&snapshot).map_err(|error| error.to_string())?
            > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
        {
            return Err("World snapshot exceeds its original canonical byte bound".into());
        }
        Ok(CapturedSnapshot {
            snapshot,
            _charges: self.charges,
        })
    }
}

struct CapturedSnapshot {
    snapshot: WorldStateSnapshotV1,
    _charges: ChargedBuffer<AllocationCharge>,
}

fn capture(
    world: &WorldBlock<'_>,
    expected: &WorldStateAccumulator,
    budget: &AllocationBudget,
) -> Result<CapturedSnapshot, String> {
    let index = field_index().as_ref().map_err(Clone::clone)?;
    let count = usize::try_from(expected.entries()).map_err(|error| error.to_string())?;
    let snapshot = SnapshotCollector::new(budget, count, index.canonical)?;
    let mut builder = Builder {
        index,
        accumulator: WorldStateAccumulator::empty(),
        direction: Direction::Capture,
        visited: vec![false; index.canonical],
        snapshot: Some(snapshot),
        snapshot_field: None,
    };
    world.project_world(&mut builder)?;
    if builder.visited.iter().any(|visited| !visited) {
        return Err("World snapshot omits a canonical registry field".into());
    }
    if builder.accumulator != *expected {
        return Err("World snapshot does not match the complete stored World accumulator".into());
    }
    builder
        .snapshot
        .take()
        .ok_or("World snapshot collector is absent")?
        .finish(index.schema)
}

// Complete reconstruction uses only private native journal preimages. The
// stored complete World is first independently cold-checked by `capture`.
fn reconstruct(
    captured: &CapturedSnapshot,
    cut: &CutCapsule,
    budget: &AllocationBudget,
) -> Result<CapturedSnapshot, String> {
    let index = field_index().as_ref().map_err(Clone::clone)?;
    let count = usize::try_from(cut.entries).map_err(|e| e.to_string())?;
    let mut collector = SnapshotCollector::new(budget, count, 0)?;
    let mut seen = ChargedBuffer::new(cut.changes().len(), budget).map_err(|e| e.to_string())?;
    for _ in 0..cut.changes().len() {
        seen.push_reserved(false);
    }
    for entry in &captured.snapshot.entries {
        let value = if let Some((position, before, after)) =
            cut.change_for(&entry.field_id, entry.kind, entry.key_hash)
        {
            if seen.as_slice()[position] || after != Some(entry.value_hash) {
                return Err("World cut tail differs from the complete applied preimage".into());
            }
            seen.as_mut_slice()[position] = true;
            before
        } else {
            Some(entry.value_hash)
        };
        if let Some(value) = value {
            collector.push(&entry.field_id, entry.kind, entry.key_hash, value)?;
        }
    }
    for (position, (id, kind, key, before, after)) in cut.changes().enumerate() {
        match after {
            Some(_) if !seen.as_slice()[position] => {
                return Err("World cut tail omits a complete applied element".into());
            }
            None if seen.as_slice()[position] => {
                return Err("World cut absent tail appears in the applied World".into());
            }
            None => {
                if let Some(value) = before {
                    collector.push(id, kind, key, value)?;
                }
            }
            Some(_) => {}
        }
    }
    let reconstructed = collector.finish(index.schema)?;
    if reconstructed.snapshot.root().map_err(|e| e.to_string())? != cut.root {
        return Err("World cut complete preimages do not reconstruct certified R".into());
    }
    Ok(reconstructed)
}

fn require_target(
    snapshot: &WorldStateSnapshotV1,
    id: &str,
    kind: WorldStateElementKindV1,
    key: Option<Hash>,
    value: Hash,
) -> Result<(), String> {
    let row = snapshot
        .entries
        .binary_search_by(|entry| {
            (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&(id, kind, key))
        })
        .ok()
        .and_then(|index| snapshot.entries.get(index));
    if row.is_none_or(|entry| entry.value_hash != value) {
        return Err(format!(
            "World cut exact typed target {id} differs from certified execution"
        ));
    }
    Ok(())
}

fn require_complete_table_count(
    snapshot: &WorldStateSnapshotV1,
    field: &str,
    count: usize,
) -> Result<(), String> {
    let mut certified = 0usize;
    for entry in &snapshot.entries {
        if entry.field_id == field {
            if entry.kind != WorldStateElementKindV1::Table || entry.key_hash.is_none() {
                return Err(format!(
                    "World names original {field} has an incompatible native field kind"
                ));
            }
            certified = certified
                .checked_add(1)
                .ok_or("World names original count overflows")?;
        }
    }
    if certified != count {
        return Err(format!(
            "World names original {field} omits or adds certified keys"
        ));
    }
    Ok(())
}

fn require_names_read_authority(
    world: &impl WorldReadOnly,
    authority: &AccountId,
) -> Result<(), String> {
    world
        .account(authority)
        .map_err(|_| "World names read authority is not registered")?;
    let permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::query::CanReadAllLedgerData.into();
    let direct = world
        .account_permissions_iter(authority)
        .map_err(|error| error.to_string())?
        .into_iter()
        .any(|stored| stored == &permission);
    let assigned = world.account_roles_iter(authority).any(|id| {
        world
            .roles()
            .get(id)
            .is_some_and(|role| role.permissions().any(|stored| stored == &permission))
    });
    if !direct && !assigned {
        return Err("World names originals require existing native CanReadAllLedgerData".into());
    }
    Ok(())
}

fn require_cut(view: &StateView<'_>, tip: &CommittedBlock) -> Result<(), String> {
    let native = view
        .native_execution_tip()
        .ok_or("World snapshot has no original native execution tip")?;
    if tip.height() < 2
        || tip.header().is_none()
        || u64::try_from(view.height()).ok() != Some(tip.height())
        || view.latest_block_hash() != Some(tip.block_hash())
        || native.height() != tip.height()
        || native.iroha_hash() != tip.block_hash()
        || native.core_hash() != tip.core_hash()
        || native.result() != tip.result()
        || native.creation_time_ms() != tip.block_time_ms()
        || tip.commitment().height != tip.height()
    {
        return Err(
            "World snapshot certified execution differs from the current applied cut".into(),
        );
    }
    Ok(())
}

impl State {
    /// Exact schema commitment of this build's canonical native World registry.
    /// Consumers must compare it with the authenticated snapshot before assigning
    /// typed meaning to a field or proving that a typed key is absent.
    /// # Errors
    /// The compiled registry has an invalid or inconsistent canonical schema.
    pub fn native_world_schema_hash_v1() -> Result<Hash, String> {
        Ok(field_index().as_ref().map_err(Clone::clone)?.schema)
    }

    /// Publish complete current-state evidence and exact provider authority originals.
    ///
    /// This uses the same original certified pre-tail capture as other complete
    /// World projections. It cannot publish a post-tail substitution or reconstruct
    /// authority from a restored cache. The callback must only produce response
    /// data and must fund any retained copies from its original operation budget.
    /// # Errors
    /// Missing or malformed native heads/owner, changed typed preimages, foreign
    /// or unstable certified cut, or exhausted allocation/wire bounds.
    pub fn with_native_provider_admission_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        budget: &AllocationBudget,
        consume: impl FnOnce(ProviderAdmissionSnapshotOriginalsV1<'_>) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let (council_head, council_predecessor) =
                admission_originals(snapshot, world, None, budget)?;
            let (provider_head, provider_predecessor) =
                admission_originals(snapshot, world, Some(provider), budget)?;
            let owner = world
                .provider_owners
                .get(&provider)
                .ok_or("World snapshot native provider owner is absent")?;
            require_target(
                snapshot,
                "world.provider_owners",
                WorldStateElementKindV1::Table,
                Some(hash_value(&provider)?),
                hash_value(owner)?,
            )?;
            consume(ProviderAdmissionSnapshotOriginalsV1 {
                world: snapshot,
                council_head,
                council_predecessor,
                provider_head,
                provider_predecessor,
                owner,
                stream_token: stream_token_originals(snapshot, world, provider, budget)?,
            })
        })
    }

    /// Publish native custody presence or absence independently of provider admission.
    /// The callback receives only borrowed data from the original certified World cut.
    /// It must retain all allocation charges and must not perform authorization or side effects.
    /// # Errors
    /// Missing owner, private/unbound root, corrupt native history, tail-modified originals,
    /// unavailable or changed certified cut, or exhausted finite allocation bounds.
    pub fn with_native_stream_token_custody_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            &WorldStateSnapshotV1,
            &AccountId,
            Option<(&Vec<u8>, &Vec<u8>)>,
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            if provider.as_bytes() == &[0; 32]
                || crate::sumeragi::lanes::routing::committed_root_scope(world)
                    != Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
            {
                return Err(
                    "Custody projection requires a nonzero provider on the global root".into(),
                );
            }
            let owner = world
                .provider_owners
                .get(&provider)
                .ok_or("World snapshot native provider owner is absent")?;
            require_target(
                snapshot,
                "world.provider_owners",
                WorldStateElementKindV1::Table,
                Some(hash_value(&provider)?),
                hash_value(owner)?,
            )?;
            let current = stream_token_originals(snapshot, world, provider, budget)?;
            if current.is_none() {
                use iroha_data_model::sorafs::stream_token_custody::history::{
                    head_key, record_key,
                };
                // Current typed absence cannot hide a value in the certified pre-tail cut.
                for key in [head_key(provider), record_key(provider, 1)] {
                    let target = (
                        "world.smart_contract_state",
                        WorldStateElementKindV1::Table,
                        Some(hash_value(&key)?),
                    );
                    if snapshot
                        .entries
                        .binary_search_by(|entry| {
                            (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&target)
                        })
                        .is_ok()
                    {
                        return Err(
                            "Custody absence differs from the certified original cut".into()
                        );
                    }
                }
            }
            consume(snapshot, owner, current)
        })
    }

    /// Publish the exact original SNS lease bytes at one native certified World cut.
    ///
    /// This is data publication only. The independent recipient selects its finality decision,
    /// qualified native schema, expected owner and current lease-validity time.
    /// # Errors
    /// Private or unbound root, noncanonical selector, absent or tail-modified record, changed
    /// certified cut, unavailable original publication custody, or finite allocation bounds.
    pub fn with_native_sns_lease_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        selector: &iroha_data_model::sns::NameSelectorV1,
        budget: &AllocationBudget,
        consume: impl FnOnce(&WorldStateSnapshotV1, &Vec<u8>) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        use iroha_data_model::{
            block::consensus::SumeragiRootScope,
            sns::{NameSelectorV1, lease::MAX_SNS_LEASE_RECORD_BYTES_V1, record_storage_key},
        };
        if NameSelectorV1::new(selector.suffix_id, &selector.label).map_err(|e| e.to_string())?
            != *selector
        {
            return Err("SNS lease selector is not canonical".into());
        }
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            if crate::sumeragi::lanes::routing::committed_root_scope(world)
                != Some(SumeragiRootScope::Global)
            {
                return Err("SNS lease projection requires the authenticated global root".into());
            }
            let key = record_storage_key(selector);
            let bytes = world
                .smart_contract_state
                .get(&key)
                .ok_or("SNS lease record is absent")?;
            if bytes.is_empty() || bytes.len() > MAX_SNS_LEASE_RECORD_BYTES_V1 {
                return Err("SNS lease original exceeds its finite bound".into());
            }
            require_target(
                snapshot,
                "world.smart_contract_state",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key)?),
                hash_value(bytes)?,
            )?;
            consume(snapshot, bytes)
        })
    }

    /// Borrow two distinct immutable execution record originals at one certified cut.
    /// Missing, oversized, post-result or changed originals refuse publication.
    /// The original native cut owner retains network, root, generation and capacity checks.
    pub fn with_native_execution_records_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        keys: &[iroha_model_base::state_path::StatePath; 2],
        budget: &AllocationBudget,
        consume: impl FnOnce(&WorldStateSnapshotV1, &Vec<u8>, &Vec<u8>) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        if keys[0] == keys[1] {
            return Err("World snapshot target keys must differ".into());
        }
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let first = world
                .smart_contract_state
                .get(&keys[0])
                .ok_or("World snapshot first immutable execution record is absent")?;
            let second = world
                .smart_contract_state
                .get(&keys[1])
                .ok_or("World snapshot second immutable execution record is absent")?;
            if first.len() > 64 * 1024 || second.len() > 64 * 1024 {
                return Err(
                    "World snapshot immutable execution record exceeds its reader bound".into(),
                );
            }
            for (key, value) in [(&keys[0], first), (&keys[1], second)] {
                require_target(
                    snapshot,
                    "world.smart_contract_state",
                    WorldStateElementKindV1::Table,
                    Some(hash_value(key)?),
                    hash_value(value)?,
                )?;
            }
            consume(snapshot, first, second)
        })
    }

    /// Publish complete canonical alias bindings and smart-contract key originals
    /// to a currently registered native ledger-wide reader at one certified cut.
    ///
    /// The signed HTTP corridor must authenticate `authority` independently.
    /// This method requires its exact existing `CanReadAllLedgerData` token under
    /// the same locked World overlay, including directly held or assigned-role
    /// permissions. It never grants or delegates that genesis-only capability.
    /// All canonical binding values and all smart-contract keys must match the
    /// reconstructed certified snapshot. Only dataspace SNS values are exposed;
    /// unrelated smart-contract values remain withheld. Callback storage and all
    /// snapshot entries are charged to the caller's original finite operation pool.
    ///
    /// # Errors
    /// Absent or revoked read root, uncertified/changed cut, incomplete originals,
    /// post-result changed originals, finite allocation or canonical wire bounds.
    pub fn with_native_resource_names_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        authority: &AccountId,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            &WorldStateSnapshotV1,
            &[(&AssetDefinitionId, &AssetDefinitionAliasBindingRecord)],
            &[&iroha_model_base::state_path::StatePath],
            &[(&iroha_model_base::state_path::StatePath, &Vec<u8>)],
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(
            tip,
            Some(authority),
            budget,
            |snapshot, world| {
                let aliases_len = world.asset_definition_alias_bindings.iter().count();
                let keys_len = world.smart_contract_state.iter().count();
                let _prefix_charge = budget
                    .try_reserve_bytes(64)
                    .map_err(|error| error.to_string())?;
                let mut prefix = String::new();
                prefix
                    .try_reserve_exact(64)
                    .map_err(|error| error.to_string())?;
                use std::fmt::Write as _;
                write!(
                    &mut prefix,
                    "sns/records/{}/",
                    iroha_data_model::sns::DATASPACE_ALIAS_SUFFIX_ID
                )
                .map_err(|error| error.to_string())?;
                let sns_len = world
                    .smart_contract_state
                    .iter()
                    .filter(|(key, _)| key.as_ref().starts_with(&prefix))
                    .count();
                require_complete_table_count(
                    snapshot,
                    "world.asset_definition_alias_bindings",
                    aliases_len,
                )?;
                require_complete_table_count(snapshot, "world.smart_contract_state", keys_len)?;
                let mut aliases =
                    ChargedBuffer::new(aliases_len, budget).map_err(|e| e.to_string())?;
                let mut keys = ChargedBuffer::new(keys_len, budget).map_err(|e| e.to_string())?;
                let mut sns = ChargedBuffer::new(sns_len, budget).map_err(|e| e.to_string())?;
                for (key, value) in world.asset_definition_alias_bindings.iter() {
                    require_target(
                        snapshot,
                        "world.asset_definition_alias_bindings",
                        WorldStateElementKindV1::Table,
                        Some(hash_value(key)?),
                        hash_value(value)?,
                    )?;
                    aliases.push_reserved((key, value));
                }
                for (key, value) in world.smart_contract_state.iter() {
                    // Even withheld values must match this cut: no post-tail key or
                    // value can be relabeled as an original certified projection.
                    require_target(
                        snapshot,
                        "world.smart_contract_state",
                        WorldStateElementKindV1::Table,
                        Some(hash_value(key)?),
                        hash_value(value)?,
                    )?;
                    keys.push_reserved(key);
                    if key.as_ref().starts_with(&prefix) {
                        sns.push_reserved((key, value));
                    }
                }
                consume(
                    snapshot,
                    aliases.as_slice(),
                    keys.as_slice(),
                    sns.as_slice(),
                )
            },
        )
    }

    fn with_native_world_state_snapshot_cut_v1<T>(
        &self,
        tip: &CommittedBlock,
        read_authority: Option<&AccountId>,
        budget: &AllocationBudget,
        consume: impl FnOnce(&WorldStateSnapshotV1, &WorldBlock<'_>) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        let publication_release = self.view_publication_release();
        let generation = self.state_view_generation();
        if generation % 2 != 0 {
            return Err(StateViewError::Busy(publication_release).into());
        }
        if tip.commitment().schedule.current.network_id != *self.network_id_ref() {
            return Err("World snapshot native tip belongs to another network".into());
        }
        {
            let view = self.try_view_once()?;
            require_cut(&view, tip)?;
        }
        let cut = self.native_world_cut.lock().as_ref().cloned()
            .ok_or("World snapshot has no original certified pre-tail capture; restored state requires native replay")?;
        if cut.generation != generation
            || cut.tip.height() != tip.height()
            || cut.tip.iroha_hash() != tip.block_hash()
            || cut.tip.core_hash() != tip.core_hash()
            || cut.tip.result() != tip.result()
            || cut.tip.creation_time_ms() != tip.block_time_ms()
            || cut.root != tip.commitment().execution.world_state_root
        {
            return Err(
                "World snapshot original journal belongs to another certified generation".into(),
            );
        }
        let result = {
            // Acquire only storage overlays, under the caller's original pool.
            // State::block would also initialize height-bound execution state.
            let world = self
                .world
                .try_block(budget)
                .map_err(WorldStateSnapshotError::Acquisition)?;
            let expected = world.state_accumulator.get();
            if expected.root()? != cut.applied_root || expected.entries() != cut.applied_entries {
                return Err("World snapshot acquired another complete applied World".into());
            }
            if let Some(authority) = read_authority {
                require_names_read_authority(&world, authority)?;
            }
            let captured = capture(&world, expected, budget)?;
            let certified = reconstruct(&captured, &cut, budget)?;
            consume(&certified.snapshot, &world)
        };
        let view = self.try_view_once()?;
        require_cut(&view, tip)?;
        if !is_stable_state_view_generation(generation, self.state_view_generation()) {
            return Err("World snapshot publication generation changed".into());
        }
        result.map_err(Into::into)
    }
}

fn admission_originals<'a>(
    snapshot: &WorldStateSnapshotV1,
    world: &'a WorldBlock<'_>,
    subject: Option<iroha_data_model::sorafs::capacity::ProviderId>,
    budget: &AllocationBudget,
) -> Result<(&'a Vec<u8>, Option<&'a Vec<u8>>), String> {
    use crate::query::provider_admission::{AdmissionHistoryPathV1, path, read_head};
    // The canonical reader can retain two 8 MiB decoded heads and a 2 MiB
    // predecessor digest frame. Fund this finite scratch before it allocates;
    // only borrowed originals escape this helper, so the reservation ends here.
    let _scratch = budget
        .try_reserve_bytes(18 * 1024 * 1024)
        .map_err(|error| error.to_string())?;
    let head = read_head(world, subject)
        .map_err(|e| e.to_string())?
        .ok_or("World snapshot native provider admission head is absent")?;
    let read_original = |suffix: AdmissionHistoryPathV1| -> Result<&'a Vec<u8>, String> {
        let key = path(subject, suffix);
        let bytes = world
            .smart_contract_state
            .get(&key)
            .ok_or("World snapshot native provider admission original is absent")?;
        require_target(
            snapshot,
            "world.smart_contract_state",
            WorldStateElementKindV1::Table,
            Some(hash_value(&key)?),
            hash_value(bytes)?,
        )?;
        Ok(bytes)
    };
    let bytes = read_original(AdmissionHistoryPathV1::Head)?;
    read_original(AdmissionHistoryPathV1::Revision(head.revision))?;
    let previous = (head.revision > 1)
        .then(|| read_original(AdmissionHistoryPathV1::Revision(head.revision - 1)))
        .transpose()?;
    Ok((bytes, previous))
}

fn stream_token_originals<'a>(
    snapshot: &WorldStateSnapshotV1,
    world: &'a WorldBlock<'_>,
    provider: iroha_data_model::sorafs::capacity::ProviderId,
    budget: &AllocationBudget,
) -> Result<Option<(&'a Vec<u8>, &'a Vec<u8>)>, String> {
    use crate::query::stream_token_custody::{head_key, height_key, read_active, record_key};
    // Current/predecessor controls, enrollment and key-first-use validation have
    // at most eight concurrent 256 KiB bounded decode/encode workspaces.
    let _scratch = budget
        .try_reserve_bytes(2 * 1024 * 1024)
        .map_err(|error| error.to_string())?;
    let Some(active) = read_active(world, provider).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let original = |key: StatePath| -> Result<&'a Vec<u8>, String> {
        let bytes = world
            .smart_contract_state
            .get(&key)
            .ok_or("World snapshot token custody original is absent")?;
        require_target(
            snapshot,
            "world.smart_contract_state",
            WorldStateElementKindV1::Table,
            Some(hash_value(&key)?),
            hash_value(bytes)?,
        )?;
        Ok(bytes)
    };
    let head = original(head_key(provider))?;
    let record = original(record_key(provider, active.index.revision))?;
    original(height_key(
        provider,
        active.index.height,
        active.index.ordinal,
    ))?;
    Ok(Some((head, record)))
}
#[path = "world_state_snapshot/authority_originals.rs"]
mod authority_originals;

#[cfg(test)]
#[path = "world_state_snapshot_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "world_state_snapshot_multisig_tests.rs"]
mod multisig_tests;
