//! Original-pool public rows, canonical bytes and immutable nested owner custody.

use std::{alloc::Layout, io::Write};

use iroha_allocation::{AllocationCharge, AllocationRefusal, ChargedBuffer};
use iroha_data_model::fastpq::FastpqExecutionBalanceV1;

use super::{funded_paths::FundedPaths, *};

const KEY_PREFIX: &[u8] = b"iroha:fastpq:execution-quantity-key:v1\0";
const QUANTITY_VALUE_DOMAIN: &[u8] = b"fastpq:quantity:v1:smt:value|";

/// Payload adapter which forwards the original typed object without cloning it.
struct Field<'a, T>(&'a T);
impl<T: norito::SerializePayload> norito::SerializePayload for Field<'_, T> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        self.0.serialize(writer)
    }
}

#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover.execution_effect.QuantityKeyView",
    frame = "iroha_data_model::fastpq::FastpqExecutionQuantityKeyV1"
)]
enum Key<'a> {
    #[codec(index = 0)]
    Balance(Field<'a, FastpqExecutionBalanceV1>),
    #[codec(index = 1)]
    Supply(Field<'a, FastpqExecutionAssetV1>),
    #[codec(index = 2)]
    Lifecycle(Field<'a, FastpqExecutionAssetV1>),
}

fn keys(kind: &FastpqExecutionEffectKindV1) -> [Key<'_>; 2] {
    match kind {
        FastpqExecutionEffectKindV1::Transfer(t) => [
            Key::Balance(Field(&t.source)),
            Key::Balance(Field(&t.destination)),
        ],
        FastpqExecutionEffectKindV1::Mint(t) | FastpqExecutionEffectKindV1::Burn(t) => [
            Key::Balance(Field(&t.balance)),
            Key::Supply(Field(&t.balance.asset)),
        ],
        FastpqExecutionEffectKindV1::Retire(asset) => {
            [Key::Supply(Field(asset)), Key::Lifecycle(Field(asset))]
        }
    }
}

fn overflow() -> crate::Error {
    AllocationRefusal::DemandOverflow.into()
}
fn add_layout<T>(sum: &mut usize, count: usize) -> Result<()> {
    let bytes = Layout::array::<T>(count).map_err(|_| overflow())?.size();
    *sum = sum.checked_add(bytes).ok_or_else(overflow)?;
    Ok(())
}

struct AssetState<'a> {
    asset: &'a FastpqExecutionAssetV1,
    scale: u32,
    retired: bool,
    nonzero_balances: usize,
}
struct Row {
    key: ChargedBuffer<u8>,
    pre_value: ChargedBuffer<u8>,
    post_value: ChargedBuffer<u8>,
    operation: FastpqOperationKind,
    ordinal: u32,
    leg: usize,
    asset: usize,
    balance: bool,
    key_index: usize,
    before: FastpqQuantityUnits,
    after: FastpqQuantityUnits,
    amount: FastpqQuantityUnits,
}

/// Conservative exact-layout sum; no collection or complete frame is created.
/// The value bound covers each complete nominal frame independently. Key bytes
/// are measured from borrowed original ports, including the canonical prefix.
pub(super) fn allocation_bytes(
    effects: &FastpqExecutionEffectsV1,
    limits: ExecutionEffectLimits,
) -> Result<usize> {
    preflight(effects, None, limits)?;
    let count = effects.effects.len();
    let rows = count.checked_mul(2).ok_or_else(overflow)?;
    let mut total = 0;
    add_layout::<AssetState<'_>>(&mut total, count)?;
    add_layout::<Row>(&mut total, rows)?;
    add_layout::<usize>(&mut total, rows)?;
    add_layout::<Option<FastpqQuantityUnits>>(&mut total, rows)?;
    add_layout::<PublicKeyAllocation>(&mut total, rows)?;
    add_layout::<AllocationCharge>(&mut total, rows)?;
    add_layout::<FastpqStateTransition>(&mut total, rows)?;
    add_layout::<AllocationCharge>(&mut total, rows.checked_mul(3).ok_or_else(overflow)?)?;
    add_layout::<ExecutionEffectRow>(&mut total, rows)?;
    add_layout::<[usize; 2]>(&mut total, count)?;
    total = total
        .checked_add(FundedPaths::allocation_bytes(rows)?)
        .ok_or_else(overflow)?;
    let values = rows
        .checked_mul(2)
        .and_then(|n| n.checked_mul(super::super::QUANTITY_VALUE_MAX_BYTES_V1))
        .ok_or_else(overflow)?;
    add_layout::<u8>(&mut total, values)?;
    for effect in &effects.effects {
        for key in keys(&effect.kind) {
            let size = KEY_PREFIX
                .len()
                .checked_add(norito::canonical_frame_len(&key)?)
                .ok_or_else(overflow)?;
            check_limit("max_execution_effect_bytes", size, limits.max_public_bytes)?;
            // One row allocation and at most one distinct-key allocation.
            add_layout::<u8>(&mut total, size)?;
            add_layout::<u8>(&mut total, size)?;
        }
    }
    Ok(total)
}

struct BufferWriter<'a>(&'a mut ChargedBuffer<u8>);
impl Write for BufferWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn frame<T: norito::NoritoSerialize>(
    value: &T,
    prefix: &[u8],
    max: usize,
    reservation: &mut AllocationReservation,
) -> Result<ChargedBuffer<u8>> {
    let length = prefix
        .len()
        .checked_add(norito::canonical_frame_len(value)?)
        .ok_or_else(overflow)?;
    check_limit("max_execution_effect_bytes", length, max)?;
    let mut bytes = ChargedBuffer::from_reservation(length, reservation)?;
    let mut writer = BufferWriter(&mut bytes);
    writer
        .write_all(prefix)
        .map_err(|_| invariant("funded frame prefix exceeds backing"))?;
    norito::core::write_canonical_to_writer(value, &mut writer)?;
    if bytes.as_slice().len() != length {
        return Err(invariant("funded frame differs from measured length"));
    }
    Ok(bytes)
}
fn copy_bytes(bytes: &[u8], reservation: &mut AllocationReservation) -> Result<ChargedBuffer<u8>> {
    let mut output = ChargedBuffer::from_reservation(bytes.len(), reservation)?;
    output
        .append(bytes)
        .map_err(|_| invariant("funded key copy exceeds backing"))?;
    Ok(output)
}

// Canonical fields precede their nested charge ledger. There is no mutation,
// extraction, Clone or Vec replacement API on either enclosing output owner.
pub(super) struct Transitions {
    values: ChargedBuffer<FastpqStateTransition>,
    charges: ChargedBuffer<AllocationCharge>,
}
impl Transitions {
    fn new(count: usize, reservation: &mut AllocationReservation) -> Result<Self> {
        Ok(Self {
            values: ChargedBuffer::from_reservation(count, reservation)?,
            charges: ChargedBuffer::from_reservation(
                count.checked_mul(3).ok_or_else(overflow)?,
                reservation,
            )?,
        })
    }
    pub(super) fn as_slice(&self) -> &[FastpqStateTransition] {
        self.values.as_slice()
    }
    #[allow(unsafe_code)]
    fn push(&mut self, row: Row) {
        assert!(self.values.as_slice().len() < self.values.capacity());
        assert!(self.charges.capacity() - self.charges.as_slice().len() >= 3);
        // SAFETY: all three primitive byte buffers retain their exact allocations.
        // Capacity was checked before extraction. No fallible operation, allocator
        // call or callback separates the canonical fields from their original
        // charges; output fields are destroyed before the ledger on every path.
        let (key, key_charge) = unsafe { row.key.into_allocation_parts() };
        let (pre_value, pre_charge) = unsafe { row.pre_value.into_allocation_parts() };
        let (post_value, post_charge) = unsafe { row.post_value.into_allocation_parts() };
        self.values.push_reserved(FastpqStateTransition {
            key,
            pre_value,
            post_value,
            operation: row.operation,
        });
        for charge in [key_charge, pre_charge, post_charge] {
            self.charges.push_reserved(charge);
        }
    }
    #[cfg(test)]
    pub(super) fn fixture_copy(&self) -> Vec<FastpqStateTransition> {
        self.as_slice().to_vec()
    }
}
impl std::fmt::Debug for Transitions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_slice().fmt(f)
    }
}

pub(super) struct KeyAllocations {
    values: ChargedBuffer<PublicKeyAllocation>,
    charges: ChargedBuffer<AllocationCharge>,
}
impl KeyAllocations {
    fn new(count: usize, reservation: &mut AllocationReservation) -> Result<Self> {
        Ok(Self {
            values: ChargedBuffer::from_reservation(count, reservation)?,
            charges: ChargedBuffer::from_reservation(count, reservation)?,
        })
    }
    pub(super) fn as_slice(&self) -> &[PublicKeyAllocation] {
        self.values.as_slice()
    }
    #[allow(unsafe_code)]
    fn push(&mut self, bytes: ChargedBuffer<u8>, key_hash: [u8; 32], path: u32) {
        assert!(self.values.as_slice().len() < self.values.capacity());
        assert!(self.charges.as_slice().len() < self.charges.capacity());
        // SAFETY: the exact byte allocation and original credit are moved into
        // private immutable output fields, in deallocation-before-refund order.
        let (key, charge) = unsafe { bytes.into_allocation_parts() };
        self.values.push_reserved(PublicKeyAllocation {
            key,
            key_hash,
            path,
        });
        self.charges.push_reserved(charge);
    }
}
impl std::fmt::Debug for KeyAllocations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_slice().fmt(f)
    }
}

fn asset_states<'a>(
    effects: &'a FastpqExecutionEffectsV1,
    reservation: &mut AllocationReservation,
) -> Result<ChargedBuffer<AssetState<'a>>> {
    let mut states = ChargedBuffer::from_reservation(effects.effects.len(), reservation)?;
    for effect in &effects.effects {
        let (asset, values) = quantities(&effect.kind);
        asset
            .incarnation
            .validate()
            .map_err(|_| invariant("execution effect asset incarnation is invalid"))?;
        let scale = values
            .into_iter()
            .flatten()
            .map(Quantity::scale)
            .max()
            .unwrap_or(0);
        states.push_reserved(AssetState {
            asset,
            scale,
            retired: false,
            nonzero_balances: 0,
        });
    }
    states
        .as_mut_slice()
        .sort_unstable_by(|a, b| a.asset.cmp(b.asset));
    let mut unique = 0;
    for read in 0..states.as_slice().len() {
        if unique != 0 && states.as_slice()[unique - 1].asset == states.as_slice()[read].asset {
            let scale = states.as_slice()[read].scale;
            states.as_mut_slice()[unique - 1].scale =
                states.as_slice()[unique - 1].scale.max(scale);
        } else {
            states.as_mut_slice().swap(unique, read);
            unique += 1;
        }
    }
    states.truncate(unique);
    Ok(states)
}

fn normalized_values(
    kind: &FastpqExecutionEffectKindV1,
    scale: u32,
) -> Result<[FastpqQuantityUnits; 5]> {
    if let Some(values) = quantities(kind).1 {
        let values = values.map(|q| {
            FastpqQuantityUnits::from_quantity(q, scale)
                .ok_or_else(|| invariant("execution effect normalization failed"))
        });
        let [
            amount,
            first_before,
            first_after,
            second_before,
            second_after,
        ] = values;
        Ok([
            amount?,
            first_before?,
            first_after?,
            second_before?,
            second_after?,
        ])
    } else {
        let zero_limbs = [0; iroha_data_model::fastpq::FASTPQ_QUANTITY_UNIT_LIMBS];
        let mut one_limbs = zero_limbs;
        one_limbs[0] = 1;
        let zero = FastpqQuantityUnits::from_limbs(zero_limbs, scale)
            .ok_or_else(|| invariant("retirement supply scale is invalid"))?;
        let absent = FastpqQuantityUnits::from_limbs(zero_limbs, 0)
            .ok_or_else(|| invariant("retirement lifecycle zero is invalid"))?;
        let present = FastpqQuantityUnits::from_limbs(one_limbs, 0)
            .ok_or_else(|| invariant("retirement lifecycle one is invalid"))?;
        Ok([zero, zero, zero, present, absent])
    }
}

fn build_rows(
    effects: &FastpqExecutionEffectsV1,
    states: &[AssetState<'_>],
    limits: ExecutionEffectLimits,
    reservation: &mut AllocationReservation,
) -> Result<ChargedBuffer<Row>> {
    let mut rows = ChargedBuffer::from_reservation(effects.effects.len() * 2, reservation)?;
    for (index, effect) in effects.effects.iter().enumerate() {
        if effect.ordinal != checked_u32(index)? {
            return Err(invariant("execution effect ordinals are not contiguous"));
        }
        let asset = states
            .binary_search_by(|state| state.asset.cmp(quantities(&effect.kind).0))
            .expect("asset census contains each original effect");
        let [
            amount,
            first_before,
            first_after,
            second_before,
            second_after,
        ] = normalized_values(&effect.kind, states[asset].scale)?;
        let operation = check_effect_arithmetic(
            &effect.kind,
            amount,
            &[first_before, first_after, second_before, second_after],
        )?;
        for (leg, (key, (before, after))) in keys(&effect.kind)
            .into_iter()
            .zip([(first_before, first_after), (second_before, second_after)])
            .enumerate()
        {
            let balance = matches!(key, Key::Balance(_));
            let key = frame(&key, KEY_PREFIX, limits.max_public_bytes, reservation)?;
            let pre_value = frame(
                &super::super::quantity::quantity_value_frame(&before),
                &[],
                super::super::QUANTITY_VALUE_MAX_BYTES_V1,
                reservation,
            )?;
            let post_value = frame(
                &super::super::quantity::quantity_value_frame(&after),
                &[],
                super::super::QUANTITY_VALUE_MAX_BYTES_V1,
                reservation,
            )?;
            rows.push_reserved(Row {
                key,
                pre_value,
                post_value,
                operation,
                ordinal: effect.ordinal,
                leg,
                asset,
                balance,
                key_index: usize::MAX,
                before,
                after,
                amount,
            });
        }
    }
    Ok(rows)
}

/// Assign immutable complete-key indices without hashing keys into a second map.
fn index_keys(
    rows: &mut [Row],
    limits: ExecutionEffectLimits,
    reservation: &mut AllocationReservation,
) -> Result<usize> {
    let mut order = ChargedBuffer::from_reservation(rows.len(), reservation)?;
    for index in 0..rows.len() {
        order.push_reserved(index);
    }
    order.as_mut_slice().sort_unstable_by(|a, b| {
        rows[*a]
            .key
            .as_slice()
            .cmp(rows[*b].key.as_slice())
            .then(a.cmp(b))
    });
    let mut previous = None;
    let mut count = 0;
    for &index in order.as_slice() {
        if previous
            .is_none_or(|last: usize| rows[last].key.as_slice() != rows[index].key.as_slice())
        {
            count += 1;
            check_limit("max_execution_effect_keys", count, limits.max_unique_keys)?;
        }
        rows[index].key_index = count - 1;
        previous = Some(index);
    }
    Ok(count)
}

/// Validate chronology before canonical sorting, including sequential self ports.
fn chronology(
    effects: &FastpqExecutionEffectsV1,
    rows: &[Row],
    states: &mut [AssetState<'_>],
    unique_keys: usize,
    reservation: &mut AllocationReservation,
) -> Result<()> {
    let mut last = ChargedBuffer::from_reservation(unique_keys, reservation)?;
    for _ in 0..unique_keys {
        last.push_reserved(None);
    }
    for (ordinal, effect) in effects.effects.iter().enumerate() {
        let pair = &rows[ordinal * 2..ordinal * 2 + 2];
        let asset = &mut states[pair[0].asset];
        if asset.retired {
            return Err(invariant("execution effect uses a retired incarnation"));
        }
        if matches!(effect.kind, FastpqExecutionEffectKindV1::Retire(_)) {
            if asset.nonzero_balances != 0 {
                return Err(invariant(
                    "execution effect retires a nonzero observed balance",
                ));
            }
            asset.retired = true;
        }
        for row in pair {
            let previous: Option<FastpqQuantityUnits> = last.as_slice()[row.key_index];
            if previous.is_some_and(|value| value != row.before) {
                return Err(invariant(
                    "execution effect repeated-key quantities do not chain",
                ));
            }
            if row.balance {
                if previous.is_some_and(|v| v.limbs().iter().any(|limb| *limb != 0)) {
                    asset.nonzero_balances = asset
                        .nonzero_balances
                        .checked_sub(1)
                        .ok_or_else(|| invariant("execution balance census underflow"))?;
                }
                if row.after.limbs().iter().any(|limb| *limb != 0) {
                    asset.nonzero_balances = asset
                        .nonzero_balances
                        .checked_add(1)
                        .ok_or_else(|| invariant("execution balance census overflow"))?;
                }
            }
            last.as_mut_slice()[row.key_index] = Some(row.after);
        }
    }
    Ok(())
}

fn leaf(key_hash: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let value_hash = Hash::new_from_chunks(&[QUANTITY_VALUE_DOMAIN, bytes]);
    Hash::new_from_chunks(&[super::super::LEAF_DOMAIN, key_hash, value_hash.as_ref()]).into()
}

pub(super) fn prepare(
    effects: &FastpqExecutionEffectsV1,
    public_inputs: FastpqPublicInputs,
    limits: ExecutionEffectLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<(Transitions, PreparedExecutionEffects)> {
    if !reservation.belongs_to(budget) {
        return Err(crate::Error::AllocationForeignPool);
    }
    let demand = allocation_bytes(effects, limits)?;
    check_context(effects, &public_inputs)?;
    let mut reservation = reservation.try_partition_bytes(demand)?;
    let mut assets = asset_states(effects, &mut reservation)?;
    let mut normalized = build_rows(effects, assets.as_slice(), limits, &mut reservation)?;
    let count = normalized.as_slice().len();
    let unique_keys = index_keys(normalized.as_mut_slice(), limits, &mut reservation)?;
    chronology(
        effects,
        normalized.as_slice(),
        assets.as_mut_slice(),
        unique_keys,
        &mut reservation,
    )?;
    // Explicit original ordinal/port tie breakers preserve the old stable order
    // while using allocation-free in-place sorting.
    normalized.as_mut_slice().sort_unstable_by(|a, b| {
        (
            a.key.as_slice(),
            operation_rank(a.operation),
            a.ordinal,
            a.leg,
        )
            .cmp(&(
                b.key.as_slice(),
                operation_rank(b.operation),
                b.ordinal,
                b.leg,
            ))
    });
    let mut paths = FundedPaths::from_reservation(unique_keys, budget, &mut reservation)?;
    let mut keys = KeyAllocations::new(unique_keys, &mut reservation)?;
    let mut steps = 0;
    for row in normalized.as_slice() {
        if keys
            .as_slice()
            .last()
            .is_none_or(|last| last.key.as_slice() != row.key.as_slice())
        {
            let key_hash: [u8; 32] =
                Hash::new_from_chunks(&[KEY_DOMAIN, row.key.as_slice()]).into();
            let base = u32::from_le_bytes(key_hash[..4].try_into().expect("four key-hash bytes"));
            let path = paths.allocate(base, &mut steps, limits.max_allocation_steps)?;
            keys.push(
                copy_bytes(row.key.as_slice(), &mut reservation)?,
                key_hash,
                path,
            );
        }
    }
    let mut rows = ChargedBuffer::from_reservation(count, &mut reservation)?;
    let mut transitions = Transitions::new(count, &mut reservation)?;
    let mut pairs = ChargedBuffer::from_reservation(effects.effects.len(), &mut reservation)?;
    for _ in &effects.effects {
        pairs.push_reserved([usize::MAX; 2]);
    }
    for row in normalized.drain_all() {
        let key = &keys.as_slice()[row.key_index];
        let update = PublicUpdate {
            old_leaf: digest_limbs(leaf(&key.key_hash, row.pre_value.as_slice())),
            new_leaf: digest_limbs(leaf(&key.key_hash, row.post_value.as_slice())),
            path: key.path,
        };
        pairs.as_mut_slice()[row.ordinal as usize][row.leg] = rows.as_slice().len();
        rows.push_reserved(ExecutionEffectRow {
            effect_ordinal: row.ordinal,
            leg: row.leg,
            key_index: row.key_index,
            scale: row.before.scale(),
            before: row.before,
            after: row.after,
            amount: row.amount,
            update,
        });
        transitions.push(row);
    }
    let (ordering_hash, _) = bounded_canonical_digest(
        ORDERING_DOMAIN,
        &TransitionSequence(transitions.as_slice()),
        limits.max_public_bytes,
    )?;
    let hashes = count.checked_mul(2).ok_or_else(overflow)?;
    Ok((
        transitions,
        PreparedExecutionEffects {
            public_inputs: inputs(public_inputs),
            keys,
            rows,
            pairs,
            ordering_hash,
            work: PublicPreparationWork {
                public_bytes: 0,
                key_hashes: unique_keys,
                value_hashes: hashes,
                leaf_hashes: hashes,
                allocation_steps: steps,
            },
        },
    ))
}

#[cfg(test)]
mod tests;
