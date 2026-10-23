//! Norito JSON helpers for MV storage types.
//!
//! This module provides thin conversion helpers so that downstream crates can
//! encode/decode MV `Storage`/`Cell` instances using the Norito JSON machinery
//! without pulling Serde into the dependency graph. The former `mv::serde`
//! shim has been removed; callers should import these helpers directly.
use crate::{
    Key, Value,
    cell::{Block as CellBlock, Cell, CellAllocationCharges},
    storage::{Block as StorageBlock, Storage, StorageMode, StorageReadOnly},
};
use concread::bptree::{BptreeMap, BptreeMapReadTxn, MapMode, NodeCloning};
use core::{fmt, marker::PhantomData};
use norito::json::{
    self, BoundedJsonError, JsonDeserialize, JsonKeyCodec, JsonSerialize, JsonWriteSink,
};
use std::{collections::BTreeMap, ops::Deref};
/// Helper interface for parsing JSON object keys into typed values.
pub trait KeySeed: Clone {
    /// Target key type.
    type Key;
    /// Convert a borrowed JSON object key into `Self::Key`.
    fn parse_key(&self, key: &str) -> Result<Self::Key, json::Error>;
}
/// Helper interface for parsing JSON values into typed payloads.
pub trait ValueSeed: Clone {
    /// Target value type.
    type Value;
    /// Convert a Norito JSON `Value` into `Self::Value`.
    fn parse_value(&self, value: json::Value) -> Result<Self::Value, json::Error>;
    /// Decode one value directly from the streaming Norito JSON parser.
    fn parse_parser(&self, parser: &mut json::Parser<'_>) -> Result<Self::Value, json::Error>;
}
/// Key seed that relies on `FromStr` with deterministic error reporting.
#[derive(Debug, Default)]
pub struct KeyFromStr<T>(PhantomData<T>);
impl<T> KeyFromStr<T> {
    /// Construct a new seed (type inference helper).
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
impl<T> Clone for KeyFromStr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for KeyFromStr<T> {}
impl<T> KeySeed for KeyFromStr<T>
where
    T: core::str::FromStr,
    T::Err: fmt::Display,
{
    type Key = T;
    fn parse_key(&self, key: &str) -> Result<Self::Key, json::Error> {
        key.parse::<T>()
            .map_err(|err| json::Error::Message(format!("invalid map key `{key}`: {err}")))
    }
}
/// Key seed that delegates to [`JsonKeyCodec`] implementations.
#[derive(Debug, Default)]
pub struct CodecKeySeed<K>(PhantomData<K>);
impl<K> CodecKeySeed<K> {
    /// Construct a new seed (type inference helper).
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
impl<K> Clone for CodecKeySeed<K> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<K> Copy for CodecKeySeed<K> {}
impl<K> KeySeed for CodecKeySeed<K>
where
    K: JsonKeyCodec,
{
    type Key = K;
    fn parse_key(&self, key: &str) -> Result<Self::Key, json::Error> {
        K::decode_json_key(key)
    }
}
/// Value seed that delegates directly to `JsonDeserialize`.
#[derive(Debug, Default)]
pub struct ValueFromJson<T>(PhantomData<T>);
impl<T> ValueFromJson<T> {
    /// Construct a new seed (type inference helper).
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
impl<T> Clone for ValueFromJson<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for ValueFromJson<T> {}
impl<T> ValueSeed for ValueFromJson<T>
where
    T: JsonDeserialize,
{
    type Value = T;
    fn parse_value(&self, value: json::Value) -> Result<Self::Value, json::Error> {
        json::value::from_value(value)
    }
    fn parse_parser(&self, parser: &mut json::Parser<'_>) -> Result<Self::Value, json::Error> {
        T::json_deserialize(parser)
    }
}
/// One present predecessor value in the first-release MV snapshot schema.
///
/// A missing predecessor is encoded as `null`; this object is always present
/// when an original value exists, even when that original value itself is null.
/// Its sole `value` member is required. Retired unwrapped values are rejected.
pub struct SnapshotUndoValue<V> {
    /// The exact original value, without inferring presence from its JSON token.
    pub value: V,
}

// TODO: migrate and qualify the complete enclosing State snapshot writer and its original funding.
impl<V: JsonSerialize> JsonSerialize for SnapshotUndoValue<V> {
    fn json_serialize(&self, out: &mut String) {
        write_present_undo(&self.value, out);
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_present_undo_to(&self.value, out)
    }
}

impl<V: JsonDeserialize> JsonDeserialize for SnapshotUndoValue<V> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parse_present_undo(&ValueFromJson::<V>::new(), parser).map(|value| Self { value })
    }
}

/// Serialize an exact predecessor option with explicit present-value framing.
///
/// This borrows the original value; it neither clones the payload nor constructs
/// a temporary JSON value, string, map or restored runtime owner.
pub fn json_serialize_undo<V: JsonSerialize>(undo: &Option<V>, out: &mut String) {
    match undo {
        Some(value) => write_present_undo(value, out),
        None => out.push_str("null"),
    }
}

fn write_present_undo<V: JsonSerialize + ?Sized>(value: &V, out: &mut String) {
    out.push_str("{\"value\":");
    value.json_serialize(out);
    out.push('}');
}

fn parse_present_undo<S: ValueSeed>(
    seed: &S,
    parser: &mut json::Parser<'_>,
) -> Result<S::Value, json::Error> {
    parse_present_undo_with(
        parser,
        &mut |parser| seed.parse_parser(parser),
        &mut OrdinaryCellKeys,
    )
}

// Both ordinary and admitted Cell reads, plus ordinary Storage undo values,
// use this one explicit present-value grammar. The destination only owns keys.
fn parse_present_undo_with<'a, V, D: CellKeyDestination>(
    parser: &mut json::Parser<'a>,
    parse_value: &mut impl FnMut(&mut json::Parser<'a>) -> Result<V, D::Error>,
    keys: &mut D,
) -> Result<V, D::Error> {
    let mut map = json::MapVisitor::new(parser)?;
    // The outer option records member presence independently of a nullable V.
    let mut value = None;
    while let Some(key) = keys.next(&mut map)? {
        match cell_key_text(&key)? {
            "value" => {
                if value.is_some() {
                    return Err(cell_field_error("duplicate undo value field").into());
                }
                value = Some(map.parse_value_with_parser_typed(&mut *parse_value)?);
            }
            _ => return Err(cell_field_error("unknown undo value field").into()),
        }
    }
    map.finish()?;
    value.ok_or_else(|| cell_field_error("missing undo value field").into())
}

// Fixed schema diagnostics never allocate a copy of attacker-selected text.
fn cell_field_error(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}
trait CellKeyText {
    fn text(&self) -> Result<&str, json::Error>;
}
impl CellKeyText for String {
    fn text(&self) -> Result<&str, json::Error> {
        Ok(self.as_str())
    }
}
fn cell_key_text<'a, T: CellKeyText>(key: &'a json::KeyRef<'_, T>) -> Result<&'a str, json::Error> {
    match key {
        json::KeyRef::Borrowed(text) => Ok(text),
        json::KeyRef::Owned(text) => text.text(),
    }
}
trait CellKeyDestination {
    type Error: From<json::Error>;
    type Text: CellKeyText;
    fn next<'a>(
        &mut self,
        map: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a, Self::Text>>, Self::Error>;
}
struct OrdinaryCellKeys;
impl CellKeyDestination for OrdinaryCellKeys {
    type Error = json::Error;
    type Text = String;
    fn next<'a>(
        &mut self,
        map: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a>>, json::Error> {
        map.next_key()
    }
}
struct CellKeyBuffer<B>(B);
impl<B: AsMut<[u8]>> AsMut<[u8]> for CellKeyBuffer<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl<B: AsRef<[u8]>> CellKeyText for CellKeyBuffer<B> {
    fn text(&self) -> Result<&str, json::Error> {
        std::str::from_utf8(self.0.as_ref()).map_err(|_| json::Error::InvalidUtf8)
    }
}
struct BufferedCellKeys<F, B, E> {
    reserve: F,
    marker: PhantomData<fn() -> (B, E)>,
}
impl<F, B, E> CellKeyDestination for BufferedCellKeys<F, B, E>
where
    F: FnMut(usize) -> Result<B, E>,
    B: AsMut<[u8]> + AsRef<[u8]>,
    E: From<json::Error>,
{
    type Error = E;
    type Text = CellKeyBuffer<B>;
    fn next<'a>(
        &mut self,
        map: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a, Self::Text>>, E> {
        map.next_key_with_buffer(|length| (self.reserve)(length).map(CellKeyBuffer))
    }
}

/// Parse exact current and optional original undo values without constructing a Cell.
///
/// The tuple is `(current, undo)`. This is the same first-release grammar used by
/// [`CellSeeded`]: both `blocks` and `revert` are required, and a present predecessor
/// is exactly `{ "value": V }`, including when `V` itself is null. No payload is
/// cloned and no untracked Cell, publication identity or EBR owner is created.
///
/// `reserve_key` is called only for escaped keys, after the original Norito string
/// checks and logical decode reservation. It must return an initialized destination
/// of exactly the requested length. Both outer and undo-wrapper keys use it.
/// `parse_value` receives the same original parser and must consume one value.
/// The caller retains the source, admission pool and typed value custody and funds
/// complete Cell initialization before parsing; it may compare canonical bytes
/// before moving these values into the admitted Cell owner.
///
/// # Errors
/// Preserves original JSON and typed callback failures. Rejects missing, duplicate,
/// unknown and retired unwrapped undo forms with allocation-free schema errors.
/// Document completion and canonical comparison remain the enclosing caller's job.
pub fn parse_cell_values_with<'a, V, E, B>(
    parser: &mut json::Parser<'a>,
    mut parse_value: impl FnMut(&mut json::Parser<'a>) -> Result<V, E>,
    reserve_key: impl FnMut(usize) -> Result<B, E>,
) -> Result<(V, Option<V>), E>
where
    E: From<json::Error>,
    B: AsMut<[u8]> + AsRef<[u8]>,
{
    parse_cell_values(
        parser,
        &mut parse_value,
        &mut BufferedCellKeys {
            reserve: reserve_key,
            marker: PhantomData,
        },
    )
}

fn parse_cell_values<'a, V, D: CellKeyDestination>(
    parser: &mut json::Parser<'a>,
    parse_value: &mut impl FnMut(&mut json::Parser<'a>) -> Result<V, D::Error>,
    keys: &mut D,
) -> Result<(V, Option<V>), D::Error> {
    let mut map = json::MapVisitor::new(parser)?;
    let mut revert = None;
    let mut blocks = None;
    while let Some(key) = keys.next(&mut map)? {
        match cell_key_text(&key)? {
            "revert" => {
                if revert.is_some() {
                    return Err(cell_field_error("duplicate Cell revert field").into());
                }
                revert = Some(map.parse_value_with_parser_typed(|parser| {
                    parser.skip_ws();
                    if parser.try_consume_null()? {
                        Ok(None)
                    } else {
                        parse_present_undo_with(parser, parse_value, keys).map(Some)
                    }
                })?);
            }
            "blocks" => {
                if blocks.is_some() {
                    return Err(cell_field_error("duplicate Cell blocks field").into());
                }
                blocks = Some(map.parse_value_with_parser_typed(&mut *parse_value)?);
            }
            _ => return Err(cell_field_error("unknown Cell field").into()),
        }
    }
    map.finish()?;
    let revert = revert.ok_or_else(|| cell_field_error("missing Cell revert field"))?;
    let blocks = blocks.ok_or_else(|| cell_field_error("missing Cell blocks field"))?;
    Ok((blocks, revert))
}

/// Deserialize `Storage<K, V>` using custom key/value seeds.
#[derive(Debug, Clone)]
pub struct StorageSeeded<KS, VS> {
    /// Seed used to parse object keys.
    pub kseed: KS,
    /// Seed used to parse object values.
    pub vseed: VS,
}
impl<KS, VS> StorageSeeded<KS, VS>
where
    KS: KeySeed,
    VS: ValueSeed,
    KS::Key: Key + Ord,
    VS::Value: Value,
{
    /// Parse `Storage` from `parser`, expecting `{ "revert": {..}, "blocks": {..} }`.
    pub fn deserialize(
        &self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Storage<KS::Key, VS::Value>, json::Error> {
        let mut map = json::MapVisitor::new(parser)?;
        let mut revert: Option<BTreeMap<KS::Key, Option<VS::Value>>> = None;
        let mut blocks: Option<BptreeMap<KS::Key, VS::Value>> = None;
        while let Some(key) = map.next_key()? {
            match key.as_str() {
                "revert" => {
                    if revert.is_some() {
                        return Err(json::MapVisitor::duplicate_field("revert"));
                    }
                    revert = Some(map.parse_value_with_parser(|parser| self.parse_revert(parser))?);
                }
                "blocks" => {
                    if blocks.is_some() {
                        return Err(json::MapVisitor::duplicate_field("blocks"));
                    }
                    blocks = Some(map.parse_value_with_parser(|parser| self.parse_blocks(parser))?);
                }
                other => {
                    return Err(json::MapVisitor::unknown_field(other));
                }
            }
        }
        map.finish()?;
        let revert = revert.ok_or_else(|| json::MapVisitor::missing_field("revert"))?;
        let blocks = blocks.ok_or_else(|| json::MapVisitor::missing_field("blocks"))?;
        Ok(Storage {
            allocation: None,
            publication: crate::publication::Publication::new(),
            revert_released: crate::ReleaseNotification::default(),
            blocks_released: crate::ReleaseNotification::default(),
            revert: revert.into_iter().collect(),
            blocks,
        })
    }
    fn parse_revert(
        &self,
        parser: &mut json::Parser<'_>,
    ) -> Result<BTreeMap<KS::Key, Option<VS::Value>>, json::Error> {
        let mut map = json::MapVisitor::new(parser)?;
        let mut out = BTreeMap::new();
        while let Some(key_ref) = map.next_key()? {
            let key_str = key_ref.as_str().to_owned();
            let key = self.kseed.parse_key(&key_str)?;
            let parsed = map.parse_value_with_parser(|parser| {
                parser.skip_ws();
                if parser.try_consume_null()? {
                    Ok(None)
                } else {
                    parse_present_undo(&self.vseed, parser).map(Some)
                }
            })?;
            if out.insert(key, parsed).is_some() {
                return Err(json::Error::DuplicateField { field: key_str });
            }
        }
        map.finish()?;
        Ok(out)
    }
    fn parse_blocks(
        &self,
        parser: &mut json::Parser<'_>,
    ) -> Result<BptreeMap<KS::Key, VS::Value>, json::Error> {
        let mut map = json::MapVisitor::new(parser)?;
        let mut entries = BTreeMap::new();
        while let Some(key_ref) = map.next_key()? {
            let key_str = key_ref.as_str().to_owned();
            let key = self.kseed.parse_key(&key_str)?;
            let value = map.parse_value_with_parser(|parser| self.vseed.parse_parser(parser))?;
            if entries.insert(key, value).is_some() {
                return Err(json::Error::DuplicateField { field: key_str });
            }
        }
        map.finish()?;
        Ok(BptreeMap::from_iter(entries))
    }
}
/// Deserialize `Cell<V>` using a custom seed.
#[derive(Debug, Clone)]
pub struct CellSeeded<S> {
    /// Seed used to parse the inner value.
    pub seed: S,
}
impl<S> CellSeeded<S>
where
    S: ValueSeed,
    S::Value: Value,
{
    /// Parse `Cell` from `parser`, expecting `{ "revert": null | { "value": <Value> }, "blocks": <Value> }`.
    pub fn deserialize(
        &self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Cell<S::Value>, json::Error> {
        self.deserialize_charged(parser, CellAllocationCharges::untracked())
    }

    /// Restore exact current/undo values into their original prepaid EBR owners.
    ///
    /// Both charges must be admitted before this call. Capacity refusal belongs
    /// to that admission operation and is never converted into a JSON error.
    /// This uses the same explicit present-undo object parser as
    /// [`Self::deserialize`], without cloning values or creating dummy generations.
    /// Parse failure drops the unused charges; success moves them into the actual
    /// EBR allocations until physical reclamation, including retired readers.
    ///
    /// The charges cover only what the caller prepaid. The exact outer layouts
    /// from [`Cell::allocation_layouts`] exclude seed payloads, parser scratch,
    /// publication identities, notifications and collector bookkeeping. Their
    /// funding, later nested growth and aggregate State admission remain separate.
    /// No default charged decoder can infer or acquire those resources.
    ///
    /// ```compile_fail
    /// use iroha_allocation::{AllocationCharge};
    /// use mv::{cell::Cell};
    /// fn requires_default_decode<T: norito::json::JsonDeserialize>() {}
    /// requires_default_decode::<Cell<u64, AllocationCharge>>();
    /// ```
    pub fn deserialize_charged<Charge: Send + Sync + 'static>(
        &self,
        parser: &mut json::Parser<'_>,
        charges: CellAllocationCharges<Charge>,
    ) -> Result<Cell<S::Value, Charge>, json::Error> {
        let (blocks, revert) = parse_cell_values(
            parser,
            &mut |parser| self.seed.parse_parser(parser),
            &mut OrdinaryCellKeys,
        )?;
        Ok(Cell::from_values_charged(blocks, revert, charges))
    }
}
impl<K, V, M: StorageMode<K, V>> JsonSerialize for Storage<K, V, M>
where
    K: JsonKeyCodec + Key,
    V: JsonSerialize + Value,
{
    fn json_serialize(&self, out: &mut String) {
        let revert = self.revert.read();
        let blocks = self.blocks.read();
        out.push('{');
        out.push_str("\"revert\":");
        write_revert(revert.iter(), out);
        out.push(',');
        out.push_str("\"blocks\":");
        write_blocks(&blocks, out);
        out.push('}');
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let revert = self.revert.read();
        let blocks = self.blocks.read();
        write_original_storage_to(revert.iter(), blocks.iter(), out)
    }
}
impl<K, V, M: StorageMode<K, V>> JsonSerialize for StorageBlock<'_, K, V, M>
where
    K: JsonKeyCodec + Key,
    V: JsonSerialize + Value,
{
    fn json_serialize(&self, out: &mut String) {
        write_original_storage(self.revert_map().iter(), self.iter(), out);
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_original_storage_to(self.revert_map().iter(), self.iter(), out)
    }
}
impl<K, V, A, M: StorageMode<K, V>> JsonSerialize for crate::storage::Detached<K, V, A, M>
where
    K: JsonKeyCodec + Key,
    V: JsonSerialize + Value,
{
    fn json_serialize(&self, out: &mut String) {
        let images = self.original_images();
        write_original_storage(images.undo_entries(), images.current_entries(), out);
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let images = self.original_images();
        write_original_storage_to(images.undo_entries(), images.current_entries(), out)
    }
}

// The same snapshot layout reads either attached or frozen original generations.
// No current target view, payload clone or intermediate snapshot is constructed.
fn write_original_storage<'a, K, V>(
    undo: impl Iterator<Item = (&'a K, &'a Option<V>)>,
    entries: impl Iterator<Item = (&'a K, &'a V)>,
    out: &mut String,
) where
    K: JsonKeyCodec + 'a,
    V: JsonSerialize + 'a,
{
    out.push('{');
    out.push_str("\"revert\":");
    write_revert(undo, out);
    out.push(',');
    out.push_str("\"blocks\":{");
    let mut first = true;
    for (key, value) in entries {
        write_storage_json_entry(key, value, &mut first, out);
    }
    out.push_str("}}");
}

/// Serialize the exact storage JSON after applying ordered block-local changes.
///
/// This read-only projection preserves the first pre-block undo value for every
/// previously touched key. A newly touched key records its current value as undo,
/// even when removing an absent key. Both maps are streamed in storage-key order;
/// no existing key, value, or full store is cloned or decoded.
pub fn json_serialize_storage_block_with_changes<K, V, M: StorageMode<K, V>>(
    block: &StorageBlock<'_, K, V, M>,
    changes: &BTreeMap<K, Option<V>>,
    out: &mut String,
) where
    K: JsonKeyCodec + Key,
    V: JsonSerialize + Value,
{
    out.push_str("{\"revert\":{");
    let mut first = true;
    let mut revert = block.revert_map().iter().peekable();
    for key in changes.keys() {
        while let Some((previous_key, previous)) = revert.peek().copied() {
            if previous_key >= key {
                break;
            }
            write_storage_undo_entry(previous_key, previous.as_ref(), &mut first, out);
            revert.next();
        }
        let previous = match revert.peek().copied() {
            Some((previous_key, previous)) if previous_key == key => {
                revert.next();
                previous.as_ref()
            }
            _ => block.get(key),
        };
        write_storage_undo_entry(key, previous, &mut first, out);
    }
    for (key, previous) in revert {
        write_storage_undo_entry(key, previous.as_ref(), &mut first, out);
    }
    out.push_str("},\"blocks\":{");
    first = true;
    let mut current = block.iter().peekable();
    for (key, replacement) in changes {
        while let Some((current_key, value)) = current.peek().copied() {
            if current_key >= key {
                break;
            }
            write_storage_json_entry(current_key, value, &mut first, out);
            current.next();
        }
        if current
            .peek()
            .is_some_and(|(current_key, _)| *current_key == key)
        {
            current.next();
        }
        if let Some(value) = replacement {
            write_storage_json_entry(key, value, &mut first, out);
        }
    }
    for (key, value) in current {
        write_storage_json_entry(key, value, &mut first, out);
    }
    out.push_str("}}");
}
fn write_storage_undo_entry<K: JsonKeyCodec, V: JsonSerialize>(
    key: &K,
    value: Option<&V>,
    first: &mut bool,
    out: &mut String,
) {
    if !*first {
        out.push(',');
    }
    *first = false;
    key.encode_json_key(out);
    out.push(':');
    match value {
        Some(value) => write_present_undo(value, out),
        None => out.push_str("null"),
    }
}
fn write_storage_json_entry<K: JsonKeyCodec, V: JsonSerialize>(
    key: &K,
    value: &V,
    first: &mut bool,
    out: &mut String,
) {
    if !*first {
        out.push(',');
    }
    *first = false;
    key.encode_json_key(out);
    out.push(':');
    value.json_serialize(out);
}
impl<V, Charge> JsonSerialize for Cell<V, Charge>
where
    V: JsonSerialize + Value,
    Charge: Send + Sync + 'static,
{
    fn json_serialize(&self, out: &mut String) {
        let revert = self.revert.read();
        let blocks = self.blocks.read();
        out.push('{');
        out.push_str("\"revert\":");
        json_serialize_undo(revert.deref(), out);
        out.push(',');
        out.push_str("\"blocks\":");
        JsonSerialize::json_serialize(blocks.deref(), out);
        out.push('}');
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let revert = self.revert.read();
        let blocks = self.blocks.read();
        write_cell_values_to(revert.deref(), blocks.deref(), out)
    }
}
impl<V, Charge> JsonSerialize for CellBlock<'_, V, Charge>
where
    V: JsonSerialize + Value,
    Charge: Send + Sync + 'static,
{
    fn json_serialize(&self, out: &mut String) {
        write_original_cell(self.original_undo(), self.get(), out);
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_cell_values_to(self.original_undo(), self.get(), out)
    }
}
impl<V, A, Charge> JsonSerialize for crate::cell::Detached<V, A, Charge>
where
    V: JsonSerialize + Value,
    Charge: Send + Sync + 'static,
{
    fn json_serialize(&self, out: &mut String) {
        write_original_cell(self.original_undo(), self.get(), out);
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_cell_values_to(self.original_undo(), self.get(), out)
    }
}

fn write_original_cell<V: JsonSerialize>(undo: &Option<V>, value: &V, out: &mut String) {
    out.push('{');
    out.push_str("\"revert\":");
    json_serialize_undo(undo, out);
    out.push(',');
    out.push_str("\"blocks\":");
    value.json_serialize(out);
    out.push('}');
}

// Each entered container is released on a returned key, leaf or sink refusal.
// All projections borrow the exact original generation and its retained undo.
fn write_container_to(
    out: &mut dyn JsonWriteSink,
    write: impl FnOnce(&mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
) -> Result<(), BoundedJsonError> {
    out.begin_container()?;
    let result = write(out);
    out.end_container();
    result
}

fn write_present_undo_to<V: JsonSerialize + ?Sized>(
    value: &V,
    out: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    write_container_to(out, |out| {
        out.push_str("{\"value\":")?;
        value.json_serialize_to(out)?;
        out.push('}')
    })
}

fn write_undo_value_to<V: JsonSerialize>(
    undo: &Option<V>,
    out: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    match undo {
        Some(value) => write_present_undo_to(value, out),
        None => out.push_str("null"),
    }
}

fn write_storage_entries_to<'a, K, V>(
    entries: impl Iterator<Item = (&'a K, &'a V)>,
    out: &mut dyn JsonWriteSink,
    mut write_value: impl FnMut(&V, &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
) -> Result<(), BoundedJsonError>
where
    K: JsonKeyCodec + 'a,
    V: 'a,
{
    write_container_to(out, |out| {
        out.push('{')?;
        for (index, (key, value)) in entries.enumerate() {
            if index != 0 {
                out.push(',')?;
            }
            key.encode_json_key_to(out)?;
            out.push(':')?;
            write_value(value, out)?;
        }
        out.push('}')
    })
}

fn write_original_storage_to<'a, K, V>(
    undo: impl Iterator<Item = (&'a K, &'a Option<V>)>,
    current: impl Iterator<Item = (&'a K, &'a V)>,
    out: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError>
where
    K: JsonKeyCodec + 'a,
    V: JsonSerialize + 'a,
{
    write_container_to(out, |out| {
        out.push_str("{\"revert\":")?;
        write_storage_entries_to(undo, out, write_undo_value_to::<V>)?;
        out.push_str(",\"blocks\":")?;
        write_storage_entries_to(current, out, V::json_serialize_to)?;
        out.push('}')
    })
}

/// Write the canonical Cell snapshot directly from borrowed original values.
///
/// Uses the same writer as attached and detached Cells, without cloning payloads
/// or constructing a Cell. This permits bounded canonical comparison before EBR
/// initialization; `undo` preserves explicit presence even for a null payload.
///
/// # Errors
/// Returns the original bounded sink or nested serialization failure.
pub fn write_cell_values_to<V: JsonSerialize>(
    undo: &Option<V>,
    current: &V,
    out: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    write_container_to(out, |out| {
        out.push_str("{\"revert\":")?;
        write_undo_value_to(undo, out)?;
        out.push_str(",\"blocks\":")?;
        current.json_serialize_to(out)?;
        out.push('}')
    })
}

impl<K, V> JsonDeserialize for Storage<K, V>
where
    K: JsonKeyCodec + Key + Ord,
    V: JsonSerialize + JsonDeserialize + Value,
{
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        StorageSeeded {
            kseed: CodecKeySeed::<K>::new(),
            vseed: ValueFromJson::<V>::new(),
        }
        .deserialize(parser)
    }
}
impl<V> JsonDeserialize for Cell<V>
where
    V: JsonSerialize + JsonDeserialize + Value,
    ValueFromJson<V>: ValueSeed<Value = V>,
{
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        CellSeeded {
            seed: ValueFromJson::<V>::new(),
        }
        .deserialize(parser)
    }
}
fn write_revert<'a, K, V>(mut iter: impl Iterator<Item = (&'a K, &'a Option<V>)>, out: &mut String)
where
    K: JsonKeyCodec + 'a,
    V: JsonSerialize + 'a,
{
    out.push('{');
    if let Some((key, value)) = iter.next() {
        key.encode_json_key(out);
        out.push(':');
        json_serialize_undo(value, out);
        for (key, value) in iter {
            out.push(',');
            key.encode_json_key(out);
            out.push(':');
            json_serialize_undo(value, out);
        }
    }
    out.push('}');
}
fn write_blocks<K, V, M: MapMode + NodeCloning<K, V>>(
    blocks: &BptreeMapReadTxn<'_, K, V, M>,
    out: &mut String,
) where
    K: JsonKeyCodec + Clone + Ord + fmt::Debug + Send + Sync + 'static,
    V: JsonSerialize + Clone + Send + Sync + 'static,
{
    out.push('{');
    let mut iter = blocks.iter();
    if let Some((key, value)) = iter.next() {
        key.encode_json_key(out);
        out.push(':');
        value.json_serialize(out);
        for (key, value) in iter {
            out.push(',');
            key.encode_json_key(out);
            out.push(':');
            value.json_serialize(out);
        }
    }
    out.push('}');
}
#[cfg(test)]
#[path = "json/cell_values_tests.rs"]
mod cell_values_tests;

#[cfg(test)]
#[path = "json/strict_undo_tests.rs"]
mod strict_undo_tests;

#[cfg(test)]
#[path = "json/explicit_undo_tests.rs"]
mod explicit_undo_tests;

#[cfg(test)]
#[path = "json/frozen_original_tests.rs"]
mod frozen_original_tests;

#[cfg(test)]
#[path = "json/charged_cell_tests.rs"]
mod charged_cell_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageReadOnly;
    use norito::json::{from_json, to_json};
    fn sample_storage() -> Storage<String, i32> {
        let storage = Storage::default();
        {
            let mut block = storage.block();
            block.insert("foo".to_owned(), 1);
            block.insert("bar".to_owned(), 2);
            block.commit();
        }
        storage
    }
    #[derive(Clone, Copy)]
    struct StreamingOnlyValueSeed;
    impl ValueSeed for StreamingOnlyValueSeed {
        type Value = i32;
        fn parse_value(&self, _value: json::Value) -> Result<Self::Value, json::Error> {
            Err(json::Error::Message(
                "streaming-only test seed received an owned JSON value".to_owned(),
            ))
        }
        fn parse_parser(&self, parser: &mut json::Parser<'_>) -> Result<Self::Value, json::Error> {
            i32::json_deserialize(parser)
        }
    }
    #[test]
    fn storage_and_cell_seeded_decode_stream_values_directly() {
        let mut parser = json::Parser::new(
            r#"{"revert":{"stale":{"value":3},"gone":null},"blocks":{"live":7}}"#,
        );
        let storage = StorageSeeded {
            kseed: CodecKeySeed::<String>::new(),
            vseed: StreamingOnlyValueSeed,
        }
        .deserialize(&mut parser)
        .expect("storage values decode through the streaming seed");
        parser.skip_ws();
        assert!(parser.eof());
        assert_eq!(storage.view().get("live"), Some(&7));
        let mut parser = json::Parser::new(r#"{"revert":{"value":1},"blocks":2}"#);
        let cell = CellSeeded {
            seed: StreamingOnlyValueSeed,
        }
        .deserialize(&mut parser)
        .expect("cell values decode through the streaming seed");
        parser.skip_ws();
        assert!(parser.eof());
        assert_eq!(*cell.view(), 2);
    }
    #[test]
    fn storage_projection_without_changes_is_byte_identical_and_read_only() {
        let storage = sample_storage();
        let mut block = storage.block();
        block.insert("foo".to_owned(), 9);
        block.remove("absent".to_owned());
        let original = to_json(&block).expect("original block JSON");
        let mut projected = String::new();
        json_serialize_storage_block_with_changes(&block, &BTreeMap::new(), &mut projected);
        assert_eq!(projected, original);
        assert_eq!(to_json(&block).expect("unchanged block JSON"), original);
    }
    #[test]
    fn storage_projection_matches_mutation_and_commit_with_first_touch_undo() {
        fn fixture() -> Storage<String, i32> {
            [("a", 10), ("c", 30), ("e", 50), ("z", 90)]
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect()
        }
        fn earlier_writes(block: &mut StorageBlock<'_, String, i32>) {
            block.insert("a".to_owned(), 11);
            block.insert("b".to_owned(), 20);
            block.remove("c".to_owned());
            let mut transaction = block.transaction();
            transaction.insert("e".to_owned(), 51);
            transaction.apply();
            block.remove("untouched-absence".to_owned());
        }
        let original_storage = fixture();
        let equivalent_storage = fixture();
        let mut original = original_storage.block();
        let mut equivalent = equivalent_storage.block();
        earlier_writes(&mut original);
        earlier_writes(&mut equivalent);
        let changes: BTreeMap<_, _> = [
            ("a", Some(12)),
            ("b", None),
            ("c", Some(31)),
            ("d", Some(40)),
            ("e", None),
            ("missing", None),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        let before = to_json(&original).expect("original JSON");
        let mut projected = String::new();
        json_serialize_storage_block_with_changes(&original, &changes, &mut projected);
        for (key, value) in &changes {
            match value {
                Some(value) => {
                    equivalent.insert(key.clone(), *value);
                }
                None => {
                    equivalent.remove(key.clone());
                }
            }
        }
        assert_eq!(projected, to_json(&equivalent).expect("mutated JSON"));
        assert_eq!(to_json(&original).expect("read-only original"), before);
        assert_eq!(equivalent.revert_map().get("a"), Some(&Some(10)));
        assert_eq!(equivalent.revert_map().get("b"), Some(&None));
        assert_eq!(equivalent.revert_map().get("c"), Some(&Some(30)));
        assert_eq!(equivalent.revert_map().get("missing"), Some(&None));
        equivalent.commit();
        assert_eq!(
            projected,
            to_json(&equivalent_storage).expect("committed JSON")
        );
    }
    #[test]
    fn storage_projection_preserves_key_codec_and_storage_order() {
        let storage: Storage<u64, i32> = [(2, 20), (10, 100)].into_iter().collect();
        let equivalent: Storage<u64, i32> = [(2, 20), (10, 100)].into_iter().collect();
        let block = storage.block();
        let mut changed = equivalent.block();
        let changes = [(1, Some(10)), (2, Some(21)), (11, None)]
            .into_iter()
            .collect();
        let mut projected = String::new();
        json_serialize_storage_block_with_changes(&block, &changes, &mut projected);
        changed.insert(1, 10);
        changed.insert(2, 21);
        changed.remove(11);
        assert_eq!(projected, to_json(&changed).expect("numeric key JSON"));
        assert!(projected.contains("\"1\":10,\"2\":21,\"10\":100"));
    }
    #[test]
    fn storage_roundtrip() {
        let storage = sample_storage();
        let json = to_json(&storage).expect("serialize");
        let decoded: Storage<String, i32> = from_json(&json).expect("deserialize");
        let storage_view = storage.view();
        let decoded_view = decoded.view();
        assert_eq!(decoded_view.len(), storage_view.len());
        for (k, v) in storage_view.iter() {
            let decoded_v = decoded_view.get(k).expect("present");
            assert_eq!(decoded_v, v);
        }
    }
    #[test]
    fn cell_roundtrip() {
        let cell = Cell::new(42i32);
        let json = to_json(&cell).expect("serialize");
        let decoded: Cell<i32> = from_json(&json).expect("deserialize");
        assert_eq!(*decoded.view(), 42);
    }
    #[test]
    fn storage_roundtrip_array_key() {
        let storage: Storage<[u8; 4], i32> = Storage::new();
        {
            let mut block = storage.block();
            block.insert([0xAA, 0xBB, 0xCC, 0xDD], 7);
            block.commit();
        }
        let json = to_json(&storage).expect("serialize hex key");
        let decoded: Storage<[u8; 4], i32> = from_json(&json).expect("deserialize hex key");
        assert_eq!(decoded.view().get(&[0xAA, 0xBB, 0xCC, 0xDD]), Some(&7));
    }
    #[test]
    fn coordinate_tuple_keys_preserve_escaping_limits_and_undo() {
        let key = ("a\u{1f}\"b\\c".to_owned(), u64::MAX, 0);
        let storage = Storage::<(String, u64, u64), u64>::new();
        {
            let mut block = storage.block();
            block.insert(key.clone(), 7);
            block.commit();
        }
        let encoded = to_json(&storage).unwrap();
        let decoded: Storage<(String, u64, u64), u64> = from_json(&encoded).unwrap();
        assert_eq!(decoded.view().get(&key), Some(&7));
        assert!(decoded.block_and_revert().is_empty());
        for malformed in [
            "",
            "a",
            "a\u{1f}1\u{1f}2",
            "\"a\"\u{1f}18446744073709551616\u{1f}0",
            "\"a\"\u{1f}1\u{1f}0\u{1f}3",
        ] {
            assert!(
                <(String, u64, u64)>::decode_json_key(malformed).is_err(),
                "{malformed:?}"
            );
        }
    }
    #[test]
    fn storage_roundtrip_tuple_key() {
        let storage: Storage<(String, String), i32> = Storage::new();
        {
            let mut block = storage.block();
            block.insert(("namespace".into(), "contract".into()), 11);
            block.commit();
        }
        let json = to_json(&storage).expect("serialize tuple key");
        let decoded: Storage<(String, String), i32> =
            from_json(&json).expect("deserialize tuple key");
        assert_eq!(
            decoded
                .view()
                .get(&(String::from("namespace"), String::from("contract"))),
            Some(&11)
        );
    }
    #[test]
    fn storage_roundtrip_inrou_replica_tuple_key() {
        let storage: Storage<(String, String, u16), i32> = Storage::new();
        {
            let mut block = storage.block();
            block.insert(("service".into(), "1.2.3".into(), 7), 42);
            block.commit();
        }
        let json = to_json(&storage).expect("serialize inrou replica tuple key");
        let decoded: Storage<(String, String, u16), i32> =
            from_json(&json).expect("deserialize inrou replica tuple key");
        assert_eq!(
            decoded
                .view()
                .get(&(String::from("service"), String::from("1.2.3"), 7)),
            Some(&42)
        );
    }
}

#[cfg(test)]
#[path = "json/checked_snapshot_tests.rs"]
mod checked_snapshot_tests;
