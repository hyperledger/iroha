//! Construction-independent contract of the single State-owned keyed commitment.
//!
//! `specs/sumeragi.md` §16 is the normative text; rule numbers `K1`..`K12` below
//! refer to its §16.4. This module fixes only what every candidate construction
//! must agree on:
//!
//! - the **committed object**: a finite map from `(table identity, canonical key
//!   bytes)` to canonical value bytes, over the canonical tables and cells that the
//!   exhaustive authority registry declares ([`StateSchema::from_registry`]);
//! - the **statements** a witness can establish against one 32-byte root:
//!   inclusion, absence and a complete half-open key range of one table;
//! - the **update**: one block's net change set, applied atomically.
//!
//! It selects no tree, arity, hash or witness encoding. Task G.2 prototypes
//! candidates behind [`KeyedStateCommitment`] and measures them; task G.3 selects
//! one, publishes its root in the execution result and deletes the alternatives.
//! Until then nothing here is consensus state: no root produced through this
//! interface is published, certified or admitted.
//!
//! Witnesses are opaque canonical byte strings, so native and in-circuit
//! measurements count the same bytes and a carried witness is validated from
//! transaction bytes alone. Verification is a pure function of the schema, the
//! root, the statement and the witness bytes: it reads no State, cache, clock or
//! node configuration, and its only outcomes are acceptance and deterministic
//! rejection.
//!
//! The G.2 candidates are development-only prototypes in
//! `fastpq_prover::state_commitment_prototypes`; `candidates_tests.rs` puts each
//! behind this interface and runs `conformance::check_contract` on it (unit tests
//! built with the `state-commitment-prototypes` feature). Their measurements are
//! in `specs/state_commitment_candidates.json`. No candidate is selected here.
//! TODO(G.3): bind the selected construction to the State publication owner and
//! replace the World state accumulator root in the execution result. Move
//! [`KeyedStateRoot`] beside `ExecutionCommitment` as the one shared type, with an
//! explicit Norito codec for the payload that [`KeyedStateRoot::from_payload`] fixes.

use super::{Canonical, CanonicalLayout, Field, Role, Schema};

/// Domain tag of [`StateSchema::canonical_bytes`].
pub(crate) const SCHEMA_DOMAIN: &[u8] = b"iroha:state-keyed-commitment:schema:v1\0";

/// Byte length of every keyed State root, whatever the construction.
pub(crate) const ROOT_BYTES: usize = 32;

/// The only key of a cell: a cell is the single entry at the empty key of its table.
pub(crate) const CELL_KEY: &[u8] = &[];

/// Root of the keyed State commitment: 32 opaque bytes fixed by the construction.
///
/// The bytes carry no `iroha_crypto::Hash` marker bit and no field-element
/// interpretation; only equality is meaningful outside the construction.
///
/// This is the prototype of the wire type of `parent_keyed_state_root` and
/// `keyed_state_root` (`specs/sumeragi.md` §16.6). A construction whose native root
/// is not 32 bytes commits a normalisation hash of it; G.2 measures and G.3 freezes
/// that encoding. A marker-setting `Hash` conversion is never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct KeyedStateRoot(pub(crate) [u8; ROOT_BYTES]);

impl KeyedStateRoot {
    /// The Norito payload of a root field: exactly [`ROOT_BYTES`] raw bytes with all 256
    /// bits preserved. The enclosing record keeps its own field framing.
    pub(crate) const fn payload(&self) -> &[u8; ROOT_BYTES] {
        &self.0
    }

    /// Decode the payload of a root field.
    ///
    /// Only exactly [`ROOT_BYTES`] bytes are a root. An element-framed array, a
    /// length-prefixed byte string, a shorter or a longer payload is not one, and no
    /// marker bit is checked, set or cleared.
    pub(crate) fn from_payload(payload: &[u8]) -> Option<Self> {
        <[u8; ROOT_BYTES]>::try_from(payload).ok().map(Self)
    }
}

/// Whether a committed identity is a keyed table or a singleton cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TableShape {
    /// Zero or more entries under canonical key bytes.
    Table,
    /// At most one entry, at [`CELL_KEY`].
    Cell,
}

impl TableShape {
    /// Stable tag in the canonical schema descriptor.
    const fn tag(self) -> u8 {
        match self {
            Self::Table => 0,
            Self::Cell => 1,
        }
    }
}

/// One committed table or cell: its registry identity and codec identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TableDescriptor {
    id: String,
    shape: TableShape,
    key_schema: String,
    value_schema: String,
}

impl TableDescriptor {
    /// Describe a keyed table with its key and value codec identities.
    pub(crate) fn table(
        id: impl Into<String>,
        key_schema: impl Into<String>,
        value_schema: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            shape: TableShape::Table,
            key_schema: key_schema.into(),
            value_schema: value_schema.into(),
        }
    }

    /// Describe a singleton cell with its value codec identity.
    pub(crate) fn cell(id: impl Into<String>, value_schema: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            shape: TableShape::Cell,
            key_schema: String::new(),
            value_schema: value_schema.into(),
        }
    }

    /// Stable registry identity, for example `world.accounts`.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Table or cell.
    pub(crate) fn shape(&self) -> TableShape {
        self.shape
    }

    /// Codec identity of the key; empty for a cell.
    pub(crate) fn key_schema(&self) -> &str {
        &self.key_schema
    }

    /// Codec identity of the value.
    pub(crate) fn value_schema(&self) -> &str {
        &self.value_schema
    }
}

/// A schema that cannot be committed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SchemaError {
    /// A table identity is empty.
    #[error("keyed State schema has an empty table identity")]
    EmptyIdentity,
    /// Two descriptors share one identity.
    #[error("keyed State schema declares {0} twice")]
    DuplicateTable(String),
    /// A table has no key codec, or a cell declares one.
    #[error("keyed State schema has an inconsistent key codec for {0}")]
    KeyCodec(String),
    /// A value codec identity is empty.
    #[error("keyed State schema has no value codec for {0}")]
    ValueCodec(String),
    /// An identity or the table count does not fit the descriptor's `u32` lengths.
    #[error("keyed State schema exceeds the descriptor length bound")]
    Length,
    /// The registry still declares an unresolved projection for this field.
    #[error("State authority field has no complete V1 schema: {0}")]
    Unresolved(&'static str),
}

/// The complete ordered set of committed tables and cells (rule K1).
///
/// Tables are held in the canonical order: ascending bytes of their identities.
/// That order is the table order of every root, range and result layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StateSchema {
    tables: Vec<TableDescriptor>,
}

impl StateSchema {
    /// Validate descriptors and place them in the canonical identity order.
    ///
    /// # Errors
    /// An identity is empty or repeated, a codec identity is missing or misplaced, or a
    /// length exceeds `u32`.
    pub(crate) fn new(mut tables: Vec<TableDescriptor>) -> Result<Self, SchemaError> {
        if u32::try_from(tables.len()).is_err() {
            return Err(SchemaError::Length);
        }
        for table in &tables {
            if table.id.is_empty() {
                return Err(SchemaError::EmptyIdentity);
            }
            let key_declared = !table.key_schema.is_empty();
            if key_declared != (table.shape == TableShape::Table) {
                return Err(SchemaError::KeyCodec(table.id.clone()));
            }
            if table.value_schema.is_empty() {
                return Err(SchemaError::ValueCodec(table.id.clone()));
            }
            for text in [&table.id, &table.key_schema, &table.value_schema] {
                if u32::try_from(text.len()).is_err() {
                    return Err(SchemaError::Length);
                }
            }
        }
        tables.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
        if let Some(pair) = tables.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(SchemaError::DuplicateTable(pair[0].id.clone()));
        }
        Ok(Self { tables })
    }

    /// The committed tables and cells in canonical order.
    pub(crate) fn tables(&self) -> &[TableDescriptor] {
        &self.tables
    }

    /// Canonical position and descriptor of a declared identity.
    pub(crate) fn table(&self, id: &str) -> Option<(usize, &TableDescriptor)> {
        self.tables
            .binary_search_by(|table| table.id.as_bytes().cmp(id.as_bytes()))
            .ok()
            .map(|index| (index, &self.tables[index]))
    }

    /// The canonical descriptor bytes that every construction binds into its root (K1):
    ///
    /// ```text
    /// SCHEMA_DOMAIN ‖ le32(count) ‖ for each table in canonical order:
    ///   shape ‖ le32(len(id)) ‖ id ‖ le32(len(key)) ‖ key ‖ le32(len(value)) ‖ value
    /// ```
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = SCHEMA_DOMAIN.to_vec();
        push_len(&mut bytes, self.tables.len());
        for table in &self.tables {
            bytes.push(table.shape.tag());
            for text in [&table.id, &table.key_schema, &table.value_schema] {
                push_len(&mut bytes, text.len());
                bytes.extend_from_slice(text.as_bytes());
            }
        }
        bytes
    }

    /// Check one `(table, key)` position: the table is declared and a cell uses [`CELL_KEY`].
    ///
    /// # Errors
    /// See [`StatementError`].
    pub(crate) fn check_key(&self, table: &str, key: &[u8]) -> Result<usize, StatementError> {
        let (index, descriptor) = self.table(table).ok_or(StatementError::UnknownTable)?;
        if descriptor.shape == TableShape::Cell && key != CELL_KEY {
            return Err(StatementError::CellKey);
        }
        Ok(index)
    }

    /// Check a range statement (K6): the table is declared, the interval is nonempty and
    /// the claimed entries are strictly ascending inside it.
    ///
    /// This is the construction-independent part of range verification. It establishes
    /// nothing about the committed State.
    ///
    /// # Errors
    /// See [`StatementError`].
    pub(crate) fn check_range(
        &self,
        table: &str,
        range: KeyRange<'_>,
        entries: &[Entry<'_>],
    ) -> Result<usize, StatementError> {
        let (index, descriptor) = self.table(table).ok_or(StatementError::UnknownTable)?;
        range.validate()?;
        let mut previous: Option<&[u8]> = None;
        for entry in entries {
            if !range.contains(entry.key) {
                return Err(StatementError::EntryOutsideRange);
            }
            if descriptor.shape == TableShape::Cell && entry.key != CELL_KEY {
                return Err(StatementError::CellKey);
            }
            if previous.is_some_and(|previous| previous >= entry.key) {
                return Err(StatementError::EntryOrder);
            }
            previous = Some(entry.key);
        }
        Ok(index)
    }

    /// The schema of the actual State: every canonical table and cell of the exhaustive
    /// authority registry, nested owners included.
    ///
    /// Derived indexes, authenticated history and node-local fields are not committed
    /// entries; the registry classifies them and the inventory
    /// (`specs/state_table_inventory.json`) records why.
    ///
    /// # Errors
    /// A canonical field still declares a `Required` projection, or two fields share an
    /// identity.
    pub(crate) fn from_registry(fields: &'static [Field]) -> Result<Self, SchemaError> {
        let mut tables = Vec::new();
        collect_registry(fields, &mut tables)?;
        Self::new(tables)
    }
}

fn push_len(bytes: &mut Vec<u8>, length: usize) {
    // `StateSchema::new` bounds every length by `u32`.
    let length = u32::try_from(length).expect("schema lengths were validated");
    bytes.extend_from_slice(&length.to_le_bytes());
}

fn collect_registry(
    fields: &'static [Field],
    tables: &mut Vec<TableDescriptor>,
) -> Result<(), SchemaError> {
    for field in fields {
        match field.role {
            Role::Canonical(Canonical::Table { key, value }) => tables.push(TableDescriptor {
                id: field.id.to_owned(),
                shape: TableShape::Table,
                key_schema: codec_identity(field.id, key)?,
                value_schema: codec_identity(field.id, value)?,
            }),
            Role::Canonical(Canonical::Cell(value)) => tables.push(TableDescriptor {
                id: field.id.to_owned(),
                shape: TableShape::Cell,
                key_schema: String::new(),
                value_schema: codec_identity(field.id, value)?,
            }),
            Role::Canonical(Canonical::Owner(children)) => collect_registry(children, tables)?,
            Role::Derived { .. } | Role::History { .. } | Role::Local(_) => {}
        }
    }
    Ok(())
}

/// The codec identity of a registry schema: codec kind, declared identity and layout.
///
/// `norito:<nominal name>@<major>.<minor>.<flags>` for a declared Norito type and
/// `semantic:<identity>@<major>.<minor>.<flags>` for a semantic projection.
pub(crate) fn codec_identity(field: &'static str, schema: Schema) -> Result<String, SchemaError> {
    let (kind, identity, layout): (&str, std::borrow::Cow<'static, str>, CanonicalLayout) =
        match schema {
            Schema::Norito {
                nominal_name,
                layout,
            } => ("norito", nominal_name(), layout),
            Schema::Semantic {
                identity, layout, ..
            } => ("semantic", std::borrow::Cow::Borrowed(identity), layout),
            Schema::Required { .. } => return Err(SchemaError::Unresolved(field)),
        };
    Ok(format!(
        "{kind}:{identity}@{}.{}.{}",
        layout.major, layout.minor, layout.flags
    ))
}

/// One committed entry: canonical key and value bytes inside one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    /// Canonical key bytes ([`CELL_KEY`] for a cell).
    pub(crate) key: &'a [u8],
    /// Canonical value bytes; an empty value is present, never absent.
    pub(crate) value: &'a [u8],
}

/// One net change of a block: the value after the block, or `None` when the key is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Change<'a> {
    /// Registry identity of the table or cell.
    pub(crate) table: &'a str,
    /// Canonical key bytes ([`CELL_KEY`] for a cell).
    pub(crate) key: &'a [u8],
    /// Canonical value bytes after the block, or `None` for an absent key.
    pub(crate) value: Option<&'a [u8]>,
}

/// A half-open interval of canonical key bytes inside one table (K6).
///
/// Keys are compared as byte strings. `lower` is inclusive; `upper` is exclusive and
/// `None` is unbounded, so `KeyRange::FULL` is the complete table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyRange<'a> {
    /// Inclusive lower bound; the empty string is the start of the table.
    pub(crate) lower: &'a [u8],
    /// Exclusive upper bound; `None` is the end of the table.
    pub(crate) upper: Option<&'a [u8]>,
}

impl<'a> KeyRange<'a> {
    /// Every key of a table.
    pub(crate) const FULL: KeyRange<'static> = KeyRange {
        lower: &[],
        upper: None,
    };

    /// The interval `[lower, upper)`.
    pub(crate) const fn new(lower: &'a [u8], upper: Option<&'a [u8]>) -> Self {
        Self { lower, upper }
    }

    /// An interval must admit at least one byte string: `lower < upper`.
    ///
    /// # Errors
    /// [`StatementError::EmptyRange`] when the upper bound does not exceed the lower.
    pub(crate) fn validate(&self) -> Result<(), StatementError> {
        match self.upper {
            Some(upper) if upper <= self.lower => Err(StatementError::EmptyRange),
            _ => Ok(()),
        }
    }

    /// Whether `key` lies inside the interval.
    pub(crate) fn contains(&self, key: &[u8]) -> bool {
        key >= self.lower && self.upper.is_none_or(|upper| key < upper)
    }
}

/// The exclusive upper bound of the keys that start with `prefix`, or `None` when no
/// byte string bounds them (an empty or all-`0xff` prefix).
///
/// A tuple or record key encodes every component as `[len][payload]` (Norito's field
/// framing), so "every key whose leading components are `c`" is the interval
/// `[p, prefix_upper_bound(p))` for the exact leading bytes `p` that the key encoding
/// emits for those components, framing included. The bare encoding of a component
/// alone is not that prefix.
pub(crate) fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let last = prefix.iter().rposition(|byte| *byte != u8::MAX)?;
    let mut upper = prefix[..=last].to_vec();
    upper[last] += 1;
    Some(upper)
}

/// Opaque canonical witness bytes of one statement (K9).
///
/// The encoding belongs to the construction. Verification consumes it completely:
/// truncated encodings and trailing bytes are rejected, and every byte counts toward
/// the carried witness caps of a transaction. Proofs need not be non-malleable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Witness(Vec<u8>);

impl Witness {
    /// Wrap witness bytes received from a transaction or produced by a prover.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The canonical witness bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A statement that is ill-formed before any commitment is consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StatementError {
    /// The table identity is not declared by the schema.
    #[error("the keyed State schema does not declare this table")]
    UnknownTable,
    /// A cell was addressed with a key other than the empty key.
    #[error("a cell has only the empty key")]
    CellKey,
    /// The interval's upper bound does not exceed its lower bound.
    #[error("the key interval is empty")]
    EmptyRange,
    /// A claimed range entry lies outside the interval.
    #[error("a claimed entry lies outside the key interval")]
    EntryOutsideRange,
    /// Claimed range entries are not strictly ascending by key bytes.
    #[error("claimed entries are not strictly ascending")]
    EntryOrder,
}

/// Why a construction could not complete an operation on this node.
///
/// A local failure is never a verdict about a transaction: the caller retries or
/// defers. Verification has no such outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LocalFailure {
    /// A local memory or work budget refused the operation.
    #[error("local resources were refused")]
    Resources,
    /// Local durable storage of the construction's nodes failed.
    #[error("local storage failed")]
    Storage,
}

/// A change set that was refused; the commitment is unchanged (K10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UpdateError {
    /// A change addresses an undeclared table or a cell under a nonempty key.
    #[error("invalid keyed State change: {0}")]
    Statement(#[from] StatementError),
    /// One `(table, key)` occurs twice in a net change set.
    #[error("a net change set names one key twice")]
    DuplicateChange,
    /// A local failure of the construction. Never a verdict.
    #[error("keyed State construction failed locally: {0}")]
    Local(LocalFailure),
}

/// A witness that the prover cannot produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProveError {
    /// The statement is ill-formed.
    #[error("invalid keyed State statement: {0}")]
    Statement(#[from] StatementError),
    /// Inclusion was requested for an absent key.
    #[error("the key is absent")]
    KeyAbsent,
    /// Absence was requested for a present key.
    #[error("the key is present")]
    KeyPresent,
    /// A local failure of the construction. Never a verdict.
    #[error("keyed State construction failed locally: {0}")]
    Local(LocalFailure),
}

/// Deterministic rejection of a carried witness.
///
/// Verification has no local-failure outcome: it is a pure function of its inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Rejection {
    /// The statement is ill-formed.
    #[error("invalid keyed State statement: {0}")]
    Statement(#[from] StatementError),
    /// The witness bytes are not a canonical witness of this construction.
    #[error("the witness is malformed")]
    Malformed,
    /// The witness is well-formed but does not establish the statement at this root.
    #[error("the witness does not establish the statement at this root")]
    NotProven,
}

/// One candidate construction of the keyed State commitment.
///
/// An implementation owns the committed entries (or their digests) of one State
/// version and answers the three statement kinds against its root. The contract
/// (`specs/sumeragi.md` §16.4, K1..K12) is checked by `conformance::check_contract`.
pub(crate) trait KeyedStateCommitment: Sized {
    /// Stable identity of the construction and its parameters, recorded with every
    /// measurement (for example `reference-oracle/v1`).
    const CONSTRUCTION: &'static str;

    /// The commitment of the State with no entries under `schema`.
    fn empty(schema: &StateSchema) -> Self;

    /// Apply one block's net change set. Each `(table, key)` occurs at most once; a
    /// `None` value for an absent key and a value equal to the committed one are
    /// no-ops. Either every change is applied or none is (K10).
    ///
    /// # Errors
    /// See [`UpdateError`]; the commitment is unchanged.
    fn apply(&mut self, changes: &[Change<'_>]) -> Result<(), UpdateError>;

    /// The root: a function of the schema and the committed entries alone (K1, K2).
    fn root(&self) -> KeyedStateRoot;

    /// Number of committed entries.
    fn entries(&self) -> u64;

    /// Witness that `(table, key)` is present with its committed value (K4).
    ///
    /// # Errors
    /// The statement is ill-formed or the key is absent.
    fn prove_inclusion(&self, table: &str, key: &[u8]) -> Result<Witness, ProveError>;

    /// Witness that `(table, key)` is absent (K5).
    ///
    /// # Errors
    /// The statement is ill-formed or the key is present.
    fn prove_absence(&self, table: &str, key: &[u8]) -> Result<Witness, ProveError>;

    /// Witness of every committed entry of `table` inside `range`, in key order (K6).
    ///
    /// # Errors
    /// The statement is ill-formed.
    fn prove_range(&self, table: &str, range: KeyRange<'_>) -> Result<Witness, ProveError>;

    /// Accept iff `root` commits `(table, key) ↦ value`.
    ///
    /// # Errors
    /// See [`Rejection`].
    fn verify_inclusion(
        schema: &StateSchema,
        root: &KeyedStateRoot,
        table: &str,
        key: &[u8],
        value: &[u8],
        witness: &Witness,
    ) -> Result<(), Rejection>;

    /// Accept iff `root` commits no entry at `(table, key)`.
    ///
    /// # Errors
    /// See [`Rejection`].
    fn verify_absence(
        schema: &StateSchema,
        root: &KeyedStateRoot,
        table: &str,
        key: &[u8],
        witness: &Witness,
    ) -> Result<(), Rejection>;

    /// Accept iff `entries` is exactly the ascending list of every entry of `table`
    /// that `root` commits inside `range`.
    ///
    /// # Errors
    /// See [`Rejection`].
    fn verify_range(
        schema: &StateSchema,
        root: &KeyedStateRoot,
        table: &str,
        range: KeyRange<'_>,
        entries: &[Entry<'_>],
        witness: &Witness,
    ) -> Result<(), Rejection>;
}

// The G.2 candidate prototypes behind this contract; development only.
// TODO(G.3): remove with the prototypes.
#[cfg(all(test, feature = "state-commitment-prototypes"))]
mod candidates_tests;
#[cfg(test)]
pub(crate) mod conformance;
#[cfg(test)]
pub(crate) mod reference;
#[cfg(test)]
mod tests;
