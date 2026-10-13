//! Multi-table wrapper of the prototype engines.
//!
//! The committed object of `specs/sumeragi.md` §16.1 is a map from `(table,
//! key)` to value under one schema. This wrapper turns it into the single
//! ordered keyspace the engines commit:
//!
//! - the composite key is `be32(table position) ‖ key`, so composite byte
//!   order is the canonical order (table position, then key bytes) and no key
//!   of one table is a key of another;
//! - the interval `[lower, upper)` of table `t` is the composite interval from
//!   `be32(t) ‖ lower` to `be32(t) ‖ upper`, or to `be32(t + 1)` when unbounded;
//! - the root is `compress(DOMAIN_ROOT, structure root, H(schema descriptor))`
//!   encoded as 32 bytes, so the schema descriptor is bound for the empty State
//!   as well.
//!
//! The schema is read from the canonical descriptor bytes that
//! `StateSchema::canonical_bytes` produces; this module does not define a
//! second schema.

use std::sync::{Arc, Mutex};

use super::{
    DOMAIN_ROOT, DOMAIN_SCHEMA, Engine, Reject, Storage,
    hash::{DIGEST_BYTES, Digest, HashProfile, digest_from_bytes, digest_to_bytes},
};

/// Domain tag of the canonical schema descriptor (`specs/sumeragi.md` §16.1).
const SCHEMA_DESCRIPTOR_DOMAIN: &[u8] = b"iroha:state-keyed-commitment:schema:v1\0";

/// Shape tag of a cell in the descriptor.
const SHAPE_CELL: u8 = 1;

/// A statement or change that is ill formed before any commitment is consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementFault {
    /// The table position is not declared by the schema.
    UnknownTable,
    /// A cell was addressed with a key other than the empty key.
    CellKey,
    /// The interval's upper bound does not exceed its lower bound.
    EmptyRange,
    /// A claimed range entry lies outside the interval.
    EntryOutsideRange,
    /// Claimed range entries are not strictly ascending.
    EntryOrder,
    /// One position occurs twice in a net change set.
    DuplicateChange,
}

/// Why verification did not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The statement is ill formed.
    Statement(StatementFault),
    /// The witness does not establish the statement.
    Witness(Reject),
}

impl From<StatementFault> for VerifyError {
    fn from(fault: StatementFault) -> Self {
        Self::Statement(fault)
    }
}

impl From<Reject> for VerifyError {
    fn from(reject: Reject) -> Self {
        Self::Witness(reject)
    }
}

/// Reader over descriptor bytes.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(length)?;
        self.0 = tail;
        Some(head)
    }

    fn le32(&mut self) -> Option<usize> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(bytes)).ok()
    }
}

/// The tables of a canonical schema descriptor, in canonical order.
///
/// The descriptor digest of each hash profile is computed once and kept: it is
/// a constant of the schema, and a verifier that rehashed the descriptor for
/// every witness would measure the descriptor, not the witness. Clones share
/// the kept digests.
#[derive(Clone, Debug)]
pub struct PrototypeSchema {
    descriptor: Vec<u8>,
    tables: Vec<(String, bool)>,
    digests: Arc<Mutex<Vec<(&'static str, Digest)>>>,
}

impl PartialEq for PrototypeSchema {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor
    }
}

impl Eq for PrototypeSchema {}

impl PrototypeSchema {
    /// Parse canonical schema descriptor bytes.
    ///
    /// Returns `None` unless the bytes are exactly one descriptor: the domain
    /// tag, the table count and for each table its shape and its three
    /// length-prefixed identities.
    #[must_use]
    pub fn from_descriptor(descriptor: &[u8]) -> Option<Self> {
        let mut cursor = Cursor(descriptor.strip_prefix(SCHEMA_DESCRIPTOR_DOMAIN)?);
        let count = cursor.le32()?;
        let mut tables = Vec::new();
        for _ in 0..count {
            let shape = cursor.take(1)?[0];
            let length = cursor.le32()?;
            let identity = core::str::from_utf8(cursor.take(length)?).ok()?.to_owned();
            for _ in 0..2 {
                let length = cursor.le32()?;
                cursor.take(length)?;
            }
            tables.push((identity, shape == SHAPE_CELL));
        }
        cursor.0.is_empty().then(|| Self {
            descriptor: descriptor.to_vec(),
            tables,
            digests: Arc::default(),
        })
    }

    /// The canonical descriptor bytes.
    #[must_use]
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }

    /// Number of committed tables and cells.
    #[must_use]
    pub fn tables(&self) -> u32 {
        u32::try_from(self.tables.len()).expect("the descriptor count is a u32")
    }

    /// Registry identity of the table at a canonical position.
    #[must_use]
    pub fn identity(&self, table: u32) -> Option<&str> {
        self.tables
            .get(table as usize)
            .map(|(identity, _)| identity.as_str())
    }

    /// Canonical position of a registry identity.
    #[must_use]
    pub fn position(&self, identity: &str) -> Option<u32> {
        self.tables
            .binary_search_by(|(candidate, _)| candidate.as_bytes().cmp(identity.as_bytes()))
            .ok()
            .and_then(|position| u32::try_from(position).ok())
    }

    /// Whether the table at a canonical position is a cell.
    #[must_use]
    pub fn is_cell(&self, table: u32) -> Option<bool> {
        self.tables.get(table as usize).map(|(_, cell)| *cell)
    }

    /// Digest of the descriptor under one hash profile, hashed on first use.
    ///
    /// # Panics
    /// Panics when a thread panicked while it held the digest cache.
    #[must_use]
    pub fn digest<H: HashProfile>(&self) -> Digest {
        let mut digests = self
            .digests
            .lock()
            .expect("the digest cache is not poisoned");
        if let Some((_, digest)) = digests.iter().find(|(profile, _)| *profile == H::NAME) {
            return *digest;
        }
        let digest = H::hash_bytes(DOMAIN_SCHEMA, &self.descriptor);
        digests.push((H::NAME, digest));
        digest
    }

    fn check_key(&self, table: u32, key: &[u8]) -> Result<(), StatementFault> {
        match self.is_cell(table) {
            None => Err(StatementFault::UnknownTable),
            Some(true) if !key.is_empty() => Err(StatementFault::CellKey),
            Some(_) => Ok(()),
        }
    }

    fn check_range(
        &self,
        table: u32,
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
    ) -> Result<(), StatementFault> {
        let cell = self.is_cell(table).ok_or(StatementFault::UnknownTable)?;
        if upper.is_some_and(|upper| upper <= lower) {
            return Err(StatementFault::EmptyRange);
        }
        let mut previous: Option<&[u8]> = None;
        for (key, _) in entries {
            if *key < lower || upper.is_some_and(|upper| *key >= upper) {
                return Err(StatementFault::EntryOutsideRange);
            }
            if cell && !key.is_empty() {
                return Err(StatementFault::CellKey);
            }
            if previous.is_some_and(|previous| previous >= *key) {
                return Err(StatementFault::EntryOrder);
            }
            previous = Some(key);
        }
        Ok(())
    }
}

/// The composite key of one position.
#[must_use]
pub fn composite_key(table: u32, key: &[u8]) -> Vec<u8> {
    let mut composite = Vec::with_capacity(4 + key.len());
    composite.extend_from_slice(&table.to_be_bytes());
    composite.extend_from_slice(key);
    composite
}

/// The composite interval of one table's key interval.
pub(super) fn composite_range(
    table: u32,
    lower: &[u8],
    upper: Option<&[u8]>,
) -> (Vec<u8>, Option<Vec<u8>>) {
    // An unbounded interval ends where the next table position begins.
    let end = upper.map_or_else(
        || table.checked_add(1).map(|next| next.to_be_bytes().to_vec()),
        |upper| Some(composite_key(table, upper)),
    );
    (composite_key(table, lower), end)
}

/// The normalised 32-byte root of a structure root under a schema digest.
#[must_use]
pub fn normalised_root<H: HashProfile>(structure: &Digest, schema: &Digest) -> [u8; DIGEST_BYTES] {
    digest_to_bytes(&H::compress(DOMAIN_ROOT, 0, structure, schema))
}

/// One net change of a block: table position, key and the value after the
/// block, or `None` when the key is absent.
pub type TableChange<'a> = (u32, &'a [u8], Option<&'a [u8]>);

/// One prototype engine under a schema.
pub struct KeyedMap<E: Engine> {
    engine: E,
    schema: PrototypeSchema,
    schema_digest: Digest,
}

impl<E: Engine> Clone for KeyedMap<E> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            schema: self.schema.clone(),
            schema_digest: self.schema_digest,
        }
    }
}

impl<E: Engine> KeyedMap<E> {
    /// The State with no entries under `schema`.
    #[must_use]
    pub fn empty(schema: PrototypeSchema) -> Self {
        let schema_digest = schema.digest::<E::Hash>();
        Self {
            engine: E::new(),
            schema,
            schema_digest,
        }
    }

    /// The schema.
    #[must_use]
    pub fn schema(&self) -> &PrototypeSchema {
        &self.schema
    }

    /// The engine, for its witness openings and storage figures.
    #[must_use]
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Apply one net change set, completely or not at all.
    ///
    /// # Errors
    /// A change addresses an undeclared table or a cell under a nonempty key,
    /// or one position occurs twice; the commitment is unchanged.
    pub fn apply(&mut self, changes: &[TableChange<'_>]) -> Result<(), StatementFault> {
        let mut composite = Vec::with_capacity(changes.len());
        for (table, key, value) in changes {
            self.schema.check_key(*table, key)?;
            composite.push((composite_key(*table, key), *value));
        }
        let mut sorted: Vec<&[u8]> = composite.iter().map(|(key, _)| key.as_slice()).collect();
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StatementFault::DuplicateChange);
        }
        let borrowed: Vec<(&[u8], Option<&[u8]>)> = composite
            .iter()
            .map(|(key, value)| (key.as_slice(), *value))
            .collect();
        self.engine.apply(&borrowed);
        Ok(())
    }

    /// The 32-byte root: a function of the schema and the entries alone.
    #[must_use]
    pub fn root(&self) -> [u8; DIGEST_BYTES] {
        normalised_root::<E::Hash>(&self.engine.structure_root(), &self.schema_digest)
    }

    /// Number of committed entries.
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.engine.len()
    }

    /// Size of the authenticated structure.
    #[must_use]
    pub fn storage(&self) -> Storage {
        self.engine.storage()
    }

    /// Witness that a position is present; `Ok(None)` when it is absent.
    ///
    /// # Errors
    /// The statement is ill formed.
    pub fn prove_inclusion(
        &self,
        table: u32,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StatementFault> {
        self.schema.check_key(table, key)?;
        Ok(self.engine.prove_inclusion(&composite_key(table, key)))
    }

    /// Witness that a position is absent; `Ok(None)` when it is present.
    ///
    /// # Errors
    /// The statement is ill formed.
    pub fn prove_absence(&self, table: u32, key: &[u8]) -> Result<Option<Vec<u8>>, StatementFault> {
        self.schema.check_key(table, key)?;
        Ok(self.engine.prove_absence(&composite_key(table, key)))
    }

    /// Witness of every entry of `table` with `lower <= key < upper`.
    ///
    /// # Errors
    /// The statement is ill formed.
    pub fn prove_range(
        &self,
        table: u32,
        lower: &[u8],
        upper: Option<&[u8]>,
    ) -> Result<Vec<u8>, StatementFault> {
        self.schema.check_range(table, lower, upper, &[])?;
        let (lower, upper) = composite_range(table, lower, upper);
        Ok(self.engine.prove_range(&lower, upper.as_deref()))
    }

    fn accept(
        schema: &PrototypeSchema,
        root: &[u8; DIGEST_BYTES],
        structure: Result<Digest, Reject>,
    ) -> Result<(), VerifyError> {
        if normalised_root::<E::Hash>(&structure?, &schema.digest::<E::Hash>()) == *root {
            Ok(())
        } else {
            Err(Reject::NotProven.into())
        }
    }

    /// Accept iff `root` commits `(table, key)` with exactly `value`.
    ///
    /// # Errors
    /// See [`VerifyError`].
    pub fn verify_inclusion(
        schema: &PrototypeSchema,
        root: &[u8; DIGEST_BYTES],
        table: u32,
        key: &[u8],
        value: &[u8],
        witness: &[u8],
    ) -> Result<(), VerifyError> {
        schema.check_key(table, key)?;
        let structure = E::inclusion_root(&composite_key(table, key), value, witness);
        Self::accept(schema, root, structure)
    }

    /// Accept iff `root` commits no entry at `(table, key)`.
    ///
    /// # Errors
    /// See [`VerifyError`].
    pub fn verify_absence(
        schema: &PrototypeSchema,
        root: &[u8; DIGEST_BYTES],
        table: u32,
        key: &[u8],
        witness: &[u8],
    ) -> Result<(), VerifyError> {
        schema.check_key(table, key)?;
        let structure = E::absence_root(&composite_key(table, key), witness);
        Self::accept(schema, root, structure)
    }

    /// Accept iff `entries` is exactly the ascending list of every entry of
    /// `table` that `root` commits with `lower <= key < upper`.
    ///
    /// # Errors
    /// See [`VerifyError`].
    pub fn verify_range(
        schema: &PrototypeSchema,
        root: &[u8; DIGEST_BYTES],
        table: u32,
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<(), VerifyError> {
        schema.check_range(table, lower, upper, entries)?;
        let keys: Vec<Vec<u8>> = entries
            .iter()
            .map(|(key, _)| composite_key(table, key))
            .collect();
        let composite: Vec<(&[u8], &[u8])> = keys
            .iter()
            .zip(entries)
            .map(|(key, (_, value))| (key.as_slice(), *value))
            .collect();
        let (lower, upper) = composite_range(table, lower, upper);
        let structure = E::range_root(&lower, upper.as_deref(), &composite, witness);
        Self::accept(schema, root, structure)
    }
}

/// Decode a 32-byte root into the digest words of a profile, or `None` when
/// the bytes cannot be a root of that profile.
#[must_use]
pub fn root_digest<H: HashProfile>(root: &[u8; DIGEST_BYTES]) -> Option<Digest> {
    let digest = digest_from_bytes(root);
    H::is_canonical(&digest).then_some(digest)
}

/// Build canonical schema descriptor bytes from `(identity, key codec, value
/// codec)` rows; an empty key codec declares a cell. Rows are sorted by
/// identity bytes. For tests and workloads that have no registry.
#[must_use]
pub fn descriptor_from_rows(rows: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut bytes = SCHEMA_DESCRIPTOR_DOMAIN.to_vec();
    let length = |length: usize| {
        u32::try_from(length)
            .expect("prototype schema lengths fit u32")
            .to_le_bytes()
    };
    bytes.extend_from_slice(&length(sorted.len()));
    for (identity, key, value) in sorted {
        bytes.push(u8::from(key.is_empty()));
        for text in [identity, key, value] {
            bytes.extend_from_slice(&length(text.len()));
            bytes.extend_from_slice(text.as_bytes());
        }
    }
    bytes
}
