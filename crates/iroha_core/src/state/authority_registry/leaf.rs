//! Bounded canonical Norito leaves for explicitly selected State authority tables.
//!
//! This owner only commits the rows its caller supplies. It cannot certify that
//! every row or every authoritative table was supplied. Its hashed lookup/range
//! tree and separate digest-only raw-Norito-key ordered tree cover only scoped
//! rows. Neither owns a finalized State root or publication/recovery state.
//! TODO: fund proof outputs, metadata and complete authoritative
//! owner traversal before State cutover. Paired scoped trees consume one streaming
//! canonical encoding per value; their caller must still prove completeness.

use super::{Canonical, Field, Role, STATE_FIELDS, Schema, V1_LAYOUT};
use iroha_crypto::{
    Hash, MAX_NORITO_KEY_BYTES, MAX_NORITO_TREE_ENTRIES, MAX_NORITO_TREE_PAYLOAD_BYTES,
    MAX_NORITO_VALUE_BYTES, MerkleMap, MerkleMapError, MerkleMapLookupProof, MerkleMapRangeError,
    MerkleMapRangeProof, MerkleMapReadError, NoritoKeyDigestRangeProofV1,
    NoritoKeyDigestRangeTreeV1, NoritoKeyRangeError, NoritoKeyRangeTreeV1,
    NoritoKeyRangeVerifyRequestV1, VerifiedNoritoKeyDigestRangeV1, digest_norito_value_frame_v1,
};
use norito::{NoritoSchema, codec::Encode};
use std::{
    convert::Infallible,
    io::{self, Write},
};

#[path = "leaf/encoding_error.rs"]
mod encoding_error;
use encoding_error::{EncodingError, EncodingOperation, EncodingReason};

const SCHEMA_START: &[u8] = b"iroha:state-table-substrate:schema:start:v1\0";
const SCHEMA_FIELD: &[u8] = b"iroha:state-table-substrate:schema:field:v1\0";
const KEY_PAYLOAD: &[u8] = b"iroha:state-table-substrate:key-payload:v1\0";
const VALUE_PAYLOAD: &[u8] = b"iroha:state-table-substrate:value-payload:v1\0";
const PATH: &[u8] = b"iroha:state-table-substrate:path:v1\0";
const ROOT: &[u8] = b"iroha:state-table-substrate:root:v1\0";
const PAIRED_ROOT: &[u8] = b"iroha:state-table-substrate:paired-root:v1\0";

/// Operational bounds for one scoped, cold table-leaf construction.
///
/// The caller supplies these limits independently of the original local pool.
/// Proof output and metadata funding remain separate cutover obligations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LeafLimits {
    /// Maximum number of explicitly selected tables.
    pub max_tables: usize,
    /// Maximum number of retained rows across those tables.
    pub max_rows: u64,
    /// Maximum bare Norito payload bytes for each key or value.
    pub max_payload_bytes: usize,
    /// Maximum aggregate retained key/digest and ordered-node framing for one
    /// paired table.
    /// Standalone full-value ordered tables count their retained raw frames.
    pub max_ordered_table_bytes: usize,
    /// Maximum aggregate canonical value bytes emitted across both encoding
    /// passes of one paired table capture or one full-value verification.
    pub max_streamed_value_bytes: u64,
}

/// A rejected scoped leaf operation never produces a partially published root.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LeafError {
    /// The requested field is absent from the typed State authority inventory.
    /// The caller retains its input; refusal must not copy an unbounded identity.
    #[error("unknown State authority field")]
    UnknownField,
    /// The field exists but is not an independent canonical table.
    #[error("State authority field is not a canonical table: {0}")]
    NotCanonicalTable(&'static str),
    /// A canonical table still lacks a complete V1 key/value schema.
    #[error("State authority table has an unresolved schema: {0}")]
    UnresolvedSchema(&'static str),
    /// The declared layout is not the fixed first-release layout.
    #[error("State authority table has a non-V1 layout: {0}")]
    NonV1Layout(&'static str),
    /// The supplied key or value type does not match the declared nominal type.
    #[error("State authority table key/value type mismatch: {0}")]
    TypeMismatch(&'static str),
    /// A row was supplied for a table omitted from this scoped builder.
    /// The caller retains its input; refusal must not copy an unbounded identity.
    #[error("State authority table was not selected")]
    TableNotSelected,
    /// The selected-table count exceeded the admitted operational bound.
    #[error("selected State table count exceeds the admitted bound")]
    TableLimit,
    /// The row count exceeded the admitted operational bound.
    #[error("State table row count exceeds the admitted bound")]
    RowLimit,
    /// One key or value exceeded the admitted streaming payload bound.
    #[error("State table key or value exceeds the admitted payload bound")]
    PayloadLimit,
    /// All paired-table value rows exceeded the aggregate encoding work bound.
    #[error("State table values exceed the admitted aggregate streaming bound")]
    StreamedTableLimit,
    /// The exact table/key row was already supplied.
    #[error("duplicate State table row: {0}")]
    DuplicateRow(&'static str),
    /// The same table identity was selected twice.
    #[error("duplicate selected State table: {0}")]
    DuplicateTable(&'static str),
    /// A canonical serializer or Merkle update failed without publishing a root.
    #[error("State table leaf construction failed: {0}")]
    Encoding(EncodingError),
    /// An existing source validator rejected its structural invariants.
    /// This moves its original owned diagnostic without rendering another copy;
    /// that validator's scratch/error custody remains separate from codec custody.
    #[error("State table source validation failed: {0}")]
    SourceValidation(String),
    /// Trigger-local work, native source, fixed counter or exact codec refusal.
    #[error(transparent)]
    TriggerContracts(crate::smartcontracts::triggers::set::TriggerContractError),
    /// Exact domain-owner derivation failed or its local capture must be deferred.
    #[error("State domain-owner derivation failed: {0}")]
    DomainOwnership(#[from] super::domain_ownership::DomainOwnershipError),
    /// Alias ownership, primary labels or reverse membership failed at the retained cut.
    #[error("State account-alias derivation failed: {0}")]
    AliasOwnership(#[from] super::account_alias_ownership::AliasOwnershipError),
    /// Original account identity/index checks refused this native cut.
    #[error(transparent)]
    IdentityOwnership(#[from] super::account_identity_ownership::IdentityOwnershipError),
    /// Original NFT or RWA rows and grouped indexes disagree or cannot be retained.
    #[error(transparent)]
    GroupedOwnership(#[from] super::grouped_ownership::GroupedOwnershipError),
    /// A local allocation was refused before a canonical table frame was written.
    #[error("State table canonical frame allocation failed")]
    Allocation,
    /// The original pool refused staged backing or a complete lookup-node path.
    #[error("State table allocation admission failed: {0}")]
    Admission(iroha_allocation::AllocationRefusal),
    /// An admitted lookup node's physical allocation or prepaid partition failed.
    #[error("State table lookup allocation failed: {0}")]
    LookupAllocation(#[source] iroha_allocation::PrepaidSharedError),
    /// An ordered raw-key table exceeded its bound or had malformed rows.
    #[error("State table ordered Norito-key construction failed: {0}")]
    OrderedRange(NoritoKeyRangeError),
    /// The lookup path claims a different scoped selected-table root.
    #[error("State table lookup proof does not match its selected-table root")]
    RootMismatch,
    /// The typed full-value preimage does not match the authenticated digest.
    #[error("canonical value preimage differs from the authenticated State table digest")]
    ValuePreimageMismatch,
    /// The map lookup path is forged, incomplete, or malformed.
    #[error("invalid State table lookup proof: {0}")]
    InvalidProof(MerkleMapReadError<Infallible>),
    /// A hashed-key interval is invalid, excessive, incomplete, or forged.
    #[error("invalid State table hashed-key range proof: {0}")]
    InvalidRange(MerkleMapRangeError),
}

impl From<crate::smartcontracts::triggers::set::TriggerContractError> for LeafError {
    fn from(error: crate::smartcontracts::triggers::set::TriggerContractError) -> Self {
        match error {
            crate::smartcontracts::triggers::set::TriggerContractError::Semantic(failure) => {
                Self::SourceValidation(failure.original_message())
            }
            error => Self::TriggerContracts(error),
        }
    }
}

fn find_field(fields: &'static [Field], id: &str) -> Option<&'static Field> {
    for field in fields {
        if field.id == id {
            return Some(field);
        }
        if let Role::Canonical(Canonical::Owner(children)) = field.role {
            if let Some(found) = find_field(children, id) {
                return Some(found);
            }
        }
    }
    None
}

fn declared_table(id: &str) -> Result<&'static Field, LeafError> {
    let field = find_field(STATE_FIELDS, id).ok_or(LeafError::UnknownField)?;
    match field.role {
        Role::Canonical(Canonical::Table { key, value }) => {
            if !matches!(key, Schema::Norito { .. }) || matches!(value, Schema::Required { .. }) {
                return Err(LeafError::UnresolvedSchema(field.id));
            }
            for schema in [key, value] {
                let layout = match schema {
                    Schema::Norito { layout, .. } | Schema::Semantic { layout, .. } => layout,
                    Schema::Required { .. } => unreachable!("required schema was rejected"),
                };
                if layout != V1_LAYOUT {
                    return Err(LeafError::NonV1Layout(field.id));
                }
            }
            Ok(field)
        }
        _ => Err(LeafError::NotCanonicalTable(field.id)),
    }
}

fn schema_name(schema: Schema) -> &'static str {
    match schema {
        Schema::Norito { .. } => "norito",
        Schema::Semantic { .. } => "semantic",
        Schema::Required { .. } => "required",
    }
}

fn schema_identity(schema: Schema) -> std::borrow::Cow<'static, str> {
    match schema {
        Schema::Norito { nominal_name, .. } => nominal_name(),
        Schema::Semantic { identity, .. } | Schema::Required { identity, .. } => {
            std::borrow::Cow::Borrowed(identity)
        }
    }
}

fn fold_schema(accumulator: Hash, field: &Field, key: Schema, value: Schema) -> Hash {
    let key_name = schema_identity(key);
    let value_name = schema_identity(value);
    let id_len = u64::try_from(field.id.len()).expect("static field identity fits u64");
    let key_len = u64::try_from(key_name.len()).expect("nominal key identity fits u64");
    let value_len = u64::try_from(value_name.len()).expect("nominal value identity fits u64");
    Hash::new_from_chunks(&[
        SCHEMA_FIELD,
        accumulator.as_ref(),
        &id_len.to_le_bytes(),
        field.id.as_bytes(),
        schema_name(key).as_bytes(),
        &key_len.to_le_bytes(),
        key_name.as_bytes(),
        schema_name(value).as_bytes(),
        &value_len.to_le_bytes(),
        value_name.as_bytes(),
        &[V1_LAYOUT.major, V1_LAYOUT.minor, V1_LAYOUT.flags],
    ])
}

#[cfg(test)]
#[path = "leaf/overflow_pause.rs"]
pub(in crate::state) mod overflow_pause;

struct BoundedWriter<'a> {
    inner: &'a mut dyn Write,
    remaining: usize,
    exceeded: &'a mut bool,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if *self.exceeded || bytes.len() > self.remaining {
            *self.exceeded = true;
            #[cfg(test)]
            overflow_pause::observe_overflow();
            return Err(io::ErrorKind::InvalidData.into());
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct TripleHashWriter<'a> {
    raw: &'a mut dyn Write,
    lookup: &'a mut dyn Write,
    ordered: &'a mut dyn Write,
}

impl Write for TripleHashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.raw.write_all(bytes)?;
        self.lookup.write_all(bytes)?;
        self.ordered.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.raw.flush()?;
        self.lookup.flush()?;
        self.ordered.flush()
    }
}

/// Hash one complete canonical encoding into both paired roots without
/// materializing value-sized buffers. The raw digest detects a changing encoder
/// between the length pass and the common second pass.
fn stream_bare_payload_digests<T: Encode>(
    value: &T,
    schema_identity: &str,
    max_payload_bytes: usize,
) -> Result<(Hash, Hash, usize), LeafError> {
    let max_payload_bytes = max_payload_bytes.min(u32::MAX as usize);
    let mut encoded = Ok(0_usize);
    let mut exceeded = false;
    let first_raw = Hash::new_from_writer(|raw| {
        let mut bounded = BoundedWriter {
            inner: raw,
            remaining: max_payload_bytes,
            exceeded: &mut exceeded,
        };
        // Lend the result out of the hash callback. Boxing it into io::Error
        // would allocate on the refusal path and lose the original category.
        encoded = norito::codec::encode_adaptive_into(value, &mut bounded);
        Ok(())
    });
    if exceeded {
        return Err(LeafError::PayloadLimit);
    }
    let length =
        encoded.map_err(|error| EncodingError::codec(EncodingOperation::MeasurePayload, error))?;
    if length > max_payload_bytes {
        return Err(LeafError::PayloadLimit);
    }
    let first_raw =
        first_raw.map_err(|error| EncodingError::io(EncodingOperation::MeasurePayload, error))?;
    let length32 = u32::try_from(length).map_err(|_| LeafError::PayloadLimit)?;
    let length64 = u64::from(length32);
    let identity_len = u64::try_from(schema_identity.len()).map_err(|_| LeafError::PayloadLimit)?;
    let mut second_raw = None;
    let mut ordered_digest = None;
    let mut encoded = Ok(0_usize);
    let mut exceeded = false;
    let lookup_digest = Hash::new_from_writer(|lookup| {
        lookup.write_all(VALUE_PAYLOAD)?;
        lookup.write_all(&identity_len.to_le_bytes())?;
        lookup.write_all(schema_identity.as_bytes())?;
        lookup.write_all(&[V1_LAYOUT.major, V1_LAYOUT.minor, V1_LAYOUT.flags])?;
        let raw = Hash::new_from_writer(|raw| {
            ordered_digest = Some(digest_norito_value_frame_v1(length32, |ordered| {
                let mut triple = TripleHashWriter {
                    raw,
                    lookup,
                    ordered,
                };
                let mut bounded = BoundedWriter {
                    inner: &mut triple,
                    remaining: length,
                    exceeded: &mut exceeded,
                };
                encoded = norito::codec::encode_adaptive_into(value, &mut bounded);
                Ok(())
            })?);
            Ok(())
        })?;
        second_raw = Some(raw);
        lookup.write_all(&length64.to_le_bytes())
    });
    if exceeded {
        return Err(EncodingError::new(
            EncodingOperation::HashPairedValue,
            EncodingReason::ChangedLength,
        )
        .into());
    }
    let written =
        encoded.map_err(|error| EncodingError::codec(EncodingOperation::HashPairedValue, error))?;
    if written != length {
        return Err(EncodingError::new(
            EncodingOperation::HashPairedValue,
            EncodingReason::ChangedLength,
        )
        .into());
    }
    let lookup_digest = lookup_digest
        .map_err(|error| EncodingError::io(EncodingOperation::HashPairedValue, error))?;
    if second_raw != Some(first_raw) {
        return Err(EncodingError::new(
            EncodingOperation::HashPairedValue,
            EncodingReason::ChangedPayload,
        )
        .into());
    }
    Ok((
        ordered_digest.expect("successful digest frame has a digest"),
        lookup_digest,
        length,
    ))
}

fn typed_bare_payload_digests<T: Encode + NoritoSchema>(
    table: &'static str,
    schema: Schema,
    value: &T,
    max_payload_bytes: usize,
) -> Result<(Hash, Hash, usize), LeafError> {
    let Schema::Norito {
        nominal_name,
        layout,
    } = schema
    else {
        return Err(LeafError::UnresolvedSchema(table));
    };
    if layout != V1_LAYOUT {
        return Err(LeafError::NonV1Layout(table));
    }
    let declared = nominal_name();
    if declared != norito::schema::identity::nominal_name::<T>() {
        return Err(LeafError::TypeMismatch(table));
    }
    stream_bare_payload_digests(value, &declared, max_payload_bytes)
}

fn semantic_bare_payload_digests<T: Encode>(
    table: &'static str,
    schema: Schema,
    expected_identity: &'static str,
    value: &T,
    max_payload_bytes: usize,
) -> Result<(Hash, Hash, usize), LeafError> {
    let Schema::Semantic {
        identity, layout, ..
    } = schema
    else {
        return Err(LeafError::UnresolvedSchema(table));
    };
    if layout != V1_LAYOUT {
        return Err(LeafError::NonV1Layout(table));
    }
    if identity != expected_identity {
        return Err(LeafError::TypeMismatch(table));
    }
    stream_bare_payload_digests(value, identity, max_payload_bytes)
}

fn typed_payload_hash<T: Encode + NoritoSchema>(
    table: &'static str,
    schema: Schema,
    value: &T,
    domain: &'static [u8],
    max_payload_bytes: usize,
) -> Result<Hash, LeafError> {
    let Schema::Norito {
        nominal_name,
        layout,
    } = schema
    else {
        return Err(LeafError::UnresolvedSchema(table));
    };
    if layout != V1_LAYOUT {
        return Err(LeafError::NonV1Layout(table));
    }
    let declared = nominal_name();
    if declared != norito::schema::identity::nominal_name::<T>() {
        return Err(LeafError::TypeMismatch(table));
    }
    let name_len = u64::try_from(declared.len()).map_err(|_| LeafError::PayloadLimit)?;
    let mut exceeded = false;
    let mut encoded = Ok(0_usize);
    let digest = Hash::new_from_writer(|writer| {
        writer.write_all(domain)?;
        writer.write_all(&name_len.to_le_bytes())?;
        writer.write_all(declared.as_bytes())?;
        writer.write_all(&[layout.major, layout.minor, layout.flags])?;
        {
            let mut bounded = BoundedWriter {
                inner: writer,
                remaining: max_payload_bytes,
                exceeded: &mut exceeded,
            };
            encoded = norito::codec::encode_adaptive_into(value, &mut bounded);
        }
        if let Ok(length) = &encoded {
            let length = u64::try_from(*length).map_err(|_| io::ErrorKind::InvalidData)?;
            writer.write_all(&length.to_le_bytes())?;
        }
        Ok(())
    });
    if exceeded {
        return Err(LeafError::PayloadLimit);
    }
    encoded.map_err(|error| EncodingError::codec(EncodingOperation::HashTypedPayload, error))?;
    digest.map_err(|error| EncodingError::io(EncodingOperation::HashTypedPayload, error).into())
}

#[path = "leaf/frame.rs"]
mod frame;
use frame::typed_bare_payload;

fn bare_payload_hash(
    table: &'static str,
    schema: Schema,
    payload: &[u8],
    domain: &'static [u8],
) -> Result<Hash, LeafError> {
    let (name, layout) = match schema {
        Schema::Norito {
            nominal_name,
            layout,
        } => (nominal_name(), layout),
        Schema::Semantic {
            identity, layout, ..
        } => (std::borrow::Cow::Borrowed(identity), layout),
        Schema::Required { .. } => return Err(LeafError::UnresolvedSchema(table)),
    };
    if layout != V1_LAYOUT {
        return Err(LeafError::NonV1Layout(table));
    }
    let name_len = u64::try_from(name.len()).expect("nominal schema identity fits u64");
    let payload_len = u64::try_from(payload.len()).map_err(|_| LeafError::PayloadLimit)?;
    Ok(Hash::new_from_chunks(&[
        domain,
        &name_len.to_le_bytes(),
        name.as_bytes(),
        &[layout.major, layout.minor, layout.flags],
        payload,
        &payload_len.to_le_bytes(),
    ]))
}

fn scoped_root(schema: Hash, table_count: usize, row_count: u64, map_root: Hash) -> Hash {
    let tables = u64::try_from(table_count).expect("selected table count fits u64");
    Hash::new_from_chunks(&[
        ROOT,
        schema.as_ref(),
        &tables.to_le_bytes(),
        &row_count.to_le_bytes(),
        map_root.as_ref(),
    ])
}

fn paired_root(table: &str, row_count: u64, lookup_root: Hash, ordered_root: Hash) -> Hash {
    let table_len = u64::try_from(table.len()).expect("static table identity fits u64");
    Hash::new_from_chunks(&[
        PAIRED_ROOT,
        &table_len.to_le_bytes(),
        table.as_bytes(),
        &row_count.to_le_bytes(),
        lookup_root.as_ref(),
        ordered_root.as_ref(),
    ])
}

/// Complete hashed-leaf-key interval under one explicitly selected table set.
///
/// The map root is an untrusted claim. Verification binds it to an independently
/// supplied scoped root before checking the complete range proof. Hash intervals
/// are not original Norito-key intervals or table-local ordering.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalTableHashRangeProof {
    map_root: Hash,
    range: MerkleMapRangeProof,
}

/// A bounded commitment to an explicitly selected subset of canonical tables.
///
/// Selection, table schemas, key types, value types, and row count are bound.
/// The caller must enumerate every selected table row from one immutable cut;
/// this type does not certify that completeness itself.
pub(crate) struct CanonicalTableLeafSet {
    selection: TableSelection,
    leaves: MerkleMap,
}

/// Two immutable indexes built from one complete canonical encoding per row.
///
/// The paired root binds a hashed lookup tree and raw-key ordered value
/// digests. Full value bytes are not retained or disclosed by ranges. The
/// caller still owns complete enumeration and finalized State authentication.
pub(crate) struct CanonicalTablePairedSnapshot {
    lookup: CanonicalTableLeafSet,
    ordered: NoritoKeyDigestRangeTreeV1,
    root: Hash,
}

fn charge_digest_row(
    total: &mut usize,
    key_len: usize,
    limits: LeafLimits,
) -> Result<(), LeafError> {
    // During construction both the sorted input and ordered tree own a key.
    // Three digests cover the two retained values and the ordered copy.
    let charge = key_len
        .checked_mul(2)
        .and_then(|size| size.checked_add(3 * Hash::LENGTH))
        .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?;
    let maximum = limits
        .max_ordered_table_bytes
        .min(MAX_NORITO_TREE_PAYLOAD_BYTES);
    *total = total
        .checked_add(charge)
        .filter(|total| *total <= maximum)
        .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?;
    Ok(())
}

/// Admit both encoder passes before starting a full-value row. Key framing is
/// separately bounded by the row count and per-key payload limit.
fn value_stream_bound(limits: LeafLimits, spent: u64) -> Result<usize, LeafError> {
    let remaining = limits
        .max_streamed_value_bytes
        .checked_sub(spent)
        .ok_or(LeafError::StreamedTableLimit)?;
    let per_pass = usize::try_from(remaining / 2).unwrap_or(usize::MAX);
    Ok(limits.max_payload_bytes.min(per_pass))
}

fn charge_streamed_value(
    spent: &mut u64,
    length: usize,
    limits: LeafLimits,
) -> Result<(), LeafError> {
    let charge = u64::try_from(length)
        .ok()
        .and_then(|length| length.checked_mul(2))
        .ok_or(LeafError::StreamedTableLimit)?;
    *spent = spent
        .checked_add(charge)
        .filter(|total| *total <= limits.max_streamed_value_bytes)
        .ok_or(LeafError::StreamedTableLimit)?;
    Ok(())
}

fn value_stream_error(error: LeafError, bound: usize, limits: LeafLimits) -> LeafError {
    if error == LeafError::PayloadLimit && bound < limits.max_payload_bytes {
        LeafError::StreamedTableLimit
    } else {
        error
    }
}

impl CanonicalTablePairedSnapshot {
    /// Exact identity of the sole table whose retained rows own this pair.
    pub(crate) fn table_id(&self) -> &'static str {
        self.lookup
            .selection
            .first_table_id()
            .expect("paired snapshot selects exactly one table")
    }

    /// Number of rows retained by both scoped trees.
    pub(crate) fn row_count(&self) -> usize {
        self.ordered.len()
    }

    /// Scoped paired root; this is not a complete State commitment.
    pub(crate) fn root(&self) -> Hash {
        self.root
    }

    /// Scoped hashed-lookup component root bound by `root()`.
    pub(crate) fn lookup_root(&self) -> Hash {
        self.lookup.root()
    }

    /// Scoped raw-key ordered component root bound by `root()`.
    pub(crate) fn ordered_root(&self) -> Hash {
        self.ordered.root()
    }

    /// Export an inclusion or absence path for a typed key in this table.
    pub(crate) fn prove_lookup<K: Encode + NoritoSchema>(
        &self,
        table: &str,
        key: &K,
    ) -> Result<MerkleMapLookupProof, LeafError> {
        self.lookup.prove_lookup(table, key)
    }

    /// Export a complete raw-key interval from this table's retained rows.
    ///
    /// # Errors
    /// Rejects invalid bounds, excessive rows or bytes, or local allocation
    /// refusal before returning any proof.
    pub(crate) fn prove_raw_range(
        &self,
        start: &[u8],
        end: &[u8],
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<NoritoKeyDigestRangeProofV1, LeafError> {
        self.ordered
            .prove_range(start, end, max_rows, max_bytes)
            .map_err(LeafError::OrderedRange)
    }
}

#[path = "leaf/paired.rs"]
mod paired;
pub(in crate::state) use paired::{
    RetainedSemanticError, RetainedSemanticRows, TypedPairedRowAllowance, TypedPairedRowError,
    TypedPairedTableBuilder,
};

impl CanonicalTableLeafSet {
    /// Verify a selected-table lookup beneath an independent paired root.
    ///
    /// The supplied ordered component root is bound by the paired root. The
    /// complete-State owner must authenticate that paired root separately.
    ///
    /// # Errors
    /// Rejects a mismatched table/schema/row count, component root, lookup
    /// path, or resource limit.
    pub(crate) fn verify_paired_lookup<K: Encode + NoritoSchema>(
        table: &str,
        limits: LeafLimits,
        expected_paired_root: &Hash,
        ordered_root: &Hash,
        key: &K,
        proof: &MerkleMapLookupProof,
    ) -> Result<Option<Hash>, LeafError> {
        let selection = TableSelection::new(&[table], limits)?;
        let row_count = proof.entry_count();
        if row_count > limits.max_rows {
            return Err(LeafError::RowLimit);
        }
        let lookup_root = scoped_root(
            selection.schema,
            selection.len(),
            row_count,
            proof.claimed_root(),
        );
        if paired_root(table, row_count, lookup_root, *ordered_root) != *expected_paired_root {
            return Err(LeafError::RootMismatch);
        }
        Self::verify_lookup(&[table], limits, &lookup_root, table, key, proof)
    }

    /// Verify a complete raw-Norito-key interval beneath an independent pair.
    ///
    /// The supplied hashed lookup and ordered component roots are bound by the
    /// paired root. The returned rows have selected-table scope only.
    ///
    /// # Errors
    /// Rejects a mismatched table/schema/row count, component root, incomplete
    /// interval, or resource limit.
    pub(crate) fn verify_paired_raw_range<'a>(
        table: &str,
        limits: LeafLimits,
        expected_paired_root: &Hash,
        lookup_root: &Hash,
        ordered_root: &Hash,
        start: &[u8],
        end: &[u8],
        max_rows: usize,
        max_bytes: usize,
        proof: &'a NoritoKeyDigestRangeProofV1,
    ) -> Result<VerifiedNoritoKeyDigestRangeV1<'a>, LeafError> {
        let selection = TableSelection::new(&[table], limits)?;
        let row_count = u64::from(proof.entry_count());
        if row_count > limits.max_rows {
            return Err(LeafError::RowLimit);
        }
        if paired_root(table, row_count, *lookup_root, *ordered_root) != *expected_paired_root {
            return Err(LeafError::RootMismatch);
        }
        proof
            .verify(NoritoKeyRangeVerifyRequestV1 {
                expected_root: ordered_root,
                schema_hash: &selection.schema,
                domain: table.as_bytes(),
                start,
                end,
                max_rows,
                max_bytes,
            })
            .map_err(LeafError::OrderedRange)
    }

    /// Check a full typed canonical value against a verified digest-only row.
    ///
    /// The `verified` value must come from `verify_paired_raw_range` under an
    /// independently authenticated paired root. A digest-only range does not
    /// disclose or itself validate any full value bytes.
    ///
    /// # Errors
    /// Rejects absent keys, schema mismatch, oversized or changing encodings,
    /// and a different full-value preimage.
    pub(crate) fn verify_paired_value_preimage<V: Encode + NoritoSchema>(
        table: &str,
        limits: LeafLimits,
        verified: &VerifiedNoritoKeyDigestRangeV1<'_>,
        key: &[u8],
        value: &V,
    ) -> Result<(), LeafError> {
        let selection = TableSelection::new(&[table], limits)?;
        if verified.schema_hash() != selection.schema
            || verified.domain_hash() != Hash::new(table.as_bytes())
        {
            return Err(LeafError::RootMismatch);
        }
        let Some((table, (_, value_schema))) = selection.table(table) else {
            unreachable!("selected table remains registered")
        };
        let digest = verified
            .rows()
            .find_map(|(row_key, digest)| (row_key == key).then_some(digest))
            .ok_or(LeafError::ValuePreimageMismatch)?;
        let bound = value_stream_bound(limits, 0)?;
        let (actual, _, length) = typed_bare_payload_digests(table, value_schema, value, bound)
            .map_err(|error| value_stream_error(error, bound, limits))?;
        let mut streamed_bytes = 0;
        charge_streamed_value(&mut streamed_bytes, length, limits)?;
        if actual != digest {
            return Err(LeafError::ValuePreimageMismatch);
        }
        Ok(())
    }

    /// Build one scoped ordered table from typed native-Norito rows.
    ///
    /// This binds the registry's table identity, nominal key/value schemas and
    /// fixed V1 layout, then sorts the exact canonical bare key bytes. The
    /// caller still owns complete row enumeration and an independently
    /// authenticated State root. This separate ordered root cannot substitute
    /// for the finalized State root or prove an omitted table is complete.
    ///
    /// # Errors
    /// Refuses type/schema mismatch, oversized or changing encodings, row and
    /// allocation limits, and duplicate canonical key bytes.
    pub(crate) fn ordered_table_from_rows<'a, K, V>(
        table: &str,
        limits: LeafLimits,
        rows: impl IntoIterator<Item = (&'a K, &'a V)>,
    ) -> Result<NoritoKeyRangeTreeV1, LeafError>
    where
        K: Encode + NoritoSchema + 'a,
        V: Encode + NoritoSchema + 'a,
    {
        let selection = TableSelection::new(&[table], limits)?;
        let Some((table, (key_schema, value_schema))) = selection.table(table) else {
            unreachable!("selected table remains registered")
        };
        let max_rows = limits.max_rows.min(MAX_NORITO_TREE_ENTRIES as u64);
        let max_bytes = limits
            .max_ordered_table_bytes
            .min(MAX_NORITO_TREE_PAYLOAD_BYTES);
        let mut total_bytes = 0_usize;
        let mut encoded = Vec::new();
        for (key, value) in rows {
            if encoded.len() as u64 >= max_rows {
                return Err(LeafError::RowLimit);
            }
            let key = typed_bare_payload(
                table,
                key_schema,
                key,
                limits.max_payload_bytes.min(MAX_NORITO_KEY_BYTES),
                frame::vector,
            )?;
            let value = typed_bare_payload(
                table,
                value_schema,
                value,
                limits.max_payload_bytes.min(MAX_NORITO_VALUE_BYTES),
                frame::vector,
            )?;
            total_bytes = total_bytes
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?;
            if total_bytes > max_bytes {
                return Err(LeafError::OrderedRange(NoritoKeyRangeError::Capacity));
            }
            encoded.try_reserve(1).map_err(|_| LeafError::Allocation)?;
            encoded.push((key, value));
        }
        encoded.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        NoritoKeyRangeTreeV1::from_sorted(
            selection.schema,
            table.as_bytes(),
            encoded
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .map_err(LeafError::OrderedRange)
    }

    /// Select canonical tables and retain their caller's original lookup-node pool.
    pub(crate) fn new(
        ids: &[&str],
        limits: LeafLimits,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, LeafError> {
        Ok(Self {
            selection: TableSelection::new(ids, limits)?,
            leaves: MerkleMap::new(budget),
        })
    }

    /// Commit one key/value row with an exact declared nominal type and V1 layout.
    pub(crate) fn insert<K: Encode + NoritoSchema, V: Encode + NoritoSchema>(
        &mut self,
        table: &str,
        key: &K,
        value: &V,
    ) -> Result<(), LeafError> {
        if self.leaves.len() >= self.selection.limits.max_rows {
            return Err(LeafError::RowLimit);
        }
        let path = self.key_path(table, key)?;
        let Some((table, (_, value_schema))) = self.selection.table(table) else {
            unreachable!("key_path admitted only selected tables")
        };
        let value_hash = typed_payload_hash(
            table,
            value_schema,
            value,
            VALUE_PAYLOAD,
            self.selection.limits.max_payload_bytes,
        )?;
        self.leaves
            .replace(path, None, Some(value_hash))
            .map_err(|error| lookup_error(error, table))?;
        Ok(())
    }

    fn key_path<K: Encode + NoritoSchema>(&self, table: &str, key: &K) -> Result<Hash, LeafError> {
        self.selection.key_path(table, key)
    }

    /// Export a bounded inclusion or absence path within the selected rows.
    ///
    /// The caller still owns complete row enumeration and authenticates this
    /// scoped root independently. This is not a finalized State witness.
    pub(crate) fn prove_lookup<K: Encode + NoritoSchema>(
        &self,
        table: &str,
        key: &K,
    ) -> Result<MerkleMapLookupProof, LeafError> {
        Ok(self.leaves.prove_lookup(&self.key_path(table, key)?))
    }

    /// Export every selected row in the half-open hashed-leaf-key interval.
    ///
    /// Hashing the table identity and canonical key bytes does not preserve
    /// native Norito-key order. The caller still owns complete enumeration of
    /// the selected tables, and this proof has no finalized-State authority.
    ///
    /// # Errors
    /// Rejects invalid bounds, row ceilings above the admitted limit, excessive
    /// range size, or local allocation refusal.
    pub(crate) fn prove_hashed_key_range(
        &self,
        start: &Hash,
        end: &Hash,
        max_rows: usize,
    ) -> Result<CanonicalTableHashRangeProof, LeafError> {
        if u64::try_from(max_rows).unwrap_or(u64::MAX) > self.selection.limits.max_rows {
            return Err(LeafError::RowLimit);
        }
        let range = self
            .leaves
            .prove_range(start, end, max_rows)
            .map_err(LeafError::InvalidRange)?;
        Ok(CanonicalTableHashRangeProof {
            map_root: self.leaves.root(),
            range,
        })
    }

    /// Check one selected-table path against an independently supplied scoped root.
    ///
    /// The selection and native key schema are rebuilt from the typed registry.
    /// A present row returns its canonical value digest; the caller must still
    /// authenticate any concrete value preimage against that digest.
    ///
    /// # Errors
    /// Rejects an unselected or unresolved table, a malformed key, an excessive
    /// row count, a root mismatch, or an incomplete/forged Merkle path.
    pub(crate) fn verify_lookup<K: Encode + NoritoSchema>(
        ids: &[&str],
        limits: LeafLimits,
        expected_root: &Hash,
        table: &str,
        key: &K,
        proof: &MerkleMapLookupProof,
    ) -> Result<Option<Hash>, LeafError> {
        let selection = TableSelection::new(ids, limits)?;
        let path = selection.key_path(table, key)?;
        if proof.entry_count() > limits.max_rows {
            return Err(LeafError::RowLimit);
        }
        let map_root = proof.claimed_root();
        if scoped_root(
            selection.schema,
            selection.len(),
            proof.entry_count(),
            map_root,
        ) != *expected_root
        {
            return Err(LeafError::RootMismatch);
        }
        proof
            .verify(&map_root, &path)
            .map_err(LeafError::InvalidProof)
    }

    /// Verify a complete hashed-key interval against an independent scoped root.
    ///
    /// The returned ordered pairs contain hashed leaf keys and value digests.
    /// They do not authenticate concrete value preimages, native Norito-key
    /// order, omitted authoritative tables, or State finality.
    ///
    /// # Errors
    /// Rejects a different selection/schema, excessive total or range rows,
    /// wrong root, malformed interval, or incomplete Merkle expansion.
    pub(crate) fn verify_hashed_key_range(
        ids: &[&str],
        limits: LeafLimits,
        expected_root: &Hash,
        start: &Hash,
        end: &Hash,
        max_rows: usize,
        proof: &CanonicalTableHashRangeProof,
    ) -> Result<Vec<(Hash, Hash)>, LeafError> {
        let selection = TableSelection::new(ids, limits)?;
        if proof.range.entry_count() > limits.max_rows
            || u64::try_from(max_rows).unwrap_or(u64::MAX) > limits.max_rows
        {
            return Err(LeafError::RowLimit);
        }
        if scoped_root(
            selection.schema,
            selection.len(),
            proof.range.entry_count(),
            proof.map_root,
        ) != *expected_root
        {
            return Err(LeafError::RootMismatch);
        }
        proof
            .range
            .verify(&proof.map_root, start, end, max_rows)
            .map_err(LeafError::InvalidRange)
    }

    /// Return the selected-table root, including empty selected tables.
    ///
    /// This is not a complete State commitment and has no finality authority.
    pub(crate) fn root(&self) -> Hash {
        scoped_root(
            self.selection.schema,
            self.selection.len(),
            self.leaves.len(),
            self.leaves.root(),
        )
    }
}

#[cfg(test)]
mod tests;

mod selection;
use selection::TableSelection;

fn lookup_error(error: MerkleMapError, table: &'static str) -> LeafError {
    match error {
        MerkleMapError::PreimageMismatch { .. } => LeafError::DuplicateRow(table),
        MerkleMapError::Capacity => LeafError::RowLimit,
        MerkleMapError::Admission(error) => LeafError::Admission(error),
        MerkleMapError::Allocation(error) => LeafError::LookupAllocation(error),
    }
}

#[cfg(test)]
mod lookup_funding_tests;

#[cfg(test)]
#[path = "leaf/literal_identity_tests.rs"]
mod literal_identity_tests;

#[cfg(test)]
#[path = "leaf/encoding_custody_tests.rs"]
mod encoding_custody_tests;
