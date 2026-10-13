//! Compiled wire-schema identity shared by release manifests and `/status.build`.
//!
//! The identity hashes a canonical rendering of the compiled [`iroha_schema`]
//! descriptions of the covered wire roots, explicitly named native-format
//! descriptors, and the IVM ABI hash. Equality identifies these covered layouts
//! and ABI; it makes no claim about undescribed opaque byte domains or semantic
//! validation rules. This module renders and hashes the roots and supplies the
//! block wire root ([`covered_wire_schema`], rooted at [`SignedBlock`]);
//! `iroha_core::release_identity::wire_schema_hash` adds the consensus wire root
//! (`iroha_sumeragi::message::WireMessage` and native `Evidence` frames), then the
//! canonical `ExecutionResultCommitment` payload root and the codec-owned
//! `certified_result::wire_identity` description of its native `X || body` framing.
//! Executables report that combined identity.
//! The rendering includes no target label or process-local `TypeId` values.
//! Explicit native descriptors bind actual compiled framing, including payload
//! alignment; equal identities across supported targets require equal covered
//! layouts. It also depends on enabled features: for example
//! `PublicKey`'s `Algorithm` lists its `bls`, `gost` and `sm` variants only when
//! those features are compiled in. Release tooling must read it from a build with
//! the release feature set.
//!
//! `ivm_abi` depends on this crate, so the IVM ABI hash is an explicit input
//! rather than computed here. Executables obtain it from
//! `ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1)`.

use std::collections::{BTreeMap, BTreeSet};

use iroha_schema::{IntoSchema, MetaMap, MetaMapEntry, Metadata};

use crate::block::SignedBlock;

/// Domain separator of the first-release wire-schema identity.
pub const WIRE_SCHEMA_HASH_DOMAIN_V1: &[u8] = b"iroha.wire_schema.v1\0";

/// Compiled schema of the block wire root: [`SignedBlock`] and every type it reaches.
#[must_use]
pub fn covered_wire_schema() -> MetaMap {
    <SignedBlock as IntoSchema>::schema()
}

/// Deterministic identity of compiled roots, explicit native formats and the IVM ABI.
///
/// `roots` holds the closed compiled schema of each covered wire root, in the
/// fixed order of the identity. Each root is rendered against its own types, so
/// two roots may describe different types under one schema identifier without
/// making a reference ambiguous. Within a root every type reference is rendered
/// through its schema identifier, and the rendered entries are ordered by
/// identifier and then by their complete rendering, which keeps the result
/// independent of process-local `TypeId` values and map iteration order even when
/// two entries share an identifier. The identity is meaningful only for roots for
/// which [`wire_root_defects`] reports nothing.
///
/// `native_formats` is an ordered list of `(name, descriptor)` pairs owned by
/// codecs whose framing is not represented by a Norito schema. Names and byte
/// descriptions are separately length-prefixed, and the list is separated from
/// the schema roots. Include every claimed native format explicitly; an empty
/// list asserts only the supplied Norito roots and ABI.
///
/// Pass the IVM ABI hash of the policy the binary executes
/// (`ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1)`).
#[must_use]
pub fn wire_schema_hash_of(
    roots: &[&MetaMap],
    native_formats: &[(&str, &[u8])],
    ivm_abi_hash: [u8; 32],
) -> [u8; 32] {
    hash_rendered_roots(
        roots.iter().copied().map(render_root).collect(),
        native_formats,
        ivm_abi_hash,
    )
}

/// Why [`wire_schema_hash_of`] cannot identify one compiled root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireRootDefect {
    /// The entry with this schema identifier references a type the root does not describe.
    UnregisteredReference(String),
    /// Entries with different descriptions share this schema identifier.
    AmbiguousIdentifier(String),
}

/// Every defect of one compiled wire root, ordered and without duplicates.
///
/// A root must describe every type its entries reference, and entries that share
/// a schema identifier must render identically. References are rendered through
/// identifiers, so an unregistered reference hashes deterministically but never
/// equals a closed schema, and an ambiguous identifier cannot tell which of its
/// types a reference names.
#[must_use]
pub fn wire_root_defects(schema: &MetaMap) -> Vec<WireRootDefect> {
    let names = type_names(schema);
    let mut renderings = BTreeMap::new();
    let mut defects = BTreeSet::new();
    for (_, entry) in schema.iter() {
        if references(&entry.metadata)
            .iter()
            .any(|reference| !names.contains_key(reference))
        {
            defects.insert(WireRootDefect::UnregisteredReference(entry.type_id.clone()));
        }
        let (id, rendered) = render_entry(&names, entry);
        if renderings
            .insert(id, rendered.clone())
            .is_some_and(|previous| previous != rendered)
        {
            defects.insert(WireRootDefect::AmbiguousIdentifier(id.to_owned()));
        }
    }
    defects.into_iter().collect()
}

/// The schema identifier of every type one root describes.
fn type_names(schema: &MetaMap) -> BTreeMap<core::any::TypeId, &str> {
    schema
        .iter()
        .map(|(type_id, entry)| (*type_id, entry.type_id.as_str()))
        .collect()
}

/// The rendered entries of one root against its own types.
fn render_root(schema: &MetaMap) -> Vec<(&str, Vec<u8>)> {
    let names = type_names(schema);
    schema
        .iter()
        .map(|(_, entry)| render_entry(&names, entry))
        .collect()
}

/// One entry's identifier and its canonical rendering (identifier, name, metadata).
fn render_entry<'a>(
    names: &BTreeMap<core::any::TypeId, &str>,
    entry: &'a MetaMapEntry,
) -> (&'a str, Vec<u8>) {
    let mut rendered = CanonicalPreimage::default();
    rendered.text(&entry.type_id);
    rendered.text(&entry.type_name);
    render_metadata(&mut rendered, names, &entry.metadata);
    (entry.type_id.as_str(), rendered.0)
}

/// Hash rendered roots in order after the domain and ABI; each root's entries are
/// ordered by `(identifier, rendering)`.
fn hash_rendered_roots(
    roots: Vec<Vec<(&str, Vec<u8>)>>,
    native_formats: &[(&str, &[u8])],
    ivm_abi_hash: [u8; 32],
) -> [u8; 32] {
    let mut preimage = CanonicalPreimage::default();
    preimage.bytes(WIRE_SCHEMA_HASH_DOMAIN_V1);
    preimage.bytes(&ivm_abi_hash);
    preimage.count(roots.len());
    for mut entries in roots {
        entries.sort_unstable();
        preimage.count(entries.len());
        for (_, rendered) in entries {
            preimage.0.extend_from_slice(&rendered);
        }
    }
    preimage.tag("native-wire-formats");
    preimage.count(native_formats.len());
    for (name, descriptor) in native_formats {
        preimage.text(name);
        preimage.bytes(descriptor);
    }
    iroha_crypto::Hash::new(preimage.0).into()
}

/// The types one compiled description references.
fn references(metadata: &Metadata) -> Vec<core::any::TypeId> {
    match metadata {
        Metadata::Struct(fields) => fields.declarations.iter().map(|field| field.ty).collect(),
        Metadata::Tuple(fields) => fields.types.clone(),
        Metadata::Enum(variants) => variants
            .variants
            .iter()
            .filter_map(|variant| variant.ty)
            .collect(),
        Metadata::FixedPoint(fixed) => vec![fixed.base],
        Metadata::Array(array) => vec![array.ty],
        Metadata::Vec(vector) => vec![vector.ty],
        Metadata::Map(map) => vec![map.key, map.value],
        Metadata::Option(inner) => vec![*inner],
        Metadata::Result(result) => vec![result.ok, result.err],
        Metadata::Bitmap(bitmap) => vec![bitmap.repr],
        Metadata::Int(_) | Metadata::Float(_) | Metadata::String | Metadata::Bool => Vec::new(),
    }
}

/// Length-prefixed canonical byte stream; every item is self-delimiting.
#[derive(Default)]
struct CanonicalPreimage(Vec<u8>);

impl CanonicalPreimage {
    fn count(&mut self, value: usize) {
        self.0.extend_from_slice(&(value as u64).to_le_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.0.extend_from_slice(value);
    }
    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    fn tag(&mut self, value: &str) {
        self.text(value);
    }
    fn reference(&mut self, names: &BTreeMap<core::any::TypeId, &str>, id: core::any::TypeId) {
        // `wire_root_defects` reports an unregistered edge; it still hashes
        // deterministically but can never equal a closed schema.
        self.text(names.get(&id).copied().unwrap_or("\0unregistered"));
    }
}

fn render_metadata(
    out: &mut CanonicalPreimage,
    names: &BTreeMap<core::any::TypeId, &str>,
    metadata: &Metadata,
) {
    match metadata {
        Metadata::Struct(fields) => {
            out.tag("struct");
            out.count(fields.declarations.len());
            for field in &fields.declarations {
                out.text(&field.name);
                out.reference(names, field.ty);
            }
        }
        Metadata::Tuple(fields) => {
            out.tag("tuple");
            out.count(fields.types.len());
            for ty in &fields.types {
                out.reference(names, *ty);
            }
        }
        Metadata::Enum(variants) => {
            out.tag("enum");
            out.count(variants.variants.len());
            for variant in &variants.variants {
                out.text(&variant.tag);
                out.bytes(&variant.discriminant.to_le_bytes());
                match variant.ty {
                    Some(ty) => {
                        out.tag("some");
                        out.reference(names, ty);
                    }
                    None => out.tag("none"),
                }
            }
        }
        Metadata::Int(mode) => out.tag(match mode {
            iroha_schema::IntMode::FixedWidth => "int:fixed",
            iroha_schema::IntMode::Compact => "int:compact",
        }),
        Metadata::Float(mode) => out.tag(match mode {
            iroha_schema::FloatMode::Binary32 => "float:32",
            iroha_schema::FloatMode::Binary64 => "float:64",
        }),
        Metadata::String => out.tag("string"),
        Metadata::Bool => out.tag("bool"),
        Metadata::FixedPoint(fixed) => {
            out.tag("fixed");
            out.reference(names, fixed.base);
            out.bytes(&fixed.decimal_places.to_le_bytes());
        }
        Metadata::Array(array) => {
            out.tag("array");
            out.reference(names, array.ty);
            out.bytes(&array.len.to_le_bytes());
        }
        Metadata::Vec(vector) => {
            out.tag("vec");
            out.reference(names, vector.ty);
        }
        Metadata::Map(map) => {
            out.tag("map");
            out.reference(names, map.key);
            out.reference(names, map.value);
        }
        Metadata::Option(inner) => {
            out.tag("option");
            out.reference(names, *inner);
        }
        Metadata::Result(result) => {
            out.tag("result");
            out.reference(names, result.ok);
            out.reference(names, result.err);
        }
        Metadata::Bitmap(bitmap) => {
            out.tag("bitmap");
            out.reference(names, bitmap.repr);
            out.count(bitmap.masks.len());
            for mask in &bitmap.masks {
                out.text(&mask.name);
                out.bytes(&mask.mask.to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use iroha_schema::{Declaration, NamedFieldsMeta, VecMeta};

    use super::*;
    use crate::{block::BlockHeader, sumeragi::SumeragiStatus};

    const ABI: [u8; 32] = [0xA1; 32];

    fn block_hash(ivm_abi_hash: [u8; 32]) -> [u8; 32] {
        wire_schema_hash_of(&[&covered_wire_schema()], &[], ivm_abi_hash)
    }

    /// Two closed roots that describe different types under the schema identifier
    /// `String`: `Box<str>` shares `String`'s identifier, and the second root gives it a
    /// different description.
    fn roots_sharing_an_identifier() -> (MetaMap, MetaMap) {
        let first = <Option<String> as IntoSchema>::schema();
        let mut second = MetaMap::new();
        second.insert::<Box<str>>(Metadata::Bool);
        second.insert::<Option<Box<str>>>(Metadata::Option(core::any::TypeId::of::<Box<str>>()));
        (first, second)
    }

    #[test]
    fn wire_schema_hash_is_stable_across_calls_and_schema_rebuilds() {
        let schema = covered_wire_schema();
        let first = wire_schema_hash_of(&[&schema], &[], ABI);
        assert_eq!(first, wire_schema_hash_of(&[&schema], &[], ABI));
        assert_eq!(
            first,
            block_hash(ABI),
            "a rebuilt schema hashes identically"
        );
        assert_ne!(first, [0; 32]);
    }

    /// The block root is closed, and no two of its entries share a schema identifier with
    /// different content, so nothing in the identity relies on the tie-break today.
    #[test]
    fn covered_schema_is_a_closed_unambiguous_block_root() {
        let schema = covered_wire_schema();
        assert!(schema.contains_key::<SignedBlock>());
        assert!(schema.contains_key::<BlockHeader>());
        let defects = wire_root_defects(&schema);
        assert!(defects.is_empty(), "{defects:?}");
    }

    #[test]
    fn wire_root_defects_report_open_references_and_ambiguous_identifiers() {
        let mut open = MetaMap::new();
        open.insert::<Vec<u8>>(Metadata::Vec(VecMeta {
            ty: core::any::TypeId::of::<u8>(),
        }));
        assert_eq!(
            wire_root_defects(&open),
            [WireRootDefect::UnregisteredReference("Vec<u8>".to_owned())]
        );
        <u8 as IntoSchema>::update_schema_map(&mut open);
        assert!(
            wire_root_defects(&open).is_empty(),
            "registering the target closes the root"
        );

        let (first, second) = roots_sharing_an_identifier();
        assert!(wire_root_defects(&first).is_empty());
        assert!(wire_root_defects(&second).is_empty());
        let mut merged = first;
        <Option<Box<str>> as IntoSchema>::update_schema_map(&mut merged);
        assert!(
            wire_root_defects(&merged).is_empty(),
            "entries that share an identifier with one rendering are not ambiguous"
        );
        merged.insert::<Box<str>>(Metadata::Bool);
        assert_eq!(
            wire_root_defects(&merged),
            [WireRootDefect::AmbiguousIdentifier("String".to_owned())]
        );
    }

    /// Entries that share a schema identifier are ordered by their rendering, so the identity
    /// never depends on which `TypeId` each entry happens to have in this build.
    #[test]
    fn shared_identifiers_are_ordered_by_rendering_not_type_id() {
        let entry = |type_name: &str, metadata: Metadata| MetaMapEntry {
            type_id: "Shared".to_owned(),
            type_name: type_name.to_owned(),
            metadata,
        };
        let names = BTreeMap::new();
        let first = entry("First", Metadata::Bool);
        let second = entry("Second", Metadata::String);
        let forward = hash_rendered_roots(
            vec![vec![
                render_entry(&names, &first),
                render_entry(&names, &second),
            ]],
            &[],
            ABI,
        );
        let reverse = hash_rendered_roots(
            vec![vec![
                render_entry(&names, &second),
                render_entry(&names, &first),
            ]],
            &[],
            ABI,
        );
        assert_eq!(forward, reverse);
        let other = hash_rendered_roots(
            vec![vec![
                render_entry(&names, &first),
                render_entry(&names, &first),
            ]],
            &[],
            ABI,
        );
        assert_ne!(forward, other, "the content of each entry is bound");
        let split = hash_rendered_roots(
            vec![
                vec![render_entry(&names, &first)],
                vec![render_entry(&names, &second)],
            ],
            &[],
            ABI,
        );
        assert_ne!(forward, split, "the root of each entry is bound");
        let renamed = entry("First<0..=1>", Metadata::Bool);
        assert_ne!(
            hash_rendered_roots(vec![vec![render_entry(&names, &first)]], &[], ABI),
            hash_rendered_roots(vec![vec![render_entry(&names, &renamed)]], &[], ABI),
            "the name of each entry is bound, including the length bounds a byte domain names"
        );
    }

    /// Roots that describe different types under one identifier stay distinguishable, the
    /// order of the roots is bound, and every root counts.
    #[test]
    fn roots_are_rendered_against_their_own_types() {
        let (first, second) = roots_sharing_an_identifier();
        let both = wire_schema_hash_of(&[&first, &second], &[], ABI);
        assert_eq!(both, wire_schema_hash_of(&[&first, &second], &[], ABI));
        assert_ne!(both, wire_schema_hash_of(&[&second, &first], &[], ABI));
        assert_ne!(both, wire_schema_hash_of(&[&first], &[], ABI));
        assert_ne!(both, wire_schema_hash_of(&[&first, &first], &[], ABI));
        assert_ne!(
            wire_schema_hash_of(&[], &[], ABI),
            wire_schema_hash_of(&[&MetaMap::new()], &[], ABI),
            "an empty root still counts"
        );
    }

    #[test]
    fn wire_schema_hash_binds_the_ivm_abi_hash() {
        let mut other = ABI;
        other[31] ^= 1;
        assert_ne!(block_hash(ABI), block_hash(other));
    }

    #[test]
    fn native_formats_bind_names_bytes_order_and_unambiguous_boundaries() {
        let hash = |formats: &[(&str, &[u8])]| wire_schema_hash_of(&[], formats, ABI);
        let first = [("a", b"bc".as_slice())];
        let expected = hash(&first);
        assert_eq!(expected, hash(&first));
        for other in [
            vec![],
            vec![("ab", b"c".as_slice())],
            vec![("a", b"bd".as_slice())],
            vec![("a", b"bc".as_slice()), ("a", b"bc".as_slice())],
        ] {
            assert_ne!(expected, hash(&other));
        }
        assert_ne!(
            hash(&[("a", b"1"), ("b", b"2")]),
            hash(&[("b", b"2"), ("a", b"1")])
        );
    }

    #[test]
    fn wire_schema_hash_changes_when_a_covered_type_changes() {
        let baseline = covered_wire_schema();
        let expected = wire_schema_hash_of(&[&baseline], &[], ABI);

        let Some(Metadata::Struct(fields)) = baseline.get::<BlockHeader>().cloned() else {
            panic!("BlockHeader is a named-field structure");
        };
        let mut widened = baseline.clone();
        let mut declarations = fields.declarations.clone();
        declarations.push(Declaration {
            name: "hypothetical_field".to_owned(),
            ty: core::any::TypeId::of::<u64>(),
        });
        widened.insert::<BlockHeader>(Metadata::Struct(NamedFieldsMeta { declarations }));
        assert_ne!(
            wire_schema_hash_of(&[&widened], &[], ABI),
            expected,
            "adding a field changes the identity"
        );

        let mut renamed = baseline.clone();
        let mut declarations = fields.declarations.clone();
        declarations[0].name.push('_');
        renamed.insert::<BlockHeader>(Metadata::Struct(NamedFieldsMeta { declarations }));
        assert_ne!(
            wire_schema_hash_of(&[&renamed], &[], ABI),
            expected,
            "renaming a field changes the identity"
        );

        let mut reordered = baseline.clone();
        let mut declarations = fields.declarations;
        declarations.swap(0, 1);
        reordered.insert::<BlockHeader>(Metadata::Struct(NamedFieldsMeta { declarations }));
        assert_ne!(
            wire_schema_hash_of(&[&reordered], &[], ABI),
            expected,
            "reordering fields changes the identity"
        );

        let mut extended = baseline;
        <SumeragiStatus as IntoSchema>::update_schema_map(&mut extended);
        assert_ne!(
            wire_schema_hash_of(&[&extended], &[], ABI),
            expected,
            "the identity covers exactly the supplied compiled schema"
        );
        assert_eq!(
            block_hash(ABI),
            expected,
            "the block root does not include diagnostics-only types"
        );
    }
}
