//! Algebraic strict-DER execution trace for the closed zk-X509 profile.
//!
//! The native parser in [`super::der`] is the authoritative differential oracle. This module
//! deliberately implements an independent parser and witness compiler. Its committed rows bind
//! every input byte exactly once, constrain identifier and length minimality, reconstructed spans,
//! nesting, primitive canonicality, and DER `SET OF` ordering. The trace uses a fixed first-release
//! capacity; no BER compatibility or alternate encoding path is accepted.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::{PrivateTableV1, zeroize_fields_v1, zeroize_words_v1};

#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::der_limits::{
    ZK_X509_DER_MAX_DOCUMENT_BYTES_V1, ZK_X509_DER_MAX_NESTING_DEPTH_V1,
    ZK_X509_DER_MAX_VALUE_BYTES_V1, ZK_X509_DER_MAX_VALUES_V1,
};
#[cfg(test)]
use super::io_air::ZkX509IoTraceV1;
#[cfg(test)]
use super::profile::ZK_X509_MAX_CRL_ENTRIES_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    io_air::{
        ZkX509IoChannelDeclarationV1, ZkX509IoChannelWitnessV1, ZkX509IoEndpointV1,
        ZkX509IoSegmentRoleV1,
    },
    profile::{
        ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1, ZK_X509_MAX_SERIAL_BYTES_V1,
        ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
    },
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use iroha_data_model::privacy::{
    ZK_X509_MAX_CRL_AGE_SECONDS_V1, ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use thiserror::Error;
/// The profile admits at most three certificates and one complete CRL.
pub const ZK_X509_DER_AIR_MAX_DOCUMENTS_V1: usize = 4;
/// Five leaf, four per-CA, and two CRL extension payloads.
pub const ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1: usize = 15;
/// Extension payloads are disjoint slices of the four top-level documents.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const ZK_X509_DER_AIR_MAX_TOTAL_EMBEDDED_BYTES_V1: usize =
    ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 * ZK_X509_DER_MAX_DOCUMENT_BYTES_V1;
/// First-release RFC 5280 admission cap for each certificate and complete CRL.
///
/// The generic strict-DER parser deliberately retains its defensive 16 KiB
/// ceiling.  The closed X.509 relation uses this tighter cap to keep its
/// independent semantic and output adapter on a native `2^18` domain.
pub const ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1: usize = 4_096;
/// A u32 tag uses at most one initial and five base-128 identifier octets.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1: usize = 6;
/// A value of at most 16 KiB uses at most three DER length octets.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const ZK_X509_DER_AIR_LENGTH_BYTES_V1: usize = 3;
/// Address width for the inclusive `0..=16_384` boundary.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const ZK_X509_DER_AIR_ADDRESS_BITS_V1: usize = 15;
/// Fixed universal-tag selector count.
pub const ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1: usize = 19;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const UNIVERSAL_TAGS_V1: [u32; ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1] = [
    1, 2, 3, 4, 5, 6, 10, 12, 16, 17, 18, 19, 20, 22, 23, 24, 26, 28, 30,
];
/// Fixed-width little-endian bit decomposition.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerRangeWitnessV1<const BITS: usize> {
    /// Packed value.
    pub(crate) value: F,
    /// Little-endian Boolean bits.
    pub(crate) bits: [F; BITS],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<const BITS: usize> ZkX509DerRangeWitnessV1<BITS> {
    fn zeroize_private_v1(&mut self) {
        zeroize_fields_v1(core::slice::from_mut(&mut self.value));
        zeroize_fields_v1(&mut self.bits);
    }
    fn from_u64(value: u64) -> Self {
        Self {
            value: F(value),
            bits: core::array::from_fn(|bit| F((value >> bit) & 1)),
        }
    }
    fn zero() -> Self {
        Self::from_u64(0)
    }
    fn constraints(self) -> Vec<F> {
        let mut constraints = Vec::with_capacity(BITS + 1);
        constraints.extend(self.bits.iter().map(|bit| bit.mul(bit.sub(F::ONE))));
        let packed = self
            .bits
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (bit, value)| {
                sum.add(value.mul(F(1_u64 << bit)))
            });
        constraints.push(self.value.sub(packed));
        constraints
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
type ByteWitnessV1 = ZkX509DerRangeWitnessV1<8>;
#[cfg(any(test, feature = "privacy-release-evidence"))]
type AddressWitnessV1 = ZkX509DerRangeWitnessV1<ZK_X509_DER_AIR_ADDRESS_BITS_V1>;
/// One exact private document byte.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerByteRowV1 {
    /// Zero-based document byte address.
    pub(crate) offset: AddressWitnessV1,
    /// Canonical byte decomposition.
    pub(crate) value: ByteWitnessV1,
}
/// One byte emitted by a node header or primitive-content row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerByteEventV1 {
    /// Zero-based document byte address.
    pub(crate) offset: u16,
    /// Algebraic byte value.
    pub(crate) value: F,
}
/// One preorder DER value.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509DerNodeRowV1 {
    /// Preorder value ordinal.
    pub(crate) ordinal: ZkX509DerRangeWitnessV1<11>,
    /// Encoded-value start.
    pub(crate) start: AddressWitnessV1,
    /// Content start after identifier and length.
    pub(crate) content_start: AddressWitnessV1,
    /// Content length.
    pub(crate) content_len: AddressWitnessV1,
    /// Exclusive encoded-value end.
    pub(crate) end: AddressWitnessV1,
    /// Number of constructed ancestors.
    pub(crate) depth: ZkX509DerRangeWitnessV1<5>,
    /// Tag class (`0=universal`, `1=application`, `2=context`, `3=private`).
    pub(crate) tag_class: ZkX509DerRangeWitnessV1<2>,
    /// Primitive/constructed bit.
    pub(crate) constructed: F,
    /// Canonical u32 tag number.
    pub(crate) tag_number: ZkX509DerRangeWitnessV1<32>,
    /// Encoded identifier width.
    pub(crate) identifier_len: ZkX509DerRangeWitnessV1<3>,
    /// Encoded length width.
    pub(crate) length_len: ZkX509DerRangeWitnessV1<2>,
    /// Identifier octets, zero outside `identifier_len`.
    pub(crate) identifier: [ByteWitnessV1; ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1],
    /// Identifier active prefix.
    pub(crate) identifier_active: [F; ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1],
    /// Base-128 accumulators for the five possible high-tag octets.
    pub(crate) tag_accumulators: [F; ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1 - 1],
    /// Inverse proving a high-tag first group is nonzero.
    pub(crate) first_high_group_inverse: F,
    /// Unsigned `tag_number - 31` in high-tag form; zero otherwise.
    pub(crate) tag_minus_31: ZkX509DerRangeWitnessV1<32>,
    /// Length octets, zero outside `length_len`.
    pub(crate) length: [ByteWitnessV1; ZK_X509_DER_AIR_LENGTH_BYTES_V1],
    /// Length active prefix.
    pub(crate) length_active: [F; ZK_X509_DER_AIR_LENGTH_BYTES_V1],
    /// Inverse proving the first long-form body octet is nonzero.
    pub(crate) first_long_body_inverse: F,
    /// Unsigned `content_len - 128` in long form; zero otherwise.
    pub(crate) content_minus_128: AddressWitnessV1,
    /// Unsigned `16_384 - content_len`.
    pub(crate) max_minus_content: AddressWitnessV1,
    /// One-hot selector for an admitted universal tag; all zero otherwise.
    pub(crate) universal_selectors: [F; ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1],
    /// Exclusive ends of constructed ancestors, outermost first.
    pub(crate) ancestor_ends: [AddressWitnessV1; ZK_X509_DER_MAX_NESTING_DEPTH_V1],
    /// Active ancestor prefix.
    pub(crate) ancestor_active: [F; ZK_X509_DER_MAX_NESTING_DEPTH_V1],
    /// Unsigned `ancestor_end - end`, zero for inactive ancestors.
    pub(crate) ancestor_gaps: [AddressWitnessV1; ZK_X509_DER_MAX_NESTING_DEPTH_V1],
    /// Inverses for nonzero ancestor gaps.
    pub(crate) ancestor_gap_inverses: [F; ZK_X509_DER_MAX_NESTING_DEPTH_V1],
    /// Equality flags for `ancestor_end == end`.
    pub(crate) ancestor_gap_is_zero: [F; ZK_X509_DER_MAX_NESTING_DEPTH_V1],
    /// Equality flag for empty content.
    pub(crate) content_is_zero: F,
    /// Inverse for nonempty content.
    pub(crate) content_inverse: F,
}
/// One primitive content octet and its local canonicality state.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509DerPrimitiveRowV1 {
    /// Owning preorder node.
    pub(crate) node: ZkX509DerRangeWitnessV1<11>,
    /// Copied absolute start of the owning primitive contents.
    pub(crate) content_start: AddressWitnessV1,
    /// Offset within the primitive contents.
    pub(crate) content_offset: AddressWitnessV1,
    /// Absolute document address.
    pub(crate) document_offset: AddressWitnessV1,
    /// Content octet.
    pub(crate) value: ByteWitnessV1,
    /// First/last content selectors.
    pub(crate) first: F,
    pub(crate) last: F,
    /// Copied tag class/number.
    pub(crate) tag_class: ZkX509DerRangeWitnessV1<2>,
    pub(crate) tag_number: ZkX509DerRangeWitnessV1<32>,
    /// Copied one-hot selector for an admitted universal tag. Keeping these selectors in the
    /// committed row avoids witness-dependent branching in the extension-domain evaluator.
    pub(crate) universal_selectors: [F; ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1],
    /// OID subidentifier-start state before/after this octet.
    pub(crate) oid_start_before: F,
    pub(crate) oid_start_after: F,
    /// BIT STRING unused-bit one-hot selector, carried over the payload.
    pub(crate) unused_bit_selectors: [F; 8],
    /// Inverse used for INTEGER first-octet equality checks.
    pub(crate) first_zero_inverse: F,
    pub(crate) first_ff_inverse: F,
    /// Equality flags for INTEGER first octet.
    pub(crate) first_is_zero: F,
    pub(crate) first_is_ff: F,
}
/// One bytewise lexicographic comparison row for adjacent `SET OF` children.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509DerSetOrderRowV1 {
    /// Owning SET and adjacent child ordinals.
    pub(crate) set_node: ZkX509DerRangeWitnessV1<11>,
    pub(crate) left_node: ZkX509DerRangeWitnessV1<11>,
    pub(crate) right_node: ZkX509DerRangeWitnessV1<11>,
    /// Common-prefix byte offset.
    pub(crate) offset: AddressWitnessV1,
    /// Compared bytes.
    pub(crate) left: ByteWitnessV1,
    pub(crate) right: ByteWitnessV1,
    /// Comparator state before/after this byte.
    pub(crate) equal_before: F,
    pub(crate) less_before: F,
    pub(crate) equal_after: F,
    pub(crate) less_after: F,
    /// Packed-byte equality flag and inverse.
    pub(crate) bytes_equal: F,
    pub(crate) byte_difference_inverse: F,
    /// `right - left - 1 + 256*borrow`, decomposed into eight bits.
    pub(crate) comparison_difference: ByteWitnessV1,
    /// Borrow bit; `left < right` equals `1-borrow`.
    pub(crate) comparison_borrow: F,
}
/// Complete trace for one exact DER document.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509DerDocumentTraceV1 {
    /// Private document bytes, represented as a sequential constrained table.
    pub(crate) bytes: Vec<ZkX509DerByteRowV1>,
    /// Preorder value rows.
    pub(crate) nodes: Vec<ZkX509DerNodeRowV1>,
    /// Primitive content rows.
    pub(crate) primitive_rows: Vec<ZkX509DerPrimitiveRowV1>,
    /// Adjacent-child SET comparators.
    pub(crate) set_order_rows: Vec<ZkX509DerSetOrderRowV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_node_rows_v1(rows: &mut [ZkX509DerNodeRowV1]) {
    for row in rows {
        row.ordinal.zeroize_private_v1();
        row.start.zeroize_private_v1();
        row.content_start.zeroize_private_v1();
        row.content_len.zeroize_private_v1();
        row.end.zeroize_private_v1();
        row.depth.zeroize_private_v1();
        row.tag_class.zeroize_private_v1();
        zeroize_fields_v1(core::slice::from_mut(&mut row.constructed));
        row.tag_number.zeroize_private_v1();
        row.identifier_len.zeroize_private_v1();
        row.length_len.zeroize_private_v1();
        for value in &mut row.identifier {
            value.zeroize_private_v1();
        }
        zeroize_fields_v1(&mut row.identifier_active);
        zeroize_fields_v1(&mut row.tag_accumulators);
        zeroize_fields_v1(core::slice::from_mut(&mut row.first_high_group_inverse));
        row.tag_minus_31.zeroize_private_v1();
        for value in &mut row.length {
            value.zeroize_private_v1();
        }
        zeroize_fields_v1(&mut row.length_active);
        zeroize_fields_v1(core::slice::from_mut(&mut row.first_long_body_inverse));
        row.content_minus_128.zeroize_private_v1();
        row.max_minus_content.zeroize_private_v1();
        zeroize_fields_v1(&mut row.universal_selectors);
        for value in &mut row.ancestor_ends {
            value.zeroize_private_v1();
        }
        zeroize_fields_v1(&mut row.ancestor_active);
        for value in &mut row.ancestor_gaps {
            value.zeroize_private_v1();
        }
        zeroize_fields_v1(&mut row.ancestor_gap_inverses);
        zeroize_fields_v1(&mut row.ancestor_gap_is_zero);
        zeroize_fields_v1(core::slice::from_mut(&mut row.content_is_zero));
        zeroize_fields_v1(core::slice::from_mut(&mut row.content_inverse));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_primitive_rows_v1(rows: &mut [ZkX509DerPrimitiveRowV1]) {
    for row in rows {
        row.node.zeroize_private_v1();
        row.content_start.zeroize_private_v1();
        row.content_offset.zeroize_private_v1();
        row.document_offset.zeroize_private_v1();
        row.value.zeroize_private_v1();
        zeroize_fields_v1(core::slice::from_mut(&mut row.first));
        zeroize_fields_v1(core::slice::from_mut(&mut row.last));
        row.tag_class.zeroize_private_v1();
        row.tag_number.zeroize_private_v1();
        zeroize_fields_v1(&mut row.universal_selectors);
        zeroize_fields_v1(core::slice::from_mut(&mut row.oid_start_before));
        zeroize_fields_v1(core::slice::from_mut(&mut row.oid_start_after));
        zeroize_fields_v1(&mut row.unused_bit_selectors);
        zeroize_fields_v1(core::slice::from_mut(&mut row.first_zero_inverse));
        zeroize_fields_v1(core::slice::from_mut(&mut row.first_ff_inverse));
        zeroize_fields_v1(core::slice::from_mut(&mut row.first_is_zero));
        zeroize_fields_v1(core::slice::from_mut(&mut row.first_is_ff));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_set_rows_v1(rows: &mut [ZkX509DerSetOrderRowV1]) {
    for row in rows {
        row.set_node.zeroize_private_v1();
        row.left_node.zeroize_private_v1();
        row.right_node.zeroize_private_v1();
        row.offset.zeroize_private_v1();
        row.left.zeroize_private_v1();
        row.right.zeroize_private_v1();
        zeroize_fields_v1(core::slice::from_mut(&mut row.equal_before));
        zeroize_fields_v1(core::slice::from_mut(&mut row.less_before));
        zeroize_fields_v1(core::slice::from_mut(&mut row.equal_after));
        zeroize_fields_v1(core::slice::from_mut(&mut row.less_after));
        zeroize_fields_v1(core::slice::from_mut(&mut row.bytes_equal));
        zeroize_fields_v1(core::slice::from_mut(&mut row.byte_difference_inverse));
        row.comparison_difference.zeroize_private_v1();
        zeroize_fields_v1(core::slice::from_mut(&mut row.comparison_borrow));
    }
}
/// Preserve initialized row erasure when growing private witness storage.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn reserve_private_rows_v1<T: Clone>(
    rows: &mut Vec<T>,
    additional: usize,
    erase: fn(&mut [T]),
) -> Result<(), ZkX509DerAirErrorV1> {
    let required = rows
        .len()
        .checked_add(additional)
        .ok_or(ZkX509DerAirErrorV1::Resource)?;
    if required <= rows.capacity() {
        return Ok(());
    }
    let capacity = required
        .max(
            rows.capacity()
                .checked_mul(2)
                .ok_or(ZkX509DerAirErrorV1::Resource)?,
        )
        .max(4);
    let mut replacement = PrivateTableV1::new(Vec::new(), erase);
    replacement
        .try_reserve_exact(capacity)
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    replacement.extend(rows.iter().cloned());
    erase(rows);
    rows.clear();
    *rows = replacement.into_vec();
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509DerDocumentTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509DerDocumentTraceV1 {
    fn zeroize_private_v1(&mut self) {
        for row in &mut self.bytes {
            row.offset.zeroize_private_v1();
            row.value.zeroize_private_v1();
        }
        self.bytes.clear();
        zeroize_node_rows_v1(&mut self.nodes);
        self.nodes.clear();
        zeroize_primitive_rows_v1(&mut self.primitive_rows);
        self.primitive_rows.clear();
        zeroize_set_rows_v1(&mut self.set_order_rows);
        self.set_order_rows.clear();
    }
}
/// Allocation-free exact resource plan.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerAirResourcePlanV1 {
    /// Number of documents.
    pub(crate) documents: usize,
    /// Exact private bytes.
    pub(crate) bytes: usize,
    /// Exact parsed values.
    pub(crate) nodes: usize,
    /// Exact primitive-content rows.
    pub(crate) primitive_rows: usize,
    /// Exact SET comparator rows.
    pub(crate) set_order_rows: usize,
    /// Fixed maximum document rows after padding.
    pub(crate) fixed_byte_capacity: usize,
    /// Fixed maximum node rows after padding.
    pub(crate) fixed_node_capacity: usize,
}
/// Fixed first-release resource envelope plus exact active RFC 5280 counts.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509Rfc5280ResourcePlanV1 {
    pub(crate) top_level_documents: usize,
    pub(crate) embedded_documents: usize,
    pub(crate) embedded_copy_rows: usize,
    pub(crate) path_rows: usize,
    pub(crate) io_channels: usize,
    pub(crate) io_access_rows: usize,
    pub(crate) fixed_top_level_byte_capacity: usize,
    pub(crate) fixed_embedded_byte_capacity: usize,
    pub(crate) fixed_top_level_node_capacity: usize,
    pub(crate) fixed_embedded_node_capacity: usize,
}
/// DER AIR construction or constraint failure.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509DerAirErrorV1 {
    /// Empty, oversized, or noncanonical DER input.
    #[error("zk-X509 DER AIR input is invalid")]
    Input,
    /// Node spans, traversal, nesting, or row grouping are invalid.
    #[error("zk-X509 DER AIR topology is invalid")]
    Topology,
    /// A packed value or Boolean decomposition is invalid.
    #[error("zk-X509 DER AIR range constraint is invalid")]
    Range,
    /// Identifier, tag form, or length constraints failed.
    #[error("zk-X509 DER AIR header constraint is invalid")]
    Header,
    /// Primitive-content canonicality failed.
    #[error("zk-X509 DER AIR primitive constraint is invalid")]
    Primitive,
    /// Canonical `SET OF` ordering failed.
    #[error("zk-X509 DER AIR SET ordering constraint is invalid")]
    SetOrder,
    /// A byte-copy or exact coverage constraint failed.
    #[error("zk-X509 DER AIR byte binding is invalid")]
    ByteBinding,
    /// Fixed resource arithmetic or allocation failed.
    #[error("zk-X509 DER AIR resource bound is exceeded")]
    Resource,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug)]
struct ParsedHeaderV1<'a> {
    start: usize,
    content_start: usize,
    content_len: usize,
    end: usize,
    tag_class: u8,
    constructed: bool,
    tag_number: u32,
    identifier: &'a [u8],
    length: &'a [u8],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn inverse_or_zero_v1(value: F) -> F {
    // Only malformed residues take the rejection path; canonical zero uses
    // the same fixed exponentiation schedule as every canonical nonzero value.
    F::canonical(value.0).map_or(F::ZERO, F::inverse_or_zero_canonical_v1)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn pack_bits_v1(bits: &[F]) -> F {
    bits.iter()
        .copied()
        .enumerate()
        .fold(F::ZERO, |sum, (bit, value)| {
            sum.add(value.mul(F(1_u64 << bit)))
        })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn all_zero_v1(constraints: &[F]) -> bool {
    constraints.iter().all(|constraint| *constraint == F::ZERO)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_header_v1(
    input: &[u8],
    start: usize,
    container_end: usize,
) -> Result<ParsedHeaderV1<'_>, ZkX509DerAirErrorV1> {
    if start >= container_end || container_end > input.len() {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    let first = input[start];
    let tag_class = first >> 6;
    let constructed = first & 0x20 != 0;
    let low_tag = u32::from(first & 0x1f);
    let mut cursor = start + 1;
    let mut tag_number = low_tag;
    if low_tag == 0x1f {
        let first_high = *input.get(cursor).ok_or(ZkX509DerAirErrorV1::Header)?;
        if first_high == 0x80 {
            return Err(ZkX509DerAirErrorV1::Header);
        }
        tag_number = 0;
        let mut groups = 0_usize;
        loop {
            let byte = *input.get(cursor).ok_or(ZkX509DerAirErrorV1::Header)?;
            tag_number = tag_number
                .checked_mul(128)
                .and_then(|value| value.checked_add(u32::from(byte & 0x7f)))
                .ok_or(ZkX509DerAirErrorV1::Header)?;
            cursor = cursor.checked_add(1).ok_or(ZkX509DerAirErrorV1::Resource)?;
            groups += 1;
            if groups > ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1 - 1 {
                return Err(ZkX509DerAirErrorV1::Header);
            }
            if byte & 0x80 == 0 {
                break;
            }
        }
        if tag_number < 31 {
            return Err(ZkX509DerAirErrorV1::Header);
        }
    }
    let identifier = input
        .get(start..cursor)
        .ok_or(ZkX509DerAirErrorV1::Header)?;
    if tag_class == 0 {
        if tag_number == 0 {
            return Err(ZkX509DerAirErrorV1::Header);
        }
        let expected_constructed = match tag_number {
            1..=6 | 10 | 12 | 18..=20 | 22..=24 | 26 | 28 | 30 => false,
            16 | 17 => true,
            _ => return Err(ZkX509DerAirErrorV1::Header),
        };
        if constructed != expected_constructed {
            return Err(ZkX509DerAirErrorV1::Header);
        }
    }
    let length_start = cursor;
    let first_length = *input.get(cursor).ok_or(ZkX509DerAirErrorV1::Header)?;
    cursor = cursor.checked_add(1).ok_or(ZkX509DerAirErrorV1::Resource)?;
    let content_len = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let body_len = usize::from(first_length & 0x7f);
        if body_len == 0 || body_len > ZK_X509_DER_AIR_LENGTH_BYTES_V1 - 1 {
            return Err(ZkX509DerAirErrorV1::Header);
        }
        let body = input
            .get(cursor..cursor + body_len)
            .ok_or(ZkX509DerAirErrorV1::Header)?;
        if body[0] == 0 {
            return Err(ZkX509DerAirErrorV1::Header);
        }
        let mut length = 0_usize;
        for byte in body {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(ZkX509DerAirErrorV1::Resource)?;
        }
        if length < 128 {
            return Err(ZkX509DerAirErrorV1::Header);
        }
        cursor += body_len;
        length
    };
    if content_len > ZK_X509_DER_MAX_VALUE_BYTES_V1 {
        return Err(ZkX509DerAirErrorV1::Resource);
    }
    let end = cursor
        .checked_add(content_len)
        .ok_or(ZkX509DerAirErrorV1::Resource)?;
    if end > container_end {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    Ok(ParsedHeaderV1 {
        start,
        content_start: cursor,
        content_len,
        end,
        tag_class,
        constructed,
        tag_number,
        identifier,
        length: &input[length_start..cursor],
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_primitive_contents_v1(
    header: &ParsedHeaderV1<'_>,
    contents: &[u8],
) -> Result<(), ZkX509DerAirErrorV1> {
    if header.constructed || header.tag_class != 0 {
        return Ok(());
    }
    match header.tag_number {
        1 => {
            if contents.len() != 1 || !matches!(contents[0], 0 | 0xff) {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
        }
        2 | 10 => {
            let first = *contents.first().ok_or(ZkX509DerAirErrorV1::Primitive)?;
            if let Some(second) = contents.get(1).copied() {
                if (first == 0 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0) {
                    return Err(ZkX509DerAirErrorV1::Primitive);
                }
            }
        }
        3 => {
            let unused = *contents.first().ok_or(ZkX509DerAirErrorV1::Primitive)?;
            if unused > 7
                || (contents.len() == 1 && unused != 0)
                || (unused != 0
                    && contents
                        .last()
                        .is_some_and(|last| last & ((1_u8 << unused) - 1) != 0))
            {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
        }
        5 => {
            if !contents.is_empty() {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
        }
        6 => {
            if contents.is_empty() {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
            let mut starts = true;
            for byte in contents {
                if starts && *byte == 0x80 {
                    return Err(ZkX509DerAirErrorV1::Primitive);
                }
                starts = byte & 0x80 == 0;
            }
            if !starts {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
        }
        _ => {}
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_node_row_v1(
    ordinal: usize,
    header: &ParsedHeaderV1<'_>,
    ancestors: &[usize],
) -> Result<ZkX509DerNodeRowV1, ZkX509DerAirErrorV1> {
    let mut identifier = [ByteWitnessV1::zero(); ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1];
    let mut identifier_active = [F::ZERO; ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1];
    for (index, byte) in header.identifier.iter().copied().enumerate() {
        identifier[index] = ByteWitnessV1::from_u64(u64::from(byte));
        identifier_active[index] = F::ONE;
    }
    let mut tag_accumulators = [F::ZERO; ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1 - 1];
    let mut accumulator = 0_u64;
    for (index, byte) in header.identifier.iter().copied().skip(1).enumerate() {
        accumulator = accumulator
            .checked_mul(128)
            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
            .ok_or(ZkX509DerAirErrorV1::Resource)?;
        tag_accumulators[index] = F(accumulator);
    }
    let long_tag = header.identifier.len() > 1;
    let first_high_group = header
        .identifier
        .get(1)
        .map_or(0, |byte| u64::from(byte & 0x7f));
    let mut length = [ByteWitnessV1::zero(); ZK_X509_DER_AIR_LENGTH_BYTES_V1];
    let mut length_active = [F::ZERO; ZK_X509_DER_AIR_LENGTH_BYTES_V1];
    for (index, byte) in header.length.iter().copied().enumerate() {
        length[index] = ByteWitnessV1::from_u64(u64::from(byte));
        length_active[index] = F::ONE;
    }
    let long_length = header.length[0] & 0x80 != 0;
    let first_long_body = header.length.get(1).copied().unwrap_or(0);
    let mut universal_selectors = [F::ZERO; ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1];
    if header.tag_class == 0 {
        let selector = UNIVERSAL_TAGS_V1
            .iter()
            .position(|tag| *tag == header.tag_number)
            .ok_or(ZkX509DerAirErrorV1::Header)?;
        universal_selectors[selector] = F::ONE;
    }
    let mut ancestor_ends = [AddressWitnessV1::zero(); ZK_X509_DER_MAX_NESTING_DEPTH_V1];
    let mut ancestor_active = [F::ZERO; ZK_X509_DER_MAX_NESTING_DEPTH_V1];
    let mut ancestor_gaps = [AddressWitnessV1::zero(); ZK_X509_DER_MAX_NESTING_DEPTH_V1];
    let mut ancestor_gap_inverses = [F::ZERO; ZK_X509_DER_MAX_NESTING_DEPTH_V1];
    let mut ancestor_gap_is_zero = [F::ZERO; ZK_X509_DER_MAX_NESTING_DEPTH_V1];
    for (index, ancestor_end) in ancestors.iter().copied().enumerate() {
        let gap = ancestor_end
            .checked_sub(header.end)
            .ok_or(ZkX509DerAirErrorV1::Topology)?;
        ancestor_ends[index] = AddressWitnessV1::from_u64(
            u64::try_from(ancestor_end).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        );
        ancestor_active[index] = F::ONE;
        ancestor_gaps[index] = AddressWitnessV1::from_u64(
            u64::try_from(gap).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        );
        ancestor_gap_is_zero[index] = F(u64::from(gap == 0));
        ancestor_gap_inverses[index] = inverse_or_zero_v1(F(
            u64::try_from(gap).map_err(|_| ZkX509DerAirErrorV1::Resource)?
        ));
    }
    let content_len =
        u64::try_from(header.content_len).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    Ok(ZkX509DerNodeRowV1 {
        ordinal: ZkX509DerRangeWitnessV1::from_u64(
            u64::try_from(ordinal).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        start: AddressWitnessV1::from_u64(
            u64::try_from(header.start).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        content_start: AddressWitnessV1::from_u64(
            u64::try_from(header.content_start).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        content_len: AddressWitnessV1::from_u64(content_len),
        end: AddressWitnessV1::from_u64(
            u64::try_from(header.end).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        depth: ZkX509DerRangeWitnessV1::from_u64(
            u64::try_from(ancestors.len()).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        tag_class: ZkX509DerRangeWitnessV1::from_u64(u64::from(header.tag_class)),
        constructed: F(u64::from(header.constructed)),
        tag_number: ZkX509DerRangeWitnessV1::from_u64(u64::from(header.tag_number)),
        identifier_len: ZkX509DerRangeWitnessV1::from_u64(
            u64::try_from(header.identifier.len()).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        length_len: ZkX509DerRangeWitnessV1::from_u64(
            u64::try_from(header.length.len()).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        identifier,
        identifier_active,
        tag_accumulators,
        first_high_group_inverse: if long_tag {
            inverse_or_zero_v1(F(first_high_group))
        } else {
            F::ZERO
        },
        tag_minus_31: if long_tag {
            ZkX509DerRangeWitnessV1::from_u64(u64::from(header.tag_number - 31))
        } else {
            ZkX509DerRangeWitnessV1::zero()
        },
        length,
        length_active,
        first_long_body_inverse: if long_length {
            inverse_or_zero_v1(F(u64::from(first_long_body)))
        } else {
            F::ZERO
        },
        content_minus_128: if long_length {
            AddressWitnessV1::from_u64(content_len - 128)
        } else {
            AddressWitnessV1::zero()
        },
        max_minus_content: AddressWitnessV1::from_u64(
            u64::try_from(ZK_X509_DER_MAX_VALUE_BYTES_V1 - header.content_len)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        ),
        universal_selectors,
        ancestor_ends,
        ancestor_active,
        ancestor_gaps,
        ancestor_gap_inverses,
        ancestor_gap_is_zero,
        content_is_zero: F(u64::from(header.content_len == 0)),
        content_inverse: inverse_or_zero_v1(F(content_len)),
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_primitive_rows_v1(
    node: usize,
    header: &ParsedHeaderV1<'_>,
    contents: &[u8],
    output: &mut Vec<ZkX509DerPrimitiveRowV1>,
) -> Result<(), ZkX509DerAirErrorV1> {
    reserve_private_rows_v1(output, contents.len(), zeroize_primitive_rows_v1)?;
    let mut oid_start = header.tag_class == 0 && header.tag_number == 6;
    let unused = if header.tag_class == 0 && header.tag_number == 3 {
        contents.first().copied()
    } else {
        None
    };
    let mut universal_selectors = [F::ZERO; ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1];
    if header.tag_class == 0 {
        let selector = UNIVERSAL_TAGS_V1
            .iter()
            .position(|tag| *tag == header.tag_number)
            .ok_or(ZkX509DerAirErrorV1::Header)?;
        universal_selectors[selector] = F::ONE;
    }
    for (offset, byte) in contents.iter().copied().enumerate() {
        let first = offset == 0;
        let oid_after = header.tag_class == 0 && header.tag_number == 6 && byte & 0x80 == 0;
        let mut unused_bit_selectors = [F::ZERO; 8];
        if let Some(unused) = unused {
            unused_bit_selectors[usize::from(unused)] = F::ONE;
        }
        let first_is_zero = first && byte == 0;
        let first_is_ff = first && byte == 0xff;
        output.push(ZkX509DerPrimitiveRowV1 {
            node: ZkX509DerRangeWitnessV1::from_u64(
                u64::try_from(node).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            content_start: AddressWitnessV1::from_u64(
                u64::try_from(header.content_start).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            content_offset: AddressWitnessV1::from_u64(
                u64::try_from(offset).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            document_offset: AddressWitnessV1::from_u64(
                u64::try_from(header.content_start + offset)
                    .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            value: ByteWitnessV1::from_u64(u64::from(byte)),
            first: F(u64::from(first)),
            last: F(u64::from(offset + 1 == contents.len())),
            tag_class: ZkX509DerRangeWitnessV1::from_u64(u64::from(header.tag_class)),
            tag_number: ZkX509DerRangeWitnessV1::from_u64(u64::from(header.tag_number)),
            universal_selectors,
            oid_start_before: F(u64::from(oid_start)),
            oid_start_after: F(u64::from(oid_after)),
            unused_bit_selectors,
            first_zero_inverse: if first {
                inverse_or_zero_v1(F(u64::from(byte)))
            } else {
                F::ZERO
            },
            first_ff_inverse: if first {
                inverse_or_zero_v1(F(u64::from(byte)).sub(F(0xff)))
            } else {
                F::ZERO
            },
            first_is_zero: F(u64::from(first_is_zero)),
            first_is_ff: F(u64::from(first_is_ff)),
        });
        oid_start = oid_after;
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_set_comparison_rows_v1(
    input: &[u8],
    set_node: usize,
    left_node: usize,
    right_node: usize,
    left: core::ops::Range<usize>,
    right: core::ops::Range<usize>,
    output: &mut Vec<ZkX509DerSetOrderRowV1>,
) -> Result<(), ZkX509DerAirErrorV1> {
    let left_bytes = input
        .get(left.clone())
        .ok_or(ZkX509DerAirErrorV1::Topology)?;
    let right_bytes = input
        .get(right.clone())
        .ok_or(ZkX509DerAirErrorV1::Topology)?;
    if left_bytes > right_bytes {
        return Err(ZkX509DerAirErrorV1::SetOrder);
    }
    let common = left_bytes.len().min(right_bytes.len());
    reserve_private_rows_v1(output, common, zeroize_set_rows_v1)?;
    let mut equal = true;
    let mut less = false;
    for offset in 0..common {
        let left_byte = left_bytes[offset];
        let right_byte = right_bytes[offset];
        let bytes_equal = left_byte == right_byte;
        let byte_less = left_byte < right_byte;
        let equal_after = equal && bytes_equal;
        let less_after = less || (equal && byte_less);
        let borrow = u8::from(!byte_less);
        let difference = u16::from(right_byte)
            .wrapping_sub(u16::from(left_byte))
            .wrapping_sub(1)
            .wrapping_add(256 * u16::from(borrow)) as u8;
        let packed_difference = F(u64::from(left_byte)).sub(F(u64::from(right_byte)));
        output.push(ZkX509DerSetOrderRowV1 {
            set_node: ZkX509DerRangeWitnessV1::from_u64(
                u64::try_from(set_node).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            left_node: ZkX509DerRangeWitnessV1::from_u64(
                u64::try_from(left_node).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            right_node: ZkX509DerRangeWitnessV1::from_u64(
                u64::try_from(right_node).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            offset: AddressWitnessV1::from_u64(
                u64::try_from(offset).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            left: ByteWitnessV1::from_u64(u64::from(left_byte)),
            right: ByteWitnessV1::from_u64(u64::from(right_byte)),
            equal_before: F(u64::from(equal)),
            less_before: F(u64::from(less)),
            equal_after: F(u64::from(equal_after)),
            less_after: F(u64::from(less_after)),
            bytes_equal: F(u64::from(bytes_equal)),
            byte_difference_inverse: inverse_or_zero_v1(packed_difference),
            comparison_difference: ByteWitnessV1::from_u64(u64::from(difference)),
            comparison_borrow: F(u64::from(borrow)),
        });
        equal = equal_after;
        less = less_after;
    }
    if !less && !(equal && left_bytes.len() <= right_bytes.len()) {
        return Err(ZkX509DerAirErrorV1::SetOrder);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct CompilerV1<'a> {
    input: &'a [u8],
    trace: ZkX509DerDocumentTraceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl CompilerV1<'_> {
    fn compile_value(
        &mut self,
        start: usize,
        container_end: usize,
        ancestors: &mut Vec<usize>,
    ) -> Result<(usize, usize), ZkX509DerAirErrorV1> {
        if ancestors.len() >= ZK_X509_DER_MAX_NESTING_DEPTH_V1 {
            return Err(ZkX509DerAirErrorV1::Resource);
        }
        if self.trace.nodes.len() >= ZK_X509_DER_MAX_VALUES_V1 {
            return Err(ZkX509DerAirErrorV1::Resource);
        }
        let header = parse_header_v1(self.input, start, container_end)?;
        let ordinal = self.trace.nodes.len();
        reserve_private_rows_v1(&mut self.trace.nodes, 1, zeroize_node_rows_v1)?;
        self.trace
            .nodes
            .push(build_node_row_v1(ordinal, &header, ancestors)?);
        if header.constructed {
            let mut cursor = header.content_start;
            let mut previous_child: Option<(usize, core::ops::Range<usize>)> = None;
            ancestors.push(header.end);
            while cursor < header.end {
                let child_start = cursor;
                let (child, child_end) = self.compile_value(cursor, header.end, ancestors)?;
                if child_end <= cursor {
                    return Err(ZkX509DerAirErrorV1::Topology);
                }
                if header.tag_class == 0 && header.tag_number == 17 {
                    if let Some((previous, span)) = previous_child.take() {
                        build_set_comparison_rows_v1(
                            self.input,
                            ordinal,
                            previous,
                            child,
                            span,
                            child_start..child_end,
                            &mut self.trace.set_order_rows,
                        )?;
                    }
                    previous_child = Some((child, child_start..child_end));
                }
                cursor = child_end;
            }
            if let Some(last) = ancestors.last_mut() {
                zeroize_words_v1(core::slice::from_mut(last));
            }
            ancestors.pop();
            if cursor != header.end {
                return Err(ZkX509DerAirErrorV1::Topology);
            }
        } else {
            let contents = &self.input[header.content_start..header.end];
            validate_primitive_contents_v1(&header, contents)?;
            build_primitive_rows_v1(ordinal, &header, contents, &mut self.trace.primitive_rows)?;
        }
        Ok((ordinal, header.end))
    }
}
/// Compile and validate one exact DER document.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_strict_der_document_trace_v1(
    input: &[u8],
) -> Result<ZkX509DerDocumentTraceV1, ZkX509DerAirErrorV1> {
    if input.is_empty() || input.len() > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let mut compiler = CompilerV1 {
        input,
        trace: ZkX509DerDocumentTraceV1 {
            bytes: Vec::new(),
            nodes: Vec::new(),
            primitive_rows: Vec::new(),
            set_order_rows: Vec::new(),
        },
    };
    let mut ancestors = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
    ancestors
        .try_reserve_exact(ZK_X509_DER_MAX_NESTING_DEPTH_V1)
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    let (_, end) = compiler.compile_value(0, input.len(), &mut ancestors)?;
    if end != input.len() {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    compiler.trace.set_order_rows.sort_unstable_by_key(|row| {
        (
            row.set_node.value.0,
            row.left_node.value.0,
            row.right_node.value.0,
            row.offset.value.0,
        )
    });
    let bytes = &mut compiler.trace.bytes;
    bytes
        .try_reserve_exact(input.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for (offset, value) in input.iter().copied().enumerate() {
        bytes.push(ZkX509DerByteRowV1 {
            offset: AddressWitnessV1::from_u64(
                u64::try_from(offset).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            value: ByteWitnessV1::from_u64(u64::from(value)),
        });
    }
    let trace = compiler.trace;
    trace.validate()?;
    Ok(trace)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn evaluate_byte_constraints_v1(row: ZkX509DerByteRowV1) -> Vec<F> {
    let mut constraints = row.offset.constraints();
    constraints.extend(row.value.constraints());
    constraints
}
/// Evaluate all local algebraic identities for one node row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_der_node_constraints_v1(row: &ZkX509DerNodeRowV1) -> Vec<F> {
    let mut constraints = Vec::new();
    constraints.extend(row.ordinal.constraints());
    constraints.extend(row.start.constraints());
    constraints.extend(row.content_start.constraints());
    constraints.extend(row.content_len.constraints());
    constraints.extend(row.end.constraints());
    constraints.extend(row.depth.constraints());
    constraints.extend(row.tag_class.constraints());
    constraints.extend(row.tag_number.constraints());
    constraints.extend(row.identifier_len.constraints());
    constraints.extend(row.length_len.constraints());
    constraints.extend(row.tag_minus_31.constraints());
    constraints.extend(row.content_minus_128.constraints());
    constraints.extend(row.max_minus_content.constraints());
    constraints.push(row.constructed.mul(row.constructed.sub(F::ONE)));
    for byte in row.identifier {
        constraints.extend(byte.constraints());
    }
    for index in 0..ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1 {
        let active = row.identifier_active[index];
        constraints.push(active.mul(active.sub(F::ONE)));
        if index == 0 {
            constraints.push(active.sub(F::ONE));
        } else {
            constraints.push(active.mul(F::ONE.sub(row.identifier_active[index - 1])));
        }
        constraints.push(F::ONE.sub(active).mul(row.identifier[index].value));
    }
    constraints.push(
        row.identifier_len
            .value
            .sub(row.identifier_active.iter().copied().fold(F::ZERO, F::add)),
    );
    let first = row.identifier[0];
    let class = first.bits[6].add(first.bits[7].mul(F(2)));
    let low_tag = pack_bits_v1(&first.bits[..5]);
    constraints.push(row.tag_class.value.sub(class));
    constraints.push(row.constructed.sub(first.bits[5]));
    let long_tag = row.identifier_active[1];
    constraints.push(long_tag.mul(low_tag.sub(F(31))));
    constraints.push(F::ONE.sub(long_tag).mul(row.tag_number.value.sub(low_tag)));
    let first_high_group = pack_bits_v1(&row.identifier[1].bits[..7]);
    constraints.push(
        first_high_group
            .mul(row.first_high_group_inverse)
            .sub(long_tag),
    );
    constraints.push(F::ONE.sub(long_tag).mul(row.first_high_group_inverse));
    for high in 0..ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1 - 1 {
        let identifier_index = high + 1;
        let active = row.identifier_active[identifier_index];
        let next_active = row
            .identifier_active
            .get(identifier_index + 1)
            .copied()
            .unwrap_or(F::ZERO);
        let last = active.mul(F::ONE.sub(next_active));
        let not_last = active.mul(next_active);
        constraints.push(last.mul(row.identifier[identifier_index].bits[7]));
        constraints.push(not_last.mul(row.identifier[identifier_index].bits[7].sub(F::ONE)));
        let low = pack_bits_v1(&row.identifier[identifier_index].bits[..7]);
        let expected = if high == 0 {
            low
        } else {
            row.tag_accumulators[high - 1].mul(F(128)).add(low)
        };
        constraints.push(active.mul(row.tag_accumulators[high].sub(expected)));
        constraints.push(F::ONE.sub(active).mul(row.tag_accumulators[high]));
    }
    let final_tag = (0..ZK_X509_DER_AIR_IDENTIFIER_BYTES_V1 - 1).fold(F::ZERO, |sum, high| {
        let identifier_index = high + 1;
        let last = row.identifier_active[identifier_index].mul(
            F::ONE.sub(
                row.identifier_active
                    .get(identifier_index + 1)
                    .copied()
                    .unwrap_or(F::ZERO),
            ),
        );
        sum.add(last.mul(row.tag_accumulators[high]))
    });
    constraints.push(long_tag.mul(row.tag_number.value.sub(final_tag)));
    constraints.push(
        row.tag_minus_31
            .value
            .sub(long_tag.mul(row.tag_number.value.sub(F(31)))),
    );
    let class_is_universal = F::ONE
        .sub(row.tag_class.bits[0])
        .mul(F::ONE.sub(row.tag_class.bits[1]));
    let selector_sum = row
        .universal_selectors
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    constraints.push(selector_sum.sub(class_is_universal));
    for (selector, tag) in row
        .universal_selectors
        .iter()
        .copied()
        .zip(UNIVERSAL_TAGS_V1)
    {
        constraints.push(selector.mul(selector.sub(F::ONE)));
        constraints.push(selector.mul(row.tag_number.value.sub(F(u64::from(tag)))));
    }
    let constructed_universal = row.universal_selectors[8].add(row.universal_selectors[9]);
    constraints.push(class_is_universal.mul(row.constructed.sub(constructed_universal)));
    for byte in row.length {
        constraints.extend(byte.constraints());
    }
    for index in 0..ZK_X509_DER_AIR_LENGTH_BYTES_V1 {
        let active = row.length_active[index];
        constraints.push(active.mul(active.sub(F::ONE)));
        if index == 0 {
            constraints.push(active.sub(F::ONE));
        } else {
            constraints.push(active.mul(F::ONE.sub(row.length_active[index - 1])));
        }
        constraints.push(F::ONE.sub(active).mul(row.length[index].value));
    }
    constraints.push(
        row.length_len
            .value
            .sub(row.length_active.iter().copied().fold(F::ZERO, F::add)),
    );
    let long_length = row.length[0].bits[7];
    let length_count = pack_bits_v1(&row.length[0].bits[..7]);
    constraints.push(
        row.length_len
            .value
            .sub(F::ONE.add(long_length.mul(length_count))),
    );
    constraints.push(
        long_length
            .mul(length_count.sub(F::ONE))
            .mul(length_count.sub(F(2))),
    );
    let first_body = row.length[1].value;
    constraints.push(first_body.mul(row.first_long_body_inverse).sub(long_length));
    constraints.push(F::ONE.sub(long_length).mul(row.first_long_body_inverse));
    let is_two = long_length.mul(length_count.sub(F::ONE));
    let is_one = long_length.sub(is_two);
    let short_length = pack_bits_v1(&row.length[0].bits[..7]);
    let decoded_length = F::ONE
        .sub(long_length)
        .mul(short_length)
        .add(is_one.mul(first_body))
        .add(is_two.mul(first_body.mul(F(256)).add(row.length[2].value)));
    constraints.push(row.content_len.value.sub(decoded_length));
    constraints.push(
        row.content_minus_128
            .value
            .sub(long_length.mul(row.content_len.value.sub(F(128)))),
    );
    constraints.push(
        row.max_minus_content
            .value
            .add(row.content_len.value)
            .sub(F(
                u64::try_from(ZK_X509_DER_MAX_VALUE_BYTES_V1).expect("DER limit fits u64")
            )),
    );
    constraints.push(
        row.content_start.value.sub(
            row.start
                .value
                .add(row.identifier_len.value)
                .add(row.length_len.value),
        ),
    );
    constraints.push(
        row.end
            .value
            .sub(row.content_start.value.add(row.content_len.value)),
    );
    constraints.push(row.content_is_zero.mul(row.content_is_zero.sub(F::ONE)));
    constraints.push(row.content_len.value.mul(row.content_is_zero));
    constraints.push(
        row.content_len
            .value
            .mul(row.content_inverse)
            .sub(F::ONE.sub(row.content_is_zero)),
    );
    constraints.push(row.content_is_zero.mul(row.content_inverse));
    let depth_from_prefix = row.ancestor_active.iter().copied().fold(F::ZERO, F::add);
    constraints.push(row.depth.value.sub(depth_from_prefix));
    for index in 0..ZK_X509_DER_MAX_NESTING_DEPTH_V1 {
        constraints.extend(row.ancestor_ends[index].constraints());
        constraints.extend(row.ancestor_gaps[index].constraints());
        let active = row.ancestor_active[index];
        let is_zero = row.ancestor_gap_is_zero[index];
        constraints.push(active.mul(active.sub(F::ONE)));
        constraints.push(is_zero.mul(is_zero.sub(F::ONE)));
        if index > 0 {
            constraints.push(active.mul(F::ONE.sub(row.ancestor_active[index - 1])));
        }
        constraints.push(F::ONE.sub(active).mul(row.ancestor_ends[index].value));
        constraints.push(F::ONE.sub(active).mul(row.ancestor_gaps[index].value));
        constraints.push(F::ONE.sub(active).mul(row.ancestor_gap_inverses[index]));
        constraints.push(F::ONE.sub(active).mul(is_zero));
        constraints.push(
            active.mul(
                row.ancestor_ends[index]
                    .value
                    .sub(row.end.value)
                    .sub(row.ancestor_gaps[index].value),
            ),
        );
        constraints.push(row.ancestor_gaps[index].value.mul(is_zero));
        constraints.push(
            row.ancestor_gaps[index]
                .value
                .mul(row.ancestor_gap_inverses[index])
                .sub(active.sub(is_zero)),
        );
        constraints.push(is_zero.mul(row.ancestor_gap_inverses[index]));
        if index > 0 {
            let retained = active.sub(is_zero);
            let previous_retained =
                row.ancestor_active[index - 1].sub(row.ancestor_gap_is_zero[index - 1]);
            constraints.push(retained.mul(F::ONE.sub(previous_retained)));
        }
    }
    // Primitive universal values with mandatory sizes/nonempty contents.
    constraints.push(row.universal_selectors[0].mul(row.content_len.value.sub(F::ONE)));
    constraints.push(row.universal_selectors[4].mul(row.content_len.value));
    for selector in [1_usize, 2, 5, 6] {
        constraints.push(row.universal_selectors[selector].mul(row.content_is_zero));
    }
    constraints
}
/// Evaluate the gap-free preorder transition between adjacent node rows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_der_node_transition_constraints_v1(
    row: &ZkX509DerNodeRowV1,
    next: Option<&ZkX509DerNodeRowV1>,
    document_len: usize,
) -> Vec<F> {
    let mut constraints = Vec::new();
    let has_child = row.constructed.mul(F::ONE.sub(row.content_is_zero));
    let retained: [F; ZK_X509_DER_MAX_NESTING_DEPTH_V1] = core::array::from_fn(|index| {
        row.ancestor_active[index].sub(row.ancestor_gap_is_zero[index])
    });
    match next {
        Some(next) => {
            constraints.push(next.ordinal.value.sub(row.ordinal.value.add(F::ONE)));
            let expected_start = has_child
                .mul(row.content_start.value)
                .add(F::ONE.sub(has_child).mul(row.end.value));
            constraints.push(next.start.value.sub(expected_start));
            let retained_count = retained.iter().copied().fold(F::ZERO, F::add);
            constraints.push(
                next.depth.value.sub(
                    has_child
                        .mul(row.depth.value.add(F::ONE))
                        .add(F::ONE.sub(has_child).mul(retained_count)),
                ),
            );
            for index in 0..ZK_X509_DER_MAX_NESTING_DEPTH_V1 {
                let previous_active = if index == 0 {
                    F::ZERO
                } else {
                    row.ancestor_active[index - 1]
                };
                let push = F::ONE.sub(row.ancestor_active[index]).mul(if index == 0 {
                    F::ONE
                } else {
                    previous_active
                });
                let child_active = row.ancestor_active[index].add(push);
                let child_end = row.ancestor_active[index]
                    .mul(row.ancestor_ends[index].value)
                    .add(push.mul(row.end.value));
                let expected_active = has_child
                    .mul(child_active)
                    .add(F::ONE.sub(has_child).mul(retained[index]));
                let expected_end = has_child.mul(child_end).add(
                    F::ONE
                        .sub(has_child)
                        .mul(retained[index])
                        .mul(row.ancestor_ends[index].value),
                );
                constraints.push(next.ancestor_active[index].sub(expected_active));
                constraints.push(next.ancestor_ends[index].value.sub(expected_end));
            }
        }
        None => {
            constraints.push(has_child);
            constraints.push(row.end.value.sub(F(
                u64::try_from(document_len).expect("DER document length fits u64"),
            )));
            constraints.extend(retained);
        }
    }
    constraints
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_der_primitive_constraints_v1(row: &ZkX509DerPrimitiveRowV1) -> Vec<F> {
    let mut constraints = Vec::new();
    constraints.extend(row.node.constraints());
    constraints.extend(row.content_start.constraints());
    constraints.extend(row.content_offset.constraints());
    constraints.extend(row.document_offset.constraints());
    constraints.extend(row.value.constraints());
    constraints.extend(row.tag_class.constraints());
    constraints.extend(row.tag_number.constraints());
    for selector in [
        row.first,
        row.last,
        row.oid_start_before,
        row.oid_start_after,
    ] {
        constraints.push(selector.mul(selector.sub(F::ONE)));
    }
    constraints.push(
        row.document_offset
            .value
            .sub(row.content_start.value.add(row.content_offset.value)),
    );
    let first_delta_zero = row.value.value;
    constraints.push(row.first_is_zero.mul(row.first_is_zero.sub(F::ONE)));
    constraints.push(first_delta_zero.mul(row.first_is_zero));
    constraints.push(
        first_delta_zero
            .mul(row.first_zero_inverse)
            .sub(row.first.sub(row.first_is_zero)),
    );
    constraints.push(row.first_is_zero.mul(row.first_zero_inverse));
    constraints.push(F::ONE.sub(row.first).mul(row.first_zero_inverse));
    constraints.push(F::ONE.sub(row.first).mul(row.first_is_zero));
    let first_delta_ff = row.value.value.sub(F(0xff));
    constraints.push(row.first_is_ff.mul(row.first_is_ff.sub(F::ONE)));
    constraints.push(first_delta_ff.mul(row.first_is_ff));
    constraints.push(
        first_delta_ff
            .mul(row.first_ff_inverse)
            .sub(row.first.sub(row.first_is_ff)),
    );
    constraints.push(row.first_is_ff.mul(row.first_ff_inverse));
    constraints.push(F::ONE.sub(row.first).mul(row.first_ff_inverse));
    constraints.push(F::ONE.sub(row.first).mul(row.first_is_ff));
    let is_universal = F::ONE
        .sub(row.tag_class.bits[0])
        .mul(F::ONE.sub(row.tag_class.bits[1]));
    let universal_selector_sum = row
        .universal_selectors
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    constraints.push(universal_selector_sum.sub(is_universal));
    for (selector, tag) in row
        .universal_selectors
        .iter()
        .copied()
        .zip(UNIVERSAL_TAGS_V1)
    {
        constraints.push(selector.mul(selector.sub(F::ONE)));
        constraints.push(selector.mul(row.tag_number.value.sub(F(u64::from(tag)))));
    }
    let boolean = row.universal_selectors[0];
    constraints.push(boolean.mul(row.value.value.mul(row.value.value.sub(F(0xff)))));
    constraints.push(boolean.mul(row.first.sub(F::ONE)));
    constraints.push(boolean.mul(row.last.sub(F::ONE)));
    let oid = row.universal_selectors[5];
    constraints.push(oid.mul(row.first).mul(row.oid_start_before.sub(F::ONE)));
    let continuation = row.value.bits[7];
    constraints.push(oid.mul(row.oid_start_after.sub(F::ONE.sub(continuation))));
    let is_128 = continuation.mul(
        row.value.bits[..7]
            .iter()
            .copied()
            .fold(F::ONE, |product, bit| product.mul(F::ONE.sub(bit))),
    );
    constraints.push(oid.mul(row.oid_start_before).mul(is_128));
    constraints.push(oid.mul(row.last).mul(row.oid_start_after.sub(F::ONE)));
    constraints.push(F::ONE.sub(oid).mul(row.oid_start_before));
    constraints.push(F::ONE.sub(oid).mul(row.oid_start_after));
    let selector_sum = row
        .unused_bit_selectors
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    for selector in row.unused_bit_selectors {
        constraints.push(selector.mul(selector.sub(F::ONE)));
    }
    let bit_string = row.universal_selectors[2];
    constraints.push(selector_sum.sub(bit_string));
    let unused = row
        .unused_bit_selectors
        .iter()
        .copied()
        .enumerate()
        .fold(F::ZERO, |sum, (value, selector)| {
            sum.add(selector.mul(F(value as u64)))
        });
    constraints.push(bit_string.mul(row.first).mul(row.value.value.sub(unused)));
    constraints.push(bit_string.mul(row.first).mul(row.last).mul(unused));
    for bit in 0..8 {
        let bit_must_be_zero = row.unused_bit_selectors[bit + 1..]
            .iter()
            .copied()
            .fold(F::ZERO, F::add);
        constraints.push(
            bit_string
                .mul(row.last)
                .mul(F::ONE.sub(row.first))
                .mul(bit_must_be_zero)
                .mul(row.value.bits[bit]),
        );
    }
    constraints
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_der_set_order_constraints_v1(row: &ZkX509DerSetOrderRowV1) -> Vec<F> {
    let mut constraints = Vec::new();
    constraints.extend(row.set_node.constraints());
    constraints.extend(row.left_node.constraints());
    constraints.extend(row.right_node.constraints());
    constraints.extend(row.offset.constraints());
    constraints.extend(row.left.constraints());
    constraints.extend(row.right.constraints());
    constraints.extend(row.comparison_difference.constraints());
    for selector in [
        row.equal_before,
        row.less_before,
        row.equal_after,
        row.less_after,
        row.bytes_equal,
        row.comparison_borrow,
    ] {
        constraints.push(selector.mul(selector.sub(F::ONE)));
    }
    constraints.push(row.equal_before.mul(row.less_before));
    let difference = row.left.value.sub(row.right.value);
    constraints.push(difference.mul(row.bytes_equal));
    constraints.push(
        difference
            .mul(row.byte_difference_inverse)
            .sub(F::ONE.sub(row.bytes_equal)),
    );
    constraints.push(row.bytes_equal.mul(row.byte_difference_inverse));
    constraints.push(
        row.right
            .value
            .sub(row.left.value)
            .sub(F::ONE)
            .add(row.comparison_borrow.mul(F(256)))
            .sub(row.comparison_difference.value),
    );
    let byte_less = F::ONE.sub(row.comparison_borrow);
    constraints.push(row.equal_after.sub(row.equal_before.mul(row.bytes_equal)));
    constraints.push(
        row.less_after.sub(
            row.less_before.add(
                row.equal_before
                    .mul(F::ONE.sub(row.bytes_equal))
                    .mul(byte_less),
            ),
        ),
    );
    constraints
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509DerNodeRowV1 {
    fn header_events(&self) -> Result<Vec<ZkX509DerByteEventV1>, ZkX509DerAirErrorV1> {
        let start =
            usize::try_from(self.start.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        let identifier_len = usize::try_from(self.identifier_len.value.0)
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        let length_len =
            usize::try_from(self.length_len.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        let mut events = Vec::new();
        events
            .try_reserve_exact(identifier_len + length_len)
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        for index in 0..identifier_len {
            events.push(ZkX509DerByteEventV1 {
                offset: u16::try_from(start + index).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                value: self.identifier[index].value,
            });
        }
        for index in 0..length_len {
            events.push(ZkX509DerByteEventV1 {
                offset: u16::try_from(start + identifier_len + index)
                    .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                value: self.length[index].value,
            });
        }
        Ok(events)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509DerDocumentTraceV1 {
    /// Exact active document length.
    #[cfg(test)]
    pub(crate) fn document_len(&self) -> usize {
        self.bytes.len()
    }
    /// Validate all local, transition, byte-cover, and SET-order constraints.
    pub(crate) fn validate(&self) -> Result<(), ZkX509DerAirErrorV1> {
        if self.bytes.is_empty() || self.bytes.len() > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        for (index, row) in self.bytes.iter().copied().enumerate() {
            if !all_zero_v1(&evaluate_byte_constraints_v1(row))
                || row.offset.value.0
                    != u64::try_from(index).map_err(|_| ZkX509DerAirErrorV1::Resource)?
            {
                return Err(ZkX509DerAirErrorV1::Range);
            }
        }
        if self.nodes.is_empty() || self.nodes.len() > ZK_X509_DER_MAX_VALUES_V1 {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        for (index, row) in self.nodes.iter().enumerate() {
            if row.ordinal.value.0
                != u64::try_from(index).map_err(|_| ZkX509DerAirErrorV1::Resource)?
                || !all_zero_v1(&evaluate_der_node_constraints_v1(row))
            {
                return Err(ZkX509DerAirErrorV1::Header);
            }
            let transition = evaluate_der_node_transition_constraints_v1(
                row,
                self.nodes.get(index + 1),
                self.bytes.len(),
            );
            if !all_zero_v1(&transition) {
                return Err(ZkX509DerAirErrorV1::Topology);
            }
        }
        if self.nodes[0].start.value != F::ZERO
            || self.nodes[0].depth.value != F::ZERO
            || self.nodes[0].end.value
                != F(u64::try_from(self.bytes.len()).map_err(|_| ZkX509DerAirErrorV1::Resource)?)
        {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        let mut coverage = Vec::new();
        for node in &self.nodes {
            coverage.extend(node.header_events()?);
        }
        coverage
            .try_reserve(self.primitive_rows.len())
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        let mut previous_primitive: Option<&ZkX509DerPrimitiveRowV1> = None;
        for row in &self.primitive_rows {
            if !all_zero_v1(&evaluate_der_primitive_constraints_v1(row)) {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
            let node_index =
                usize::try_from(row.node.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
            let node = self
                .nodes
                .get(node_index)
                .ok_or(ZkX509DerAirErrorV1::Topology)?;
            let content_offset = usize::try_from(row.content_offset.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
            let document_offset = usize::try_from(row.document_offset.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
            if node.constructed != F::ZERO
                || row.tag_class.value != node.tag_class.value
                || row.tag_number.value != node.tag_number.value
                || row.universal_selectors != node.universal_selectors
                || row.content_start.value != node.content_start.value
                || document_offset
                    != usize::try_from(node.content_start.value.0)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?
                        + content_offset
                || row.value.value
                    != self
                        .bytes
                        .get(document_offset)
                        .ok_or(ZkX509DerAirErrorV1::ByteBinding)?
                        .value
                        .value
            {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
            let content_len = usize::try_from(node.content_len.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
            if row.first != F(u64::from(content_offset == 0))
                || row.last != F(u64::from(content_offset + 1 == content_len))
            {
                return Err(ZkX509DerAirErrorV1::Primitive);
            }
            if let Some(previous) = previous_primitive {
                if previous.node.value == row.node.value {
                    if row.content_offset.value != previous.content_offset.value.add(F::ONE)
                        || row.oid_start_before != previous.oid_start_after
                    {
                        return Err(ZkX509DerAirErrorV1::Primitive);
                    }
                    let signed_integer = previous.tag_class.value == F::ZERO
                        && matches!(previous.tag_number.value.0, 2 | 10);
                    if signed_integer
                        && previous.first_is_zero != F::ZERO
                        && row.content_offset.value == F::ONE
                        && row.value.bits[7] == F::ZERO
                    {
                        return Err(ZkX509DerAirErrorV1::Primitive);
                    }
                    if signed_integer
                        && previous.first_is_ff != F::ZERO
                        && row.content_offset.value == F::ONE
                        && row.value.bits[7] == F::ONE
                    {
                        return Err(ZkX509DerAirErrorV1::Primitive);
                    }
                } else if row.first != F::ONE || previous.last != F::ONE {
                    return Err(ZkX509DerAirErrorV1::Topology);
                }
            } else if row.first != F::ONE {
                return Err(ZkX509DerAirErrorV1::Topology);
            }
            coverage.push(ZkX509DerByteEventV1 {
                offset: u16::try_from(document_offset)
                    .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                value: row.value.value,
            });
            previous_primitive = Some(row);
        }
        if previous_primitive.is_some_and(|row| row.last != F::ONE) {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        coverage.sort_unstable_by_key(|event| (event.offset, event.value.0));
        if coverage.len() != self.bytes.len() {
            return Err(ZkX509DerAirErrorV1::ByteBinding);
        }
        for (offset, (event, byte)) in coverage.iter().zip(&self.bytes).enumerate() {
            if usize::from(event.offset) != offset || event.value != byte.value.value {
                return Err(ZkX509DerAirErrorV1::ByteBinding);
            }
        }
        let expected_set_rows = self.expected_set_order_rows()?;
        if expected_set_rows.len() != self.set_order_rows.len() {
            return Err(ZkX509DerAirErrorV1::SetOrder);
        }
        let mut previous_set: Option<&ZkX509DerSetOrderRowV1> = None;
        for (row, expected) in self.set_order_rows.iter().zip(expected_set_rows) {
            if !all_zero_v1(&evaluate_der_set_order_constraints_v1(row)) {
                return Err(ZkX509DerAirErrorV1::SetOrder);
            }
            if (
                row.set_node.value.0,
                row.left_node.value.0,
                row.right_node.value.0,
                row.offset.value.0,
                row.left.value.0,
                row.right.value.0,
            ) != expected
            {
                return Err(ZkX509DerAirErrorV1::SetOrder);
            }
            let set = self
                .nodes
                .get(
                    usize::try_from(row.set_node.value.0)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                )
                .ok_or(ZkX509DerAirErrorV1::SetOrder)?;
            let left = self
                .nodes
                .get(
                    usize::try_from(row.left_node.value.0)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                )
                .ok_or(ZkX509DerAirErrorV1::SetOrder)?;
            let right = self
                .nodes
                .get(
                    usize::try_from(row.right_node.value.0)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                )
                .ok_or(ZkX509DerAirErrorV1::SetOrder)?;
            if set.tag_class.value != F::ZERO
                || set.tag_number.value != F(17)
                || left.depth.value != set.depth.value.add(F::ONE)
                || right.depth.value != left.depth.value
            {
                return Err(ZkX509DerAirErrorV1::SetOrder);
            }
            let offset =
                usize::try_from(row.offset.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
            let left_address = usize::try_from(left.start.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?
                + offset;
            let right_address = usize::try_from(right.start.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?
                + offset;
            if row.left.value
                != self
                    .bytes
                    .get(left_address)
                    .ok_or(ZkX509DerAirErrorV1::SetOrder)?
                    .value
                    .value
                || row.right.value
                    != self
                        .bytes
                        .get(right_address)
                        .ok_or(ZkX509DerAirErrorV1::SetOrder)?
                        .value
                        .value
            {
                return Err(ZkX509DerAirErrorV1::SetOrder);
            }
            if let Some(previous) = previous_set {
                let same_pair = previous.set_node.value == row.set_node.value
                    && previous.left_node.value == row.left_node.value
                    && previous.right_node.value == row.right_node.value;
                if same_pair {
                    if row.offset.value != previous.offset.value.add(F::ONE)
                        || row.equal_before != previous.equal_after
                        || row.less_before != previous.less_after
                    {
                        return Err(ZkX509DerAirErrorV1::SetOrder);
                    }
                } else if row.offset.value != F::ZERO
                    || row.equal_before != F::ONE
                    || row.less_before != F::ZERO
                {
                    return Err(ZkX509DerAirErrorV1::SetOrder);
                }
            } else if row.offset.value != F::ZERO
                || row.equal_before != F::ONE
                || row.less_before != F::ZERO
            {
                return Err(ZkX509DerAirErrorV1::SetOrder);
            }
            previous_set = Some(row);
        }
        self.validate_set_order_terminals()?;
        Ok(())
    }
    fn expected_set_order_rows(
        &self,
    ) -> Result<Vec<(u64, u64, u64, u64, u64, u64)>, ZkX509DerAirErrorV1> {
        let mut expected = Vec::new();
        for (set_index, set) in self.nodes.iter().enumerate() {
            if set.tag_class.value != F::ZERO || set.tag_number.value != F(17) {
                continue;
            }
            let set_depth = set.depth.value.0;
            let set_end = set.end.value.0;
            let set_start = set.content_start.value.0;
            let children: Vec<_> = self
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    node.depth.value.0 == set_depth + 1
                        && node.start.value.0 >= set_start
                        && node.end.value.0 <= set_end
                        && usize::try_from(set_depth)
                            .ok()
                            .and_then(|depth| node.ancestor_ends.get(depth))
                            .is_some_and(|end| end.value.0 == set_end)
                })
                .collect();
            for pair in children.windows(2) {
                let (left_index, left) = pair[0];
                let (right_index, right) = pair[1];
                let left_len = left
                    .end
                    .value
                    .0
                    .checked_sub(left.start.value.0)
                    .ok_or(ZkX509DerAirErrorV1::SetOrder)?;
                let right_len = right
                    .end
                    .value
                    .0
                    .checked_sub(right.start.value.0)
                    .ok_or(ZkX509DerAirErrorV1::SetOrder)?;
                let common = left_len.min(right_len);
                for offset in 0..common {
                    let left_address = usize::try_from(left.start.value.0 + offset)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
                    let right_address = usize::try_from(right.start.value.0 + offset)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
                    expected.push((
                        u64::try_from(set_index).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                        u64::try_from(left_index).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                        u64::try_from(right_index).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                        offset,
                        self.bytes
                            .get(left_address)
                            .ok_or(ZkX509DerAirErrorV1::SetOrder)?
                            .value
                            .value
                            .0,
                        self.bytes
                            .get(right_address)
                            .ok_or(ZkX509DerAirErrorV1::SetOrder)?
                            .value
                            .value
                            .0,
                    ));
                }
            }
        }
        Ok(expected)
    }
    fn validate_set_order_terminals(&self) -> Result<(), ZkX509DerAirErrorV1> {
        let mut index = 0_usize;
        while index < self.set_order_rows.len() {
            let first = &self.set_order_rows[index];
            let mut end = index + 1;
            while end < self.set_order_rows.len()
                && self.set_order_rows[end].set_node.value == first.set_node.value
                && self.set_order_rows[end].left_node.value == first.left_node.value
                && self.set_order_rows[end].right_node.value == first.right_node.value
            {
                end += 1;
            }
            let terminal = &self.set_order_rows[end - 1];
            let left = &self.nodes[usize::try_from(first.left_node.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?];
            let right = &self.nodes[usize::try_from(first.right_node.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?];
            let left_len = left.end.value.0 - left.start.value.0;
            let right_len = right.end.value.0 - right.start.value.0;
            if terminal.less_after != F::ONE
                && !(terminal.equal_after == F::ONE && left_len <= right_len)
            {
                return Err(ZkX509DerAirErrorV1::SetOrder);
            }
            index = end;
        }
        Ok(())
    }
}
/// Derive an exact multi-document resource plan without padding allocations.
#[cfg(test)]
pub fn plan_zk_x509_der_air_v1(
    traces: &[ZkX509DerDocumentTraceV1],
) -> Result<ZkX509DerAirResourcePlanV1, ZkX509DerAirErrorV1> {
    if traces.is_empty() || traces.len() > ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 {
        return Err(ZkX509DerAirErrorV1::Resource);
    }
    let bytes = traces.iter().try_fold(0_usize, |sum, trace| {
        sum.checked_add(trace.bytes.len())
            .ok_or(ZkX509DerAirErrorV1::Resource)
    })?;
    let nodes = traces.iter().try_fold(0_usize, |sum, trace| {
        sum.checked_add(trace.nodes.len())
            .ok_or(ZkX509DerAirErrorV1::Resource)
    })?;
    let primitive_rows = traces.iter().try_fold(0_usize, |sum, trace| {
        sum.checked_add(trace.primitive_rows.len())
            .ok_or(ZkX509DerAirErrorV1::Resource)
    })?;
    let set_order_rows = traces.iter().try_fold(0_usize, |sum, trace| {
        sum.checked_add(trace.set_order_rows.len())
            .ok_or(ZkX509DerAirErrorV1::Resource)
    })?;
    Ok(ZkX509DerAirResourcePlanV1 {
        documents: traces.len(),
        bytes,
        nodes,
        primitive_rows,
        set_order_rows,
        fixed_byte_capacity: traces
            .len()
            .checked_mul(ZK_X509_DER_MAX_DOCUMENT_BYTES_V1)
            .ok_or(ZkX509DerAirErrorV1::Resource)?,
        fixed_node_capacity: traces
            .len()
            .checked_mul(ZK_X509_DER_MAX_VALUES_V1)
            .ok_or(ZkX509DerAirErrorV1::Resource)?,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_AUTHORITY_KEY_IDENTIFIER_V1: &[u8] = &[0x55, 0x1d, 0x23];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_SUBJECT_KEY_IDENTIFIER_V1: &[u8] = &[0x55, 0x1d, 0x0e];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_KEY_USAGE_V1: &[u8] = &[0x55, 0x1d, 0x0f];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_BASIC_CONSTRAINTS_V1: &[u8] = &[0x55, 0x1d, 0x13];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_EXTENDED_KEY_USAGE_V1: &[u8] = &[0x55, 0x1d, 0x25];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_CRL_NUMBER_V1: &[u8] = &[0x55, 0x1d, 0x14];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_COUNTRY_NAME_V1: &[u8] = &[0x55, 0x04, 0x06];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_ORGANIZATION_NAME_V1: &[u8] = &[0x55, 0x04, 0x0a];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_ORGANIZATIONAL_UNIT_NAME_V1: &[u8] = &[0x55, 0x04, 0x0b];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_COMMON_NAME_V1: &[u8] = &[0x55, 0x04, 0x03];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_CLIENT_AUTHENTICATION_V1: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_DOCUMENT_SIGNING_V1: &[u8] = super::profile::ZK_X509_DOCUMENT_SIGNING_EKU_DER_VALUE_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const OID_WALLET_IDENTITY_V1: &[u8] = super::profile::ZK_X509_WALLET_IDENTITY_EKU_DER_VALUE_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const ECDSA_SHA256_ALGORITHM_V1: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const P256_ALGORITHM_V1: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];
#[cfg(any(test, feature = "privacy-release-evidence"))]
const KEY_USAGE_KEY_CERT_SIGN_V1: u16 = 1 << 5;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const KEY_USAGE_CRL_SIGN_V1: u16 = 1 << 6;
/// Closed extended-key-usage code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZkX509DerEkuV1 {
    /// id-kp-clientAuth.
    ClientAuthentication,
    /// Iroha document-signing EKU.
    DocumentSigning,
    /// Iroha wallet-identity EKU.
    WalletIdentity,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Default for ZkX509DerEkuV1 {
    fn default() -> Self {
        Self::ClientAuthentication
    }
}
// The valid default variant is the desired erased value; Zeroize writes it
// through its volatile default-value implementation without invalid enum bytes.
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::DefaultIsZeroes for ZkX509DerEkuV1 {}

/// Verifier-fixed RFC 5280 predicates consumed by the DER/path segment.
///
/// Certificate depth, encoded lengths, exact certificate validity intervals, and exact CRL update
/// times are deliberately absent. They are private witness data. The public presentation interval
/// is a short, non-empty interval inside which the credential may be presented; every private
/// certificate/CRL interval must cover it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509Rfc5280StatementV1 {
    /// Inclusive lower and upper presentation-time bounds.
    pub(crate) presentation_not_before_unix_seconds: u64,
    pub(crate) presentation_not_after_unix_seconds: u64,
    /// Exact leaf key-usage flags in RFC named-bit order.
    pub(crate) leaf_key_usage: u16,
    /// Exact ordered leaf EKUs.
    pub(crate) leaf_extended_key_usages: Vec<ZkX509DerEkuV1>,
    /// Governed complete-CRL revision.
    pub(crate) crl_number: u64,
    /// Subject-name fields disclosed through the projection segment.
    pub(crate) disclosed_attribute_indices: Vec<u8>,
}
/// Verifier-recognized grammar state for one semantic DER node.
///
/// These states are not parser annotations trusted by the proof. The RFC adapter derives each state
/// from the verifier-fixed document kind, the parent's state, the child ordinal, and the strict-DER
/// node tuple. The owner trace retains the resulting provenance so that no semantic output is
/// detached from its unique source node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
#[cfg_attr(
    not(any(test, feature = "privacy-release-evidence")),
    expect(
        dead_code,
        reason = "only the test and release-evidence RFC adapters construct every grammar role"
    )
)]
pub enum ZkX509Rfc5280GrammarRoleV1 {
    Certificate = 1,
    CertificateTbs = 2,
    CertificateOuterAlgorithm = 3,
    CertificateSignatureValue = 4,
    CertificateVersion = 5,
    CertificateVersionInteger = 6,
    CertificateSerial = 7,
    CertificateTbsAlgorithm = 8,
    CertificateIssuer = 9,
    CertificateValidity = 10,
    CertificateNotBefore = 11,
    CertificateNotAfter = 12,
    CertificateSubject = 13,
    CertificateSpki = 14,
    CertificateSpkiAlgorithm = 15,
    CertificatePublicKey = 16,
    CertificateExtensionsWrapper = 17,
    CertificateExtensions = 18,
    CertificateExtension = 19,
    CertificateExtensionOid = 20,
    CertificateExtensionCritical = 21,
    CertificateExtensionValue = 22,
    Crl = 23,
    CrlTbs = 24,
    CrlOuterAlgorithm = 25,
    CrlSignatureValue = 26,
    CrlVersion = 27,
    CrlTbsAlgorithm = 28,
    CrlIssuer = 29,
    CrlThisUpdate = 30,
    CrlNextUpdate = 31,
    CrlEntries = 32,
    CrlEntry = 33,
    CrlEntrySerial = 34,
    CrlEntryTime = 35,
    CrlExtensionsWrapper = 36,
    CrlExtensions = 37,
    CrlExtension = 38,
    CrlExtensionOid = 39,
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    CrlExtensionCritical = 40,
    CrlExtensionValue = 41,
    NameRdn = 42,
    NameAttribute = 43,
    NameAttributeOid = 44,
    NameAttributeValue = 45,
    AlgorithmOid = 46,
    EmbeddedAki = 47,
    EmbeddedAkiIdentifier = 48,
    EmbeddedSki = 49,
    EmbeddedKeyUsage = 50,
    EmbeddedBasicConstraints = 51,
    EmbeddedBasicConstraintsCa = 52,
    EmbeddedBasicConstraintsPathLen = 53,
    EmbeddedEku = 54,
    EmbeddedEkuOid = 55,
    EmbeddedCrlNumber = 56,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Default for ZkX509Rfc5280GrammarRoleV1 {
    fn default() -> Self {
        Self::Certificate
    }
}
// The valid default variant is the desired erased value; Zeroize writes it
// through its volatile default-value implementation without invalid enum bytes.
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::DefaultIsZeroes for ZkX509Rfc5280GrammarRoleV1 {}

/// Verifier-fixed kind of a top-level or extension-embedded DER document.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ZkX509Rfc5280DocumentKindV1 {
    Certificate = 1,
    Crl = 2,
    AuthorityKeyIdentifier = 3,
    SubjectKeyIdentifier = 4,
    KeyUsage = 5,
    BasicConstraints = 6,
    ExtendedKeyUsage = 7,
    CrlNumber = 8,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Default for ZkX509Rfc5280DocumentKindV1 {
    fn default() -> Self {
        Self::Certificate
    }
}
// The valid default variant is the desired erased value; Zeroize writes it
// through its volatile default-value implementation without invalid enum bytes.
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::DefaultIsZeroes for ZkX509Rfc5280DocumentKindV1 {}

/// Exact strict-DER provenance of one semantic grammar node.
///
/// `document` uses the DER aggregate's unified numbering: all top-level
/// documents first, followed by embedded extension documents.  The root uses
/// `parent_node = u16::MAX`; every other row names its unique direct parent.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509Rfc5280NodeProvenanceV1 {
    pub(crate) document: u8,
    pub(crate) node: u16,
    pub(crate) parent_node: u16,
    pub(crate) child_ordinal: u16,
    pub(crate) start: u16,
    pub(crate) content_start: u16,
    pub(crate) content_end: u16,
    pub(crate) depth: u8,
    pub(crate) tag_class: u8,
    pub(crate) constructed: bool,
    pub(crate) tag_number: u32,
    pub(crate) role: ZkX509Rfc5280GrammarRoleV1,
    /// Verifier-derived occurrence within a repeated grammar production.
    pub(crate) role_instance: u16,
}
/// Exact origin and grammar rows for one document.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509Rfc5280DocumentProvenanceV1 {
    pub(crate) document: u8,
    pub(crate) kind: ZkX509Rfc5280DocumentKindV1,
    /// Unified parent document/node for an embedded document; `u8::MAX` and
    /// `u16::MAX` for a top-level document.
    pub(crate) parent_document: u8,
    pub(crate) parent_node: u16,
    /// Exactly one row per strict-DER node, in node-ordinal order.
    pub(crate) nodes: Vec<ZkX509Rfc5280NodeProvenanceV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280NodeProvenanceV1 {
    /// Clear a copied grammar row before its scratch allocation is released.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_node_provenance_v1(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280DocumentProvenanceV1 {
    /// Clear all copied grammar rows and the document's private metadata.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_provenance_v1(self);
    }
}
/// One parsed closed-profile distinguished name.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ZkX509DerNameV1 {
    /// Exact encoded Name.
    pub(crate) encoded: Vec<u8>,
    /// Exact `DirectoryString` content octets at `C,O,OU,CN`.
    pub(crate) attributes: [Option<Vec<u8>>; 4],
}
/// One strict DER P-256 signature projection.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ZkX509DerSignatureV1 {
    /// Exact DER sequence.
    pub(crate) encoded: Vec<u8>,
    /// Unsigned canonical magnitudes.
    pub(crate) r: Vec<u8>,
    pub(crate) s: Vec<u8>,
}
/// Closed certificate extension projection.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ZkX509DerCertificateExtensionsV1 {
    pub(crate) authority_key_identifier: Vec<u8>,
    pub(crate) subject_key_identifier: Vec<u8>,
    pub(crate) basic_constraints_ca: bool,
    pub(crate) basic_constraints_path_len: Option<u32>,
    pub(crate) key_usage: u16,
    pub(crate) extended_key_usages: Option<Vec<ZkX509DerEkuV1>>,
}
/// One constrained certificate output.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ZkX509DerCertificateV1 {
    pub(crate) tbs_der: Vec<u8>,
    pub(crate) serial: Vec<u8>,
    pub(crate) issuer: ZkX509DerNameV1,
    pub(crate) subject: ZkX509DerNameV1,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    pub(crate) spki_der: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: ZkX509DerSignatureV1,
    pub(crate) extensions: ZkX509DerCertificateExtensionsV1,
}
/// One constrained complete-CRL output.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ZkX509DerCrlV1 {
    pub(crate) tbs_der: Vec<u8>,
    pub(crate) issuer: ZkX509DerNameV1,
    pub(crate) this_update: u64,
    pub(crate) next_update: u64,
    pub(crate) revoked_serials: Vec<Vec<u8>>,
    pub(crate) authority_key_identifier: Vec<u8>,
    pub(crate) crl_number: u64,
    pub(crate) signature: ZkX509DerSignatureV1,
}
/// One algebraic path-state row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509Rfc5280PathRowV1 {
    /// Certificate index, leaf first.
    pub(crate) certificate: ZkX509DerRangeWitnessV1<2>,
    /// Leaf/CA/root selectors.
    pub(crate) is_leaf: F,
    pub(crate) is_ca: F,
    pub(crate) is_root: F,
    /// Validation time minus lower bound and upper bound minus validation time.
    pub(crate) after_not_before: ZkX509DerRangeWitnessV1<64>,
    pub(crate) before_not_after: ZkX509DerRangeWitnessV1<64>,
    /// Subordinate CA count and path-length slack.
    pub(crate) subordinate_ca_count: ZkX509DerRangeWitnessV1<2>,
    pub(crate) path_len_slack: ZkX509DerRangeWitnessV1<32>,
    /// Exact name and key-identifier equality selectors.
    pub(crate) issuer_name_matches_parent: F,
    pub(crate) authority_key_matches_parent: F,
}
/// One exact copy from an extension OCTET STRING into its independently
/// parsed embedded-DER document.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509DerEmbeddedByteRowV1 {
    pub(crate) parent_document: ZkX509DerRangeWitnessV1<2>,
    pub(crate) parent_content_start: AddressWitnessV1,
    pub(crate) parent_offset: AddressWitnessV1,
    pub(crate) embedded_document: ZkX509DerRangeWitnessV1<4>,
    pub(crate) embedded_offset: AddressWitnessV1,
    pub(crate) value: ByteWitnessV1,
}
/// Strict DER documents plus closed RFC 5280 semantic/path outputs.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509Rfc5280TraceV1 {
    /// Certificate documents followed by the complete CRL.
    pub(crate) documents: Vec<ZkX509DerDocumentTraceV1>,
    /// Independently constrained DER documents carried by extension
    /// `extnValue` OCTET STRING contents.
    pub(crate) embedded_documents: Vec<ZkX509DerDocumentTraceV1>,
    /// Exact outer-to-embedded byte-copy rows.
    pub(crate) embedded_byte_rows: Vec<ZkX509DerEmbeddedByteRowV1>,
    /// Parsed certificate chain, leaf first.
    pub(crate) certificates: Vec<ZkX509DerCertificateV1>,
    /// Parsed complete CRL.
    pub(crate) crl: ZkX509DerCrlV1,
    /// Fixed public predicates.
    pub(crate) statement: ZkX509Rfc5280StatementV1,
    /// One row per certificate.
    pub(crate) path_rows: Vec<ZkX509Rfc5280PathRowV1>,
    /// Canonical grammar provenance for every top-level and embedded node.
    pub(crate) semantic_provenance: Vec<ZkX509Rfc5280DocumentProvenanceV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509Rfc5280TraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkX509Rfc5280TraceV1")
            .field("statement", &self.statement)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_embedded_rows_v1(rows: &mut [ZkX509DerEmbeddedByteRowV1]) {
    for row in rows {
        row.parent_document.zeroize_private_v1();
        row.parent_content_start.zeroize_private_v1();
        row.parent_offset.zeroize_private_v1();
        row.embedded_document.zeroize_private_v1();
        row.embedded_offset.zeroize_private_v1();
        row.value.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_path_rows_v1(rows: &mut [ZkX509Rfc5280PathRowV1]) {
    for row in rows {
        row.certificate.zeroize_private_v1();
        zeroize_fields_v1(core::slice::from_mut(&mut row.is_leaf));
        zeroize_fields_v1(core::slice::from_mut(&mut row.is_ca));
        zeroize_fields_v1(core::slice::from_mut(&mut row.is_root));
        row.after_not_before.zeroize_private_v1();
        row.before_not_after.zeroize_private_v1();
        row.subordinate_ca_count.zeroize_private_v1();
        row.path_len_slack.zeroize_private_v1();
        zeroize_fields_v1(core::slice::from_mut(&mut row.issuer_name_matches_parent));
        zeroize_fields_v1(core::slice::from_mut(&mut row.authority_key_matches_parent));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_bytes_v1(bytes: &mut Vec<u8>) {
    zeroize_words_v1(bytes);
    bytes.clear();
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_name_v1(name: &mut ZkX509DerNameV1) {
    zeroize_bytes_v1(&mut name.encoded);
    for attribute in &mut name.attributes {
        if let Some(value) = attribute {
            zeroize_bytes_v1(value);
        }
        *attribute = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_signature_v1(signature: &mut ZkX509DerSignatureV1) {
    zeroize_bytes_v1(&mut signature.encoded);
    zeroize_bytes_v1(&mut signature.r);
    zeroize_bytes_v1(&mut signature.s);
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_certificate_v1(certificate: &mut ZkX509DerCertificateV1) {
    zeroize_bytes_v1(&mut certificate.tbs_der);
    zeroize_bytes_v1(&mut certificate.serial);
    zeroize_name_v1(&mut certificate.issuer);
    zeroize_name_v1(&mut certificate.subject);
    zeroize_words_v1(core::slice::from_mut(&mut certificate.not_before));
    zeroize_words_v1(core::slice::from_mut(&mut certificate.not_after));
    zeroize_bytes_v1(&mut certificate.spki_der);
    zeroize_bytes_v1(&mut certificate.public_key);
    zeroize_signature_v1(&mut certificate.signature);
    zeroize_extensions_v1(&mut certificate.extensions);
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_crl_v1(crl: &mut ZkX509DerCrlV1) {
    zeroize_bytes_v1(&mut crl.tbs_der);
    zeroize_name_v1(&mut crl.issuer);
    zeroize_words_v1(core::slice::from_mut(&mut crl.this_update));
    zeroize_words_v1(core::slice::from_mut(&mut crl.next_update));
    for serial in &mut crl.revoked_serials {
        zeroize_bytes_v1(serial);
    }
    crl.revoked_serials.clear();
    zeroize_bytes_v1(&mut crl.authority_key_identifier);
    zeroize_words_v1(core::slice::from_mut(&mut crl.crl_number));
    zeroize_signature_v1(&mut crl.signature);
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_node_provenance_v1(node: &mut ZkX509Rfc5280NodeProvenanceV1) {
    zeroize_words_v1(core::slice::from_mut(&mut node.document));
    zeroize_words_v1(core::slice::from_mut(&mut node.node));
    zeroize_words_v1(core::slice::from_mut(&mut node.parent_node));
    zeroize_words_v1(core::slice::from_mut(&mut node.child_ordinal));
    zeroize_words_v1(core::slice::from_mut(&mut node.start));
    zeroize_words_v1(core::slice::from_mut(&mut node.content_start));
    zeroize_words_v1(core::slice::from_mut(&mut node.content_end));
    zeroize_words_v1(core::slice::from_mut(&mut node.depth));
    zeroize_words_v1(core::slice::from_mut(&mut node.tag_class));
    zeroize_words_v1(core::slice::from_mut(&mut node.constructed));
    zeroize_words_v1(core::slice::from_mut(&mut node.tag_number));
    zeroize_words_v1(core::slice::from_mut(&mut node.role));
    zeroize_words_v1(core::slice::from_mut(&mut node.role_instance));
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_optional_provenance_v1(rows: &mut [Option<ZkX509Rfc5280NodeProvenanceV1>]) {
    for row in rows {
        if let Some(node) = row {
            zeroize_node_provenance_v1(node);
        }
        *row = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_provenance_v1(document: &mut ZkX509Rfc5280DocumentProvenanceV1) {
    zeroize_words_v1(core::slice::from_mut(&mut document.document));
    zeroize_words_v1(core::slice::from_mut(&mut document.kind));
    zeroize_words_v1(core::slice::from_mut(&mut document.parent_document));
    zeroize_words_v1(core::slice::from_mut(&mut document.parent_node));
    for node in &mut document.nodes {
        zeroize_node_provenance_v1(node);
    }
    document.nodes.clear();
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_extensions_v1(extensions: &mut ZkX509DerCertificateExtensionsV1) {
    zeroize_bytes_v1(&mut extensions.authority_key_identifier);
    zeroize_bytes_v1(&mut extensions.subject_key_identifier);
    zeroize_words_v1(core::slice::from_mut(&mut extensions.basic_constraints_ca));
    zeroize_words_v1(core::slice::from_mut(
        &mut extensions.basic_constraints_path_len,
    ));
    zeroize_words_v1(core::slice::from_mut(&mut extensions.key_usage));
    if let Some(extended_key_usages) = &mut extensions.extended_key_usages {
        zeroize_words_v1(extended_key_usages);
        extended_key_usages.clear();
    }
    extensions.extended_key_usages = None;
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509DerNameV1 {
    fn drop(&mut self) {
        zeroize_name_v1(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509DerSignatureV1 {
    fn drop(&mut self) {
        zeroize_signature_v1(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509DerCertificateExtensionsV1 {
    fn drop(&mut self) {
        zeroize_extensions_v1(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509DerCertificateV1 {
    fn drop(&mut self) {
        zeroize_certificate_v1(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509DerCrlV1 {
    fn drop(&mut self) {
        zeroize_crl_v1(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509Rfc5280DocumentProvenanceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509Rfc5280TraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280TraceV1 {
    /// Recursively overwrite exact DER bytes, parsed semantic projections,
    /// path rows, and all witness-bearing field traces.
    pub(crate) fn zeroize_private_v1(&mut self) {
        for document in &mut self.documents {
            document.zeroize_private_v1();
        }
        self.documents.clear();
        for document in &mut self.embedded_documents {
            document.zeroize_private_v1();
        }
        self.embedded_documents.clear();
        zeroize_embedded_rows_v1(&mut self.embedded_byte_rows);
        self.embedded_byte_rows.clear();
        self.certificates.clear();
        zeroize_crl_v1(&mut self.crl);
        zeroize_path_rows_v1(&mut self.path_rows);
        self.path_rows.clear();
        self.semantic_provenance.clear();
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.documents.is_empty()
            && self.embedded_documents.is_empty()
            && self.embedded_byte_rows.is_empty()
            && self.certificates.is_empty()
            && self.path_rows.is_empty()
            && self.semantic_provenance.is_empty()
            && self.crl.tbs_der.is_empty()
            && self.crl.issuer.encoded.is_empty()
            && self.crl.issuer.attributes.iter().all(Option::is_none)
            && self.crl.this_update == 0
            && self.crl.next_update == 0
            && self.crl.revoked_serials.is_empty()
            && self.crl.authority_key_identifier.is_empty()
            && self.crl.crl_number == 0
            && self.crl.signature.encoded.is_empty()
            && self.crl.signature.r.is_empty()
            && self.crl.signature.s.is_empty()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn trace_bytes_v1(
    trace: &ZkX509DerDocumentTraceV1,
) -> Result<PrivateTableV1<u8>, ZkX509DerAirErrorV1> {
    let mut bytes = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
    bytes
        .try_reserve_exact(trace.bytes.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for row in &trace.bytes {
        bytes.push(u8::try_from(row.value.value.0).map_err(|_| ZkX509DerAirErrorV1::Range)?);
    }
    Ok(bytes)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn node_bounds_v1(
    trace: &ZkX509DerDocumentTraceV1,
    node: usize,
) -> Result<(usize, usize, usize), ZkX509DerAirErrorV1> {
    let row = trace.nodes.get(node).ok_or(ZkX509DerAirErrorV1::Topology)?;
    Ok((
        usize::try_from(row.start.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        usize::try_from(row.content_start.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        usize::try_from(row.end.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
    ))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn node_encoded_v1<'a>(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &'a [u8],
    node: usize,
) -> Result<&'a [u8], ZkX509DerAirErrorV1> {
    let (start, _, end) = node_bounds_v1(trace, node)?;
    bytes.get(start..end).ok_or(ZkX509DerAirErrorV1::Topology)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn node_contents_v1<'a>(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &'a [u8],
    node: usize,
) -> Result<&'a [u8], ZkX509DerAirErrorV1> {
    let (_, content_start, end) = node_bounds_v1(trace, node)?;
    bytes
        .get(content_start..end)
        .ok_or(ZkX509DerAirErrorV1::Topology)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn require_tag_v1(
    trace: &ZkX509DerDocumentTraceV1,
    node: usize,
    class: u64,
    constructed: bool,
    number: u32,
) -> Result<(), ZkX509DerAirErrorV1> {
    let row = trace.nodes.get(node).ok_or(ZkX509DerAirErrorV1::Topology)?;
    if row.tag_class.value != F(class)
        || row.constructed != F(u64::from(constructed))
        || row.tag_number.value != F(u64::from(number))
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn child_nodes_v1(
    trace: &ZkX509DerDocumentTraceV1,
    parent: usize,
) -> Result<Vec<usize>, ZkX509DerAirErrorV1> {
    let parent_row = trace
        .nodes
        .get(parent)
        .ok_or(ZkX509DerAirErrorV1::Topology)?;
    if parent_row.constructed != F::ONE {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    let child_depth = parent_row.depth.value.0 + 1;
    let start = parent_row.content_start.value.0;
    let end = parent_row.end.value.0;
    Ok(trace
        .nodes
        .iter()
        .enumerate()
        .skip(parent + 1)
        .take_while(|(_, node)| node.start.value.0 < end)
        .filter_map(|(index, node)| {
            (node.depth.value.0 == child_depth
                && node.start.value.0 >= start
                && node.end.value.0 <= end)
                .then_some(index)
        })
        .collect())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn require_children_v1<const N: usize>(
    trace: &ZkX509DerDocumentTraceV1,
    parent: usize,
) -> Result<[usize; N], ZkX509DerAirErrorV1> {
    child_nodes_v1(trace, parent)?
        .try_into()
        .map_err(|_| ZkX509DerAirErrorV1::Input)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn positive_integer_v1(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &[u8],
    node: usize,
    max_bytes: usize,
    allow_zero: bool,
) -> Result<Vec<u8>, ZkX509DerAirErrorV1> {
    require_tag_v1(trace, node, 0, false, 2)?;
    let encoded = node_contents_v1(trace, bytes, node)?;
    if encoded.is_empty() || encoded[0] & 0x80 != 0 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let magnitude = if encoded.len() > 1 && encoded[0] == 0 {
        &encoded[1..]
    } else {
        encoded
    };
    if magnitude.len() > max_bytes || (!allow_zero && magnitude.iter().all(|byte| *byte == 0)) {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    Ok(magnitude.to_vec())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn unsigned_integer_u64_v1(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &[u8],
    node: usize,
    max_bytes: usize,
) -> Result<u64, ZkX509DerAirErrorV1> {
    let magnitude = PrivateTableV1::new(
        positive_integer_v1(trace, bytes, node, max_bytes, true)?,
        zeroize_words_v1,
    );
    magnitude.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(256)
            .and_then(|value| value.checked_add(u64::from(*byte)))
            .ok_or(ZkX509DerAirErrorV1::Resource)
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_signature_v1(encoded: &[u8]) -> Result<ZkX509DerSignatureV1, ZkX509DerAirErrorV1> {
    let trace = build_strict_der_document_trace_v1(encoded)?;
    require_tag_v1(&trace, 0, 0, true, 16)?;
    let bytes = trace_bytes_v1(&trace)?;
    let [r, s] = require_children_v1::<2>(&trace, 0)?;
    let mut output = ZkX509DerSignatureV1::default();
    output.encoded = encoded.to_vec();
    output.r = positive_integer_v1(&trace, &bytes, r, 32, false)?;
    output.s = positive_integer_v1(&trace, &bytes, s, 32, false)?;
    Ok(output)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_decimal_v1(bytes: &[u8]) -> Result<u16, ZkX509DerAirErrorV1> {
    bytes.iter().try_fold(0_u16, |value, byte| {
        if !byte.is_ascii_digit() {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(*byte - b'0')))
            .ok_or(ZkX509DerAirErrorV1::Resource)
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_time_contents_v1(tag: u64, bytes: &[u8]) -> Result<u64, ZkX509DerAirErrorV1> {
    use time::{Date, Month, PrimitiveDateTime, Time};
    let (year, offset) = if tag == 23 {
        if bytes.len() != 13 || bytes[12] != b'Z' {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        let short = parse_decimal_v1(&bytes[..2])?;
        let year = if short >= 50 {
            1900 + i32::from(short)
        } else {
            2000 + i32::from(short)
        };
        if !(1970..=2049).contains(&year) {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        (year, 2)
    } else if tag == 24 {
        if bytes.len() != 15 || bytes[14] != b'Z' {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        let year = i32::from(parse_decimal_v1(&bytes[..4])?);
        if !(2050..=9999).contains(&year) {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        (year, 4)
    } else {
        return Err(ZkX509DerAirErrorV1::Input);
    };
    let month = Month::try_from(
        u8::try_from(parse_decimal_v1(&bytes[offset..offset + 2])?)
            .map_err(|_| ZkX509DerAirErrorV1::Input)?,
    )
    .map_err(|_| ZkX509DerAirErrorV1::Input)?;
    let day = u8::try_from(parse_decimal_v1(&bytes[offset + 2..offset + 4])?)
        .map_err(|_| ZkX509DerAirErrorV1::Input)?;
    let hour = u8::try_from(parse_decimal_v1(&bytes[offset + 4..offset + 6])?)
        .map_err(|_| ZkX509DerAirErrorV1::Input)?;
    let minute = u8::try_from(parse_decimal_v1(&bytes[offset + 6..offset + 8])?)
        .map_err(|_| ZkX509DerAirErrorV1::Input)?;
    let second = u8::try_from(parse_decimal_v1(&bytes[offset + 8..offset + 10])?)
        .map_err(|_| ZkX509DerAirErrorV1::Input)?;
    let date =
        Date::from_calendar_date(year, month, day).map_err(|_| ZkX509DerAirErrorV1::Input)?;
    let time = Time::from_hms(hour, minute, second).map_err(|_| ZkX509DerAirErrorV1::Input)?;
    u64::try_from(
        PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp(),
    )
    .map_err(|_| ZkX509DerAirErrorV1::Input)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_time_node_v1(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &[u8],
    node: usize,
) -> Result<u64, ZkX509DerAirErrorV1> {
    let row = trace.nodes.get(node).ok_or(ZkX509DerAirErrorV1::Topology)?;
    if row.tag_class.value != F::ZERO || row.constructed != F::ZERO {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    parse_time_contents_v1(
        row.tag_number.value.0,
        node_contents_v1(trace, bytes, node)?,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_name_v1(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &[u8],
    node: usize,
) -> Result<ZkX509DerNameV1, ZkX509DerAirErrorV1> {
    require_tag_v1(trace, node, 0, true, 16)?;
    let rdns = child_nodes_v1(trace, node)?;
    if rdns.is_empty() {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let mut output = ZkX509DerNameV1::default();
    for rdn in rdns {
        require_tag_v1(trace, rdn, 0, true, 17)?;
        let values = child_nodes_v1(trace, rdn)?;
        if values.is_empty() {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        for attribute in values {
            require_tag_v1(trace, attribute, 0, true, 16)?;
            let [oid, value] = require_children_v1::<2>(trace, attribute)?;
            require_tag_v1(trace, oid, 0, false, 6)?;
            let oid = node_contents_v1(trace, bytes, oid)?;
            let index = if oid == OID_COUNTRY_NAME_V1 {
                0
            } else if oid == OID_ORGANIZATION_NAME_V1 {
                1
            } else if oid == OID_ORGANIZATIONAL_UNIT_NAME_V1 {
                2
            } else if oid == OID_COMMON_NAME_V1 {
                3
            } else {
                return Err(ZkX509DerAirErrorV1::Input);
            };
            let value_row = &trace.nodes[value];
            let contents = node_contents_v1(trace, bytes, value)?;
            if contents.is_empty() || contents.len() > 256 {
                return Err(ZkX509DerAirErrorV1::Input);
            }
            if index == 0 {
                if value_row.tag_class.value != F::ZERO
                    || value_row.tag_number.value != F(19)
                    || contents.len() != 2
                    || !contents.iter().all(|byte| byte.is_ascii_uppercase())
                {
                    return Err(ZkX509DerAirErrorV1::Input);
                }
            } else if value_row.tag_class.value != F::ZERO {
                return Err(ZkX509DerAirErrorV1::Input);
            } else if value_row.tag_number.value == F(12) {
                let string =
                    core::str::from_utf8(contents).map_err(|_| ZkX509DerAirErrorV1::Input)?;
                if string.chars().any(
                    |character| matches!(u32::from(character), 0x0000..=0x001f | 0x007f..=0x009f),
                ) {
                    return Err(ZkX509DerAirErrorV1::Input);
                }
            } else if value_row.tag_number.value == F(19) {
                if !contents.iter().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            *byte,
                            b' ' | b'\''
                                | b'('
                                | b')'
                                | b'+'
                                | b','
                                | b'-'
                                | b'.'
                                | b'/'
                                | b':'
                                | b'='
                                | b'?'
                        )
                }) {
                    return Err(ZkX509DerAirErrorV1::Input);
                }
            } else {
                return Err(ZkX509DerAirErrorV1::Input);
            }
            if output.attributes[index].is_some() {
                return Err(ZkX509DerAirErrorV1::Input);
            }
            output.attributes[index] = Some(contents.to_vec());
        }
    }
    output.encoded = node_encoded_v1(trace, bytes, node)?.to_vec();
    Ok(output)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_extension_v1<'a>(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &'a [u8],
    node: usize,
) -> Result<(&'a [u8], bool, &'a [u8]), ZkX509DerAirErrorV1> {
    require_tag_v1(trace, node, 0, true, 16)?;
    let children = child_nodes_v1(trace, node)?;
    if !(2..=3).contains(&children.len()) {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    require_tag_v1(trace, children[0], 0, false, 6)?;
    let oid = node_contents_v1(trace, bytes, children[0])?;
    let (critical, value) = if children.len() == 3 {
        require_tag_v1(trace, children[1], 0, false, 1)?;
        if node_contents_v1(trace, bytes, children[1])? != [0xff] {
            // DEFAULT FALSE has exactly one representation: omission.
            return Err(ZkX509DerAirErrorV1::Input);
        }
        (true, children[2])
    } else {
        (false, children[1])
    };
    require_tag_v1(trace, value, 0, false, 4)?;
    Ok((oid, critical, node_contents_v1(trace, bytes, value)?))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn embedded_trace_v1(
    encoded: &[u8],
) -> Result<(ZkX509DerDocumentTraceV1, PrivateTableV1<u8>), ZkX509DerAirErrorV1> {
    let trace = build_strict_der_document_trace_v1(encoded)?;
    let bytes = trace_bytes_v1(&trace)?;
    Ok((trace, bytes))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_aki_inner_v1(encoded: &[u8]) -> Result<Vec<u8>, ZkX509DerAirErrorV1> {
    let (trace, bytes) = embedded_trace_v1(encoded)?;
    require_tag_v1(&trace, 0, 0, true, 16)?;
    let [identifier] = require_children_v1::<1>(&trace, 0)?;
    require_tag_v1(&trace, identifier, 2, false, 0)?;
    let identifier = node_contents_v1(&trace, &bytes, identifier)?;
    if identifier.is_empty() || identifier.len() > 64 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    Ok(identifier.to_vec())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_ski_inner_v1(encoded: &[u8]) -> Result<Vec<u8>, ZkX509DerAirErrorV1> {
    let (trace, bytes) = embedded_trace_v1(encoded)?;
    require_tag_v1(&trace, 0, 0, false, 4)?;
    let identifier = node_contents_v1(&trace, &bytes, 0)?;
    if identifier.is_empty() || identifier.len() > 64 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    Ok(identifier.to_vec())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_basic_constraints_inner_v1(
    encoded: &[u8],
) -> Result<(bool, Option<u32>), ZkX509DerAirErrorV1> {
    let (trace, bytes) = embedded_trace_v1(encoded)?;
    require_tag_v1(&trace, 0, 0, true, 16)?;
    let children = child_nodes_v1(&trace, 0)?;
    if children.is_empty() {
        return Ok((false, None));
    }
    if children.len() > 2 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    require_tag_v1(&trace, children[0], 0, false, 1)?;
    if node_contents_v1(&trace, &bytes, children[0])? != [0xff] {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let path_len = children
        .get(1)
        .map(|node| unsigned_integer_u64_v1(&trace, &bytes, *node, 4))
        .transpose()?
        .map(|value| u32::try_from(value).map_err(|_| ZkX509DerAirErrorV1::Input))
        .transpose()?;
    Ok((true, path_len))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_key_usage_inner_v1(encoded: &[u8]) -> Result<u16, ZkX509DerAirErrorV1> {
    let (trace, bytes) = embedded_trace_v1(encoded)?;
    require_tag_v1(&trace, 0, 0, false, 3)?;
    let content = node_contents_v1(&trace, &bytes, 0)?;
    let (&unused, value) = content.split_first().ok_or(ZkX509DerAirErrorV1::Input)?;
    if value.is_empty()
        || value.len() > 2
        || (value.last().copied().unwrap_or_default() & (1 << unused)) == 0
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let mut flags = 0_u16;
    for (byte_index, byte) in value.iter().copied().enumerate() {
        for bit in 0..8 {
            if byte & (0x80 >> bit) != 0 {
                flags |= 1_u16 << (byte_index * 8 + bit);
            }
        }
    }
    Ok(flags)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_eku_inner_v1(encoded: &[u8]) -> Result<Vec<ZkX509DerEkuV1>, ZkX509DerAirErrorV1> {
    let (trace, bytes) = embedded_trace_v1(encoded)?;
    require_tag_v1(&trace, 0, 0, true, 16)?;
    let children = child_nodes_v1(&trace, 0)?;
    if children.is_empty() {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let mut usages = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
    for node in children {
        require_tag_v1(&trace, node, 0, false, 6)?;
        let oid = node_contents_v1(&trace, &bytes, node)?;
        let usage = if oid == OID_CLIENT_AUTHENTICATION_V1 {
            ZkX509DerEkuV1::ClientAuthentication
        } else if oid == OID_DOCUMENT_SIGNING_V1 {
            ZkX509DerEkuV1::DocumentSigning
        } else if oid == OID_WALLET_IDENTITY_V1 {
            ZkX509DerEkuV1::WalletIdentity
        } else {
            return Err(ZkX509DerAirErrorV1::Input);
        };
        if usages.last().is_some_and(|previous| *previous >= usage) {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        usages.push(usage);
    }
    Ok(usages.into_vec())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_certificate_extensions_v1(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &[u8],
    wrapper: usize,
) -> Result<ZkX509DerCertificateExtensionsV1, ZkX509DerAirErrorV1> {
    require_tag_v1(trace, wrapper, 2, true, 3)?;
    let [sequence] = require_children_v1::<1>(trace, wrapper)?;
    require_tag_v1(trace, sequence, 0, true, 16)?;
    let extensions = child_nodes_v1(trace, sequence)?;
    if extensions.is_empty() {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let mut aki = None;
    let mut ski = None;
    let mut key_usage = None;
    let mut basic = None;
    let mut eku = None;
    let mut previous_rank = None;
    for extension in extensions {
        let (oid, critical, value) = parse_extension_v1(trace, bytes, extension)?;
        let rank = if oid == OID_AUTHORITY_KEY_IDENTIFIER_V1 {
            0
        } else if oid == OID_SUBJECT_KEY_IDENTIFIER_V1 {
            1
        } else if oid == OID_KEY_USAGE_V1 {
            2
        } else if oid == OID_BASIC_CONSTRAINTS_V1 {
            3
        } else if oid == OID_EXTENDED_KEY_USAGE_V1 {
            4
        } else {
            return Err(ZkX509DerAirErrorV1::Input);
        };
        if previous_rank.is_some_and(|previous| previous >= rank) {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        previous_rank = Some(rank);
        match rank {
            0 if !critical && aki.is_none() => {
                aki = Some(PrivateTableV1::new(
                    parse_aki_inner_v1(value)?,
                    zeroize_words_v1,
                ))
            }
            1 if !critical && ski.is_none() => {
                ski = Some(PrivateTableV1::new(
                    parse_ski_inner_v1(value)?,
                    zeroize_words_v1,
                ))
            }
            2 if critical && key_usage.is_none() => {
                key_usage = Some(parse_key_usage_inner_v1(value)?)
            }
            3 if critical && basic.is_none() => {
                basic = Some(parse_basic_constraints_inner_v1(value)?)
            }
            4 if critical && eku.is_none() => {
                eku = Some(PrivateTableV1::new(
                    parse_eku_inner_v1(value)?,
                    zeroize_words_v1,
                ))
            }
            _ => return Err(ZkX509DerAirErrorV1::Input),
        }
    }
    let (basic_constraints_ca, basic_constraints_path_len) =
        basic.ok_or(ZkX509DerAirErrorV1::Input)?;
    let mut output = ZkX509DerCertificateExtensionsV1::default();
    output.authority_key_identifier = aki.ok_or(ZkX509DerAirErrorV1::Input)?.into_vec();
    output.subject_key_identifier = ski.ok_or(ZkX509DerAirErrorV1::Input)?.into_vec();
    output.basic_constraints_ca = basic_constraints_ca;
    output.basic_constraints_path_len = basic_constraints_path_len;
    output.key_usage = key_usage.ok_or(ZkX509DerAirErrorV1::Input)?;
    output.extended_key_usages = eku.map(PrivateTableV1::into_vec);
    Ok(output)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_certificate_document_v1(
    trace: &ZkX509DerDocumentTraceV1,
) -> Result<ZkX509DerCertificateV1, ZkX509DerAirErrorV1> {
    trace.validate()?;
    let mut output = ZkX509DerCertificateV1::default();
    let bytes = trace_bytes_v1(trace)?;
    require_tag_v1(trace, 0, 0, true, 16)?;
    let [tbs, outer_algorithm, signature_value] = require_children_v1::<3>(trace, 0)?;
    require_tag_v1(trace, tbs, 0, true, 16)?;
    if node_encoded_v1(trace, &bytes, outer_algorithm)? != ECDSA_SHA256_ALGORITHM_V1 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    require_tag_v1(trace, signature_value, 0, false, 3)?;
    let signature_content = node_contents_v1(trace, &bytes, signature_value)?;
    if signature_content.first() != Some(&0) {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    output.signature = parse_signature_v1(&signature_content[1..])?;
    let fields = child_nodes_v1(trace, tbs)?;
    if fields.len() != 8 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let version = fields[0];
    require_tag_v1(trace, version, 2, true, 0)?;
    if node_contents_v1(trace, &bytes, version)? != [0x02, 0x01, 0x02] {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    output.serial = positive_integer_v1(trace, &bytes, fields[1], 20, false)?;
    if node_encoded_v1(trace, &bytes, fields[2])? != ECDSA_SHA256_ALGORITHM_V1 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    output.issuer = parse_name_v1(trace, &bytes, fields[3])?;
    require_tag_v1(trace, fields[4], 0, true, 16)?;
    let [not_before_node, not_after_node] = require_children_v1::<2>(trace, fields[4])?;
    output.not_before = parse_time_node_v1(trace, &bytes, not_before_node)?;
    output.not_after = parse_time_node_v1(trace, &bytes, not_after_node)?;
    if output.not_after < output.not_before {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    output.subject = parse_name_v1(trace, &bytes, fields[5])?;
    require_tag_v1(trace, fields[6], 0, true, 16)?;
    let [algorithm, key_value] = require_children_v1::<2>(trace, fields[6])?;
    if node_encoded_v1(trace, &bytes, algorithm)? != P256_ALGORITHM_V1 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    require_tag_v1(trace, key_value, 0, false, 3)?;
    let key_content = node_contents_v1(trace, &bytes, key_value)?;
    if key_content.first() != Some(&0)
        || key_content.len() != 66
        || key_content.get(1) != Some(&0x04)
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    output.extensions = parse_certificate_extensions_v1(trace, &bytes, fields[7])?;
    output.tbs_der = node_encoded_v1(trace, &bytes, tbs)?.to_vec();
    output.spki_der = node_encoded_v1(trace, &bytes, fields[6])?.to_vec();
    output.public_key = key_content[1..].to_vec();
    Ok(output)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_crl_extensions_v1(
    trace: &ZkX509DerDocumentTraceV1,
    bytes: &[u8],
    wrapper: usize,
) -> Result<(Vec<u8>, u64), ZkX509DerAirErrorV1> {
    require_tag_v1(trace, wrapper, 2, true, 0)?;
    let [sequence] = require_children_v1::<1>(trace, wrapper)?;
    require_tag_v1(trace, sequence, 0, true, 16)?;
    let extensions = child_nodes_v1(trace, sequence)?;
    let mut aki = None;
    let mut crl_number = None;
    let mut previous_rank = None;
    for extension in extensions {
        let (oid, critical, value) = parse_extension_v1(trace, bytes, extension)?;
        if critical {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        let rank = if oid == OID_AUTHORITY_KEY_IDENTIFIER_V1 {
            0
        } else if oid == OID_CRL_NUMBER_V1 {
            1
        } else {
            return Err(ZkX509DerAirErrorV1::Input);
        };
        if previous_rank.is_some_and(|previous| previous >= rank) {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        previous_rank = Some(rank);
        if rank == 0 && aki.is_none() {
            aki = Some(PrivateTableV1::new(
                parse_aki_inner_v1(value)?,
                zeroize_words_v1,
            ));
        } else if rank == 1 && crl_number.is_none() {
            let (inner, inner_bytes) = embedded_trace_v1(value)?;
            crl_number = Some(unsigned_integer_u64_v1(&inner, &inner_bytes, 0, 8)?);
        } else {
            return Err(ZkX509DerAirErrorV1::Input);
        }
    }
    let aki = aki.ok_or(ZkX509DerAirErrorV1::Input)?;
    let crl_number = crl_number.ok_or(ZkX509DerAirErrorV1::Input)?;
    Ok((aki.into_vec(), crl_number))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_crl_document_v1(
    trace: &ZkX509DerDocumentTraceV1,
) -> Result<ZkX509DerCrlV1, ZkX509DerAirErrorV1> {
    trace.validate()?;
    let mut output = ZkX509DerCrlV1::default();
    let bytes = trace_bytes_v1(trace)?;
    require_tag_v1(trace, 0, 0, true, 16)?;
    let [tbs, outer_algorithm, signature_value] = require_children_v1::<3>(trace, 0)?;
    require_tag_v1(trace, tbs, 0, true, 16)?;
    if node_encoded_v1(trace, &bytes, outer_algorithm)? != ECDSA_SHA256_ALGORITHM_V1 {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    require_tag_v1(trace, signature_value, 0, false, 3)?;
    let signature_content = node_contents_v1(trace, &bytes, signature_value)?;
    if signature_content.first() != Some(&0) {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    output.signature = parse_signature_v1(&signature_content[1..])?;
    let fields = child_nodes_v1(trace, tbs)?;
    if !(6..=7).contains(&fields.len()) {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    if node_contents_v1(trace, &bytes, fields[0])? != [1]
        || node_encoded_v1(trace, &bytes, fields[1])? != ECDSA_SHA256_ALGORITHM_V1
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    require_tag_v1(trace, fields[0], 0, false, 2)?;
    output.issuer = parse_name_v1(trace, &bytes, fields[2])?;
    output.this_update = parse_time_node_v1(trace, &bytes, fields[3])?;
    output.next_update = parse_time_node_v1(trace, &bytes, fields[4])?;
    if output.next_update <= output.this_update {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let (entries, extension_index) = if fields.len() == 7 {
        require_tag_v1(trace, fields[5], 0, true, 16)?;
        (Some(fields[5]), 6)
    } else {
        (None, 5)
    };
    if let Some(entries) = entries {
        let entry_nodes = child_nodes_v1(trace, entries)?;
        if entry_nodes.is_empty() || entry_nodes.len() > 64 {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        for entry in entry_nodes {
            require_tag_v1(trace, entry, 0, true, 16)?;
            let [serial, revocation_time] = require_children_v1::<2>(trace, entry)?;
            let serial = PrivateTableV1::new(
                positive_integer_v1(trace, &bytes, serial, 20, false)?,
                zeroize_words_v1,
            );
            if parse_time_node_v1(trace, &bytes, revocation_time)? > output.this_update {
                return Err(ZkX509DerAirErrorV1::Input);
            }
            output.revoked_serials.push(serial.into_vec());
        }
    }
    (output.authority_key_identifier, output.crl_number) =
        parse_crl_extensions_v1(trace, &bytes, fields[extension_index])?;
    output.tbs_der = node_encoded_v1(trace, &bytes, tbs)?.to_vec();
    Ok(output)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn extension_value_nodes_v1(
    trace: &ZkX509DerDocumentTraceV1,
    wrapper: usize,
) -> Result<Vec<usize>, ZkX509DerAirErrorV1> {
    let [sequence] = require_children_v1::<1>(trace, wrapper)?;
    let mut values = Vec::new();
    for extension in child_nodes_v1(trace, sequence)? {
        let children = child_nodes_v1(trace, extension)?;
        let value = *children.last().ok_or(ZkX509DerAirErrorV1::Input)?;
        require_tag_v1(trace, value, 0, false, 4)?;
        values.push(value);
    }
    Ok(values)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn embedded_value_nodes_v1(
    documents: &[ZkX509DerDocumentTraceV1],
    certificate_count: usize,
) -> Result<Vec<(usize, usize)>, ZkX509DerAirErrorV1> {
    if documents.len() != certificate_count + 1 {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    let mut nodes = Vec::new();
    for (document_index, trace) in documents[..certificate_count].iter().enumerate() {
        let [tbs, _, _] = require_children_v1::<3>(trace, 0)?;
        let fields = child_nodes_v1(trace, tbs)?;
        if fields.len() != 8 {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        nodes.extend(
            extension_value_nodes_v1(trace, fields[7])?
                .into_iter()
                .map(|node| (document_index, node)),
        );
    }
    let crl_document = certificate_count;
    let crl_trace = &documents[crl_document];
    let [tbs, _, _] = require_children_v1::<3>(crl_trace, 0)?;
    let fields = child_nodes_v1(crl_trace, tbs)?;
    let wrapper = *fields.last().ok_or(ZkX509DerAirErrorV1::Input)?;
    nodes.extend(
        extension_value_nodes_v1(crl_trace, wrapper)?
            .into_iter()
            .map(|node| (crl_document, node)),
    );
    if nodes.len() > ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1 {
        return Err(ZkX509DerAirErrorV1::Resource);
    }
    Ok(nodes)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_embedded_der_v1(
    documents: &[ZkX509DerDocumentTraceV1],
    certificate_count: usize,
) -> Result<
    (
        Vec<ZkX509DerDocumentTraceV1>,
        PrivateTableV1<ZkX509DerEmbeddedByteRowV1>,
    ),
    ZkX509DerAirErrorV1,
> {
    let value_nodes = embedded_value_nodes_v1(documents, certificate_count)?;
    let mut embedded_documents = Vec::new();
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_embedded_rows_v1);
    embedded_documents
        .try_reserve_exact(value_nodes.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for (embedded_index, (parent_document, node)) in value_nodes.into_iter().enumerate() {
        let parent_trace = &documents[parent_document];
        let parent_bytes = trace_bytes_v1(parent_trace)?;
        let parent_content_start = usize::try_from(parent_trace.nodes[node].content_start.value.0)
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        let contents = node_contents_v1(parent_trace, &parent_bytes, node)?;
        let embedded = build_strict_der_document_trace_v1(contents)?;
        reserve_private_rows_v1(&mut rows, contents.len(), zeroize_embedded_rows_v1)?;
        for (embedded_offset, value) in contents.iter().copied().enumerate() {
            rows.push(ZkX509DerEmbeddedByteRowV1 {
                parent_document: ZkX509DerRangeWitnessV1::from_u64(
                    u64::try_from(parent_document).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                ),
                parent_content_start: AddressWitnessV1::from_u64(
                    u64::try_from(parent_content_start)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                ),
                parent_offset: AddressWitnessV1::from_u64(
                    u64::try_from(parent_content_start + embedded_offset)
                        .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                ),
                embedded_document: ZkX509DerRangeWitnessV1::from_u64(
                    u64::try_from(embedded_index).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                ),
                embedded_offset: AddressWitnessV1::from_u64(
                    u64::try_from(embedded_offset).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
                ),
                value: ByteWitnessV1::from_u64(u64::from(value)),
            });
        }
        embedded_documents.push(embedded);
    }
    if rows.len() > ZK_X509_DER_AIR_MAX_TOTAL_EMBEDDED_BYTES_V1 {
        return Err(ZkX509DerAirErrorV1::Resource);
    }
    Ok((embedded_documents, rows))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct SemanticProvenanceBuilderV1<'a> {
    trace: &'a ZkX509DerDocumentTraceV1,
    document: u8,
    rows: PrivateTableV1<Option<ZkX509Rfc5280NodeProvenanceV1>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> SemanticProvenanceBuilderV1<'a> {
    fn new(
        trace: &'a ZkX509DerDocumentTraceV1,
        document: usize,
    ) -> Result<Self, ZkX509DerAirErrorV1> {
        Ok(Self {
            trace,
            document: u8::try_from(document).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            rows: PrivateTableV1::new(
                vec![None; trace.nodes.len()],
                zeroize_optional_provenance_v1,
            ),
        })
    }
    fn assign(
        &mut self,
        node: usize,
        parent: Option<usize>,
        child_ordinal: usize,
        role: ZkX509Rfc5280GrammarRoleV1,
        role_instance: usize,
    ) -> Result<(), ZkX509DerAirErrorV1> {
        let row = self
            .trace
            .nodes
            .get(node)
            .ok_or(ZkX509DerAirErrorV1::Topology)?;
        if self.rows.get(node).and_then(Option::as_ref).is_some() {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        if let Some(parent) = parent {
            let children = child_nodes_v1(self.trace, parent)?;
            if children.get(child_ordinal) != Some(&node) {
                return Err(ZkX509DerAirErrorV1::Topology);
            }
        } else if node != 0 || child_ordinal != 0 {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        let provenance = ZkX509Rfc5280NodeProvenanceV1 {
            document: self.document,
            node: u16::try_from(node).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            parent_node: parent.map_or(Ok(u16::MAX), |parent| {
                u16::try_from(parent).map_err(|_| ZkX509DerAirErrorV1::Resource)
            })?,
            child_ordinal: u16::try_from(child_ordinal)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            start: u16::try_from(row.start.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            content_start: u16::try_from(row.content_start.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            content_end: u16::try_from(row.end.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            depth: u8::try_from(row.depth.value.0).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            tag_class: u8::try_from(row.tag_class.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            constructed: row.constructed == F::ONE,
            tag_number: u32::try_from(row.tag_number.value.0)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            role,
            role_instance: u16::try_from(role_instance)
                .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
        };
        self.rows[node] = Some(provenance);
        Ok(())
    }
    fn finish(
        mut self,
        kind: ZkX509Rfc5280DocumentKindV1,
        parent_document: Option<usize>,
        parent_node: Option<usize>,
    ) -> Result<ZkX509Rfc5280DocumentProvenanceV1, ZkX509DerAirErrorV1> {
        let mut output = ZkX509Rfc5280DocumentProvenanceV1 {
            document: self.document,
            kind,
            parent_document: parent_document.map_or(Ok(u8::MAX), |document| {
                u8::try_from(document).map_err(|_| ZkX509DerAirErrorV1::Resource)
            })?,
            parent_node: parent_node.map_or(Ok(u16::MAX), |node| {
                u16::try_from(node).map_err(|_| ZkX509DerAirErrorV1::Resource)
            })?,
            nodes: Vec::new(),
        };
        output
            .nodes
            .try_reserve_exact(self.rows.len())
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        for row in self.rows.iter_mut() {
            output
                .nodes
                .push(row.take().ok_or(ZkX509DerAirErrorV1::Topology)?);
        }
        Ok(output)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn assign_algorithm_provenance_v1(
    builder: &mut SemanticProvenanceBuilderV1<'_>,
    node: usize,
    parent: usize,
    child_ordinal: usize,
    role: ZkX509Rfc5280GrammarRoleV1,
    role_instance: usize,
) -> Result<(), ZkX509DerAirErrorV1> {
    builder.assign(node, Some(parent), child_ordinal, role, role_instance)?;
    for (ordinal, child) in child_nodes_v1(builder.trace, node)?.into_iter().enumerate() {
        builder.assign(
            child,
            Some(node),
            ordinal,
            ZkX509Rfc5280GrammarRoleV1::AlgorithmOid,
            role_instance
                .checked_mul(4)
                .and_then(|instance| instance.checked_add(ordinal))
                .ok_or(ZkX509DerAirErrorV1::Resource)?,
        )?;
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn assign_name_provenance_v1(
    builder: &mut SemanticProvenanceBuilderV1<'_>,
    node: usize,
    parent: usize,
    child_ordinal: usize,
    role: ZkX509Rfc5280GrammarRoleV1,
    name_instance: usize,
) -> Result<(), ZkX509DerAirErrorV1> {
    builder.assign(node, Some(parent), child_ordinal, role, name_instance)?;
    for (rdn_ordinal, rdn) in child_nodes_v1(builder.trace, node)?.into_iter().enumerate() {
        builder.assign(
            rdn,
            Some(node),
            rdn_ordinal,
            ZkX509Rfc5280GrammarRoleV1::NameRdn,
            name_instance
                .checked_mul(256)
                .and_then(|instance| instance.checked_add(rdn_ordinal))
                .ok_or(ZkX509DerAirErrorV1::Resource)?,
        )?;
        for (attribute_ordinal, attribute) in
            child_nodes_v1(builder.trace, rdn)?.into_iter().enumerate()
        {
            let instance = name_instance
                .checked_mul(1024)
                .and_then(|instance| instance.checked_add(rdn_ordinal.checked_mul(16)?))
                .and_then(|instance| instance.checked_add(attribute_ordinal))
                .ok_or(ZkX509DerAirErrorV1::Resource)?;
            builder.assign(
                attribute,
                Some(rdn),
                attribute_ordinal,
                ZkX509Rfc5280GrammarRoleV1::NameAttribute,
                instance,
            )?;
            let [oid, value] = require_children_v1::<2>(builder.trace, attribute)?;
            builder.assign(
                oid,
                Some(attribute),
                0,
                ZkX509Rfc5280GrammarRoleV1::NameAttributeOid,
                instance,
            )?;
            builder.assign(
                value,
                Some(attribute),
                1,
                ZkX509Rfc5280GrammarRoleV1::NameAttributeValue,
                instance,
            )?;
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn assign_certificate_extension_provenance_v1(
    builder: &mut SemanticProvenanceBuilderV1<'_>,
    wrapper: usize,
    parent: usize,
    child_ordinal: usize,
) -> Result<(), ZkX509DerAirErrorV1> {
    builder.assign(
        wrapper,
        Some(parent),
        child_ordinal,
        ZkX509Rfc5280GrammarRoleV1::CertificateExtensionsWrapper,
        0,
    )?;
    let [sequence] = require_children_v1::<1>(builder.trace, wrapper)?;
    builder.assign(
        sequence,
        Some(wrapper),
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateExtensions,
        0,
    )?;
    for (extension_ordinal, extension) in child_nodes_v1(builder.trace, sequence)?
        .into_iter()
        .enumerate()
    {
        builder.assign(
            extension,
            Some(sequence),
            extension_ordinal,
            ZkX509Rfc5280GrammarRoleV1::CertificateExtension,
            extension_ordinal,
        )?;
        let children = child_nodes_v1(builder.trace, extension)?;
        if !(2..=3).contains(&children.len()) {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        builder.assign(
            children[0],
            Some(extension),
            0,
            ZkX509Rfc5280GrammarRoleV1::CertificateExtensionOid,
            extension_ordinal,
        )?;
        if children.len() == 3 {
            builder.assign(
                children[1],
                Some(extension),
                1,
                ZkX509Rfc5280GrammarRoleV1::CertificateExtensionCritical,
                extension_ordinal,
            )?;
        }
        builder.assign(
            *children.last().ok_or(ZkX509DerAirErrorV1::Topology)?,
            Some(extension),
            children.len() - 1,
            ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue,
            extension_ordinal,
        )?;
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_certificate_provenance_v1(
    trace: &ZkX509DerDocumentTraceV1,
    document: usize,
) -> Result<ZkX509Rfc5280DocumentProvenanceV1, ZkX509DerAirErrorV1> {
    let mut builder = SemanticProvenanceBuilderV1::new(trace, document)?;
    builder.assign(
        0,
        None,
        0,
        ZkX509Rfc5280GrammarRoleV1::Certificate,
        document,
    )?;
    let [tbs, outer_algorithm, signature] = require_children_v1::<3>(trace, 0)?;
    builder.assign(
        tbs,
        Some(0),
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateTbs,
        document,
    )?;
    assign_algorithm_provenance_v1(
        &mut builder,
        outer_algorithm,
        0,
        1,
        ZkX509Rfc5280GrammarRoleV1::CertificateOuterAlgorithm,
        0,
    )?;
    builder.assign(
        signature,
        Some(0),
        2,
        ZkX509Rfc5280GrammarRoleV1::CertificateSignatureValue,
        document,
    )?;
    let fields = child_nodes_v1(trace, tbs)?;
    if fields.len() != 8 {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    builder.assign(
        fields[0],
        Some(tbs),
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateVersion,
        document,
    )?;
    let [version] = require_children_v1::<1>(trace, fields[0])?;
    builder.assign(
        version,
        Some(fields[0]),
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateVersionInteger,
        document,
    )?;
    builder.assign(
        fields[1],
        Some(tbs),
        1,
        ZkX509Rfc5280GrammarRoleV1::CertificateSerial,
        document,
    )?;
    assign_algorithm_provenance_v1(
        &mut builder,
        fields[2],
        tbs,
        2,
        ZkX509Rfc5280GrammarRoleV1::CertificateTbsAlgorithm,
        1,
    )?;
    assign_name_provenance_v1(
        &mut builder,
        fields[3],
        tbs,
        3,
        ZkX509Rfc5280GrammarRoleV1::CertificateIssuer,
        0,
    )?;
    builder.assign(
        fields[4],
        Some(tbs),
        4,
        ZkX509Rfc5280GrammarRoleV1::CertificateValidity,
        document,
    )?;
    let [not_before, not_after] = require_children_v1::<2>(trace, fields[4])?;
    builder.assign(
        not_before,
        Some(fields[4]),
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateNotBefore,
        document,
    )?;
    builder.assign(
        not_after,
        Some(fields[4]),
        1,
        ZkX509Rfc5280GrammarRoleV1::CertificateNotAfter,
        document,
    )?;
    assign_name_provenance_v1(
        &mut builder,
        fields[5],
        tbs,
        5,
        ZkX509Rfc5280GrammarRoleV1::CertificateSubject,
        1,
    )?;
    builder.assign(
        fields[6],
        Some(tbs),
        6,
        ZkX509Rfc5280GrammarRoleV1::CertificateSpki,
        document,
    )?;
    let [algorithm, public_key] = require_children_v1::<2>(trace, fields[6])?;
    assign_algorithm_provenance_v1(
        &mut builder,
        algorithm,
        fields[6],
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateSpkiAlgorithm,
        2,
    )?;
    builder.assign(
        public_key,
        Some(fields[6]),
        1,
        ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey,
        document,
    )?;
    assign_certificate_extension_provenance_v1(&mut builder, fields[7], tbs, 7)?;
    builder.finish(ZkX509Rfc5280DocumentKindV1::Certificate, None, None)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn assign_crl_extension_provenance_v1(
    builder: &mut SemanticProvenanceBuilderV1<'_>,
    wrapper: usize,
    parent: usize,
    child_ordinal: usize,
) -> Result<(), ZkX509DerAirErrorV1> {
    builder.assign(
        wrapper,
        Some(parent),
        child_ordinal,
        ZkX509Rfc5280GrammarRoleV1::CrlExtensionsWrapper,
        0,
    )?;
    let [sequence] = require_children_v1::<1>(builder.trace, wrapper)?;
    builder.assign(
        sequence,
        Some(wrapper),
        0,
        ZkX509Rfc5280GrammarRoleV1::CrlExtensions,
        0,
    )?;
    for (extension_ordinal, extension) in child_nodes_v1(builder.trace, sequence)?
        .into_iter()
        .enumerate()
    {
        builder.assign(
            extension,
            Some(sequence),
            extension_ordinal,
            ZkX509Rfc5280GrammarRoleV1::CrlExtension,
            extension_ordinal,
        )?;
        let children = child_nodes_v1(builder.trace, extension)?;
        if !(2..=3).contains(&children.len()) {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        builder.assign(
            children[0],
            Some(extension),
            0,
            ZkX509Rfc5280GrammarRoleV1::CrlExtensionOid,
            extension_ordinal,
        )?;
        if children.len() == 3 {
            builder.assign(
                children[1],
                Some(extension),
                1,
                ZkX509Rfc5280GrammarRoleV1::CrlExtensionCritical,
                extension_ordinal,
            )?;
        }
        builder.assign(
            *children.last().ok_or(ZkX509DerAirErrorV1::Topology)?,
            Some(extension),
            children.len() - 1,
            ZkX509Rfc5280GrammarRoleV1::CrlExtensionValue,
            extension_ordinal,
        )?;
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_crl_provenance_v1(
    trace: &ZkX509DerDocumentTraceV1,
    document: usize,
) -> Result<ZkX509Rfc5280DocumentProvenanceV1, ZkX509DerAirErrorV1> {
    let mut builder = SemanticProvenanceBuilderV1::new(trace, document)?;
    builder.assign(0, None, 0, ZkX509Rfc5280GrammarRoleV1::Crl, 0)?;
    let [tbs, outer_algorithm, signature] = require_children_v1::<3>(trace, 0)?;
    builder.assign(tbs, Some(0), 0, ZkX509Rfc5280GrammarRoleV1::CrlTbs, 0)?;
    assign_algorithm_provenance_v1(
        &mut builder,
        outer_algorithm,
        0,
        1,
        ZkX509Rfc5280GrammarRoleV1::CrlOuterAlgorithm,
        3,
    )?;
    builder.assign(
        signature,
        Some(0),
        2,
        ZkX509Rfc5280GrammarRoleV1::CrlSignatureValue,
        0,
    )?;
    let fields = child_nodes_v1(trace, tbs)?;
    if !(6..=7).contains(&fields.len()) {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    builder.assign(
        fields[0],
        Some(tbs),
        0,
        ZkX509Rfc5280GrammarRoleV1::CrlVersion,
        0,
    )?;
    assign_algorithm_provenance_v1(
        &mut builder,
        fields[1],
        tbs,
        1,
        ZkX509Rfc5280GrammarRoleV1::CrlTbsAlgorithm,
        4,
    )?;
    assign_name_provenance_v1(
        &mut builder,
        fields[2],
        tbs,
        2,
        ZkX509Rfc5280GrammarRoleV1::CrlIssuer,
        2,
    )?;
    builder.assign(
        fields[3],
        Some(tbs),
        3,
        ZkX509Rfc5280GrammarRoleV1::CrlThisUpdate,
        0,
    )?;
    builder.assign(
        fields[4],
        Some(tbs),
        4,
        ZkX509Rfc5280GrammarRoleV1::CrlNextUpdate,
        0,
    )?;
    let extension_index = if fields.len() == 7 {
        builder.assign(
            fields[5],
            Some(tbs),
            5,
            ZkX509Rfc5280GrammarRoleV1::CrlEntries,
            0,
        )?;
        for (entry_ordinal, entry) in child_nodes_v1(trace, fields[5])?.into_iter().enumerate() {
            builder.assign(
                entry,
                Some(fields[5]),
                entry_ordinal,
                ZkX509Rfc5280GrammarRoleV1::CrlEntry,
                entry_ordinal,
            )?;
            let [serial, time] = require_children_v1::<2>(trace, entry)?;
            builder.assign(
                serial,
                Some(entry),
                0,
                ZkX509Rfc5280GrammarRoleV1::CrlEntrySerial,
                entry_ordinal,
            )?;
            builder.assign(
                time,
                Some(entry),
                1,
                ZkX509Rfc5280GrammarRoleV1::CrlEntryTime,
                entry_ordinal,
            )?;
        }
        6
    } else {
        5
    };
    assign_crl_extension_provenance_v1(
        &mut builder,
        fields[extension_index],
        tbs,
        extension_index,
    )?;
    builder.finish(ZkX509Rfc5280DocumentKindV1::Crl, None, None)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn embedded_document_kind_v1(
    parent_document: usize,
    certificate_count: usize,
    role_instance: u16,
) -> Result<ZkX509Rfc5280DocumentKindV1, ZkX509DerAirErrorV1> {
    if parent_document < certificate_count {
        match role_instance {
            0 => Ok(ZkX509Rfc5280DocumentKindV1::AuthorityKeyIdentifier),
            1 => Ok(ZkX509Rfc5280DocumentKindV1::SubjectKeyIdentifier),
            2 => Ok(ZkX509Rfc5280DocumentKindV1::KeyUsage),
            3 => Ok(ZkX509Rfc5280DocumentKindV1::BasicConstraints),
            4 => Ok(ZkX509Rfc5280DocumentKindV1::ExtendedKeyUsage),
            _ => Err(ZkX509DerAirErrorV1::Topology),
        }
    } else {
        match role_instance {
            0 => Ok(ZkX509Rfc5280DocumentKindV1::AuthorityKeyIdentifier),
            1 => Ok(ZkX509Rfc5280DocumentKindV1::CrlNumber),
            _ => Err(ZkX509DerAirErrorV1::Topology),
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_embedded_provenance_v1(
    trace: &ZkX509DerDocumentTraceV1,
    document: usize,
    kind: ZkX509Rfc5280DocumentKindV1,
    parent_document: usize,
    parent_node: usize,
) -> Result<ZkX509Rfc5280DocumentProvenanceV1, ZkX509DerAirErrorV1> {
    let mut builder = SemanticProvenanceBuilderV1::new(trace, document)?;
    match kind {
        ZkX509Rfc5280DocumentKindV1::AuthorityKeyIdentifier => {
            builder.assign(0, None, 0, ZkX509Rfc5280GrammarRoleV1::EmbeddedAki, 0)?;
            let [identifier] = require_children_v1::<1>(trace, 0)?;
            builder.assign(
                identifier,
                Some(0),
                0,
                ZkX509Rfc5280GrammarRoleV1::EmbeddedAkiIdentifier,
                0,
            )?;
        }
        ZkX509Rfc5280DocumentKindV1::SubjectKeyIdentifier => {
            builder.assign(0, None, 0, ZkX509Rfc5280GrammarRoleV1::EmbeddedSki, 0)?
        }
        ZkX509Rfc5280DocumentKindV1::KeyUsage => {
            builder.assign(0, None, 0, ZkX509Rfc5280GrammarRoleV1::EmbeddedKeyUsage, 0)?
        }
        ZkX509Rfc5280DocumentKindV1::BasicConstraints => {
            builder.assign(
                0,
                None,
                0,
                ZkX509Rfc5280GrammarRoleV1::EmbeddedBasicConstraints,
                0,
            )?;
            let children = child_nodes_v1(trace, 0)?;
            if let Some(ca) = children.first() {
                builder.assign(
                    *ca,
                    Some(0),
                    0,
                    ZkX509Rfc5280GrammarRoleV1::EmbeddedBasicConstraintsCa,
                    0,
                )?;
            }
            if let Some(path_len) = children.get(1) {
                builder.assign(
                    *path_len,
                    Some(0),
                    1,
                    ZkX509Rfc5280GrammarRoleV1::EmbeddedBasicConstraintsPathLen,
                    0,
                )?;
            }
        }
        ZkX509Rfc5280DocumentKindV1::ExtendedKeyUsage => {
            builder.assign(0, None, 0, ZkX509Rfc5280GrammarRoleV1::EmbeddedEku, 0)?;
            for (ordinal, oid) in child_nodes_v1(trace, 0)?.into_iter().enumerate() {
                builder.assign(
                    oid,
                    Some(0),
                    ordinal,
                    ZkX509Rfc5280GrammarRoleV1::EmbeddedEkuOid,
                    ordinal,
                )?;
            }
        }
        ZkX509Rfc5280DocumentKindV1::CrlNumber => {
            builder.assign(0, None, 0, ZkX509Rfc5280GrammarRoleV1::EmbeddedCrlNumber, 0)?
        }
        ZkX509Rfc5280DocumentKindV1::Certificate | ZkX509Rfc5280DocumentKindV1::Crl => {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
    }
    builder.finish(kind, Some(parent_document), Some(parent_node))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_rfc5280_semantic_provenance_v1(
    documents: &[ZkX509DerDocumentTraceV1],
    embedded_documents: &[ZkX509DerDocumentTraceV1],
    certificate_count: usize,
) -> Result<Vec<ZkX509Rfc5280DocumentProvenanceV1>, ZkX509DerAirErrorV1> {
    if documents.len() != certificate_count + 1 {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    let mut provenance = Vec::new();
    provenance
        .try_reserve_exact(documents.len() + embedded_documents.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for (document, trace) in documents[..certificate_count].iter().enumerate() {
        provenance.push(build_certificate_provenance_v1(trace, document)?);
    }
    provenance.push(build_crl_provenance_v1(
        documents
            .get(certificate_count)
            .ok_or(ZkX509DerAirErrorV1::Topology)?,
        certificate_count,
    )?);
    let value_nodes = embedded_value_nodes_v1(documents, certificate_count)?;
    if value_nodes.len() != embedded_documents.len() {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    for (embedded, ((parent_document, parent_node), trace)) in
        value_nodes.into_iter().zip(embedded_documents).enumerate()
    {
        let top = provenance
            .get(parent_document)
            .ok_or(ZkX509DerAirErrorV1::Topology)?;
        let parent = top
            .nodes
            .get(parent_node)
            .ok_or(ZkX509DerAirErrorV1::Topology)?;
        if !matches!(
            parent.role,
            ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue
                | ZkX509Rfc5280GrammarRoleV1::CrlExtensionValue
        ) {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        let kind =
            embedded_document_kind_v1(parent_document, certificate_count, parent.role_instance)?;
        provenance.push(build_embedded_provenance_v1(
            trace,
            documents
                .len()
                .checked_add(embedded)
                .ok_or(ZkX509DerAirErrorV1::Resource)?,
            kind,
            parent_document,
            parent_node,
        )?);
    }
    Ok(provenance)
}
/// Evaluate one exact outer-to-embedded extension byte-copy row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_embedded_byte_constraints_v1(row: &ZkX509DerEmbeddedByteRowV1) -> Vec<F> {
    let mut constraints = row.parent_document.constraints();
    constraints.extend(row.parent_content_start.constraints());
    constraints.extend(row.parent_offset.constraints());
    constraints.extend(row.embedded_document.constraints());
    constraints.extend(row.embedded_offset.constraints());
    constraints.extend(row.value.constraints());
    constraints.push(
        row.parent_offset.value.sub(
            row.parent_content_start
                .value
                .add(row.embedded_offset.value),
        ),
    );
    constraints
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_path_rows_v1(
    statement: &ZkX509Rfc5280StatementV1,
    certificates: &[ZkX509DerCertificateV1],
) -> Result<PrivateTableV1<ZkX509Rfc5280PathRowV1>, ZkX509DerAirErrorV1> {
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_path_rows_v1);
    rows.try_reserve_exact(certificates.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for (index, certificate) in certificates.iter().enumerate() {
        let after_not_before = statement
            .presentation_not_before_unix_seconds
            .checked_sub(certificate.not_before)
            .ok_or(ZkX509DerAirErrorV1::Input)?;
        let before_not_after = certificate
            .not_after
            .checked_sub(statement.presentation_not_after_unix_seconds)
            .ok_or(ZkX509DerAirErrorV1::Input)?;
        let is_leaf = index == 0;
        let is_root = index + 1 == certificates.len();
        let is_ca = !is_leaf;
        let subordinate = index.saturating_sub(1);
        let path_len_slack = if is_ca {
            certificate
                .extensions
                .basic_constraints_path_len
                .and_then(|path_len| path_len.checked_sub(u32::try_from(subordinate).ok()?))
                .ok_or(ZkX509DerAirErrorV1::Input)?
        } else {
            0
        };
        let parent = certificates.get(index + 1).unwrap_or(certificate);
        rows.push(ZkX509Rfc5280PathRowV1 {
            certificate: ZkX509DerRangeWitnessV1::from_u64(
                u64::try_from(index).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            is_leaf: F(u64::from(is_leaf)),
            is_ca: F(u64::from(is_ca)),
            is_root: F(u64::from(is_root)),
            after_not_before: ZkX509DerRangeWitnessV1::from_u64(after_not_before),
            before_not_after: ZkX509DerRangeWitnessV1::from_u64(before_not_after),
            subordinate_ca_count: ZkX509DerRangeWitnessV1::from_u64(
                u64::try_from(subordinate).map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            ),
            path_len_slack: ZkX509DerRangeWitnessV1::from_u64(u64::from(path_len_slack)),
            issuer_name_matches_parent: F(u64::from(
                certificate.issuer.encoded == parent.subject.encoded,
            )),
            authority_key_matches_parent: F(u64::from(
                certificate.extensions.authority_key_identifier
                    == parent.extensions.subject_key_identifier,
            )),
        });
    }
    Ok(rows)
}
/// Evaluate one local RFC 5280 path-state row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_rfc5280_path_row_constraints_v1(
    row: &ZkX509Rfc5280PathRowV1,
    index: usize,
    chain_depth: usize,
) -> Vec<F> {
    let mut constraints = Vec::new();
    constraints.extend(row.certificate.constraints());
    constraints.extend(row.after_not_before.constraints());
    constraints.extend(row.before_not_after.constraints());
    constraints.extend(row.subordinate_ca_count.constraints());
    constraints.extend(row.path_len_slack.constraints());
    for selector in [
        row.is_leaf,
        row.is_ca,
        row.is_root,
        row.issuer_name_matches_parent,
        row.authority_key_matches_parent,
    ] {
        constraints.push(selector.mul(selector.sub(F::ONE)));
    }
    constraints.push(
        row.certificate
            .value
            .sub(F(u64::try_from(index).expect("path index fits u64"))),
    );
    constraints.push(row.is_leaf.sub(F(u64::from(index == 0))));
    constraints.push(row.is_ca.sub(F(u64::from(index != 0))));
    constraints.push(row.is_root.sub(F(u64::from(index + 1 == chain_depth))));
    constraints.push(row.subordinate_ca_count.value.sub(F(
        u64::try_from(index.saturating_sub(1)).expect("path index fits u64"),
    )));
    constraints.push(row.issuer_name_matches_parent.sub(F::ONE));
    constraints.push(row.authority_key_matches_parent.sub(F::ONE));
    constraints
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_rfc5280_semantics_v1(
    statement: &ZkX509Rfc5280StatementV1,
    certificates: &[ZkX509DerCertificateV1],
    crl: &ZkX509DerCrlV1,
) -> Result<(), ZkX509DerAirErrorV1> {
    let chain_depth = certificates.len();
    if !(2..=3).contains(&chain_depth)
        || statement.presentation_not_after_unix_seconds
            <= statement.presentation_not_before_unix_seconds
        || statement
            .presentation_not_after_unix_seconds
            .checked_sub(statement.presentation_not_before_unix_seconds)
            .is_none_or(|width| width > ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1)
        || statement
            .disclosed_attribute_indices
            .iter()
            .any(|index| *index >= 4)
        || statement
            .disclosed_attribute_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let leaf = &certificates[0];
    if leaf.extensions.basic_constraints_ca
        || leaf.extensions.basic_constraints_path_len.is_some()
        || leaf.extensions.key_usage != statement.leaf_key_usage
        || leaf.extensions.extended_key_usages.as_deref()
            != Some(statement.leaf_extended_key_usages.as_slice())
        || statement
            .disclosed_attribute_indices
            .iter()
            .any(|index| leaf.subject.attributes[usize::from(*index)].is_none())
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    for (index, certificate) in certificates.iter().enumerate() {
        // Every certificate is checked on its own, so the binding bounds are the
        // latest notBefore and the earliest notAfter in the path. This stays an
        // independent formulation of the canonical data-model interval
        // definition; `presentation_interval_tests` compares the two.
        if statement.presentation_not_before_unix_seconds < certificate.not_before
            || statement.presentation_not_after_unix_seconds > certificate.not_after
        {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        if index > 0
            && (!certificate.extensions.basic_constraints_ca
                || certificate
                    .extensions
                    .basic_constraints_path_len
                    .is_none_or(|path_len| path_len < u32::try_from(index - 1).unwrap_or(u32::MAX))
                || certificate.extensions.key_usage
                    != KEY_USAGE_KEY_CERT_SIGN_V1 | KEY_USAGE_CRL_SIGN_V1
                || certificate.extensions.extended_key_usages.is_some())
        {
            return Err(ZkX509DerAirErrorV1::Input);
        }
        let parent = certificates.get(index + 1).unwrap_or(certificate);
        if certificate.issuer.encoded != parent.subject.encoded
            || certificate.extensions.authority_key_identifier
                != parent.extensions.subject_key_identifier
        {
            return Err(ZkX509DerAirErrorV1::Input);
        }
    }
    let issuer = &certificates[1];
    if crl.issuer.encoded != issuer.subject.encoded
        || crl.authority_key_identifier != issuer.extensions.subject_key_identifier
        || issuer.extensions.key_usage & KEY_USAGE_CRL_SIGN_V1 == 0
        || crl.crl_number != statement.crl_number
        || statement.presentation_not_before_unix_seconds < crl.this_update
        || statement.presentation_not_after_unix_seconds >= crl.next_update
        || statement
            .presentation_not_after_unix_seconds
            .checked_sub(crl.this_update)
            .is_none_or(|age| age > ZK_X509_MAX_CRL_AGE_SECONDS_V1)
        || crl
            .revoked_serials
            .iter()
            .any(|serial| serial == &leaf.serial)
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    if crl.revoked_serials.windows(2).any(|pair| {
        pair[0].len() > pair[1].len() || (pair[0].len() == pair[1].len() && pair[0] >= pair[1])
    }) {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    Ok(())
}
/// Build the independent strict-DER and closed RFC 5280 path-state trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_rfc5280_trace_v1(
    certificate_chain_der: &[Vec<u8>],
    crl_der: &[u8],
    statement: ZkX509Rfc5280StatementV1,
) -> Result<ZkX509Rfc5280TraceV1, ZkX509DerAirErrorV1> {
    if !(2..=3).contains(&certificate_chain_der.len())
        || certificate_chain_der.iter().any(|document| {
            document.is_empty() || document.len() > ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
        })
        || crl_der.is_empty()
        || crl_der.len() > ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
    {
        return Err(ZkX509DerAirErrorV1::Input);
    }
    let mut documents = Vec::new();
    documents
        .try_reserve_exact(certificate_chain_der.len() + 1)
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    let mut certificates = Vec::new();
    certificates
        .try_reserve_exact(certificate_chain_der.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for certificate in certificate_chain_der {
        let trace = build_strict_der_document_trace_v1(certificate)?;
        certificates.push(parse_certificate_document_v1(&trace)?);
        documents.push(trace);
    }
    let crl_trace = build_strict_der_document_trace_v1(crl_der)?;
    let crl = parse_crl_document_v1(&crl_trace)?;
    documents.push(crl_trace);
    let (embedded_documents, embedded_byte_rows) =
        build_embedded_der_v1(&documents, certificates.len())?;
    let semantic_provenance =
        build_rfc5280_semantic_provenance_v1(&documents, &embedded_documents, certificates.len())?;
    validate_rfc5280_semantics_v1(&statement, &certificates, &crl)?;
    let path_rows = build_path_rows_v1(&statement, &certificates)?;
    let trace = ZkX509Rfc5280TraceV1 {
        documents,
        embedded_documents,
        embedded_byte_rows: embedded_byte_rows.into_vec(),
        certificates,
        crl,
        statement,
        path_rows: path_rows.into_vec(),
        semantic_provenance,
    };
    trace.validate()?;
    Ok(trace)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
const ZK_X509_DER_AIR_SIGNATURE_DER_BYTES_V1: usize = 72;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const ZK_X509_DER_AIR_P256_SPKI_DER_BYTES_V1: usize = 91;
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fixed_padded_v1(value: &[u8], capacity: usize) -> Result<Vec<u8>, ZkX509DerAirErrorV1> {
    if value.len() > capacity {
        return Err(ZkX509DerAirErrorV1::Resource);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    output.extend_from_slice(value);
    output.resize(capacity, 0);
    Ok(output)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_rfc5280_io_channel_v1(
    witnesses: &mut Vec<ZkX509IoChannelWitnessV1>,
    first_channel: u32,
    producer: ZkX509IoEndpointV1,
    mut consumers: Vec<ZkX509IoEndpointV1>,
    value: Vec<u8>,
) -> Result<(), ZkX509DerAirErrorV1> {
    let value = PrivateTableV1::new(value, zeroize_words_v1);
    consumers.sort_unstable();
    if consumers.is_empty() || consumers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    let index = u32::try_from(witnesses.len()).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    let channel = first_channel
        .checked_add(index)
        .ok_or(ZkX509DerAirErrorV1::Resource)?;
    let byte_len = u32::try_from(value.len()).map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    if byte_len == 0 {
        return Err(ZkX509DerAirErrorV1::Topology);
    }
    let mut witness = ZkX509IoChannelWitnessV1 {
        declaration: ZkX509IoChannelDeclarationV1 {
            channel,
            producer,
            consumers: consumers.clone(),
            byte_len,
            public_value: None,
        },
        producer_value: value.into_vec(),
        consumer_values: Vec::new(),
    };
    witness
        .consumer_values
        .try_reserve_exact(consumers.len())
        .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
    for _ in &consumers {
        witness.consumer_values.push(witness.producer_value.clone());
    }
    witnesses.push(witness);
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_length_then_padded_channels_v1(
    witnesses: &mut Vec<ZkX509IoChannelWitnessV1>,
    first_channel: u32,
    producer: ZkX509IoEndpointV1,
    consumer: ZkX509IoEndpointV1,
    value: &[u8],
    capacity: usize,
) -> Result<(), ZkX509DerAirErrorV1> {
    push_rfc5280_io_channel_v1(
        witnesses,
        first_channel,
        producer,
        vec![consumer],
        u64::try_from(value.len())
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?
            .to_be_bytes()
            .to_vec(),
    )?;
    push_rfc5280_io_channel_v1(
        witnesses,
        first_channel,
        producer,
        vec![consumer],
        fixed_padded_v1(value, capacity)?,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_padded_then_length_channels_v1(
    witnesses: &mut Vec<ZkX509IoChannelWitnessV1>,
    first_channel: u32,
    producer: ZkX509IoEndpointV1,
    consumer: ZkX509IoEndpointV1,
    value: &[u8],
    capacity: usize,
) -> Result<(), ZkX509DerAirErrorV1> {
    push_rfc5280_io_channel_v1(
        witnesses,
        first_channel,
        producer,
        vec![consumer],
        fixed_padded_v1(value, capacity)?,
    )?;
    push_rfc5280_io_channel_v1(
        witnesses,
        first_channel,
        producer,
        vec![consumer],
        u64::try_from(value.len())
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?
            .to_be_bytes()
            .to_vec(),
    )
}
/// Algebraic value exported for the optional third certificate slot.
///
/// Slots zero and one are mandatory. Slot two is active exactly for a
/// three-certificate private path.  Consumers must use the fixed slot census
/// and the canonical dummy encodings emitted below when this selector is zero.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn certificate_slot_2_active_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<u8, ZkX509DerAirErrorV1> {
    match trace.certificates.len() {
        2 => Ok(0),
        3 => Ok(1),
        _ => Err(ZkX509DerAirErrorV1::Topology),
    }
}
/// Emit the canonical strict-DER producer channels.
///
/// The initial prefix is byte-for-byte topology-compatible with the projection segment:
/// active-chain SPKIs, leaf serial length/value, then each disclosed subject-attribute content
/// length/value. Subsequent fixed channels bind three fixed certificate-TBS SHA slots, ECDSA
/// inputs, the CRL TBS and complete signed-CRL SHA inputs, the issuer SPKI SHA input, and the root
/// SPKI governed-CA membership input. Complete CRL non-revocation is proved from every parsed entry
/// by the RFC 5280 segment, without a derived CRL root or witness-selectable serial table.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn rfc5280_io_witnesses_v1(
    trace: &ZkX509Rfc5280TraceV1,
    first_channel: u32,
) -> Result<Vec<ZkX509IoChannelWitnessV1>, ZkX509DerAirErrorV1> {
    trace.validate()?;
    let strict_der = ZkX509IoEndpointV1 {
        role: ZkX509IoSegmentRoleV1::StrictDer,
        instance: 0,
    };
    let projection = ZkX509IoEndpointV1 {
        role: ZkX509IoSegmentRoleV1::Projection,
        instance: 0,
    };
    let sha = ZkX509IoEndpointV1 {
        role: ZkX509IoSegmentRoleV1::Sha256,
        instance: 0,
    };
    let p256 = ZkX509IoEndpointV1 {
        role: ZkX509IoSegmentRoleV1::P256,
        instance: 0,
    };
    let ca_accumulator = ZkX509IoEndpointV1 {
        role: ZkX509IoSegmentRoleV1::CaAccumulator,
        instance: 0,
    };
    let mut witnesses = Vec::new();
    // Projection consumes three fixed DER-encoded SPKI slots. The optional
    // slot's unique inactive encoding is 91 zero octets.
    for certificate_slot in 0..3 {
        let spki = trace.certificates.get(certificate_slot).map_or_else(
            || vec![0; ZK_X509_DER_AIR_P256_SPKI_DER_BYTES_V1],
            |certificate| certificate.spki_der.clone(),
        );
        if spki.len() != ZK_X509_DER_AIR_P256_SPKI_DER_BYTES_V1 {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        push_rfc5280_io_channel_v1(
            &mut witnesses,
            first_channel,
            strict_der,
            vec![projection],
            spki,
        )?;
    }
    let leaf = trace
        .certificates
        .first()
        .ok_or(ZkX509DerAirErrorV1::Topology)?;
    push_length_then_padded_channels_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        projection,
        &leaf.serial,
        ZK_X509_MAX_SERIAL_BYTES_V1,
    )?;
    for index in &trace.statement.disclosed_attribute_indices {
        let value = leaf.subject.attributes[usize::from(*index)]
            .as_deref()
            .ok_or(ZkX509DerAirErrorV1::Input)?;
        push_length_then_padded_channels_v1(
            &mut witnesses,
            first_channel,
            strict_der,
            projection,
            value,
            ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1,
        )?;
    }
    // SHA's first-release call census always reserves three certificate-TBS
    // slots. A depth-two path uses a canonical all-zero padded message with
    // length zero in slot two, so call indices cannot be witness-shifted.
    for certificate_slot in 0..3 {
        let tbs_der = trace
            .certificates
            .get(certificate_slot)
            .map_or(&[][..], |certificate| certificate.tbs_der.as_slice());
        push_padded_then_length_channels_v1(
            &mut witnesses,
            first_channel,
            strict_der,
            sha,
            tbs_der,
            ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
        )?;
    }
    // Copy-bind the private depth selector to the fixed P-256 aggregate.
    push_rfc5280_io_channel_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        vec![p256],
        vec![certificate_slot_2_active_v1(trace)?],
    )?;
    // P-256 likewise receives exactly three certificate-signature slots.  A
    // signature is verified with its issuer's key, except for a self-signed
    // path terminus.  The absent optional slot has a zero-length signature,
    // all-zero padding, and an all-zero real key; the P-256 sink selects its
    // verifier-owned valid dummy tuple algebraically.
    for certificate_slot in 0..3 {
        let signature = trace
            .certificates
            .get(certificate_slot)
            .map_or(&[][..], |certificate| {
                certificate.signature.encoded.as_slice()
            });
        push_padded_then_length_channels_v1(
            &mut witnesses,
            first_channel,
            strict_der,
            p256,
            signature,
            ZK_X509_DER_AIR_SIGNATURE_DER_BYTES_V1,
        )?;
        let public_key = match certificate_slot {
            0 => trace
                .certificates
                .get(1)
                .ok_or(ZkX509DerAirErrorV1::Topology)?
                .public_key
                .clone(),
            1 => trace
                .certificates
                .get(2)
                .or_else(|| trace.certificates.get(1))
                .ok_or(ZkX509DerAirErrorV1::Topology)?
                .public_key
                .clone(),
            2 => trace.certificates.get(2).map_or_else(
                || vec![0; ZK_X509_UNCOMPRESSED_P256_BYTES_V1],
                |certificate| certificate.public_key.clone(),
            ),
            _ => return Err(ZkX509DerAirErrorV1::Topology),
        };
        if public_key.len() != ZK_X509_UNCOMPRESSED_P256_BYTES_V1 {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        push_rfc5280_io_channel_v1(
            &mut witnesses,
            first_channel,
            strict_der,
            vec![p256],
            public_key,
        )?;
    }
    push_padded_then_length_channels_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        sha,
        &trace.crl.tbs_der,
        ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
    )?;
    let complete_crl_der = trace_bytes_v1(
        trace
            .documents
            .last()
            .ok_or(ZkX509DerAirErrorV1::Topology)?,
    )?;
    // The governed revocation commitment is the domain-framed SHA-256 digest
    // of the exact complete signed CRL. Keep this distinct from the
    // TBSCertList message hashed for ECDSA verification.
    push_padded_then_length_channels_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        sha,
        &complete_crl_der,
        ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
    )?;
    push_padded_then_length_channels_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        p256,
        &trace.crl.signature.encoded,
        ZK_X509_DER_AIR_SIGNATURE_DER_BYTES_V1,
    )?;
    let root = trace
        .certificates
        .last()
        .ok_or(ZkX509DerAirErrorV1::Topology)?;
    let issuer = trace
        .certificates
        .get(1)
        .ok_or(ZkX509DerAirErrorV1::Topology)?;
    // The CRL is signed by the leaf issuer.  Wallet ownership is signed by
    // the leaf subject itself.  Export both exact keys explicitly so neither
    // P-256 instance can borrow a same-width key from another slot.
    push_rfc5280_io_channel_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        vec![p256],
        issuer.public_key.clone(),
    )?;
    push_rfc5280_io_channel_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        vec![p256],
        leaf.public_key.clone(),
    )?;
    push_rfc5280_io_channel_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        vec![sha],
        issuer.spki_der.clone(),
    )?;
    push_rfc5280_io_channel_v1(
        &mut witnesses,
        first_channel,
        strict_der,
        vec![ca_accumulator],
        root.spki_der.clone(),
    )?;
    Ok(witnesses)
}
/// Compute exact active counts and the fixed first-release padding envelope.
#[cfg(test)]
pub fn plan_zk_x509_rfc5280_air_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<ZkX509Rfc5280ResourcePlanV1, ZkX509DerAirErrorV1> {
    trace.validate()?;
    let io = rfc5280_io_witnesses_v1(trace, 0)?;
    let io_access_rows = io.iter().try_fold(0_usize, |sum, witness| {
        let endpoints = witness
            .declaration
            .consumers
            .len()
            .checked_add(1)
            .ok_or(ZkX509DerAirErrorV1::Resource)?;
        let bytes = usize::try_from(witness.declaration.byte_len)
            .map_err(|_| ZkX509DerAirErrorV1::Resource)?;
        sum.checked_add(
            bytes
                .checked_mul(endpoints)
                .ok_or(ZkX509DerAirErrorV1::Resource)?,
        )
        .ok_or(ZkX509DerAirErrorV1::Resource)
    })?;
    Ok(ZkX509Rfc5280ResourcePlanV1 {
        top_level_documents: trace.documents.len(),
        embedded_documents: trace.embedded_documents.len(),
        embedded_copy_rows: trace.embedded_byte_rows.len(),
        path_rows: trace.path_rows.len(),
        io_channels: io.len(),
        io_access_rows,
        fixed_top_level_byte_capacity: ZK_X509_DER_AIR_MAX_DOCUMENTS_V1
            .checked_mul(ZK_X509_DER_MAX_DOCUMENT_BYTES_V1)
            .ok_or(ZkX509DerAirErrorV1::Resource)?,
        fixed_embedded_byte_capacity: ZK_X509_DER_AIR_MAX_TOTAL_EMBEDDED_BYTES_V1,
        fixed_top_level_node_capacity: ZK_X509_DER_AIR_MAX_DOCUMENTS_V1
            .checked_mul(ZK_X509_DER_MAX_VALUES_V1)
            .ok_or(ZkX509DerAirErrorV1::Resource)?,
        fixed_embedded_node_capacity: ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1
            .checked_mul(ZK_X509_DER_MAX_VALUES_V1)
            .ok_or(ZkX509DerAirErrorV1::Resource)?,
    })
}
/// Validate every strict-DER producer endpoint in an already validated global byte-copy trace.
#[cfg(test)]
pub fn validate_rfc5280_io_v1(
    trace: &ZkX509Rfc5280TraceV1,
    io: &ZkX509IoTraceV1,
    first_channel: u32,
) -> Result<(), ZkX509DerAirErrorV1> {
    for expected in rfc5280_io_witnesses_v1(trace, first_channel)? {
        let declaration = io
            .declarations
            .get(
                usize::try_from(expected.declaration.channel)
                    .map_err(|_| ZkX509DerAirErrorV1::Resource)?,
            )
            .ok_or(ZkX509DerAirErrorV1::ByteBinding)?;
        if declaration != &expected.declaration {
            return Err(ZkX509DerAirErrorV1::ByteBinding);
        }
        io.validate_endpoint_bytes(
            expected.declaration.channel,
            expected.declaration.producer,
            true,
            &expected.producer_value,
        )
        .map_err(|_| ZkX509DerAirErrorV1::ByteBinding)?;
        for (consumer, value) in expected
            .declaration
            .consumers
            .iter()
            .copied()
            .zip(&expected.consumer_values)
        {
            io.validate_endpoint_bytes(expected.declaration.channel, consumer, false, value)
                .map_err(|_| ZkX509DerAirErrorV1::ByteBinding)?;
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280TraceV1 {
    /// Differentially validate document traces, semantic outputs, and every
    /// local path-state identity.
    pub(crate) fn validate(&self) -> Result<(), ZkX509DerAirErrorV1> {
        if self.documents.len() != self.certificates.len() + 1
            || self.documents.iter().any(|document| {
                document.bytes.is_empty()
                    || document.bytes.len() > ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
            })
        {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        for document in &self.documents {
            document.validate()?;
        }
        let expected_certificates: Vec<_> = self.documents[..self.certificates.len()]
            .iter()
            .map(parse_certificate_document_v1)
            .collect::<Result<_, _>>()?;
        let expected_crl =
            parse_crl_document_v1(self.documents.last().ok_or(ZkX509DerAirErrorV1::Topology)?)?;
        if self.certificates != expected_certificates || self.crl != expected_crl {
            return Err(ZkX509DerAirErrorV1::ByteBinding);
        }
        let (expected_embedded_documents, expected_embedded_byte_rows) =
            build_embedded_der_v1(&self.documents, self.certificates.len())?;
        if self.embedded_documents != expected_embedded_documents
            || self.embedded_byte_rows.as_slice() != expected_embedded_byte_rows.as_slice()
            || self.embedded_documents.len() > ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1
        {
            return Err(ZkX509DerAirErrorV1::ByteBinding);
        }
        for document in &self.embedded_documents {
            document.validate()?;
        }
        let expected_provenance = build_rfc5280_semantic_provenance_v1(
            &self.documents,
            &self.embedded_documents,
            self.certificates.len(),
        )?;
        if self.semantic_provenance != expected_provenance {
            return Err(ZkX509DerAirErrorV1::ByteBinding);
        }
        for row in &self.embedded_byte_rows {
            if !all_zero_v1(&evaluate_embedded_byte_constraints_v1(row)) {
                return Err(ZkX509DerAirErrorV1::ByteBinding);
            }
        }
        validate_rfc5280_semantics_v1(&self.statement, &self.certificates, &self.crl)?;
        let expected_rows = build_path_rows_v1(&self.statement, &self.certificates)?;
        if self.path_rows.as_slice() != expected_rows.as_slice()
            || self.path_rows.len() != self.certificates.len()
        {
            return Err(ZkX509DerAirErrorV1::Topology);
        }
        for (index, row) in self.path_rows.iter().enumerate() {
            if !all_zero_v1(&evaluate_rfc5280_path_row_constraints_v1(
                row,
                index,
                self.certificates.len(),
            )) {
                return Err(ZkX509DerAirErrorV1::Topology);
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        der::{ZkX509DerLimitsV1, parse_single_der_value_v1},
        io_air::{ZkX509IoChallengesV1, ZkX509IoLaneChallengesV1, build_zk_x509_io_trace_v1},
    };
    #[test]
    fn canonical_profile_eku_subsets_and_retired_oids_are_independently_parsed() {
        let entries = [
            (
                ZkX509DerEkuV1::ClientAuthentication,
                OID_CLIENT_AUTHENTICATION_V1,
            ),
            (
                ZkX509DerEkuV1::DocumentSigning,
                super::super::profile::ZK_X509_DOCUMENT_SIGNING_EKU_DER_VALUE_V1,
            ),
            (
                ZkX509DerEkuV1::WalletIdentity,
                super::super::profile::ZK_X509_WALLET_IDENTITY_EKU_DER_VALUE_V1,
            ),
        ];
        for mask in 1_u8..8 {
            let selected: Vec<_> = entries
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1_u8 << *index) != 0)
                .map(|(_, entry)| *entry)
                .collect();
            let encoded = sequence(
                &selected
                    .iter()
                    .map(|(_, value)| oid(value))
                    .collect::<Vec<_>>(),
            );
            let expected: Vec<_> = selected.iter().map(|(usage, _)| *usage).collect();
            assert_eq!(parse_eku_inner_v1(&encoded).unwrap(), expected);
            if mask == 7 {
                assert_eq!(encoded.len(), 55);
            }
        }
        assert!(parse_eku_inner_v1(&sequence(&[])).is_err());
        for (_, value) in entries {
            assert!(parse_eku_inner_v1(&sequence(&[oid(value), oid(value)])).is_err());
        }
        for high in 1..entries.len() {
            for low in 0..high {
                assert!(
                    parse_eku_inner_v1(&sequence(&[oid(entries[high].1), oid(entries[low].1)]))
                        .is_err()
                );
            }
        }
        for last in [1, 2] {
            let retired = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb2, 0x03, 0x01, last];
            assert!(parse_eku_inner_v1(&sequence(&[oid(&retired)])).is_err());
        }
    }
    #[test]
    fn private_inverse_witness_preserves_zero_bytes_and_malformed_fallback() {
        use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;

        for word in (0_u64..=255).chain([
            65_535,
            GOLDILOCKS_MODULUS_V1 - 1,
            GOLDILOCKS_MODULUS_V1,
            GOLDILOCKS_MODULUS_V1 + 1,
            u64::MAX,
        ]) {
            let value = F(word);
            let expected = value.inv().unwrap_or(F::ZERO);
            assert_eq!(inverse_or_zero_v1(value), expected, "word {word}");
        }
    }

    fn tlv(tag: &[u8], contents: &[u8]) -> Vec<u8> {
        let mut encoded = tag.to_vec();
        if contents.len() < 128 {
            encoded.push(u8::try_from(contents.len()).expect("short DER length"));
        } else if contents.len() <= usize::from(u8::MAX) {
            encoded.extend_from_slice(&[
                0x81,
                u8::try_from(contents.len()).expect("one-octet DER length"),
            ]);
        } else {
            let length = u16::try_from(contents.len())
                .expect("test DER length")
                .to_be_bytes();
            encoded.extend_from_slice(&[0x82, length[0], length[1]]);
        }
        encoded.extend_from_slice(contents);
        encoded
    }
    fn sequence(values: &[Vec<u8>]) -> Vec<u8> {
        tlv(
            &[0x30],
            &values
                .iter()
                .flat_map(|value| value.iter().copied())
                .collect::<Vec<_>>(),
        )
    }
    fn set(values: &[Vec<u8>]) -> Vec<u8> {
        tlv(
            &[0x31],
            &values
                .iter()
                .flat_map(|value| value.iter().copied())
                .collect::<Vec<_>>(),
        )
    }
    fn rich_document() -> Vec<u8> {
        let integer = tlv(&[0x02], &[0x00, 0x80]);
        let oid = tlv(&[0x06], &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
        let bit_string = tlv(&[0x03], &[0x03, 0xa0]);
        let boolean = tlv(&[0x01], &[0xff]);
        let ordered_set = set(&[tlv(&[0x02], &[1]), tlv(&[0x02], &[2])]);
        let high_context = tlv(&[0x9f, 0x81, 0x00], &[0x5a]);
        let long_octets = tlv(&[0x04], &vec![0x77; 128]);
        sequence(&[
            integer,
            oid,
            bit_string,
            boolean,
            ordered_set,
            high_context,
            long_octets,
        ])
    }
    const CERT_NOT_BEFORE: u64 = 1_640_995_200;
    const CRL_THIS_UPDATE: u64 = 1_672_531_200;
    const CRL_NEXT_UPDATE: u64 = CRL_THIS_UPDATE + 300;
    const VALIDATION_TIME: u64 = CRL_THIS_UPDATE + 60;
    fn integer(value: u64) -> Vec<u8> {
        if value == 0 {
            return tlv(&[0x02], &[0]);
        }
        let bytes = value.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .expect("nonzero integer");
        let mut magnitude = bytes[first..].to_vec();
        if magnitude[0] & 0x80 != 0 {
            magnitude.insert(0, 0);
        }
        tlv(&[0x02], &magnitude)
    }
    fn oid(contents: &[u8]) -> Vec<u8> {
        tlv(&[0x06], contents)
    }
    fn octet_string(contents: &[u8]) -> Vec<u8> {
        tlv(&[0x04], contents)
    }
    fn bit_string(contents: &[u8], unused: u8) -> Vec<u8> {
        let mut value = Vec::with_capacity(contents.len() + 1);
        value.push(unused);
        value.extend_from_slice(contents);
        tlv(&[0x03], &value)
    }
    fn signature_der() -> Vec<u8> {
        sequence(&[integer(1), integer(1)])
    }
    fn name(country: &[u8; 2], common_name: &[u8]) -> Vec<u8> {
        sequence(&[
            set(&[sequence(&[oid(OID_COUNTRY_NAME_V1), tlv(&[0x13], country)])]),
            set(&[sequence(&[
                oid(OID_COMMON_NAME_V1),
                tlv(&[0x0c], common_name),
            ])]),
        ])
    }
    fn extension(oid_contents: &[u8], critical: bool, inner: &[u8]) -> Vec<u8> {
        let mut fields = vec![oid(oid_contents)];
        if critical {
            fields.push(tlv(&[0x01], &[0xff]));
        }
        fields.push(octet_string(inner));
        sequence(&fields)
    }
    fn aki_inner(identifier: &[u8]) -> Vec<u8> {
        sequence(&[tlv(&[0x80], identifier)])
    }
    fn spki() -> Vec<u8> {
        // The affine generator is a valid P-256 point while keeping this
        // DER/path fixture independent of the P-256 implementation.
        let point = vec![
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        sequence(&[P256_ALGORITHM_V1.to_vec(), bit_string(&point, 0)])
    }
    fn certificate_extensions(
        subject_key_identifier: &[u8],
        authority_key_identifier: &[u8],
        is_ca: bool,
        path_len: u64,
    ) -> Vec<Vec<u8>> {
        let basic_constraints = if is_ca {
            sequence(&[tlv(&[0x01], &[0xff]), integer(path_len)])
        } else {
            sequence(&[])
        };
        let key_usage = if is_ca {
            bit_string(&[0x06], 1)
        } else {
            bit_string(&[0x80], 7)
        };
        let mut extensions = vec![
            extension(
                OID_AUTHORITY_KEY_IDENTIFIER_V1,
                false,
                &aki_inner(authority_key_identifier),
            ),
            extension(
                OID_SUBJECT_KEY_IDENTIFIER_V1,
                false,
                &octet_string(subject_key_identifier),
            ),
            extension(OID_KEY_USAGE_V1, true, &key_usage),
            extension(OID_BASIC_CONSTRAINTS_V1, true, &basic_constraints),
        ];
        if !is_ca {
            extensions.push(extension(
                OID_EXTENDED_KEY_USAGE_V1,
                true,
                &sequence(&[oid(OID_CLIENT_AUTHENTICATION_V1)]),
            ));
        }
        extensions
    }
    fn certificate_with_extensions(
        serial: u64,
        issuer: &[u8],
        subject: &[u8],
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let tbs = sequence(&[
            tlv(&[0xa0], &integer(2)),
            integer(serial),
            ECDSA_SHA256_ALGORITHM_V1.to_vec(),
            issuer.to_vec(),
            sequence(&[
                tlv(&[0x17], b"220101000000Z"),
                tlv(&[0x17], b"300101000000Z"),
            ]),
            subject.to_vec(),
            spki(),
            tlv(&[0xa3], &sequence(extensions)),
        ]);
        sequence(&[
            tbs,
            ECDSA_SHA256_ALGORITHM_V1.to_vec(),
            bit_string(&signature_der(), 0),
        ])
    }
    #[allow(clippy::too_many_arguments)]
    fn certificate(
        serial: u64,
        issuer: &[u8],
        subject: &[u8],
        subject_key_identifier: &[u8],
        authority_key_identifier: &[u8],
        is_ca: bool,
        path_len: u64,
    ) -> Vec<u8> {
        certificate_with_extensions(
            serial,
            issuer,
            subject,
            &certificate_extensions(
                subject_key_identifier,
                authority_key_identifier,
                is_ca,
                path_len,
            ),
        )
    }
    fn crl_extensions(authority_key_identifier: &[u8], number: u64) -> Vec<Vec<u8>> {
        vec![
            extension(
                OID_AUTHORITY_KEY_IDENTIFIER_V1,
                false,
                &aki_inner(authority_key_identifier),
            ),
            extension(OID_CRL_NUMBER_V1, false, &integer(number)),
        ]
    }
    fn crl_with_extensions(
        issuer: &[u8],
        revoked_serials: &[u64],
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut fields = vec![
            integer(1),
            ECDSA_SHA256_ALGORITHM_V1.to_vec(),
            issuer.to_vec(),
            tlv(&[0x17], b"230101000000Z"),
            tlv(&[0x17], b"230101000500Z"),
        ];
        if !revoked_serials.is_empty() {
            fields.push(sequence(
                &revoked_serials
                    .iter()
                    .map(|serial| sequence(&[integer(*serial), tlv(&[0x17], b"221231000000Z")]))
                    .collect::<Vec<_>>(),
            ));
        }
        fields.push(tlv(&[0xa0], &sequence(extensions)));
        let tbs = sequence(&fields);
        sequence(&[
            tbs,
            ECDSA_SHA256_ALGORITHM_V1.to_vec(),
            bit_string(&signature_der(), 0),
        ])
    }
    fn crl(
        issuer: &[u8],
        authority_key_identifier: &[u8],
        number: u64,
        revoked_serials: &[u64],
    ) -> Vec<u8> {
        crl_with_extensions(
            issuer,
            revoked_serials,
            &crl_extensions(authority_key_identifier, number),
        )
    }
    fn rfc5280_fixture(
        depth: usize,
        revoked_serials: &[u64],
    ) -> (Vec<Vec<u8>>, Vec<u8>, ZkX509Rfc5280StatementV1) {
        rfc5280_fixture_with_leaf_common_name(depth, revoked_serials, b"Leaf")
    }
    fn rfc5280_fixture_with_leaf_common_name(
        depth: usize,
        revoked_serials: &[u64],
        leaf_common_name: &[u8],
    ) -> (Vec<Vec<u8>>, Vec<u8>, ZkX509Rfc5280StatementV1) {
        assert!((2..=3).contains(&depth));
        let leaf_name = name(b"IL", leaf_common_name);
        let intermediate_name = name(b"IL", b"Intermediate");
        let root_name = name(b"IL", b"Root");
        let leaf_ski = [0x11; 20];
        let intermediate_ski = [0x22; 20];
        let root_ski = [0x33; 20];
        let leaf_issuer = if depth == 2 {
            &root_name
        } else {
            &intermediate_name
        };
        let leaf_aki = if depth == 2 {
            &root_ski
        } else {
            &intermediate_ski
        };
        let mut chain = vec![certificate(
            7,
            leaf_issuer,
            &leaf_name,
            &leaf_ski,
            leaf_aki,
            false,
            0,
        )];
        if depth == 3 {
            chain.push(certificate(
                8,
                &root_name,
                &intermediate_name,
                &intermediate_ski,
                &root_ski,
                true,
                0,
            ));
        }
        chain.push(certificate(
            9,
            &root_name,
            &root_name,
            &root_ski,
            &root_ski,
            true,
            u64::try_from(depth - 2).expect("small depth"),
        ));
        let crl_issuer = if depth == 2 {
            &root_name
        } else {
            &intermediate_name
        };
        let crl_aki = if depth == 2 {
            &root_ski
        } else {
            &intermediate_ski
        };
        let crl = crl(crl_issuer, crl_aki, 42, revoked_serials);
        let statement = ZkX509Rfc5280StatementV1 {
            presentation_not_before_unix_seconds: VALIDATION_TIME,
            presentation_not_after_unix_seconds: VALIDATION_TIME + 1,
            leaf_key_usage: 1,
            leaf_extended_key_usages: vec![ZkX509DerEkuV1::ClientAuthentication],
            crl_number: 42,
            disclosed_attribute_indices: vec![0, 3],
        };
        (chain, crl, statement)
    }
    fn io_challenges() -> ZkX509IoChallengesV1 {
        let mut value = 11_u64;
        ZkX509IoChallengesV1 {
            lanes: core::array::from_fn(|_| {
                let lane = ZkX509IoLaneChallengesV1 {
                    beta: F(value),
                    channel: F(value + 1),
                    offset: F(value + 2),
                    value: F(value + 3),
                    is_write: F(value + 4),
                };
                value += 7;
                lane
            }),
        }
    }
    fn native_accepts(input: &[u8]) -> bool {
        parse_single_der_value_v1(input, ZkX509DerLimitsV1::profile()).is_ok()
    }
    #[test]
    fn native_reference_and_air_agree_on_canonical_and_adversarial_der() {
        let canonical = [
            vec![0x05, 0x00],
            vec![0x02, 0x01, 0x7f],
            vec![0x9f, 0x1f, 0x00],
            sequence(&[tlv(&[0x05], &[]), tlv(&[0x03], &[0])]),
            rich_document(),
        ];
        for (index, document) in canonical.iter().enumerate() {
            assert!(native_accepts(document), "native canonical {index}");
            let trace = build_strict_der_document_trace_v1(document)
                .unwrap_or_else(|error| panic!("AIR canonical {index}: {error:?}"));
            trace.validate().expect("canonical trace");
        }
        let adversarial = [
            vec![],
            vec![0x04],
            vec![0x04, 0x80],
            vec![0x04, 0x81, 0x7f],
            vec![0x04, 0x82, 0x00, 0x80],
            vec![0x9f, 0x80, 0],
            vec![0x9f, 0x1e, 0],
            vec![0x00, 0],
            vec![0x07, 0],
            vec![0x22, 0],
            vec![0x10, 0],
            vec![0x01, 0x01, 1],
            vec![0x05, 0x01, 0],
            vec![0x02, 0],
            vec![0x02, 2, 0, 0x7f],
            vec![0x06, 0],
            vec![0x06, 2, 0x80, 0],
            vec![0x06, 1, 0x81],
            vec![0x03, 0],
            vec![0x03, 1, 8],
            vec![0x03, 2, 3, 0xa1],
            vec![0x31, 6, 0x02, 1, 2, 0x02, 1, 1],
            vec![0x05, 0, 0x05, 0],
        ];
        for (index, document) in adversarial.iter().enumerate() {
            assert!(!native_accepts(document), "native adversarial {index}");
            assert!(
                build_strict_der_document_trace_v1(document).is_err(),
                "AIR adversarial {index}"
            );
        }
    }
    #[test]
    fn strict_der_length_tag_nesting_and_count_boundaries_match_native() {
        let canonical_lengths = [0_usize, 1, 127, 128, 255, 256, 16_380];
        for content_len in canonical_lengths {
            let document = tlv(&[0x04], &vec![0x5a; content_len]);
            assert!(
                document.len() <= ZK_X509_DER_MAX_DOCUMENT_BYTES_V1,
                "test length must stay inside the document cap"
            );
            assert!(native_accepts(&document), "native length {content_len}");
            let trace = build_strict_der_document_trace_v1(&document)
                .unwrap_or_else(|error| panic!("AIR length {content_len}: {error:?}"));
            trace.validate().expect("canonical boundary trace");
        }
        let exact_document = tlv(&[0x04], &vec![0x6b; 16_380]);
        assert_eq!(exact_document.len(), ZK_X509_DER_MAX_DOCUMENT_BYTES_V1);
        let exact_trace =
            build_strict_der_document_trace_v1(&exact_document).expect("exact document cap");
        assert_eq!(
            exact_trace.document_len(),
            ZK_X509_DER_MAX_DOCUMENT_BYTES_V1
        );
        let oversized_document = tlv(&[0x04], &vec![0x6b; 16_381]);
        assert_eq!(
            oversized_document.len(),
            ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 + 1
        );
        assert!(!native_accepts(&oversized_document));
        assert!(build_strict_der_document_trace_v1(&oversized_document).is_err());
        let canonical_u32_max_tag = vec![0x9f, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0x00];
        assert!(native_accepts(&canonical_u32_max_tag));
        let tag_trace = build_strict_der_document_trace_v1(&canonical_u32_max_tag)
            .expect("canonical u32::MAX tag");
        assert_eq!(tag_trace.nodes[0].tag_number.value.0, u64::from(u32::MAX));
        let malformed_headers = [
            vec![0x9f],
            vec![0x9f, 0x81],
            vec![0x9f, 0x80, 0x00],
            vec![0x9f, 0x1e, 0x00],
            vec![0x9f, 0x90, 0x80, 0x80, 0x80, 0x00, 0x00],
            vec![0x9f, 0x81, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00],
            vec![0x00, 0x00],
            vec![0x07, 0x00],
            vec![0x22, 0x00],
            vec![0x10, 0x00],
            vec![0x04],
            vec![0x04, 0x80],
            vec![0x04, 0x81],
            vec![0x04, 0x81, 0x7f],
            vec![0x04, 0x82, 0x00, 0x80],
            vec![0x04, 0x83, 0x01, 0x00, 0x00],
            vec![0x04, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0x04, 0x02, 0x5a],
            vec![0x05, 0x00, 0x05, 0x00],
        ];
        for (index, document) in malformed_headers.iter().enumerate() {
            assert!(!native_accepts(document), "native header family {index}");
            assert!(
                build_strict_der_document_trace_v1(document).is_err(),
                "AIR header family {index}"
            );
        }
        let mut exact_depth = vec![0x05, 0x00];
        for _ in 1..ZK_X509_DER_MAX_NESTING_DEPTH_V1 {
            exact_depth = sequence(&[exact_depth]);
        }
        assert!(native_accepts(&exact_depth));
        let exact_depth_trace =
            build_strict_der_document_trace_v1(&exact_depth).expect("exact nesting cap");
        assert_eq!(
            exact_depth_trace
                .nodes
                .iter()
                .map(|node| node.depth.value.0)
                .max(),
            Some(u64::try_from(ZK_X509_DER_MAX_NESTING_DEPTH_V1 - 1).unwrap())
        );
        let excessive_depth = sequence(&[exact_depth]);
        assert!(!native_accepts(&excessive_depth));
        assert!(build_strict_der_document_trace_v1(&excessive_depth).is_err());
        let null = tlv(&[0x05], &[]);
        let exact_values = sequence(&vec![null.clone(); ZK_X509_DER_MAX_VALUES_V1 - 1]);
        assert!(native_accepts(&exact_values));
        let exact_values_trace =
            build_strict_der_document_trace_v1(&exact_values).expect("exact value-count cap");
        assert_eq!(exact_values_trace.nodes.len(), ZK_X509_DER_MAX_VALUES_V1);
        let excessive_values = sequence(&vec![null; ZK_X509_DER_MAX_VALUES_V1]);
        assert!(!native_accepts(&excessive_values));
        assert!(build_strict_der_document_trace_v1(&excessive_values).is_err());
    }
    #[test]
    fn strict_der_set_order_equality_prefix_and_first_difference_are_closed() {
        let null = tlv(&[0x05], &[]);
        let equal_children = set(&[null.clone(), null]);
        assert!(native_accepts(&equal_children));
        build_strict_der_document_trace_v1(&equal_children)
            .expect("equal SET children are canonically nondecreasing")
            .validate()
            .expect("equal SET trace");
        let common_prefix_ordered = set(&[tlv(&[0x04], &[1, 1]), tlv(&[0x04], &[1, 2])]);
        assert!(native_accepts(&common_prefix_ordered));
        build_strict_der_document_trace_v1(&common_prefix_ordered)
            .expect("first differing byte is ordered");
        let common_prefix_reversed = set(&[tlv(&[0x04], &[1, 2]), tlv(&[0x04], &[1, 1])]);
        assert!(!native_accepts(&common_prefix_reversed));
        assert!(build_strict_der_document_trace_v1(&common_prefix_reversed).is_err());
        // Exercise the comparator terminal used by the AIR for a strict
        // byte-prefix independently of ASN.1 TLV structure: complete DER
        // values cannot themselves be strict prefixes because their lengths
        // are part of the compared encoding.
        let prefix_bytes = [0x04, 0x01, 0x04, 0x01, 0x00];
        let mut prefix_rows = Vec::new();
        build_set_comparison_rows_v1(&prefix_bytes, 0, 1, 2, 0..2, 2..5, &mut prefix_rows)
            .expect("left strict prefix orders before right");
        assert_eq!(prefix_rows.len(), 2);
        assert_eq!(
            build_set_comparison_rows_v1(&prefix_bytes, 0, 2, 1, 2..5, 0..2, &mut Vec::new(),),
            Err(ZkX509DerAirErrorV1::SetOrder)
        );
    }
    #[test]
    fn every_node_row_family_is_algebraically_bound() {
        let trace = build_strict_der_document_trace_v1(&rich_document()).expect("trace");
        assert!(trace.nodes.len() >= 10);
        for node_index in 0..trace.nodes.len() {
            let mut mutations: Vec<Box<dyn Fn(&mut ZkX509DerNodeRowV1)>> = vec![
                Box::new(|row| row.ordinal.value = row.ordinal.value.add(F::ONE)),
                Box::new(|row| row.ordinal.bits[0] = row.ordinal.bits[0].add(F::ONE)),
                Box::new(|row| row.start.value = row.start.value.add(F::ONE)),
                Box::new(|row| row.content_start.value = row.content_start.value.add(F::ONE)),
                Box::new(|row| row.content_len.value = row.content_len.value.add(F::ONE)),
                Box::new(|row| row.end.value = row.end.value.add(F::ONE)),
                Box::new(|row| row.depth.value = row.depth.value.add(F::ONE)),
                Box::new(|row| row.tag_class.value = row.tag_class.value.add(F::ONE)),
                Box::new(|row| row.constructed = row.constructed.add(F::ONE)),
                Box::new(|row| row.tag_number.value = row.tag_number.value.add(F::ONE)),
                Box::new(|row| row.identifier_len.value = row.identifier_len.value.add(F::ONE)),
                Box::new(|row| row.length_len.value = row.length_len.value.add(F::ONE)),
                Box::new(|row| row.identifier[0].value = row.identifier[0].value.add(F::ONE)),
                Box::new(|row| row.identifier[0].bits[0] = row.identifier[0].bits[0].add(F::ONE)),
                Box::new(|row| row.identifier_active[0] = row.identifier_active[0].sub(F::ONE)),
                Box::new(|row| row.universal_selectors[0] = row.universal_selectors[0].add(F::ONE)),
                Box::new(|row| row.length[0].value = row.length[0].value.add(F::ONE)),
                Box::new(|row| row.length[0].bits[0] = row.length[0].bits[0].add(F::ONE)),
                Box::new(|row| row.length_active[0] = row.length_active[0].sub(F::ONE)),
                Box::new(|row| {
                    row.max_minus_content.value = row.max_minus_content.value.add(F::ONE)
                }),
                Box::new(|row| row.content_is_zero = row.content_is_zero.add(F::ONE)),
                Box::new(|row| row.content_inverse = row.content_inverse.add(F::ONE)),
            ];
            if trace.nodes[node_index].identifier_active[1] == F::ONE {
                mutations.push(Box::new(|row| {
                    row.tag_accumulators[0] = row.tag_accumulators[0].add(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.first_high_group_inverse = row.first_high_group_inverse.add(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.tag_minus_31.value = row.tag_minus_31.value.add(F::ONE)
                }));
            }
            if trace.nodes[node_index].length_active[1] == F::ONE {
                mutations.push(Box::new(|row| {
                    row.first_long_body_inverse = row.first_long_body_inverse.add(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.content_minus_128.value = row.content_minus_128.value.add(F::ONE)
                }));
            }
            if trace.nodes[node_index].depth.value != F::ZERO {
                mutations.push(Box::new(|row| {
                    row.ancestor_ends[0].value = row.ancestor_ends[0].value.add(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.ancestor_active[0] = row.ancestor_active[0].sub(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.ancestor_gaps[0].value = row.ancestor_gaps[0].value.add(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.ancestor_gap_inverses[0] = row.ancestor_gap_inverses[0].add(F::ONE)
                }));
                mutations.push(Box::new(|row| {
                    row.ancestor_gap_is_zero[0] = row.ancestor_gap_is_zero[0].add(F::ONE)
                }));
            }
            for (mutation_index, mutate) in mutations.into_iter().enumerate() {
                let mut changed = trace.clone();
                mutate(&mut changed.nodes[node_index]);
                assert!(
                    changed.validate().is_err(),
                    "node {node_index} mutation family {mutation_index} must reject"
                );
            }
        }
    }
    #[test]
    fn every_primitive_and_set_comparator_family_is_bound() {
        let trace = build_strict_der_document_trace_v1(&rich_document()).expect("trace");
        assert!(!trace.primitive_rows.is_empty());
        assert!(!trace.set_order_rows.is_empty());
        for row_index in 0..trace.primitive_rows.len() {
            let mutations: [fn(&mut ZkX509DerPrimitiveRowV1); 18] = [
                |row| row.node.value = row.node.value.add(F::ONE),
                |row| row.content_start.value = row.content_start.value.add(F::ONE),
                |row| row.content_offset.value = row.content_offset.value.add(F::ONE),
                |row| row.document_offset.value = row.document_offset.value.add(F::ONE),
                |row| row.value.value = row.value.value.add(F::ONE),
                |row| row.value.bits[0] = row.value.bits[0].add(F::ONE),
                |row| row.first = row.first.add(F::ONE),
                |row| row.last = row.last.add(F::ONE),
                |row| row.tag_class.value = row.tag_class.value.add(F::ONE),
                |row| row.tag_number.value = row.tag_number.value.add(F::ONE),
                |row| row.universal_selectors[0] = row.universal_selectors[0].add(F::ONE),
                |row| row.oid_start_before = row.oid_start_before.add(F::ONE),
                |row| row.oid_start_after = row.oid_start_after.add(F::ONE),
                |row| row.unused_bit_selectors[0] = row.unused_bit_selectors[0].add(F::ONE),
                |row| row.first_zero_inverse = row.first_zero_inverse.add(F::ONE),
                |row| row.first_ff_inverse = row.first_ff_inverse.add(F::ONE),
                |row| row.first_is_zero = row.first_is_zero.add(F::ONE),
                |row| row.first_is_ff = row.first_is_ff.add(F::ONE),
            ];
            for (mutation_index, mutate) in mutations.into_iter().enumerate() {
                let mut changed = trace.clone();
                mutate(&mut changed.primitive_rows[row_index]);
                assert!(
                    changed.validate().is_err(),
                    "primitive row {row_index} family {mutation_index} must reject"
                );
            }
        }
        for row_index in 0..trace.set_order_rows.len() {
            let mutations: [fn(&mut ZkX509DerSetOrderRowV1); 16] = [
                |row| row.set_node.value = row.set_node.value.add(F::ONE),
                |row| row.left_node.value = row.left_node.value.add(F::ONE),
                |row| row.right_node.value = row.right_node.value.add(F::ONE),
                |row| row.offset.value = row.offset.value.add(F::ONE),
                |row| row.left.value = row.left.value.add(F::ONE),
                |row| row.right.value = row.right.value.add(F::ONE),
                |row| row.equal_before = row.equal_before.add(F::ONE),
                |row| row.less_before = row.less_before.add(F::ONE),
                |row| row.equal_after = row.equal_after.add(F::ONE),
                |row| row.less_after = row.less_after.add(F::ONE),
                |row| row.bytes_equal = row.bytes_equal.add(F::ONE),
                |row| row.byte_difference_inverse = row.byte_difference_inverse.add(F::ONE),
                |row| row.comparison_difference.value = row.comparison_difference.value.add(F::ONE),
                |row| {
                    row.comparison_difference.bits[0] =
                        row.comparison_difference.bits[0].add(F::ONE)
                },
                |row| row.comparison_borrow = row.comparison_borrow.add(F::ONE),
                |row| row.left.bits[0] = row.left.bits[0].add(F::ONE),
            ];
            for (mutation_index, mutate) in mutations.into_iter().enumerate() {
                let mut changed = trace.clone();
                mutate(&mut changed.set_order_rows[row_index]);
                assert!(
                    changed.validate().is_err(),
                    "SET row {row_index} family {mutation_index} must reject"
                );
            }
        }
        let mut omitted = trace.clone();
        omitted.set_order_rows.pop();
        assert_eq!(omitted.validate(), Err(ZkX509DerAirErrorV1::SetOrder));
        let mut reordered = trace.clone();
        reordered.set_order_rows.swap(0, 1);
        assert_eq!(reordered.validate(), Err(ZkX509DerAirErrorV1::SetOrder));
    }
    #[test]
    fn primitive_residue_shape_is_invariant_at_random_extension_domain_evaluations() {
        use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
        fn next_field(state: &mut u64) -> F {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            // Avoid Boolean values so the test exercises genuine
            // extension-domain evaluations rather than witness rows.
            F(2 + (*state % (GOLDILOCKS_MODULUS_V1 - 3)))
        }
        let trace = build_strict_der_document_trace_v1(&rich_document()).expect("trace");
        let template = trace
            .primitive_rows
            .first()
            .expect("rich document has primitive rows")
            .clone();
        let residue_count = evaluate_der_primitive_constraints_v1(&template).len();
        assert_ne!(residue_count, 0);
        // These exact values used to select Rust control-flow branches. The
        // numeric evaluator must now return one invariant residue inventory
        // both at and away from them.
        for tag in [1_u64, 3, 6, 2, u64::from(u32::MAX)] {
            let mut row = template.clone();
            row.tag_class.value = F::ZERO;
            row.tag_class.bits = [F::ZERO; 2];
            row.tag_number.value = F(tag);
            assert_eq!(
                evaluate_der_primitive_constraints_v1(&row).len(),
                residue_count
            );
            row.tag_number.value = row.tag_number.value.add(F(17));
            assert_eq!(
                evaluate_der_primitive_constraints_v1(&row).len(),
                residue_count
            );
        }
        let mut state = 0xd3a5_28f1_9b74_c60d_u64;
        for sample in 0..512 {
            let mut row = template.clone();
            row.tag_class.value = next_field(&mut state);
            row.tag_class.bits = core::array::from_fn(|_| next_field(&mut state));
            row.tag_number.value = next_field(&mut state);
            row.tag_number.bits = core::array::from_fn(|_| next_field(&mut state));
            row.value.value = next_field(&mut state);
            row.value.bits = core::array::from_fn(|_| next_field(&mut state));
            row.first = next_field(&mut state);
            row.last = next_field(&mut state);
            row.oid_start_before = next_field(&mut state);
            row.oid_start_after = next_field(&mut state);
            row.universal_selectors = core::array::from_fn(|_| next_field(&mut state));
            row.unused_bit_selectors = core::array::from_fn(|_| next_field(&mut state));
            let residues = evaluate_der_primitive_constraints_v1(&row);
            assert_eq!(
                residues.len(),
                residue_count,
                "residue inventory changed at random sample {sample}"
            );
            assert_eq!(
                residues,
                evaluate_der_primitive_constraints_v1(&row),
                "numeric evaluation is not deterministic at sample {sample}"
            );
            for selector in 0..ZK_X509_DER_AIR_UNIVERSAL_SELECTORS_V1 {
                let mut changed = row.clone();
                changed.universal_selectors[selector] =
                    changed.universal_selectors[selector].add(F::ONE);
                let changed_residues = evaluate_der_primitive_constraints_v1(&changed);
                assert_eq!(changed_residues.len(), residue_count);
                assert_ne!(
                    changed_residues, residues,
                    "universal selector {selector} was not algebraically observed at sample {sample}"
                );
            }
        }
    }
    #[test]
    fn byte_cover_topology_and_fixed_resource_caps_fail_closed() {
        let trace = build_strict_der_document_trace_v1(&rich_document()).expect("trace");
        let mut changed = trace.clone();
        changed.bytes[7].value.value = changed.bytes[7].value.value.add(F::ONE);
        assert!(changed.validate().is_err());
        let mut changed = trace.clone();
        changed.bytes[7].value.bits[0] = changed.bytes[7].value.bits[0].add(F::ONE);
        assert!(changed.validate().is_err());
        let mut changed = trace.clone();
        changed.bytes[7].offset.value = changed.bytes[7].offset.value.add(F::ONE);
        assert!(changed.validate().is_err());
        let mut changed = trace.clone();
        changed.bytes[7].offset.bits[0] = changed.bytes[7].offset.bits[0].add(F::ONE);
        assert!(changed.validate().is_err());
        let mut changed = trace.clone();
        changed.nodes.remove(1);
        assert!(changed.validate().is_err());
        let mut changed = trace.clone();
        changed.primitive_rows.remove(0);
        assert!(changed.validate().is_err());
        assert_eq!(
            plan_zk_x509_der_air_v1(&[]),
            Err(ZkX509DerAirErrorV1::Resource)
        );
        let traces = vec![trace.clone(); ZK_X509_DER_AIR_MAX_DOCUMENTS_V1];
        let plan = plan_zk_x509_der_air_v1(&traces).expect("fixed plan");
        assert_eq!(plan.documents, 4);
        assert_eq!(plan.bytes, trace.bytes.len() * 4);
        assert_eq!(plan.fixed_byte_capacity, 4 * 16_384);
        assert_eq!(plan.fixed_node_capacity, 4 * 2_048);
        let too_many = vec![trace; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 + 1];
        assert_eq!(
            plan_zk_x509_der_air_v1(&too_many),
            Err(ZkX509DerAirErrorV1::Resource)
        );
    }
    #[test]
    fn closed_rfc5280_two_and_three_certificate_paths_validate() {
        for depth in 2..=3 {
            let (chain, crl, statement) = rfc5280_fixture(depth, &[10, 11]);
            let trace = build_zk_x509_rfc5280_trace_v1(&chain, &crl, statement)
                .unwrap_or_else(|error| panic!("depth {depth}: {error:?}"));
            trace.validate().expect("closed RFC 5280 trace");
            assert_eq!(trace.documents.len(), depth + 1);
            assert_eq!(trace.path_rows.len(), depth);
            assert_eq!(
                trace.embedded_documents.len(),
                if depth == 2 { 11 } else { 15 }
            );
            assert!(!trace.embedded_byte_rows.is_empty());
            assert_eq!(trace.certificates[0].serial, [7]);
            assert_eq!(trace.crl.revoked_serials, [vec![10], vec![11]]);
            let plan = plan_zk_x509_rfc5280_air_v1(&trace).expect("fixed RFC plan");
            assert_eq!(plan.top_level_documents, depth + 1);
            assert_eq!(plan.embedded_documents, if depth == 2 { 11 } else { 15 });
            assert_eq!(plan.path_rows, depth);
            assert_eq!(plan.fixed_top_level_byte_capacity, 4 * 16_384);
            assert_eq!(plan.fixed_embedded_byte_capacity, 4 * 16_384);
            assert!(plan.io_channels > 0);
            assert!(plan.io_access_rows > plan.io_channels);
        }
    }
    #[test]
    fn certificate_and_crl_extension_grammars_reject_every_noncanonical_family() {
        let (chain, fixture_crl, statement) = rfc5280_fixture(2, &[10, 11]);
        let leaf_name = name(b"IL", b"Leaf");
        let root_name = name(b"IL", b"Root");
        let leaf_ski = [0x11; 20];
        let root_ski = [0x33; 20];
        let leaf_extensions = certificate_extensions(&leaf_ski, &root_ski, false, 0);
        let mut invalid_leaf_profiles: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
        let mut changed = leaf_extensions.clone();
        changed.swap(0, 1);
        invalid_leaf_profiles.push(("AKI/SKI order".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed.swap(2, 3);
        invalid_leaf_profiles.push(("keyUsage/basicConstraints order".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed.insert(1, changed[0].clone());
        invalid_leaf_profiles.push(("duplicate AKI".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed.push(extension(&[0x2a, 0x03], false, &tlv(&[0x05], &[])));
        invalid_leaf_profiles.push(("unknown extension".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[0] = extension(OID_AUTHORITY_KEY_IDENTIFIER_V1, true, &aki_inner(&root_ski));
        invalid_leaf_profiles.push(("critical AKI".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[1] = extension(
            OID_SUBJECT_KEY_IDENTIFIER_V1,
            true,
            &octet_string(&leaf_ski),
        );
        invalid_leaf_profiles.push(("critical SKI".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[2] = extension(OID_KEY_USAGE_V1, false, &bit_string(&[0x80], 7));
        invalid_leaf_profiles.push(("noncritical keyUsage".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[3] = extension(OID_BASIC_CONSTRAINTS_V1, false, &sequence(&[]));
        invalid_leaf_profiles.push(("noncritical basicConstraints".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[4] = extension(
            OID_EXTENDED_KEY_USAGE_V1,
            false,
            &sequence(&[oid(OID_CLIENT_AUTHENTICATION_V1)]),
        );
        invalid_leaf_profiles.push(("noncritical EKU".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[0] = sequence(&[
            oid(OID_AUTHORITY_KEY_IDENTIFIER_V1),
            tlv(&[0x01], &[0]),
            octet_string(&aki_inner(&root_ski)),
        ]);
        invalid_leaf_profiles.push(("explicit DEFAULT FALSE".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[0] = extension(OID_AUTHORITY_KEY_IDENTIFIER_V1, false, &[0x30, 0x01]);
        invalid_leaf_profiles.push(("truncated embedded AKI".into(), changed));
        let mut changed = leaf_extensions.clone();
        let mut trailing_aki = aki_inner(&root_ski);
        trailing_aki.extend_from_slice(&[0x05, 0x00]);
        changed[0] = extension(OID_AUTHORITY_KEY_IDENTIFIER_V1, false, &trailing_aki);
        invalid_leaf_profiles.push(("embedded AKI trailing value".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[0] = sequence(&[
            octet_string(&aki_inner(&root_ski)),
            oid(OID_AUTHORITY_KEY_IDENTIFIER_V1),
        ]);
        invalid_leaf_profiles.push(("extension field order".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[3] = extension(
            OID_BASIC_CONSTRAINTS_V1,
            true,
            &sequence(&[tlv(&[0x01], &[0xff])]),
        );
        invalid_leaf_profiles.push(("leaf marked CA".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[4] = extension(OID_EXTENDED_KEY_USAGE_V1, true, &sequence(&[]));
        invalid_leaf_profiles.push(("empty EKU".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[4] = extension(
            OID_EXTENDED_KEY_USAGE_V1,
            true,
            &sequence(&[
                oid(OID_CLIENT_AUTHENTICATION_V1),
                oid(OID_CLIENT_AUTHENTICATION_V1),
            ]),
        );
        invalid_leaf_profiles.push(("duplicate EKU".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[4] = extension(
            OID_EXTENDED_KEY_USAGE_V1,
            true,
            &sequence(&[oid(&[0x2a, 0x03])]),
        );
        invalid_leaf_profiles.push(("unknown EKU".into(), changed));
        let mut changed = leaf_extensions.clone();
        changed[4] = extension(
            OID_EXTENDED_KEY_USAGE_V1,
            true,
            &sequence(&[
                oid(OID_DOCUMENT_SIGNING_V1),
                oid(OID_CLIENT_AUTHENTICATION_V1),
            ]),
        );
        invalid_leaf_profiles.push(("noncanonical EKU order".into(), changed));
        for missing in 0..leaf_extensions.len() {
            let mut changed = leaf_extensions.clone();
            changed.remove(missing);
            invalid_leaf_profiles.push((format!("missing extension {missing}"), changed));
        }
        for (label, extensions) in invalid_leaf_profiles {
            let mut changed_chain = chain.clone();
            changed_chain[0] = certificate_with_extensions(7, &root_name, &leaf_name, &extensions);
            assert!(
                build_zk_x509_rfc5280_trace_v1(&changed_chain, &fixture_crl, statement.clone())
                    .is_err(),
                "leaf extension family {label}"
            );
        }
        let root_extensions = certificate_extensions(&root_ski, &root_ski, true, 0);
        let mut invalid_ca_profiles = Vec::new();
        let mut changed = root_extensions.clone();
        changed.push(extension(
            OID_EXTENDED_KEY_USAGE_V1,
            true,
            &sequence(&[oid(OID_CLIENT_AUTHENTICATION_V1)]),
        ));
        invalid_ca_profiles.push(("CA with EKU", changed));
        let mut changed = root_extensions.clone();
        changed[3] = extension(
            OID_BASIC_CONSTRAINTS_V1,
            true,
            &sequence(&[tlv(&[0x01], &[0xff])]),
        );
        invalid_ca_profiles.push(("CA without pathLenConstraint", changed));
        let mut changed = root_extensions;
        changed[2] = extension(OID_KEY_USAGE_V1, true, &bit_string(&[0x80], 7));
        invalid_ca_profiles.push(("CA with leaf keyUsage", changed));
        for (label, extensions) in invalid_ca_profiles {
            let mut changed_chain = chain.clone();
            changed_chain[1] = certificate_with_extensions(9, &root_name, &root_name, &extensions);
            assert!(
                build_zk_x509_rfc5280_trace_v1(&changed_chain, &fixture_crl, statement.clone())
                    .is_err(),
                "{label}"
            );
        }
        let crl_extensions = crl_extensions(&root_ski, 42);
        let mut invalid_crl_profiles: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
        let mut changed = crl_extensions.clone();
        changed.swap(0, 1);
        invalid_crl_profiles.push(("extension order".into(), changed));
        let mut changed = crl_extensions.clone();
        changed.insert(1, changed[0].clone());
        invalid_crl_profiles.push(("duplicate AKI".into(), changed));
        let mut changed = crl_extensions.clone();
        changed.push(extension(&[0x2a, 0x03], false, &integer(1)));
        invalid_crl_profiles.push(("unknown extension".into(), changed));
        let mut changed = crl_extensions.clone();
        changed[0] = extension(OID_AUTHORITY_KEY_IDENTIFIER_V1, true, &aki_inner(&root_ski));
        invalid_crl_profiles.push(("critical AKI".into(), changed));
        let mut changed = crl_extensions.clone();
        changed[1] = extension(OID_CRL_NUMBER_V1, true, &integer(42));
        invalid_crl_profiles.push(("critical CRL number".into(), changed));
        let mut changed = crl_extensions.clone();
        changed[0] = extension(OID_AUTHORITY_KEY_IDENTIFIER_V1, false, &[0x30, 0x01]);
        invalid_crl_profiles.push(("truncated embedded AKI".into(), changed));
        let mut changed = crl_extensions.clone();
        let mut trailing_number = integer(42);
        trailing_number.extend_from_slice(&[0x05, 0x00]);
        changed[1] = extension(OID_CRL_NUMBER_V1, false, &trailing_number);
        invalid_crl_profiles.push(("CRL number trailing value".into(), changed));
        let mut changed = crl_extensions.clone();
        changed[1] = extension(OID_CRL_NUMBER_V1, false, &tlv(&[0x02], &[0xff]));
        invalid_crl_profiles.push(("negative CRL number".into(), changed));
        for missing in 0..crl_extensions.len() {
            let mut changed = crl_extensions.clone();
            changed.remove(missing);
            invalid_crl_profiles.push((format!("missing extension {missing}"), changed));
        }
        for (label, extensions) in invalid_crl_profiles {
            let changed_crl = crl_with_extensions(&root_name, &[10, 11], &extensions);
            assert!(
                build_zk_x509_rfc5280_trace_v1(&chain, &changed_crl, statement.clone()).is_err(),
                "CRL extension family {label}"
            );
        }
    }
    #[test]
    fn closed_rfc5280_policy_rejects_adversarial_paths_and_crls() {
        let (chain, fixture_crl, statement) = rfc5280_fixture(2, &[10, 11]);
        let invalid_statements: Vec<Box<dyn Fn(&mut ZkX509Rfc5280StatementV1)>> = vec![
            Box::new(|value| value.presentation_not_before_unix_seconds = CERT_NOT_BEFORE - 1),
            Box::new(|value| value.presentation_not_after_unix_seconds = CRL_NEXT_UPDATE),
            Box::new(|value| {
                value.presentation_not_after_unix_seconds =
                    value.presentation_not_before_unix_seconds
            }),
            Box::new(|value| {
                value.presentation_not_after_unix_seconds =
                    value.presentation_not_before_unix_seconds + 301
            }),
            Box::new(|value| value.leaf_key_usage ^= 1),
            Box::new(|value| value.leaf_extended_key_usages.clear()),
            Box::new(|value| value.crl_number += 1),
            Box::new(|value| value.disclosed_attribute_indices = vec![1, 3]),
            Box::new(|value| value.disclosed_attribute_indices = vec![3, 0]),
            Box::new(|value| value.disclosed_attribute_indices = vec![0, 0]),
            Box::new(|value| value.disclosed_attribute_indices = vec![4]),
        ];
        for (index, mutate) in invalid_statements.into_iter().enumerate() {
            let mut changed = statement.clone();
            mutate(&mut changed);
            assert!(
                build_zk_x509_rfc5280_trace_v1(&chain, &fixture_crl, changed).is_err(),
                "invalid statement family {index}"
            );
        }
        let (_, revoked_leaf_crl, revoked_statement) = rfc5280_fixture(2, &[7]);
        assert!(
            build_zk_x509_rfc5280_trace_v1(&chain, &revoked_leaf_crl, revoked_statement).is_err()
        );
        let (_, duplicate_crl, duplicate_statement) = rfc5280_fixture(2, &[10, 10]);
        assert!(
            build_zk_x509_rfc5280_trace_v1(&chain, &duplicate_crl, duplicate_statement).is_err()
        );
        let (_, descending_crl, descending_statement) = rfc5280_fixture(2, &[11, 10]);
        assert!(
            build_zk_x509_rfc5280_trace_v1(&chain, &descending_crl, descending_statement).is_err()
        );
        for ordered in [[255, 256], [510, 511]] {
            let (_, ordered_crl, ordered_statement) = rfc5280_fixture(2, &ordered);
            build_zk_x509_rfc5280_trace_v1(&chain, &ordered_crl, ordered_statement)
                .expect("strict unsigned magnitude ordering boundary");
        }
        let oversized_serials =
            (10..10 + ZK_X509_MAX_CRL_ENTRIES_V1 as u64 + 1).collect::<Vec<_>>();
        let (_, oversized_crl, oversized_statement) = rfc5280_fixture(2, &oversized_serials);
        assert!(
            build_zk_x509_rfc5280_trace_v1(&chain, &oversized_crl, oversized_statement).is_err()
        );
        let mut damaged_algorithm = chain.clone();
        let offset = damaged_algorithm[0]
            .windows(ECDSA_SHA256_ALGORITHM_V1.len())
            .position(|window| window == ECDSA_SHA256_ALGORITHM_V1)
            .expect("algorithm identifier");
        damaged_algorithm[0][offset + ECDSA_SHA256_ALGORITHM_V1.len() - 1] ^= 1;
        assert!(
            build_zk_x509_rfc5280_trace_v1(&damaged_algorithm, &fixture_crl, statement.clone())
                .is_err()
        );
        let leaf_name = name(b"IL", b"Leaf");
        let root_name = name(b"IL", b"Root");
        let other_name = name(b"IL", b"Other");
        let root_ski = [0x33; 20];
        let leaf_ski = [0x11; 20];
        let wrong_issuer_chain = vec![
            certificate(7, &other_name, &leaf_name, &leaf_ski, &root_ski, false, 0),
            certificate(9, &root_name, &root_name, &root_ski, &root_ski, true, 0),
        ];
        assert!(
            build_zk_x509_rfc5280_trace_v1(&wrong_issuer_chain, &fixture_crl, statement.clone())
                .is_err()
        );
        let wrong_aki_chain = vec![
            certificate(7, &root_name, &leaf_name, &leaf_ski, &[0x44; 20], false, 0),
            certificate(9, &root_name, &root_name, &root_ski, &root_ski, true, 0),
        ];
        assert!(
            build_zk_x509_rfc5280_trace_v1(&wrong_aki_chain, &fixture_crl, statement.clone())
                .is_err()
        );
        let wrong_issuer_crl = crl(&other_name, &root_ski, 42, &[10]);
        assert!(
            build_zk_x509_rfc5280_trace_v1(&chain, &wrong_issuer_crl, statement.clone()).is_err()
        );
        let wrong_aki_crl = crl(&root_name, &[0x44; 20], 42, &[10]);
        assert!(build_zk_x509_rfc5280_trace_v1(&chain, &wrong_aki_crl, statement.clone()).is_err());
        for (start, end) in [
            (CRL_THIS_UPDATE, CRL_THIS_UPDATE + 1),
            (CRL_NEXT_UPDATE - 2, CRL_NEXT_UPDATE - 1),
        ] {
            let mut boundary_statement = statement.clone();
            boundary_statement.presentation_not_before_unix_seconds = start;
            boundary_statement.presentation_not_after_unix_seconds = end;
            build_zk_x509_rfc5280_trace_v1(&chain, &fixture_crl, boundary_statement)
                .expect("inclusive/exclusive CRL boundary");
        }
        let (depth_three, depth_three_crl, depth_three_statement) = rfc5280_fixture(3, &[10]);
        let mut insufficient_path = depth_three;
        insufficient_path[2] =
            certificate(9, &root_name, &root_name, &root_ski, &root_ski, true, 0);
        assert!(
            build_zk_x509_rfc5280_trace_v1(
                &insufficient_path,
                &depth_three_crl,
                depth_three_statement,
            )
            .is_err()
        );
    }
    #[test]
    fn every_rfc5280_output_embedded_copy_and_path_row_family_is_bound() {
        let (chain, crl, statement) = rfc5280_fixture(3, &[10, 11]);
        let trace =
            build_zk_x509_rfc5280_trace_v1(&chain, &crl, statement).expect("RFC 5280 trace");
        let output_mutations: Vec<Box<dyn Fn(&mut ZkX509Rfc5280TraceV1)>> = vec![
            Box::new(|value| value.certificates[0].tbs_der[0] ^= 1),
            Box::new(|value| value.certificates[0].serial[0] ^= 1),
            Box::new(|value| value.certificates[0].issuer.encoded[0] ^= 1),
            Box::new(|value| value.certificates[0].subject.encoded[0] ^= 1),
            Box::new(|value| {
                value.certificates[0].subject.attributes[0]
                    .as_mut()
                    .expect("country")[0] ^= 1
            }),
            Box::new(|value| value.certificates[0].not_before += 1),
            Box::new(|value| value.certificates[0].not_after -= 1),
            Box::new(|value| value.certificates[0].spki_der[0] ^= 1),
            Box::new(|value| value.certificates[0].public_key[1] ^= 1),
            Box::new(|value| value.certificates[0].signature.encoded[0] ^= 1),
            Box::new(|value| value.certificates[0].signature.r[0] ^= 1),
            Box::new(|value| value.certificates[0].signature.s[0] ^= 1),
            Box::new(|value| value.certificates[0].extensions.authority_key_identifier[0] ^= 1),
            Box::new(|value| value.certificates[0].extensions.subject_key_identifier[0] ^= 1),
            Box::new(|value| value.certificates[0].extensions.basic_constraints_ca = true),
            Box::new(|value| value.certificates[1].extensions.basic_constraints_path_len = Some(1)),
            Box::new(|value| value.certificates[0].extensions.key_usage ^= 1),
            Box::new(|value| {
                value.certificates[0]
                    .extensions
                    .extended_key_usages
                    .as_mut()
                    .expect("leaf EKU")
                    .clear()
            }),
            Box::new(|value| value.crl.tbs_der[0] ^= 1),
            Box::new(|value| value.crl.issuer.encoded[0] ^= 1),
            Box::new(|value| value.crl.this_update += 1),
            Box::new(|value| value.crl.next_update -= 1),
            Box::new(|value| value.crl.revoked_serials[0][0] ^= 1),
            Box::new(|value| value.crl.authority_key_identifier[0] ^= 1),
            Box::new(|value| value.crl.crl_number += 1),
            Box::new(|value| value.crl.signature.encoded[0] ^= 1),
            Box::new(|value| {
                value.embedded_documents[0].bytes[0].value.value =
                    value.embedded_documents[0].bytes[0].value.value.add(F::ONE)
            }),
            Box::new(|value| {
                value.embedded_documents.remove(0);
            }),
            Box::new(|value| {
                value.embedded_byte_rows.remove(0);
            }),
        ];
        for (index, mutate) in output_mutations.into_iter().enumerate() {
            let mut changed = trace.clone();
            mutate(&mut changed);
            assert!(
                changed.validate().is_err(),
                "semantic output mutation family {index}"
            );
        }
        let embedded_mutations: [fn(&mut ZkX509DerEmbeddedByteRowV1); 12] = [
            |row| row.parent_document.value = row.parent_document.value.add(F::ONE),
            |row| row.parent_document.bits[0] = row.parent_document.bits[0].add(F::ONE),
            |row| row.parent_content_start.value = row.parent_content_start.value.add(F::ONE),
            |row| row.parent_content_start.bits[0] = row.parent_content_start.bits[0].add(F::ONE),
            |row| row.parent_offset.value = row.parent_offset.value.add(F::ONE),
            |row| row.parent_offset.bits[0] = row.parent_offset.bits[0].add(F::ONE),
            |row| row.embedded_document.value = row.embedded_document.value.add(F::ONE),
            |row| row.embedded_document.bits[0] = row.embedded_document.bits[0].add(F::ONE),
            |row| row.embedded_offset.value = row.embedded_offset.value.add(F::ONE),
            |row| row.embedded_offset.bits[0] = row.embedded_offset.bits[0].add(F::ONE),
            |row| row.value.value = row.value.value.add(F::ONE),
            |row| row.value.bits[0] = row.value.bits[0].add(F::ONE),
        ];
        for (index, mutate) in embedded_mutations.into_iter().enumerate() {
            let mut changed = trace.clone();
            mutate(&mut changed.embedded_byte_rows[0]);
            assert!(
                changed.validate().is_err(),
                "embedded byte mutation family {index}"
            );
        }
        let path_mutations: [fn(&mut ZkX509Rfc5280PathRowV1); 15] = [
            |row| row.certificate.value = row.certificate.value.add(F::ONE),
            |row| row.certificate.bits[0] = row.certificate.bits[0].add(F::ONE),
            |row| row.is_leaf = row.is_leaf.add(F::ONE),
            |row| row.is_ca = row.is_ca.add(F::ONE),
            |row| row.is_root = row.is_root.add(F::ONE),
            |row| row.after_not_before.value = row.after_not_before.value.add(F::ONE),
            |row| row.after_not_before.bits[0] = row.after_not_before.bits[0].add(F::ONE),
            |row| row.before_not_after.value = row.before_not_after.value.add(F::ONE),
            |row| row.before_not_after.bits[0] = row.before_not_after.bits[0].add(F::ONE),
            |row| row.subordinate_ca_count.value = row.subordinate_ca_count.value.add(F::ONE),
            |row| row.subordinate_ca_count.bits[0] = row.subordinate_ca_count.bits[0].add(F::ONE),
            |row| row.path_len_slack.value = row.path_len_slack.value.add(F::ONE),
            |row| row.path_len_slack.bits[0] = row.path_len_slack.bits[0].add(F::ONE),
            |row| row.issuer_name_matches_parent = row.issuer_name_matches_parent.sub(F::ONE),
            |row| row.authority_key_matches_parent = row.authority_key_matches_parent.sub(F::ONE),
        ];
        for row_index in 0..trace.path_rows.len() {
            for (mutation_index, mutate) in path_mutations.into_iter().enumerate() {
                let mut changed = trace.clone();
                mutate(&mut changed.path_rows[row_index]);
                assert!(
                    changed.validate().is_err(),
                    "path row {row_index} mutation family {mutation_index}"
                );
            }
        }
    }
    #[test]
    fn semantic_provenance_rejects_omission_duplication_role_and_address_mutations() {
        let (chain, crl, statement) = rfc5280_fixture(3, &[10, 11]);
        let trace =
            build_zk_x509_rfc5280_trace_v1(&chain, &crl, statement).expect("RFC 5280 trace");
        assert_eq!(
            trace.semantic_provenance.len(),
            trace.documents.len() + trace.embedded_documents.len()
        );
        assert!(trace.semantic_provenance.iter().all(|document| {
            document
                .nodes
                .iter()
                .enumerate()
                .all(|(node, row)| usize::from(row.node) == node)
        }));
        let mut role_swap = trace.clone();
        let original = role_swap.semantic_provenance[0].nodes[1].role;
        role_swap.semantic_provenance[0].nodes[1].role =
            role_swap.semantic_provenance[0].nodes[2].role;
        role_swap.semantic_provenance[0].nodes[2].role = original;
        assert_eq!(role_swap.validate(), Err(ZkX509DerAirErrorV1::ByteBinding));
        let mut omitted = trace.clone();
        omitted.semantic_provenance[0].nodes.pop();
        assert_eq!(omitted.validate(), Err(ZkX509DerAirErrorV1::ByteBinding));
        let mut duplicated = trace.clone();
        let duplicate = duplicated.semantic_provenance[0].nodes[1];
        duplicated.semantic_provenance[0].nodes.insert(2, duplicate);
        assert_eq!(duplicated.validate(), Err(ZkX509DerAirErrorV1::ByteBinding));
        let mut changed_address = trace.clone();
        changed_address.semantic_provenance[0].nodes[1].content_start =
            changed_address.semantic_provenance[0].nodes[1]
                .content_start
                .checked_add(1)
                .expect("fixture address has slack");
        assert_eq!(
            changed_address.validate(),
            Err(ZkX509DerAirErrorV1::ByteBinding)
        );
        let mut changed_parent = trace.clone();
        changed_parent.semantic_provenance[0].nodes[2].parent_node ^= 1;
        assert_eq!(
            changed_parent.validate(),
            Err(ZkX509DerAirErrorV1::ByteBinding)
        );
        let mut changed_instance = trace;
        changed_instance.semantic_provenance[0].nodes[1].role_instance ^= 1;
        assert_eq!(
            changed_instance.validate(),
            Err(ZkX509DerAirErrorV1::ByteBinding)
        );
    }
    include!("der_air_cleanup_tests.rs");
    include!("der_air_rfc5280_io_tests.rs");
}
