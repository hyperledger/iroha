//! Compact trust-anchor membership AIR for the first zk-X509 release.
//!
//! There is exactly one governed accumulator: a sorted, padded, 4,096-leaf
//! trust-anchor tree.  A private witness contains the exact 91-byte root SPKI,
//! a twelve-bit sorted-leaf index, and twelve siblings.  Row zero owns the
//! occupied-leaf SHA call; rows one through twelve own the height-bound node
//! calls; rows 13 through 103 serialize the exact root SPKI; the remaining 3,992 rows
//! are canonical zero padding for a log-twelve native trace.
//!
//! Signed-CRL non-revocation is deliberately absent from this module.  The RFC
//! adapter parses the complete signed CRL and proves the leaf serial differs
//! from every canonical entry, while the shared SHA adapter binds the exact
//! signed-DER and governance-record commitments.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::{PrivateTableV1, zeroize_words_v1};

use super::merkle::{
    ZK_X509_CA_COMPACT_TREE_CAPACITY_V1, ZK_X509_CA_COMPACT_TREE_DEPTH_V1,
    ZK_X509_CA_SPKI_DER_BYTES_V1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    merkle::{
        ZkX509CaMembershipPathV1, ZkX509MerkleErrorV1, ca_leaf_preimage_v1, ca_leaf_v1,
        ca_node_preimage_v1, ca_node_v1,
    },
    sha_call_bus_stark::{ZkX509ShaCallRoleV1, ZkX509ShaCallWitnessV1},
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use thiserror::Error;
/// Thirteen hash rows plus 91 serialized SPKI bytes, padded to log twelve with the complete cross-proof mask closure.
pub const ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1: usize = 4_096;
/// One leaf call followed by twelve compact-tree node calls.
pub const ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1: usize = 1 + ZK_X509_CA_COMPACT_TREE_DEPTH_V1;
/// One exact row per root-SPKI DER byte.
pub const ZK_X509_CA_ACCUMULATOR_IO_ROWS_V1: usize = ZK_X509_CA_SPKI_DER_BYTES_V1;
/// First serialized root-SPKI byte row.
pub const ZK_X509_CA_ACCUMULATOR_IO_START_V1: usize = ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1;
/// All hash and serialized-byte rows before canonical padding.
pub const ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1: usize =
    ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 + ZK_X509_CA_ACCUMULATOR_IO_ROWS_V1;
/// Exact challenge-independent base width.
pub const ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1: usize = 695;
/// Base-only residue count before the four-lane SHA-call products.
pub const ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1: usize = 1_219;
pub const CA_CURRENT_START: usize = 0;
pub const CA_SIBLING_START: usize = CA_CURRENT_START + 32;
pub const CA_LEFT_START: usize = CA_SIBLING_START + 32;
pub const CA_RIGHT_START: usize = CA_LEFT_START + 32;
pub const CA_DIGEST_START: usize = CA_RIGHT_START + 32;
pub const CA_INDEX_BITS_START: usize = CA_DIGEST_START + 32;
pub const CA_DIRECTION: usize = CA_INDEX_BITS_START + ZK_X509_CA_COMPACT_TREE_DEPTH_V1;
pub const CA_DIGEST_BYTE_BITS_START: usize = CA_DIRECTION + 1;
pub const CA_SIBLING_BYTE_BITS_START: usize = CA_DIGEST_BYTE_BITS_START + 32 * 8;
pub const CA_IO_BYTE: usize = CA_SIBLING_BYTE_BITS_START + 32 * 8;
pub const CA_IO_WORD_ACC: usize = CA_IO_BYTE + 1;
pub const CA_IO_BYTE_BITS_START: usize = CA_IO_WORD_ACC + 1;
/// Byte immediately before the 91-byte dynamic SPKI field in the leaf frame.
pub const ZK_X509_CA_LEAF_SPKI_PREFIX_BYTE_V1: u8 = 91;
/// First byte offset of the dynamic SPKI within the canonical leaf frame.
pub const ZK_X509_CA_LEAF_SPKI_MESSAGE_OFFSET_V1: usize = 65;
const _: () = {
    assert!(ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 == 1 << ZK_X509_CA_COMPACT_TREE_DEPTH_V1);
    assert!(ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 == 13);
    assert!(ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 == 104);
    assert!(CA_IO_BYTE_BITS_START + 8 == ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1);
};
/// Public statement selected by the verifier.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorStatementV1 {
    /// Governed compact trust-anchor root.
    pub(crate) governed_root: [u8; 32],
}
/// Exact private compact membership witness.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorWitnessV1 {
    /// Exact canonical root-certificate SPKI DER.
    pub(crate) root_spki_der: [u8; ZK_X509_CA_SPKI_DER_BYTES_V1],
    /// Private sorted-leaf index and twelve leaf-to-root siblings.
    pub(crate) path: ZkX509CaMembershipPathV1,
}
/// Semantic kind of one fixed native row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkX509CaAccumulatorRowKindV1 {
    /// Occupied-leaf SHA call.
    Leaf,
    /// Internal-node SHA call at the contained leaf-to-root level.
    Node(u8),
    /// One exact root-SPKI DER byte at the contained offset.
    RootSpkiByte(u8),
    /// Canonical inactive row.
    Padding,
}
/// Verifier-owned location of one native row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorFixedRowV1 {
    /// Native row index.
    pub(crate) row: u16,
    /// Sole legal semantic row kind.
    pub(crate) kind: ZkX509CaAccumulatorRowKindV1,
}
impl ZkX509CaAccumulatorFixedRowV1 {
    /// Whether this row owns a SHA call.
    pub(crate) const fn sha_active(self) -> bool {
        matches!(
            self.kind,
            ZkX509CaAccumulatorRowKindV1::Leaf | ZkX509CaAccumulatorRowKindV1::Node(_)
        )
    }
    /// Whether the next row is another SHA call.
    pub(crate) const fn sha_transition(self) -> bool {
        (self.row as usize) + 1 < ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1
    }
    /// Whether the next row is another serialized SPKI byte.
    pub(crate) const fn io_transition(self) -> bool {
        matches!(
            self.kind,
            ZkX509CaAccumulatorRowKindV1::RootSpkiByte(offset)
                if offset as usize + 1 < ZK_X509_CA_ACCUMULATOR_IO_ROWS_V1
        )
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CaAccumulatorRowV1 {
    current: [u8; 32],
    sibling: [u8; 32],
    left: [u8; 32],
    right: [u8; 32],
    digest: [u8; 32],
    index_bits: [u8; ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
    direction: u8,
    io_byte: u8,
    io_word_acc: u32,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Default for CaAccumulatorRowV1 {
    fn default() -> Self {
        Self::padding()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::DefaultIsZeroes for CaAccumulatorRowV1 {}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl CaAccumulatorRowV1 {
    const fn padding() -> Self {
        Self {
            current: [0; 32],
            sibling: [0; 32],
            left: [0; 32],
            right: [0; 32],
            digest: [0; 32],
            index_bits: [0; ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
            direction: 0,
            io_byte: 0,
            io_word_acc: 0,
        }
    }
    fn fields(self) -> [F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1] {
        let mut fields = [F::ZERO; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1];
        write_bytes_v1(
            &mut fields[CA_CURRENT_START..CA_CURRENT_START + 32],
            &self.current,
        );
        write_bytes_v1(
            &mut fields[CA_SIBLING_START..CA_SIBLING_START + 32],
            &self.sibling,
        );
        write_bytes_v1(&mut fields[CA_LEFT_START..CA_LEFT_START + 32], &self.left);
        write_bytes_v1(
            &mut fields[CA_RIGHT_START..CA_RIGHT_START + 32],
            &self.right,
        );
        write_bytes_v1(
            &mut fields[CA_DIGEST_START..CA_DIGEST_START + 32],
            &self.digest,
        );
        write_bytes_v1(
            &mut fields
                [CA_INDEX_BITS_START..CA_INDEX_BITS_START + ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
            &self.index_bits,
        );
        fields[CA_DIRECTION] = F(u64::from(self.direction));
        write_byte_bits_v1(
            &mut fields[CA_DIGEST_BYTE_BITS_START..CA_DIGEST_BYTE_BITS_START + 32 * 8],
            &self.digest,
        );
        write_byte_bits_v1(
            &mut fields[CA_SIBLING_BYTE_BITS_START..CA_SIBLING_BYTE_BITS_START + 32 * 8],
            &self.sibling,
        );
        fields[CA_IO_BYTE] = F(u64::from(self.io_byte));
        fields[CA_IO_WORD_ACC] = F(u64::from(self.io_word_acc));
        write_byte_bits_v1(
            &mut fields[CA_IO_BYTE_BITS_START..CA_IO_BYTE_BITS_START + 8],
            &[self.io_byte],
        );
        fields
    }
}
/// Complete compact accumulator witness and canonical SHA calls.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorTraceV1 {
    /// Verifier-bound governed root.
    pub(crate) statement: ZkX509CaAccumulatorStatementV1,
    /// Exact private source values.
    pub(crate) witness: ZkX509CaAccumulatorWitnessV1,
    rows: [CaAccumulatorRowV1; ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1],
    /// Leaf then twelve node calls, in the shared schedule's exact order.
    pub(crate) hash_witnesses: [ZkX509ShaCallWitnessV1; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509CaAccumulatorTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkX509CaAccumulatorTraceV1")
            .field("statement", &self.statement)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509CaAccumulatorTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509CaAccumulatorTraceV1 {
    /// Overwrite the private path, derived row state, and all SHA preimages.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_words_v1(&mut self.witness.root_spki_der);
        zeroize_words_v1(core::slice::from_mut(&mut self.witness.path.index));
        zeroize_words_v1(&mut self.witness.path.siblings);
        zeroize_words_v1(&mut self.rows);
        for witness in &mut self.hash_witnesses {
            witness.zeroize_private_v1();
        }
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.witness.root_spki_der == [0; ZK_X509_CA_SPKI_DER_BYTES_V1]
            && self.witness.path.index == 0
            && self
                .witness
                .path
                .siblings
                .iter()
                .all(|sibling| *sibling == [0; 32])
            && self
                .rows
                .iter()
                .all(|row| *row == CaAccumulatorRowV1::padding())
            && self
                .hash_witnesses
                .iter()
                .all(ZkX509ShaCallWitnessV1::private_is_zeroized_v1)
    }
    /// Fixed native row count, including 8,088 canonical inactive rows.
    #[cfg(test)]
    pub(crate) const fn rows(&self) -> usize {
        ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
    }
    /// Materialize one base row.
    pub(crate) fn base_row(
        &self,
        index: usize,
    ) -> Result<[F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1], ZkX509AccumulatorAirErrorV1> {
        if index >= ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
            return Err(ZkX509AccumulatorAirErrorV1::Topology);
        }
        Ok(self
            .rows
            .get(index)
            .copied()
            .unwrap_or_else(CaAccumulatorRowV1::padding)
            .fields())
    }
    /// Differentially rebuild and algebraically validate every row.
    pub(crate) fn validate(&self) -> Result<(), ZkX509AccumulatorAirErrorV1> {
        let expected = compile_ca_accumulator_trace_v1(self.statement, self.witness)?;
        if self != &expected {
            return Err(ZkX509AccumulatorAirErrorV1::Constraint);
        }
        validate_ca_arithmetic_v1(self)
    }
}
/// Compact accumulator construction or constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509AccumulatorAirErrorV1 {
    /// A row, call, or fixed location is outside the sole schedule.
    #[error("zk-X509 compact CA accumulator topology is invalid")]
    Topology,
    /// The private sorted-leaf index is not twelve-bit.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact CA accumulator index is invalid")]
    Index,
    /// The exact root SPKI or canonical hash frame is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact CA accumulator hash input is invalid")]
    HashInput,
    /// The private path does not terminate at the governed root.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact CA accumulator root is invalid")]
    Root,
    /// A Boolean, range, transition, selection, or padding identity failed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact CA accumulator constraint is invalid")]
    Constraint,
    /// A fixed conversion or bounded allocation failed.
    #[error("zk-X509 compact CA accumulator resource bound is exceeded")]
    Resource,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl From<ZkX509MerkleErrorV1> for ZkX509AccumulatorAirErrorV1 {
    fn from(error: ZkX509MerkleErrorV1) -> Self {
        match error {
            ZkX509MerkleErrorV1::InvalidPathIndex { .. } => Self::Index,
            ZkX509MerkleErrorV1::RootMismatch => Self::Root,
            _ => Self::HashInput,
        }
    }
}
/// Return the sole fixed row at one native index.
pub fn ca_accumulator_fixed_row_v1(
    index: usize,
) -> Result<ZkX509CaAccumulatorFixedRowV1, ZkX509AccumulatorAirErrorV1> {
    let kind = match index {
        0 => ZkX509CaAccumulatorRowKindV1::Leaf,
        1..=ZK_X509_CA_COMPACT_TREE_DEPTH_V1 => ZkX509CaAccumulatorRowKindV1::Node(
            u8::try_from(index - 1).map_err(|_| ZkX509AccumulatorAirErrorV1::Resource)?,
        ),
        ZK_X509_CA_ACCUMULATOR_IO_START_V1..ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 => {
            ZkX509CaAccumulatorRowKindV1::RootSpkiByte(
                u8::try_from(index - ZK_X509_CA_ACCUMULATOR_IO_START_V1)
                    .map_err(|_| ZkX509AccumulatorAirErrorV1::Resource)?,
            )
        }
        ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 => {
            ZkX509CaAccumulatorRowKindV1::Padding
        }
        _ => return Err(ZkX509AccumulatorAirErrorV1::Topology),
    };
    Ok(ZkX509CaAccumulatorFixedRowV1 {
        row: u16::try_from(index).map_err(|_| ZkX509AccumulatorAirErrorV1::Resource)?,
        kind,
    })
}
/// Compile and validate the sole compact membership trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_ca_accumulator_trace_v1(
    statement: ZkX509CaAccumulatorStatementV1,
    witness: ZkX509CaAccumulatorWitnessV1,
) -> Result<ZkX509CaAccumulatorTraceV1, ZkX509AccumulatorAirErrorV1> {
    let trace = compile_ca_accumulator_trace_v1(statement, witness)?;
    validate_ca_arithmetic_v1(&trace)?;
    Ok(trace)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compile_ca_accumulator_trace_v1(
    statement: ZkX509CaAccumulatorStatementV1,
    witness: ZkX509CaAccumulatorWitnessV1,
) -> Result<ZkX509CaAccumulatorTraceV1, ZkX509AccumulatorAirErrorV1> {
    if usize::from(witness.path.index) >= ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 {
        return Err(ZkX509AccumulatorAirErrorV1::Index);
    }
    let index_bits = core::array::from_fn(|bit| u8::from(witness.path.index & (1_u16 << bit) != 0));
    let leaf_preimage = PrivateTableV1::new(
        ca_leaf_preimage_v1(&witness.root_spki_der)?,
        zeroize_words_v1,
    );
    let leaf_digest = ca_leaf_v1(&witness.root_spki_der)?;
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
    let mut hash_witnesses = Vec::new();
    rows.try_reserve_exact(ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1)
        .map_err(|_| ZkX509AccumulatorAirErrorV1::Resource)?;
    hash_witnesses
        .try_reserve_exact(ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1)
        .map_err(|_| ZkX509AccumulatorAirErrorV1::Resource)?;
    rows.push(CaAccumulatorRowV1 {
        current: leaf_digest,
        sibling: [0; 32],
        left: [0; 32],
        right: [0; 32],
        digest: leaf_digest,
        index_bits,
        direction: 0,
        io_byte: 0,
        io_word_acc: 0,
    });
    hash_witnesses.push(ZkX509ShaCallWitnessV1 {
        role: ZkX509ShaCallRoleV1::CaLeaf,
        message: leaf_preimage.into_vec(),
        digest: leaf_digest,
    });
    let mut current = leaf_digest;
    for (level, sibling) in witness.path.siblings.iter().copied().enumerate() {
        let direction = index_bits[level];
        let (left, right) = if direction == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        let preimage =
            PrivateTableV1::new(ca_node_preimage_v1(level, &left, &right)?, zeroize_words_v1);
        let digest = ca_node_v1(level, &left, &right)?;
        rows.push(CaAccumulatorRowV1 {
            current,
            sibling,
            left,
            right,
            digest,
            index_bits,
            direction,
            io_byte: 0,
            io_word_acc: 0,
        });
        hash_witnesses.push(ZkX509ShaCallWitnessV1 {
            role: ZkX509ShaCallRoleV1::CaNode(
                u8::try_from(level).map_err(|_| ZkX509AccumulatorAirErrorV1::Resource)?,
            ),
            message: preimage.into_vec(),
            digest,
        });
        current = digest;
    }
    if current != statement.governed_root {
        return Err(ZkX509AccumulatorAirErrorV1::Root);
    }
    let mut word_acc = 0_u32;
    for (offset, byte) in witness.root_spki_der.iter().copied().enumerate() {
        let message_offset = ZK_X509_CA_LEAF_SPKI_MESSAGE_OFFSET_V1
            .checked_add(offset)
            .ok_or(ZkX509AccumulatorAirErrorV1::Resource)?;
        word_acc = if offset == 0 {
            u32::from(ZK_X509_CA_LEAF_SPKI_PREFIX_BYTE_V1)
                .checked_mul(256)
                .and_then(|value| value.checked_add(u32::from(byte)))
                .ok_or(ZkX509AccumulatorAirErrorV1::Resource)?
        } else if message_offset % 4 == 0 {
            u32::from(byte)
        } else {
            word_acc
                .checked_mul(256)
                .and_then(|value| value.checked_add(u32::from(byte)))
                .ok_or(ZkX509AccumulatorAirErrorV1::Resource)?
        };
        rows.push(CaAccumulatorRowV1 {
            current: [0; 32],
            sibling: [0; 32],
            left: [0; 32],
            right: [0; 32],
            digest: [0; 32],
            index_bits: [0; ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
            direction: 0,
            io_byte: byte,
            io_word_acc: word_acc,
        });
    }
    let hash_witnesses = hash_witnesses
        .try_into()
        .map_err(|_: Vec<ZkX509ShaCallWitnessV1>| ZkX509AccumulatorAirErrorV1::Topology)?;
    let rows = rows
        .as_slice()
        .try_into()
        .map_err(|_| ZkX509AccumulatorAirErrorV1::Topology)?;
    Ok(ZkX509CaAccumulatorTraceV1 {
        statement,
        witness,
        rows,
        hash_witnesses,
    })
}
/// Evaluate the exact base-only residue vector at one current/next row.
///
/// SHA compression is intentionally external: the proof-facing adapter adds
/// four-lane call-product transitions to these identities.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_ca_accumulator_base_constraints_v1(
    fixed: ZkX509CaAccumulatorFixedRowV1,
    row: &[F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
    next: Option<&[F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1]>,
    governed_root: [F; 32],
) -> Vec<F> {
    let leaf = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::Leaf
    )));
    let node = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::Node(_)
    )));
    let io = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::RootSpkiByte(_)
    )));
    let padding = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::Padding
    )));
    let sha_active = leaf.add(node);
    let sha_transition = F(u64::from(fixed.sha_transition()));
    let io_transition = F(u64::from(fixed.io_transition()));
    let last = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::Node(level)
            if usize::from(level) + 1 == ZK_X509_CA_COMPACT_TREE_DEPTH_V1
    )));
    let mut residues = Vec::with_capacity(ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1);
    let digest_bits = &row[CA_DIGEST_BYTE_BITS_START..CA_DIGEST_BYTE_BITS_START + 32 * 8];
    let sibling_bits = &row[CA_SIBLING_BYTE_BITS_START..CA_SIBLING_BYTE_BITS_START + 32 * 8];
    let io_byte_bits = &row[CA_IO_BYTE_BITS_START..CA_IO_BYTE_BITS_START + 8];
    residues.extend(
        digest_bits
            .iter()
            .chain(sibling_bits.iter())
            .chain(io_byte_bits.iter())
            .map(|bit| bit.mul(bit.sub(F::ONE))),
    );
    for byte in 0..32 {
        residues.push(
            pack_little_bits_v1(&digest_bits[byte * 8..byte * 8 + 8])
                .sub(row[CA_DIGEST_START + byte]),
        );
        residues.push(
            pack_little_bits_v1(&sibling_bits[byte * 8..byte * 8 + 8])
                .sub(row[CA_SIBLING_START + byte]),
        );
    }
    residues.push(pack_little_bits_v1(io_byte_bits).sub(row[CA_IO_BYTE]));
    let index_bits =
        &row[CA_INDEX_BITS_START..CA_INDEX_BITS_START + ZK_X509_CA_COMPACT_TREE_DEPTH_V1];
    residues.extend(
        index_bits
            .iter()
            .map(|bit| sha_active.mul(bit.mul(bit.sub(F::ONE)))),
    );
    let selected_direction = match fixed.kind {
        ZkX509CaAccumulatorRowKindV1::Node(level) => index_bits[usize::from(level)],
        ZkX509CaAccumulatorRowKindV1::Leaf
        | ZkX509CaAccumulatorRowKindV1::RootSpkiByte(_)
        | ZkX509CaAccumulatorRowKindV1::Padding => F::ZERO,
    };
    residues.push(sha_active.mul(row[CA_DIRECTION].sub(selected_direction)));
    for bit in 0..ZK_X509_CA_COMPACT_TREE_DEPTH_V1 {
        let next_bit = next.map_or(F::ZERO, |next| next[CA_INDEX_BITS_START + bit]);
        residues.push(sha_transition.mul(next_bit.sub(index_bits[bit])));
    }
    for byte in 0..32 {
        let next_current = next.map_or(F::ZERO, |next| next[CA_CURRENT_START + byte]);
        residues.push(sha_transition.mul(next_current.sub(row[CA_DIGEST_START + byte])));
        residues.push(leaf.mul(row[CA_CURRENT_START + byte].sub(row[CA_DIGEST_START + byte])));
    }
    for column in [CA_SIBLING_START, CA_LEFT_START, CA_RIGHT_START] {
        residues.extend(
            row[column..column + 32]
                .iter()
                .map(|value| leaf.mul(*value)),
        );
    }
    residues.push(leaf.mul(row[CA_DIRECTION]));
    let direction = row[CA_DIRECTION];
    for byte in 0..32 {
        let current = row[CA_CURRENT_START + byte];
        let sibling = row[CA_SIBLING_START + byte];
        let left = current.add(direction.mul(sibling.sub(current)));
        let right = sibling.add(direction.mul(current.sub(sibling)));
        residues.push(node.mul(row[CA_LEFT_START + byte].sub(left)));
        residues.push(node.mul(row[CA_RIGHT_START + byte].sub(right)));
    }
    for byte in 0..32 {
        residues.push(last.mul(row[CA_DIGEST_START + byte].sub(governed_root[byte])));
    }
    // The serialized rows carry only the I/O byte and its word accumulator.
    // Zeroing the hash prefix forces its packed digest/sibling bits to zero.
    residues.extend(
        row[..CA_DIGEST_BYTE_BITS_START]
            .iter()
            .map(|value| io.mul(*value)),
    );
    residues.push(sha_active.mul(row[CA_IO_BYTE]));
    residues.push(sha_active.mul(row[CA_IO_WORD_ACC]));
    let io_first = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::RootSpkiByte(0)
    )));
    residues.push(
        io_first.mul(
            row[CA_IO_WORD_ACC].sub(
                F(u64::from(ZK_X509_CA_LEAF_SPKI_PREFIX_BYTE_V1))
                    .mul(F(256))
                    .add(row[CA_IO_BYTE]),
            ),
        ),
    );
    let same_word_to_next = F(u64::from(matches!(
        fixed.kind,
        ZkX509CaAccumulatorRowKindV1::RootSpkiByte(offset)
            if (ZK_X509_CA_LEAF_SPKI_MESSAGE_OFFSET_V1 + usize::from(offset) + 1) % 4 != 0
    )));
    let next_io_byte = next.map_or(F::ZERO, |next| next[CA_IO_BYTE]);
    let next_word_acc = next.map_or(F::ZERO, |next| next[CA_IO_WORD_ACC]);
    residues.push(
        io_transition.mul(
            next_word_acc.sub(
                same_word_to_next
                    .mul(row[CA_IO_WORD_ACC])
                    .mul(F(256))
                    .add(next_io_byte),
            ),
        ),
    );
    // Bit columns are already Boolean and packed into raw byte columns. On a
    // padding row, zeroing raw columns uniquely forces every bit column zero.
    residues.extend(
        row[..CA_DIGEST_BYTE_BITS_START]
            .iter()
            .map(|value| padding.mul(*value)),
    );
    residues.push(padding.mul(row[CA_IO_BYTE]));
    residues.push(padding.mul(row[CA_IO_WORD_ACC]));
    debug_assert_eq!(
        residues.len(),
        ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1
    );
    residues
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_ca_arithmetic_v1(
    trace: &ZkX509CaAccumulatorTraceV1,
) -> Result<(), ZkX509AccumulatorAirErrorV1> {
    let root = byte_fields_v1(trace.statement.governed_root);
    let rows = (0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
        .map(|index| trace.base_row(index))
        .collect::<Result<Vec<_>, _>>()?;
    for index in 0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
        let residues = evaluate_ca_accumulator_base_constraints_v1(
            ca_accumulator_fixed_row_v1(index)?,
            &rows[index],
            rows.get(index + 1),
            root,
        );
        if residues.len() != ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1
            || residues.iter().any(|residue| *residue != F::ZERO)
        {
            return Err(ZkX509AccumulatorAirErrorV1::Constraint);
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_bytes_v1(target: &mut [F], bytes: &[u8]) {
    debug_assert_eq!(target.len(), bytes.len());
    for (target, byte) in target.iter_mut().zip(bytes.iter().copied()) {
        *target = F(u64::from(byte));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_byte_bits_v1(target: &mut [F], bytes: &[u8]) {
    debug_assert_eq!(target.len(), bytes.len() * 8);
    for (byte_index, byte) in bytes.iter().copied().enumerate() {
        for bit in 0..8 {
            target[byte_index * 8 + bit] = F(u64::from((byte >> bit) & 1));
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn pack_little_bits_v1(bits: &[F]) -> F {
    bits.iter().enumerate().fold(F::ZERO, |value, (bit, cell)| {
        value.add(cell.mul(F(1_u64 << bit)))
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn byte_fields_v1(bytes: [u8; 32]) -> [F; 32] {
    bytes.map(|byte| F(u64::from(byte)))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::merkle::{
        ca_membership_path_from_complete_spkis_v1, ca_root_from_complete_spkis_v1,
    };
    fn spki(index: u16) -> [u8; ZK_X509_CA_SPKI_DER_BYTES_V1] {
        let mut spki = [0x42_u8; ZK_X509_CA_SPKI_DER_BYTES_V1];
        spki[..2].copy_from_slice(&index.to_be_bytes());
        spki
    }
    fn fixture() -> (ZkX509CaAccumulatorStatementV1, ZkX509CaAccumulatorWitnessV1) {
        let members = [spki(8), spki(2), spki(5), spki(1)];
        let refs = members
            .iter()
            .map(|member: &[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]| member.as_slice())
            .collect::<Vec<_>>();
        let root = ca_root_from_complete_spkis_v1(&refs).expect("root");
        let path = ca_membership_path_from_complete_spkis_v1(&refs, &members[2]).expect("path");
        (
            ZkX509CaAccumulatorStatementV1 {
                governed_root: root,
            },
            ZkX509CaAccumulatorWitnessV1 {
                root_spki_der: members[2],
                path,
            },
        )
    }
    #[test]
    fn owned_ca_source_erasure_covers_drop_invalid_root_and_unwind() {
        use super::super::private_table::inspection;
        let (statement, witness) = fixture();
        let original = build_ca_accumulator_trace_v1(statement, witness).unwrap();
        for mode in 0..3 {
            let trace = original.clone();
            let (result, observed) = inspection::observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut trace = trace;
                    if mode == 0 {
                        trace.zeroize_private_v1();
                        assert!(trace.private_is_zeroized_v1());
                        assert_eq!(trace.statement, statement);
                        Ok(())
                    } else if mode == 1 {
                        Err(())
                    } else {
                        panic!("injected CA source unwind")
                    }
                }))
            });
            assert_eq!(result.is_err(), mode == 2);
            assert!(observed.iter().any(|item| item.cells
                == ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1
                && item.nonzero_before >= ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1));
            assert!(observed.iter().all(|item| item.nonzero_after == 0));
        }
        let mut wrong_root = statement;
        wrong_root.governed_root[0] ^= 1;
        let (result, observed) =
            inspection::observe_v1(|| build_ca_accumulator_trace_v1(wrong_root, witness));
        assert!(matches!(result, Err(ZkX509AccumulatorAirErrorV1::Root)));
        // Root comparison fails after all thirteen private path rows have been
        // written, before any final trace owner exists.
        assert!(
            observed
                .iter()
                .any(|item| item.cells == ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1
                    && item.nonzero_before == item.cells)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }
    #[test]
    fn compact_trace_is_exact_and_uses_only_thirteen_sha_calls() {
        let (statement, witness) = fixture();
        let trace = build_ca_accumulator_trace_v1(statement, witness).expect("trace");
        trace.validate().expect("valid");
        assert_eq!(trace.rows(), 4_096);
        assert_eq!(trace.hash_witnesses.len(), 13);
        assert_eq!(trace.hash_witnesses[0].role, ZkX509ShaCallRoleV1::CaLeaf);
        assert_eq!(trace.hash_witnesses[0].message.len(), 156);
        for (level, call) in trace.hash_witnesses[1..].iter().enumerate() {
            assert_eq!(
                call.role,
                ZkX509ShaCallRoleV1::CaNode(u8::try_from(level).expect("level"))
            );
            assert_eq!(call.message.len(), 147);
        }
        let mut expected_word = 0_u32;
        for (offset, byte) in trace.witness.root_spki_der.iter().copied().enumerate() {
            let message_offset = ZK_X509_CA_LEAF_SPKI_MESSAGE_OFFSET_V1 + offset;
            expected_word = if offset == 0 {
                u32::from(ZK_X509_CA_LEAF_SPKI_PREFIX_BYTE_V1) * 256 + u32::from(byte)
            } else if message_offset % 4 == 0 {
                u32::from(byte)
            } else {
                expected_word * 256 + u32::from(byte)
            };
            let row = trace
                .base_row(ZK_X509_CA_ACCUMULATOR_IO_START_V1 + offset)
                .expect("serialized root SPKI");
            assert_eq!(row[CA_IO_BYTE], F(u64::from(byte)));
            assert_eq!(row[CA_IO_WORD_ACC], F(u64::from(expected_word)));
        }
        for index in ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
        {
            assert!(
                trace
                    .base_row(index)
                    .expect("padding")
                    .iter()
                    .all(|value| *value == F::ZERO)
            );
        }
    }
    #[test]
    fn index_sibling_spki_root_and_order_mutations_fail_closed() {
        let (statement, witness) = fixture();
        let mut bad_index = witness;
        bad_index.path.index = 4_096;
        assert_eq!(
            build_ca_accumulator_trace_v1(statement, bad_index),
            Err(ZkX509AccumulatorAirErrorV1::Index)
        );
        let mut bad_sibling = witness;
        bad_sibling.path.siblings[4][9] ^= 1;
        assert_eq!(
            build_ca_accumulator_trace_v1(statement, bad_sibling),
            Err(ZkX509AccumulatorAirErrorV1::Root)
        );
        let mut swapped = witness;
        swapped.path.siblings.swap(2, 3);
        assert_eq!(
            build_ca_accumulator_trace_v1(statement, swapped),
            Err(ZkX509AccumulatorAirErrorV1::Root)
        );
        let mut bad_spki = witness;
        bad_spki.root_spki_der[17] ^= 1;
        assert_eq!(
            build_ca_accumulator_trace_v1(statement, bad_spki),
            Err(ZkX509AccumulatorAirErrorV1::Root)
        );
        let mut bad_root = statement;
        bad_root.governed_root[0] ^= 1;
        assert_eq!(
            build_ca_accumulator_trace_v1(bad_root, witness),
            Err(ZkX509AccumulatorAirErrorV1::Root)
        );
    }
    #[test]
    fn every_base_cell_family_is_algebraically_live() {
        let (statement, witness) = fixture();
        let trace = build_ca_accumulator_trace_v1(statement, witness).expect("trace");
        let root = byte_fields_v1(statement.governed_root);
        let mut rows = (0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
            .map(|index| trace.base_row(index).expect("row"))
            .collect::<Vec<_>>();
        for (row_index, column) in [
            (0, CA_CURRENT_START),
            (0, CA_DIGEST_START),
            (0, CA_DIGEST_BYTE_BITS_START),
            (1, CA_SIBLING_START),
            (1, CA_LEFT_START),
            (1, CA_RIGHT_START),
            (1, CA_INDEX_BITS_START),
            (1, CA_DIRECTION),
            (1, CA_SIBLING_BYTE_BITS_START),
            (12, CA_DIGEST_START + 31),
            (ZK_X509_CA_ACCUMULATOR_IO_START_V1, CA_IO_BYTE),
            (ZK_X509_CA_ACCUMULATOR_IO_START_V1, CA_IO_BYTE_BITS_START),
            (ZK_X509_CA_ACCUMULATOR_IO_START_V1, CA_IO_WORD_ACC),
            (ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1, CA_CURRENT_START),
        ] {
            rows[row_index][column] = rows[row_index][column].add(F::ONE);
            let rejected = (0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1).any(|index| {
                evaluate_ca_accumulator_base_constraints_v1(
                    ca_accumulator_fixed_row_v1(index).expect("fixed"),
                    &rows[index],
                    rows.get(index + 1),
                    root,
                )
                .iter()
                .any(|residue| *residue != F::ZERO)
            });
            assert!(rejected, "mutation row={row_index}, column={column}");
            rows[row_index][column] = rows[row_index][column].sub(F::ONE);
        }
    }
    #[test]
    fn root_spki_fields_are_independently_byte_range_constrained() {
        let (statement, witness) = fixture();
        let trace = build_ca_accumulator_trace_v1(statement, witness).expect("trace");
        let root = byte_fields_v1(statement.governed_root);
        let row_index = ZK_X509_CA_ACCUMULATOR_IO_START_V1 + 17;
        let fixed = ca_accumulator_fixed_row_v1(row_index).expect("serialized byte");
        let next = trace.base_row(row_index + 1).expect("next");
        let mut out_of_range = trace.base_row(row_index).expect("serialized byte");
        out_of_range[CA_IO_BYTE] = F(256);
        assert!(
            evaluate_ca_accumulator_base_constraints_v1(fixed, &out_of_range, Some(&next), root,)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut non_boolean_bit = trace.base_row(row_index).expect("serialized byte");
        non_boolean_bit[CA_IO_BYTE_BITS_START] = F(2);
        assert!(
            evaluate_ca_accumulator_base_constraints_v1(
                fixed,
                &non_boolean_bit,
                Some(&next),
                root,
            )
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
    }
    #[test]
    fn fixed_schedule_rejects_out_of_range_rows() {
        assert_eq!(
            ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1),
            Err(ZkX509AccumulatorAirErrorV1::Topology)
        );
        assert!(matches!(
            ca_accumulator_fixed_row_v1(0).expect("leaf").kind,
            ZkX509CaAccumulatorRowKindV1::Leaf
        ));
        assert!(matches!(
            ca_accumulator_fixed_row_v1(12).expect("node").kind,
            ZkX509CaAccumulatorRowKindV1::Node(11)
        ));
        assert!(matches!(
            ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_IO_START_V1)
                .expect("first serialized byte")
                .kind,
            ZkX509CaAccumulatorRowKindV1::RootSpkiByte(0)
        ));
        assert!(matches!(
            ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1)
                .expect("last serialized byte")
                .kind,
            ZkX509CaAccumulatorRowKindV1::RootSpkiByte(90)
        ));
        assert!(matches!(
            ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 - 1)
                .expect("padding")
                .kind,
            ZkX509CaAccumulatorRowKindV1::Padding
        ));
    }
}
