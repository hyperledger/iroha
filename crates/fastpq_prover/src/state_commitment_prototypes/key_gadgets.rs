//! Gadgets that a private key needs beside the hash chain. Development only.
//!
//! [`super::circuit`] verifies a witness whose skeleton is verifier-known: the
//! structural checks without a hash (a disclosed neighbour is below a key, a
//! direction is a bit of a key) run on public values when the program is
//! derived. A relation that hides the key has to constrain them. This module
//! builds the two gadgets that takes as relations of their own, written
//! against [`crate::air::SemanticAir`], so their cost is measured rather than
//! estimated:
//!
//! - [`KeyOrderAir`]: one byte string is below (or not above) another in byte
//!   order, the order of the keyed State contract;
//! - [`KeyBitAir`]: stated bits of the order-preserving, prefix-free bit
//!   encoding of a key (the radix tree's `ByteKey`), which are the directions of a
//!   radix path.
//!
//! Both scan one byte per row and tie the bytes to the packing the sponge
//! absorbs ([`super::hash::pack_bytes`]): the byte length and seven-byte
//! little-endian limbs. In these standalone relations the limbs and the length
//! are verifier-known columns. In a relation that hides the key they are the
//! private message words of the sponge, shared by both row sets.
//!
//! What this does **not** establish: the gadgets are not composed into the
//! hash-chain trace. A complete private-key witness relation still has to
//! place the byte scan beside the sponge rows, make the message words private,
//! hide the branching indices behind private one-hot selectors, and constrain
//! the shape rules of a range witness. Its width and degree are those of the
//! composed trace, not the sum of the figures here.
//!
//! TODO(G.3): compose the gadgets of the selected construction into its
//! witness relation, or delete them with the prototypes. TODO(B.2): committed
//! proofs.

use sha2::{Digest as _, Sha256};

use super::hash::BYTES_PER_ELEMENT;
use crate::{
    Error, Result,
    air::{AirSchema, PolynomialField, SemanticAir, WorkLimits},
};

/// Gadget instances one statement kind of one construction needs beside its
/// hash chain when the key is private.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GadgetUse {
    /// [`KeyBitAir`] instances: one scan of one key.
    pub bit_scans: usize,
    /// [`KeyOrderAir`] instances: one comparison of two byte strings.
    pub comparisons: usize,
}

/// Private columns of one scanned byte string: eight bits of the byte, least
/// significant first, whether the row is inside the string, the running limb
/// and the number of bytes so far.
const LANE_LIVE: usize = 8;
const LANE_LIMB: usize = 9;
const LANE_COUNT: usize = 10;
const LANE_WIDTH: usize = 11;
/// Numerators of one scanned byte string.
const LANE_CONSTRAINTS: usize = 16;

/// Constraint groups a test can switch off to show that each is load-bearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GadgetGroup {
    /// Every bit and flag column is a bit.
    Bits,
    /// The string is a prefix of the rows: live rows are contiguous from the
    /// first row, their number is the stated length, and a row outside the
    /// string holds a zero byte.
    Length,
    /// The bytes are the stated seven-byte little-endian limbs.
    Packing,
    /// A stated bit of the key encoding equals the scanned bit.
    Select,
    /// The prefix flag starts set and is cleared for good by the first flagged
    /// difference.
    Prefix,
    /// While the prefix flag is set, an unflagged row holds equal symbols.
    Equal,
    /// The first flagged difference has the left symbol below the right one.
    Decide,
    /// A strict comparison found a difference.
    Strict,
}

/// Verifier-known columns every scan shares.
#[derive(Clone, Copy)]
struct Shared {
    /// One on the first row.
    first: usize,
    /// One on the last row.
    last: usize,
    /// One on the first byte of a limb.
    start: usize,
    /// One on the last byte of a limb.
    end: usize,
    /// One on the rows after the last complete limb.
    tail: usize,
    /// `256^(row mod 7)`: the weight of the row's byte in its limb.
    weight: usize,
}

const SHARED_WIDTH: usize = 6;

/// Trace rows for byte strings of at most `longest` bytes: a power of two
/// with a row past the end of the longest string, whose complete limbs cover
/// every byte.
#[must_use]
pub fn rows_for(longest: usize) -> usize {
    let mut rows = (longest + 1).next_power_of_two().max(8);
    while BYTES_PER_ELEMENT * (rows / BYTES_PER_ELEMENT) < longest {
        rows *= 2;
    }
    rows
}

/// The seven-byte little-endian limbs of a byte string: the elements
/// [`super::hash::pack_bytes`] writes after the length.
#[must_use]
pub fn limbs(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks(BYTES_PER_ELEMENT)
        .map(|limb| {
            let mut word = [0_u8; 8];
            word[..limb.len()].copy_from_slice(limb);
            u64::from_le_bytes(word)
        })
        .collect()
}

/// The byte a row's eight bit columns encode, least significant first.
fn byte_of<F: PolynomialField>(row: &[F], bits: usize) -> F {
    (0..8)
        .rev()
        .fold(F::ZERO, |value, bit| value.add(value).add(row[bits + bit]))
}

/// The numerators of one scanned byte string.
fn lane_numerators<F: PolynomialField>(
    out: &mut Vec<F>,
    disabled: Option<GadgetGroup>,
    current: &[F],
    next: &[F],
    lane: usize,
    shared: Shared,
    (limb, length): (usize, usize),
) {
    let mut push = |group: GadgetGroup, value: F| {
        out.push(if disabled == Some(group) {
            F::ZERO
        } else {
            value
        });
    };
    let live = current[lane + LANE_LIVE];
    for bit in 0..8 {
        let cell = current[lane + bit];
        push(GadgetGroup::Bits, cell.mul(cell.sub(F::ONE)));
    }
    push(GadgetGroup::Bits, live.mul(live.sub(F::ONE)));
    let dead = F::ONE.sub(live);
    // A row outside the string holds a zero byte.
    push(GadgetGroup::Length, dead.mul(byte_of(current, lane)));
    // Once a row is outside the string, every later row is.
    push(
        GadgetGroup::Length,
        F::ONE
            .sub(current[shared.last])
            .mul(next[lane + LANE_LIVE])
            .mul(dead),
    );
    // The rows after the last complete limb are outside the string.
    push(GadgetGroup::Length, current[shared.tail].mul(live));
    // The count restarts on the first row and adds one per live row.
    push(
        GadgetGroup::Length,
        next[lane + LANE_COUNT]
            .sub(
                F::ONE
                    .sub(next[shared.first])
                    .mul(current[lane + LANE_COUNT]),
            )
            .sub(next[lane + LANE_LIVE]),
    );
    push(
        GadgetGroup::Length,
        current[shared.last].mul(current[lane + LANE_COUNT].sub(current[length])),
    );
    // The running limb restarts on the first byte of a limb.
    push(
        GadgetGroup::Packing,
        next[lane + LANE_LIMB]
            .sub(
                F::ONE
                    .sub(next[shared.start])
                    .mul(current[lane + LANE_LIMB]),
            )
            .sub(next[shared.weight].mul(byte_of(next, lane))),
    );
    push(
        GadgetGroup::Packing,
        current[shared.end].mul(current[lane + LANE_LIMB].sub(current[limb])),
    );
}

/// Fill the private columns of one scanned byte string.
fn fill_lane(columns: &mut [Vec<u64>], lane: usize, bytes: &[u8]) {
    let value = |row: usize| u64::from(bytes.get(row).copied().unwrap_or(0));
    for bit in 0..8 {
        for (row, cell) in columns[lane + bit].iter_mut().enumerate() {
            *cell = (value(row) >> bit) & 1;
        }
    }
    let mut count = 0_u64;
    for (row, cell) in columns[lane + LANE_LIVE].iter_mut().enumerate() {
        *cell = u64::from(row < bytes.len());
    }
    for (row, cell) in columns[lane + LANE_COUNT].iter_mut().enumerate() {
        count += u64::from(row < bytes.len());
        *cell = count;
    }
    let mut limb = 0_u64;
    for (row, cell) in columns[lane + LANE_LIMB].iter_mut().enumerate() {
        if row % BYTES_PER_ELEMENT == 0 {
            limb = 0;
        }
        limb += value(row) << (8 * (row % BYTES_PER_ELEMENT));
        *cell = limb;
    }
}

/// The verifier-known columns every scan shares, in [`Shared`] order.
fn shared_columns(rows: usize) -> Vec<Vec<u64>> {
    let complete = BYTES_PER_ELEMENT * (rows / BYTES_PER_ELEMENT);
    let column = |value: &dyn Fn(usize) -> u64| (0..rows).map(value).collect::<Vec<u64>>();
    vec![
        column(&|row| u64::from(row == 0)),
        column(&|row| u64::from(row == rows - 1)),
        column(&|row| u64::from(row % BYTES_PER_ELEMENT == 0)),
        column(&|row| u64::from(row % BYTES_PER_ELEMENT == BYTES_PER_ELEMENT - 1)),
        column(&|row| u64::from(row >= complete)),
        column(&|row| 1 << (8 * (row % BYTES_PER_ELEMENT))),
    ]
}

/// The verifier-known limb and length columns of one stated byte string: each
/// limb on the last row of its seven bytes and the length on the last row.
fn statement_columns(rows: usize, bytes: &[u8]) -> [Vec<u64>; 2] {
    let mut limb_column = vec![0_u64; rows];
    for (index, limb) in limbs(bytes).into_iter().enumerate() {
        limb_column[BYTES_PER_ELEMENT * index + BYTES_PER_ELEMENT - 1] = limb;
    }
    let mut length = vec![0_u64; rows];
    length[rows - 1] = bytes.len() as u64;
    [limb_column, length]
}

fn statement_digest(identity: &str, rows: usize, flags: &[u8], public: &[Vec<u64>]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(identity.as_bytes());
    hasher.update((rows as u64).to_le_bytes());
    hasher.update(flags);
    for column in public {
        for word in column {
            hasher.update(word.to_le_bytes());
        }
    }
    hasher.finalize().to_vec()
}

fn out_of_range(index: usize, len: usize) -> Error {
    Error::QueryIndexOutOfRange { index, len }
}

/// Lexicographic order of two byte strings, one byte per row.
///
/// A byte string is read as symbols: a byte `b` inside the string is `b + 1`,
/// a row past its end is `0`. The first row where the symbols differ decides,
/// and the left symbol must be the smaller one, shown by an eight-bit
/// difference. A string that is a proper prefix of the other is the smaller.
/// The strict form also requires that a difference was found.
pub struct KeyOrderAir {
    rows: usize,
    strict: bool,
    public: Vec<Vec<u64>>,
    public_columns: Vec<usize>,
    statement: Vec<u8>,
    disabled: Option<GadgetGroup>,
}

/// Private columns of [`KeyOrderAir`]: the two strings, the prefix flag, the
/// difference flag and the eight bits of the deciding difference.
const ORDER_LEFT: usize = 0;
const ORDER_RIGHT: usize = LANE_WIDTH;
const ORDER_PREFIX: usize = 2 * LANE_WIDTH;
const ORDER_DIFFERENT: usize = ORDER_PREFIX + 1;
const ORDER_GAP: usize = ORDER_PREFIX + 2;
const ORDER_PRIVATE: usize = ORDER_GAP + 8;
const ORDER_SHARED: Shared = Shared {
    first: ORDER_PRIVATE,
    last: ORDER_PRIVATE + 1,
    start: ORDER_PRIVATE + 2,
    end: ORDER_PRIVATE + 3,
    tail: ORDER_PRIVATE + 4,
    weight: ORDER_PRIVATE + 5,
};
const ORDER_LEFT_LIMB: usize = ORDER_PRIVATE + SHARED_WIDTH;
const ORDER_RIGHT_LIMB: usize = ORDER_LEFT_LIMB + 2;

impl KeyOrderAir {
    /// Stable identity of the relation layout.
    pub const IDENTITY: &'static str = "iroha:g2:key-gadget:byte-string-order:row-per-byte:v0";
    /// Complete column count: 32 private and 10 verifier-known columns.
    pub const WIDTH: usize = ORDER_RIGHT_LIMB + 2;
    /// Private columns.
    pub const PRIVATE_COLUMNS: usize = ORDER_PRIVATE;
    /// Numerators: two scanned strings, ten bits and five order rules.
    pub const CONSTRAINTS: usize = 2 * LANE_CONSTRAINTS + 10 + 5;
    /// The prefix flag and the difference flag times a symbol difference, and
    /// a symbol is a flag times a byte.
    pub const DEGREE: usize = 4;

    /// The relation of `left < right` when `strict`, of `left <= right`
    /// otherwise. Both strings are the verifier-known statement here.
    #[must_use]
    pub fn new(left: &[u8], right: &[u8], strict: bool) -> Self {
        let rows = rows_for(left.len().max(right.len()));
        let mut public = shared_columns(rows);
        public.extend(statement_columns(rows, left));
        public.extend(statement_columns(rows, right));
        let statement = statement_digest(Self::IDENTITY, rows, &[u8::from(strict)], &public);
        Self {
            rows,
            strict,
            public,
            public_columns: (ORDER_PRIVATE..Self::WIDTH).collect(),
            statement,
            disabled: None,
        }
    }

    /// The same relation without one constraint group. For mutation tests.
    #[cfg(test)]
    fn without(mut self, group: GadgetGroup) -> Self {
        self.disabled = Some(group);
        self
    }

    /// The prover's column-major trace for two byte strings, filled as the
    /// rules prescribe. For strings that are not the statement, or not in the
    /// stated order, the trace violates the relation.
    ///
    /// # Panics
    /// Panics when a string is too long for the relation's rows.
    #[must_use]
    pub fn witness_columns(&self, left: &[u8], right: &[u8]) -> Vec<Vec<u64>> {
        assert!(
            rows_for(left.len().max(right.len())) <= self.rows,
            "the strings do not fit the relation's rows"
        );
        let mut columns = vec![vec![0_u64; self.rows]; Self::WIDTH];
        for (ordinal, column) in self.public.iter().enumerate() {
            columns[ORDER_PRIVATE + ordinal].copy_from_slice(column);
        }
        fill_lane(&mut columns, ORDER_LEFT, left);
        fill_lane(&mut columns, ORDER_RIGHT, right);
        let symbol =
            |bytes: &[u8], row: usize| bytes.get(row).map_or(0, |byte| u64::from(*byte) + 1);
        // The prefix flag is set up to the first row whose symbols differ.
        let decided = (0..self.rows).find(|&row| symbol(left, row) != symbol(right, row));
        let flagged = decided.map_or(self.rows, |row| row + 1);
        columns[ORDER_PREFIX][..flagged].fill(1);
        if let Some(row) = decided {
            columns[ORDER_DIFFERENT][row] = 1;
            // The eight low bits of `right - left - 1`; they are the whole
            // difference exactly when the left symbol is the smaller one.
            let gap = symbol(right, row)
                .wrapping_sub(symbol(left, row))
                .wrapping_sub(1);
            for bit in 0..8 {
                columns[ORDER_GAP + bit][row] = (gap >> bit) & 1;
            }
        }
        columns
    }

    /// Caller ceilings for the uncommitted reference of this relation.
    #[must_use]
    pub fn reference_limits(&self) -> WorkLimits {
        WorkLimits {
            max_trace_rows: crate::air::MAX_REFERENCE_TRACE_ROWS,
            max_trace_cells: self.rows * Self::WIDTH,
            max_constraints: Self::CONSTRAINTS,
            max_statement_bytes: self.statement.len(),
            max_payload_bytes: usize::MAX,
            max_work_units: usize::MAX,
        }
    }
}

impl SemanticAir for KeyOrderAir {
    fn schema(&self) -> AirSchema {
        AirSchema {
            identity: Self::IDENTITY,
            trace_rows: self.rows,
            width: Self::WIDTH,
            constraints: Self::CONSTRAINTS,
            numerator_degree_bound: Self::DEGREE * (self.rows - 1) + 1,
        }
    }

    fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }

    fn public_columns(&self) -> &[usize] {
        &self.public_columns
    }

    fn public_value(&self, ordinal: usize, row: usize) -> Result<u64> {
        self.public
            .get(ordinal)
            .and_then(|column| column.get(row))
            .copied()
            .ok_or_else(|| out_of_range(row, self.rows))
    }

    fn evaluate<F: PolynomialField>(&self, _point: F, current: &[F], next: &[F]) -> Result<Vec<F>> {
        if current.len() != Self::WIDTH || next.len() != Self::WIDTH {
            return Err(out_of_range(current.len().max(next.len()), Self::WIDTH));
        }
        let mut numerators = Vec::with_capacity(Self::CONSTRAINTS);
        for (lane, limb) in [
            (ORDER_LEFT, ORDER_LEFT_LIMB),
            (ORDER_RIGHT, ORDER_RIGHT_LIMB),
        ] {
            lane_numerators(
                &mut numerators,
                self.disabled,
                current,
                next,
                lane,
                ORDER_SHARED,
                (limb, limb + 1),
            );
        }
        let gate = |group: GadgetGroup, value: F| {
            if self.disabled == Some(group) {
                F::ZERO
            } else {
                value
            }
        };
        let (prefix, different) = (current[ORDER_PREFIX], current[ORDER_DIFFERENT]);
        for bit in 0..8 {
            let cell = current[ORDER_GAP + bit];
            numerators.push(gate(GadgetGroup::Bits, cell.mul(cell.sub(F::ONE))));
        }
        numerators.push(gate(GadgetGroup::Bits, prefix.mul(prefix.sub(F::ONE))));
        numerators.push(gate(
            GadgetGroup::Bits,
            different.mul(different.sub(F::ONE)),
        ));
        let symbol =
            |lane: usize| current[lane + LANE_LIVE].mul(byte_of(current, lane).add(F::ONE));
        let difference = symbol(ORDER_RIGHT).sub(symbol(ORDER_LEFT));
        let undecided = F::ONE.sub(different);
        // The prefix flag starts set and survives a row only without a flag.
        numerators.push(gate(
            GadgetGroup::Prefix,
            current[ORDER_SHARED.first].mul(prefix.sub(F::ONE)),
        ));
        numerators.push(gate(
            GadgetGroup::Prefix,
            F::ONE
                .sub(next[ORDER_SHARED.first])
                .mul(next[ORDER_PREFIX].sub(prefix.mul(undecided))),
        ));
        numerators.push(gate(
            GadgetGroup::Equal,
            prefix.mul(undecided).mul(difference),
        ));
        // `right - left - 1` is an eight-bit number, so `left < right`.
        numerators.push(gate(
            GadgetGroup::Decide,
            prefix
                .mul(different)
                .mul(difference.sub(F::ONE).sub(byte_of(current, ORDER_GAP))),
        ));
        // The last row is past both strings, so a set flag there means the
        // strings are equal.
        numerators.push(gate(
            GadgetGroup::Strict,
            F::embed_base(u64::from(self.strict))
                .mul(current[ORDER_SHARED.last])
                .mul(prefix),
        ));
        Ok(numerators)
    }
}

/// Stated bits of the order-preserving bit encoding of a key, one byte per
/// row.
///
/// The encoding spends nine bits per byte: a set continuation bit, then the
/// byte most significant bit first; a clear bit ends the key. Bit `9 * i + k`
/// is therefore read on row `i`: the row's live flag for `k = 0`, bit `8 - k`
/// of its byte otherwise. The stated indices and values are verifier-known
/// selector and value columns.
pub struct KeyBitAir {
    rows: usize,
    public: Vec<Vec<u64>>,
    public_columns: Vec<usize>,
    statement: Vec<u8>,
    disabled: Option<GadgetGroup>,
}

/// Encoded bits per key byte.
const ENCODED_BITS_PER_BYTE: usize = 9;
const BIT_SHARED: Shared = Shared {
    first: LANE_WIDTH,
    last: LANE_WIDTH + 1,
    start: LANE_WIDTH + 2,
    end: LANE_WIDTH + 3,
    tail: LANE_WIDTH + 4,
    weight: LANE_WIDTH + 5,
};
const BIT_LIMB: usize = LANE_WIDTH + SHARED_WIDTH;
const BIT_SELECT: usize = BIT_LIMB + 2;
const BIT_VALUE: usize = BIT_SELECT + ENCODED_BITS_PER_BYTE;

impl KeyBitAir {
    /// Stable identity of the relation layout.
    pub const IDENTITY: &'static str = "iroha:g2:key-gadget:encoded-key-bits:row-per-byte:v0";
    /// Complete column count: 11 private and 26 verifier-known columns.
    pub const WIDTH: usize = BIT_VALUE + ENCODED_BITS_PER_BYTE;
    /// Private columns.
    pub const PRIVATE_COLUMNS: usize = LANE_WIDTH;
    /// Numerators: one scanned string and one per encoded bit of a row.
    pub const CONSTRAINTS: usize = LANE_CONSTRAINTS + ENCODED_BITS_PER_BYTE;
    /// The last-row selector times two live flags.
    pub const DEGREE: usize = 3;

    /// The relation of "bit `index` of the encoding of `key` is `value`" for
    /// every stated pair. The key is the verifier-known statement here.
    #[must_use]
    pub fn new(key: &[u8], bits: &[(u32, bool)]) -> Self {
        let furthest = bits
            .iter()
            .map(|(index, _)| *index as usize / ENCODED_BITS_PER_BYTE)
            .max()
            .unwrap_or(0);
        let rows = rows_for(key.len().max(furthest));
        let mut public = shared_columns(rows);
        public.extend(statement_columns(rows, key));
        public.extend(vec![vec![0_u64; rows]; 2 * ENCODED_BITS_PER_BYTE]);
        let select = SHARED_WIDTH + 2;
        for (index, value) in bits {
            let (row, slot) = (
                *index as usize / ENCODED_BITS_PER_BYTE,
                *index as usize % ENCODED_BITS_PER_BYTE,
            );
            public[select + slot][row] = 1;
            public[select + ENCODED_BITS_PER_BYTE + slot][row] = u64::from(*value);
        }
        let statement = statement_digest(Self::IDENTITY, rows, &[], &public);
        Self {
            rows,
            public,
            public_columns: (LANE_WIDTH..Self::WIDTH).collect(),
            statement,
            disabled: None,
        }
    }

    /// The same relation without one constraint group. For mutation tests.
    #[cfg(test)]
    fn without(mut self, group: GadgetGroup) -> Self {
        self.disabled = Some(group);
        self
    }

    /// The prover's column-major trace for a key.
    ///
    /// # Panics
    /// Panics when the key is too long for the relation's rows.
    #[must_use]
    pub fn witness_columns(&self, key: &[u8]) -> Vec<Vec<u64>> {
        assert!(
            rows_for(key.len()) <= self.rows,
            "the key does not fit the relation's rows"
        );
        let mut columns = vec![vec![0_u64; self.rows]; Self::WIDTH];
        for (ordinal, column) in self.public.iter().enumerate() {
            columns[LANE_WIDTH + ordinal].copy_from_slice(column);
        }
        fill_lane(&mut columns, 0, key);
        columns
    }

    /// Caller ceilings for the uncommitted reference of this relation.
    #[must_use]
    pub fn reference_limits(&self) -> WorkLimits {
        WorkLimits {
            max_trace_rows: crate::air::MAX_REFERENCE_TRACE_ROWS,
            max_trace_cells: self.rows * Self::WIDTH,
            max_constraints: Self::CONSTRAINTS,
            max_statement_bytes: self.statement.len(),
            max_payload_bytes: usize::MAX,
            max_work_units: usize::MAX,
        }
    }
}

impl SemanticAir for KeyBitAir {
    fn schema(&self) -> AirSchema {
        AirSchema {
            identity: Self::IDENTITY,
            trace_rows: self.rows,
            width: Self::WIDTH,
            constraints: Self::CONSTRAINTS,
            numerator_degree_bound: Self::DEGREE * (self.rows - 1) + 1,
        }
    }

    fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }

    fn public_columns(&self) -> &[usize] {
        &self.public_columns
    }

    fn public_value(&self, ordinal: usize, row: usize) -> Result<u64> {
        self.public
            .get(ordinal)
            .and_then(|column| column.get(row))
            .copied()
            .ok_or_else(|| out_of_range(row, self.rows))
    }

    fn evaluate<F: PolynomialField>(&self, _point: F, current: &[F], next: &[F]) -> Result<Vec<F>> {
        if current.len() != Self::WIDTH || next.len() != Self::WIDTH {
            return Err(out_of_range(current.len().max(next.len()), Self::WIDTH));
        }
        let mut numerators = Vec::with_capacity(Self::CONSTRAINTS);
        lane_numerators(
            &mut numerators,
            self.disabled,
            current,
            next,
            0,
            BIT_SHARED,
            (BIT_LIMB, BIT_LIMB + 1),
        );
        for slot in 0..ENCODED_BITS_PER_BYTE {
            // The continuation bit is the live flag; the others are the byte,
            // most significant bit first.
            let scanned = if slot == 0 {
                current[LANE_LIVE]
            } else {
                current[8 - slot]
            };
            let stated = current[BIT_SELECT + slot].mul(scanned.sub(current[BIT_VALUE + slot]));
            numerators.push(if self.disabled == Some(GadgetGroup::Select) {
                F::ZERO
            } else {
                stated
            });
        }
        Ok(numerators)
    }
}

#[cfg(test)]
#[path = "key_gadgets_tests.rs"]
mod tests;
