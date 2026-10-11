//! The shared lookup table of the Q-leaf layout (M3 decision D2): one table
//! `[T, x_0, x_1, x_2, y_0, y_1, y_2, V]` in eight plain fixed columns that
//! the foreign-field range lookups, the SHA-256 spread lookup and the P-256
//! window lookup all read, so the SHA and window lookups ride on two of the
//! foreign-field arguments instead of owning arguments of their own.
//!
//! # Rows
//!
//! Each chip writes its own disjoint row range (the plan of
//! [`crate::q_leaf`]):
//!
//! | rows | `T` | `x_0` | `x_1..y_2` | `V` |
//! | --- | --- | --- | --- | --- |
//! | foreign-field range, `[0, 2^15)` | 0 | 0 | 0 | the row |
//! | SHA-256 spread | [`SHA_TAG_BASE`] `+ w` (0 on its zero row) | `spread(x)` | 0 | `x < 2^11` |
//! | fixed-base windows | `1 + 64 b + w` (below [`DYNAMIC_TAG_BASE`]) | point limbs | point limbs | digit `< 2^8` |
//! | dynamic window tables | [`DYNAMIC_TAG_BASE`] `+ row` | 0 (advice) | 0 (advice) | entry `1..=16` |
//! | every other row | 0 | 0 | 0 | 0 |
//!
//! Dynamic entries hold their point limbs in advice cells: the window
//! argument's table expressions are `fixed + q_dyn * advice`
//! ([`crate::p256::window`]). Every other argument reads the fixed columns
//! only.
//!
//! # Soundness of the sharing
//!
//! A host argument (a foreign-field range lookup) and its guest (SHA or
//! window) form one tuple: the guest's components first, then `V`, whose
//! input is the host's residual plus the guest's value. It is the two
//! lookups it replaces when
//!
//! 1. the activation patterns are fixed (witness independent) and at most
//!    one of host and guest is active on any row, every inactive component
//!    being zero (so an active host's tuple is `(0, .., 0, R)` and an active
//!    guest's is its own tuple);
//! 2. the tag namespaces are disjoint: foreign-field rows are exactly the
//!    rows with `T = 0` (all their other components zero), SHA tags are
//!    `2^33 + w`, dynamic tags `2^32 + row`, fixed-window tags below
//!    `2^32`;
//! 3. every `V` entry on a usable row is below `2^15` ([`VALUE_BITS`]): the
//!    width-1 foreign-field arguments read `V` alone, so any entry is a
//!    valid range value for them.
//!
//! Then a host tuple `(0, .., 0, R)` matches only a `T = 0` row, whose `V` is
//! a 15-bit value, and a guest tuple with a nonzero tag matches only rows
//! of its own namespace. The copy constraints that bind dynamic-table
//! coordinates to the computed multiples are unchanged, and the window's
//! dynamic-entry enable is zero on every fixed row (so no advice is added
//! to a fixed entry). The Q-leaf tests
//! (`q_leaf::tests`) check conditions 1-3 on the synthesized fixed columns.
//!
//! # Degree
//!
//! The lookup degree is `2 + deg(input) + deg(table)`. The `C`/`Q` range
//! residual has degree 3 (ternary patterns), so its guest must use fixed
//! table expressions (SHA: `2 + 3 + 1 = 6`); the `U` residual has degree 2,
//! so its guest may use the degree-2 dynamic window table (`2 + 2 + 2 =
//! 6`).

use iroha_pasta::PastaField;
use iroha_plonk::cs::{Column, ConstraintSystem, Expression, Fixed, VirtualCells};

use crate::ff::LIMBS;

/// Fixed columns of the shared table.
pub const TABLE_COLUMNS: usize = 2 + 2 * LIMBS;

/// Every `V` entry is below `2^VALUE_BITS`.
pub const VALUE_BITS: usize = 15;

/// The first SHA-256 spread tag (`2^33 + w` for width `w`).
pub const SHA_TAG_BASE: u64 = 1 << 33;

/// The first dynamic window tag (`2^32 + row`); fixed-window tags are below
/// it.
pub const DYNAMIC_TAG_BASE: u64 = 1 << 32;

/// The eight fixed columns `[T, x_0, x_1, x_2, y_0, y_1, y_2, V]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedTable {
    tag: Column<Fixed>,
    x: [Column<Fixed>; LIMBS],
    y: [Column<Fixed>; LIMBS],
    value: Column<Fixed>,
}

impl SharedTable {
    /// Adds the eight fixed columns.
    pub fn configure<F: PastaField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            x: core::array::from_fn(|_| meta.fixed_column()),
            y: core::array::from_fn(|_| meta.fixed_column()),
            value: meta.fixed_column(),
        }
    }

    /// The tag column `T`.
    #[must_use]
    pub const fn tag(&self) -> Column<Fixed> {
        self.tag
    }

    /// The `x` limb columns (`x_0` holds the SHA spread value).
    #[must_use]
    pub const fn x(&self) -> [Column<Fixed>; LIMBS] {
        self.x
    }

    /// The `y` limb columns.
    #[must_use]
    pub const fn y(&self) -> [Column<Fixed>; LIMBS] {
        self.y
    }

    /// The value column `V`.
    #[must_use]
    pub const fn value(&self) -> Column<Fixed> {
        self.value
    }

    /// The columns in table order.
    #[must_use]
    pub const fn columns(&self) -> [Column<Fixed>; TABLE_COLUMNS] {
        let [x0, x1, x2] = self.x;
        let [y0, y1, y2] = self.y;
        [self.tag, x0, x1, x2, y0, y1, y2, self.value]
    }
}

/// A guest's part of a shared argument: `(input, table)` pairs in table
/// order (before `V`), and the guest's addend to the `V` input.
#[derive(Clone, Debug)]
pub struct GuestLookup<F> {
    /// The guest's components other than `V`.
    pub pairs: Vec<(Expression<F>, Expression<F>)>,
    /// The guest's `V` input (zero wherever the guest is inactive).
    pub value: Expression<F>,
}

/// A chip whose lookup rides on a foreign-field range argument of the
/// shared table (see the module documentation for the conditions).
pub trait TableGuest<F: PastaField> {
    /// The guest's name (appended to the host argument's name).
    fn guest_name(&self) -> &'static str;

    /// The guest's components, queried in the host argument's closure.
    fn guest_lookup(&self, cells: &mut VirtualCells<'_, F>) -> GuestLookup<F>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_namespaces_are_disjoint() {
        // Dynamic tags 2^32 + row for rows below 2^31 stay below the SHA
        // tags, and fixed-window tags stay below the dynamic ones.
        const { assert!(DYNAMIC_TAG_BASE + (1 << 31) < SHA_TAG_BASE) };
        const { assert!(SHA_TAG_BASE + 11 < (1 << 34)) };
        assert_eq!(TABLE_COLUMNS, 8);
        assert_eq!(VALUE_BITS, crate::ff::SUBLIMB_BITS);
    }
}
