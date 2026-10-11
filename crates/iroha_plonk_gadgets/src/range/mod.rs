//! Range checks and checked unsigned arithmetic: the running-sum chip
//! ([`running_sum`]) and checked `u128`/`u64` operations on it
//! ([`u128`](mod@u128)).

pub mod algebraic15;
pub mod running_sum;
pub mod secondary;
pub mod u128;

#[cfg(test)]
mod compact_tests;

pub use running_sum::{
    LimbBits, MAX_RANGE_BITS, RangeShape, RunningSumChip, RunningSumConfig, limbs_native,
    running_sum_witness,
};
pub use u128::{UintChip, checked_add_native, checked_sub_native, fits, lt_native};
