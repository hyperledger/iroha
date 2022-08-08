//! Contains wrapper type to annotate types with `must_use` attribute

use core::borrow::{Borrow, BorrowMut};

use derive_more::{AsMut, AsRef, Constructor, Deref, Display};

/// Wrapper type to annotate types with `must_use` attribute
///
/// # Example
/// ```
/// use iroha_primitives::must_use::MustUse;
///
/// fn is_odd(num: i32) -> Result<MustUse<bool>, String> {
///     if num < 0 {
///         return Err(String::from("Number must be positive"));
///     }
///
///     if num % 2 == 0 {
///         Ok(MustUse::new(true))
///     } else {
///         Ok(MustUse::new(false))
///     }
/// }
///
/// if *is_odd(2).unwrap() {
///     println!("2 is odd");
/// }
///
/// // Will produce a warning, case `#[warn(unused_must_use)]` on by default
/// // is_odd(3).unwrap();
/// ```
#[derive(
    Constructor,
    Debug,
    Display,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsRef,
    AsMut,
    Deref,
)]
#[repr(transparent)]
#[must_use]
pub struct MustUse<T>(pub T);

impl<T> MustUse<T> {
    /// Get inner value
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Borrow<T> for MustUse<T> {
    #[inline]
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T> BorrowMut<T> for MustUse<T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
