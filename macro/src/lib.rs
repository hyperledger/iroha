//! Crate containing iroha macros

#![allow(clippy::module_name_repetitions)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use iroha_derive::*;

/// Contains functionality related to typed downcasting and encoding of trait objects
pub mod typed_any {
    #![allow(unsafe_code)]

    use core::{any::Any, fmt};

    /// Identifier for a type which is unique among the implementors of the trait
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TypeId(pub u64);

    ///
    /// # Safety
    ///
    /// Implementing this trait is **strongly** discouraged, use [`typed_any!`] macro instead
    pub unsafe trait TypedAnyVariant<O: TraitObject>
    where
        O: ?Sized,
    {
        /// Identifier for a type which is unique among the implementors of the trait
        const ID: TypeId;
    }

    /// A trait to emulate dynamic typing.
    ///
    /// # Safety
    ///
    /// Implementing this trait is **strongly** discouraged, use [`typed_any!`] macro instead
    pub unsafe trait TypedAny<O: TraitObject>
    where
        O: ?Sized,
    {
        /// Gets the `TypeId` of `self`
        fn type_id(&self) -> TypeId;
        /// Converts the type into `&dyn Any`
        fn as_any(&self) -> &dyn Any;
        /// Converts the type into `&mut dyn Any`
        fn as_any_mut(&mut self) -> &mut dyn Any;
        /// Converts the `Box<Self>` into `Box<dyn Any>`
        fn into_any(self: Box<Self>) -> Box<dyn Any>;
    }

    impl<O: TraitObject> fmt::Debug for dyn TypedAny<O> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // TODO: Could be downcasted and displayed? since it's safe
            f.debug_struct("TypedAny").finish_non_exhaustive()
        }
    }

    unsafe impl<T: TypedAnyVariant<O>, O: TraitObject> TypedAny<O> for T
    where
        T: 'static,
        O: ?Sized,
    {
        #[inline]
        fn type_id(&self) -> TypeId {
            <Self as TypedAnyVariant<O>>::ID
        }

        #[inline]
        fn as_any(&self) -> &dyn Any {
            self
        }
        #[inline]
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
        #[inline]
        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }

    /// Marker trait for trait objects
    pub trait TraitObject {}
}

/// Crate with errors
pub mod error {
    use core::{any::type_name, fmt, marker::PhantomData};

    /// Error which happens if `TryFrom` from enum variant fails
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct ErrorTryFromEnum<F, T> {
        from: PhantomData<F>,
        to: PhantomData<T>,
    }

    #[cfg(feature = "std")]
    impl<F, T> std::error::Error for ErrorTryFromEnum<F, T> {}

    impl<F, T> fmt::Debug for ErrorTryFromEnum<F, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ErrorTryFromEnum<{}, {}>",
                type_name::<F>(),
                type_name::<T>()
            )
        }
    }

    impl<F, T> Default for ErrorTryFromEnum<F, T> {
        fn default() -> Self {
            Self {
                from: PhantomData::default(),
                to: PhantomData::default(),
            }
        }
    }

    impl<F, T> fmt::Display for ErrorTryFromEnum<F, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Failed converting from {} to {}",
                type_name::<F>(),
                type_name::<T>()
            )
        }
    }
}
