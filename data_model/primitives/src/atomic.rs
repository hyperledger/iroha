//! Contains wrappers above basic atomic, providing useful impls

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use core::{cmp, sync::atomic as core_atomic};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Encode, Output, WrapperTypeDecode};
use serde::{Deserialize, Serialize, Serializer};

/// Wrapper for [`AtomicU32`]
///
/// Provides useful impls, using [`core_atomic::Ordering::Acquire`]
/// and [`core_atomic::Ordering::Release`] to load and store respectively
#[derive(Debug)]
pub struct AtomicU32(core_atomic::AtomicU32);

impl AtomicU32 {
    /// Create new [`AtomicU32Wrapper`] instance
    #[inline]
    pub fn new(num: u32) -> AtomicU32 {
        Self(core_atomic::AtomicU32::new(num))
    }

    /// Get atomic value
    #[inline]
    pub fn get(&self) -> u32 {
        self.0.load(core_atomic::Ordering::Acquire)
    }

    /// Set atomic value
    #[inline]
    pub fn set(&self, num: u32) {
        self.0.store(num, core_atomic::Ordering::Release)
    }
}

impl Clone for AtomicU32 {
    #[inline]
    fn clone(&self) -> Self {
        Self(core_atomic::AtomicU32::new(self.get()))
    }
}

impl PartialOrd for AtomicU32 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AtomicU32 {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl PartialEq for AtomicU32 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for AtomicU32 {}

impl Encode for AtomicU32 {
    #[inline]
    fn size_hint(&self) -> usize {
        self.get().size_hint()
    }

    #[inline]
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.get().encode_to(dest)
    }

    #[inline]
    fn encode(&self) -> Vec<u8> {
        self.get().encode()
    }

    #[inline]
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.get().using_encoded(f)
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        self.get().encoded_size()
    }
}

impl WrapperTypeDecode for AtomicU32 {
    type Wrapped = u32;
}

impl Serialize for AtomicU32 {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.get().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AtomicU32 {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let num = u32::deserialize(deserializer)?;
        Ok(Self::new(num))
    }
}

impl IntoSchema for AtomicU32 {
    #[inline]
    fn type_name() -> String {
        String::from("AtomicU32Wrapper")
    }

    #[inline]
    fn schema(map: &mut iroha_schema::MetaMap) {
        let _ = map
            .entry(Self::type_name())
            .or_insert(iroha_schema::Metadata::Int(
                iroha_schema::IntMode::FixedWidth,
            ));
    }
}

impl From<u32> for AtomicU32 {
    #[inline]
    fn from(num: u32) -> Self {
        Self::new(num)
    }
}
