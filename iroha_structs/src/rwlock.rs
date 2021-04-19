//! Module with asynchronous read write lock

use async_std::sync::{RwLockReadGuard, RwLockWriteGuard};
use async_std::task;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Asynchronous read write lock
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize + Clone",
    deserialize = "T: DeserializeOwned",
))]
#[serde(from = "T")]
#[serde(into = "IntoWrapper<T>")]
pub struct RwLock<T>(pub async_std::sync::RwLock<T>);

impl<T: PartialEq> PartialEq for RwLock<T> {
    fn eq(&self, other: &Self) -> bool {
        self.read().eq(&*other.read())
    }
}
impl<T: Eq> Eq for RwLock<T> {}

impl<T: Clone> Clone for RwLock<T> {
    fn clone(&self) -> Self {
        Self::new(self.read().clone())
    }
}

impl<T> From<T> for RwLock<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct IntoWrapper<T>(T);

impl<T> From<RwLock<T>> for IntoWrapper<T> {
    fn from(RwLock(value): RwLock<T>) -> Self {
        Self(value.into_inner())
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> RwLock<T> {
    /// Constructor
    pub fn new(value: T) -> Self {
        Self(async_std::sync::RwLock::new(value))
    }
}

impl<T> RwLock<T> {
    /// Returns read guard in synchronous context
    pub fn read(&'_ self) -> RwLockReadGuard<'_, T> {
        task::block_on(self.read_async())
    }
    /// Returns read guard in asynchronous context
    #[allow(clippy::future_not_send)]
    pub async fn read_async(&'_ self) -> RwLockReadGuard<'_, T> {
        self.0.read().await
    }
    /// Returns write guard in synchronous context
    pub fn write(&'_ self) -> RwLockWriteGuard<'_, T> {
        task::block_on(self.write_async())
    }
    /// Returns write guard in asynchronous context
    #[allow(clippy::future_not_send)]
    pub async fn write_async(&'_ self) -> RwLockWriteGuard<'_, T> {
        self.0.write().await
    }
}

impl<W: Encode> Encode for RwLock<W> {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.read().encode_to(dest)
    }
    fn encode(&self) -> Vec<u8> {
        self.read().encode()
    }
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.read().using_encoded(f)
    }
}

impl<T: Decode> Decode for RwLock<T> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        Ok(Self::new(T::decode(input)?))
    }

    fn skip<I: Input>(input: &mut I) -> Result<(), Error> {
        T::skip(input)
    }

    fn encoded_fixed_size() -> Option<usize> {
        T::encoded_fixed_size()
    }
}
