//! Because we require that the `iroha_data_model` crate be `no_std`
//! compatible, we cannot use the `std::net::Ipv4Addr` and the
//! like. As such it makes sense to duplicate them, and redefine the
//! behaviour.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::{AsRef, From, IntoIterator};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::ffi;

ffi::ffi_item! {
    /// An Iroha-native version of `std::net::Ipv4Addr`, duplicated here to remain `no_std` compatible.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, From, AsRef, IntoIterator, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct Ipv4Addr([u8; 4]);

    // SAFETY: `Ipv4Addr` has no trap representation in [u8; 4]
    ffi_type(unsafe {robust})
}

#[cfg(feature = "std")]
impl From<Ipv4Addr> for std::net::Ipv4Addr {
    #[inline]
    fn from(other: Ipv4Addr) -> Self {
        let Ipv4Addr([a, b, c, d]) = other;
        std::net::Ipv4Addr::new(a, b, c, d)
    }
}

impl core::fmt::Display for Ipv4Addr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl core::ops::Index<usize> for Ipv4Addr {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Ipv4Addr {
    /// The address normally associated with the local machine.
    pub const LOCALHOST: Self = Self([127, 0, 0, 1]);

    /// An unspecified address. Normally resolves to
    /// [`Self::LOCALHOST`] but might be configured to resolve to
    /// something else.
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
}

ffi::ffi_item! {
    /// An Iroha-native version of `std::net::Ipv6Addr`, duplicated here to remain `no_std` compatible.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, From, AsRef, IntoIterator, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct Ipv6Addr([u16; 8]);

    // SAFETY: `Ipv6Addr` has no trap representation in [u16; 8]
    ffi_type(unsafe {robust})
}

#[cfg(feature = "std")]
impl From<std::net::Ipv4Addr> for Ipv4Addr {
    #[inline]
    fn from(other: std::net::Ipv4Addr) -> Self {
        Self(other.octets())
    }
}

impl Ipv6Addr {
    /// The analogue of [`Ipv4Addr::LOCALHOST`], an address associated
    /// with the local machine.
    pub const LOOPBACK: Self = Self([0, 0, 0, 0_u16, 0, 0, 0, 1]);

    /// The analogue of [`Ipv4Addr::Unspecified`], an address that
    /// usually resolves to the `LOCALHOST`, but might be configured
    /// to resolve to something else.
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0_u16, 0, 0, 0, 0]);
}

impl core::ops::Index<usize> for Ipv6Addr {
    type Output = u16;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // TODO: Implement omission of zeroes.
        for i in 0_usize..7_usize {
            write!(f, "{i:x}:")?; // Need hexadecimal
        }
        write!(f, "{:x}", self[7])
    }
}
