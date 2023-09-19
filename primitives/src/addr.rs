//! Because we require that the `iroha_data_model` crate be `no_std`
//! compatible, we cannot use the `std::net::Ipv4Addr` and the
//! like. As such it makes sense to duplicate them, and redefine the
//! behaviour.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::{AsRef, DebugCustom, Display, From, IntoIterator};
use iroha_macro::FromVariant;
pub use iroha_primitives_derive::socket_addr;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{conststr::ConstString, ffi};

/// Error when parsing an address
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display)]
pub enum ParseError {
    /// Not enough segments in IP address
    NotEnoughSegments,
    /// Too many segments in IP address
    TooManySegments,
    /// Failed to parse segment in IP address
    InvalidSegment,
    /// Failed to parse port number in socket address
    InvalidPort,
    /// Failed to find port number in socket address
    NoPort,
    /// Ipv6 address contains more than one '::' abbreviation
    UnexpectedAbbreviation,
}

ffi::ffi_item! {
    /// An Iroha-native version of [`std::net::Ipv4Addr`], duplicated here
    /// to remain `no_std` compatible.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        AsRef,
        From,
        IntoIterator,
        DeserializeFromStr,
        SerializeDisplay,
        Encode,
        Decode,
        IntoSchema,
    )]
    #[display(fmt = "{}.{}.{}.{}", "self.0[0]", "self.0[1]", "self.0[2]", "self.0[3]")]
    #[debug(fmt = "{}.{}.{}.{}", "self.0[0]", "self.0[1]", "self.0[2]", "self.0[3]")]
    #[repr(transparent)]
    pub struct Ipv4Addr([u8; 4]);

    // SAFETY: `Ipv4Addr` has no trap representation in [u8; 4]
    ffi_type(unsafe {robust})
}

impl Ipv4Addr {
    /// Construct new [`Ipv4Addr`] from given octets
    pub const fn new(octets: [u8; 4]) -> Self {
        Self(octets)
    }
}

impl core::ops::Index<usize> for Ipv4Addr {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::str::FromStr for Ipv4Addr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 4];
        let mut iter = s.split('.');

        for byte in &mut bytes {
            let octet = iter
                .next()
                .ok_or(Self::Err::NotEnoughSegments)?
                .parse()
                .map_err(|_| ParseError::InvalidSegment)?;
            *byte = octet;
        }

        if iter.next().is_some() {
            Err(ParseError::TooManySegments)
        } else {
            Ok(Self(bytes))
        }
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
    /// An Iroha-native version of [`std::net::Ipv6Addr`], duplicated here
    /// to remain `no_std` compatible.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        AsRef,
        From,
        IntoIterator,
        DeserializeFromStr,
        SerializeDisplay,
        Encode,
        Decode,
        IntoSchema,
    )]
    #[repr(transparent)]
    pub struct Ipv6Addr([u16; 8]);

    // SAFETY: `Ipv6Addr` has no trap representation in [u16; 8]
    ffi_type(unsafe {robust})
}

impl Ipv6Addr {
    /// The analogue of [`Ipv4Addr::LOCALHOST`], an address associated
    /// with the local machine.
    pub const LOOPBACK: Self = Self([0, 0, 0, 0_u16, 0, 0, 0, 1]);

    /// The analogue of [`Ipv4Addr::Unspecified`], an address that
    /// usually resolves to the `LOCALHOST`, but might be configured
    /// to resolve to something else.
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0_u16, 0, 0, 0, 0]);

    /// Construct new [`Ipv6Addr`] from given segments
    pub const fn new(segments: [u16; 8]) -> Self {
        Self(segments)
    }
}

impl core::ops::Index<usize> for Ipv6Addr {
    type Output = u16;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::str::FromStr for Ipv6Addr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut words = [0u16; 8];
        let mut iter = s.split(':');

        let shorthand_pos = s.find("::");

        if s.rfind("::") != shorthand_pos {
            return Err(ParseError::UnexpectedAbbreviation);
        }

        for word in &mut words {
            let group = iter.next().ok_or(Self::Err::NotEnoughSegments)?;

            if group.is_empty() {
                break;
            }

            *word = u16::from_str_radix(group, 16).map_err(|_| ParseError::InvalidSegment)?;
        }

        if shorthand_pos.is_some() {
            let mut rev_iter = s.rsplit(':');

            for word in words.iter_mut().rev() {
                let group = rev_iter.next().unwrap();

                if group.is_empty() {
                    return Ok(Self(words));
                }

                *word = u16::from_str_radix(group, 16).map_err(|_| ParseError::InvalidSegment)?;
            }

            return Err(ParseError::TooManySegments);
        }

        if iter.next().is_some() {
            Err(ParseError::TooManySegments)
        } else {
            Ok(Self(words))
        }
    }
}

impl core::fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // TODO: Implement omission of zeroes.
        for i in 0_usize..7_usize {
            write!(f, "{:x}:", self[i])?; // Need hexadecimal
        }
        write!(f, "{:x}", self[7])
    }
}

ffi::ffi_item! {
    /// An Iroha-native version of [`std::net::IpAddr`], duplicated here
    /// to remain `no_std` compatible.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Deserialize,
        Serialize,
        Encode,
        Decode,
        IntoSchema,
        FromVariant,
        Hash,
    )]
    #[allow(variant_size_differences)] // Boxing 16 bytes probably doesn't make sense
    pub enum IpAddr {
        /// Ipv4 variant
        V4(Ipv4Addr),
        /// Ipv6 variant
        V6(Ipv6Addr),
    }
}

ffi::ffi_item! {
    /// This struct provides an Iroha-native version of [`std::net::SocketAddrV4`]. It is duplicated here
    /// in order to remain `no_std` compatible.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        DeserializeFromStr,
        SerializeDisplay,
        Encode,
        Decode,
        IntoSchema,
    )]
    #[display(fmt = "{}:{}", "self.ip", "self.port")]
    #[debug(fmt = "{}:{}", "self.ip", "self.port")]
    pub struct SocketAddrV4 {
        /// The Ipv4 address.
        pub ip: Ipv4Addr,
        /// The port number.
        pub port: u16,
    }
}

impl From<([u8; 4], u16)> for SocketAddrV4 {
    fn from(value: ([u8; 4], u16)) -> Self {
        Self {
            ip: value.0.into(),
            port: value.1,
        }
    }
}

impl core::str::FromStr for SocketAddrV4 {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (ip, port) = value.split_once(':').ok_or(ParseError::NoPort)?;
        Ok(Self {
            ip: ip.parse()?,
            port: port.parse().map_err(|_| ParseError::InvalidPort)?,
        })
    }
}

ffi::ffi_item! {
    /// This struct provides an Iroha-native version of [`std::net::SocketAddrV6`]. It is duplicated here
    /// in order to remain `no_std` compatible.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        DeserializeFromStr,
        SerializeDisplay,
        Encode,
        Decode,
        IntoSchema,
    )]
    #[display(fmt = "[{}]:{}", "self.ip", "self.port")]
    #[debug(fmt = "[{}]:{}", "self.ip", "self.port")]
    pub struct SocketAddrV6 {
        /// The Ipv6 address.
        pub ip: Ipv6Addr,
        /// The port number.
        pub port: u16,
    }
}

impl From<([u16; 8], u16)> for SocketAddrV6 {
    fn from(value: ([u16; 8], u16)) -> Self {
        Self {
            ip: value.0.into(),
            port: value.1,
        }
    }
}

impl core::str::FromStr for SocketAddrV6 {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim_start_matches('[');
        let (ip, port) = value.split_once("]:").ok_or(ParseError::NoPort)?;
        Ok(Self {
            ip: ip.parse()?,
            port: port.parse().map_err(|_| ParseError::InvalidPort)?,
        })
    }
}

ffi::ffi_item! {
    /// Socket address defined by hostname and port
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        SerializeDisplay,
        DeserializeFromStr,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub struct SocketAddrHost {
        /// The hostname
        pub host: ConstString,
        /// The port number
        pub port: u16,
    }
}

impl core::fmt::Display for SocketAddrHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl core::str::FromStr for SocketAddrHost {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s.split_once(':').ok_or(ParseError::NoPort)?;
        let port = port.parse().map_err(|_| ParseError::InvalidPort)?;
        Ok(Self {
            host: host.into(),
            port,
        })
    }
}

ffi::ffi_item! {
    /// This enum provides an Iroha-native version of [`std::net::SocketAddr`]. It is duplicated here
    /// in order to remain `no_std` compatible.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Deserialize,
        Serialize,
        Encode,
        Decode,
        IntoSchema,
        FromVariant,
    )]
    #[serde(untagged)]
    pub enum SocketAddr {
        /// An Ipv4 socket address.
        Ipv4(SocketAddrV4),
        /// An Ipv6 socket address.
        Ipv6(SocketAddrV6),
        /// A socket address identified by hostname
        Host(SocketAddrHost),
    }
}

impl SocketAddr {
    /// Extracts [`IpAddr`] from [`Self::Ipv4`] and [`Self::Ipv6`] variants
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            SocketAddr::Ipv4(addr) => Some(addr.ip.into()),
            SocketAddr::Ipv6(addr) => Some(addr.ip.into()),
            SocketAddr::Host(_) => None,
        }
    }

    /// Extracts port from [`Self`]
    pub fn port(&self) -> u16 {
        match self {
            SocketAddr::Ipv4(addr) => addr.port,
            SocketAddr::Ipv6(addr) => addr.port,
            SocketAddr::Host(addr) => addr.port,
        }
    }

    /// Serialize the data contained in this [`SocketAddr`] for use in hashing.
    pub fn payload(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            SocketAddr::Ipv4(addr) => {
                bytes.extend(addr.ip);
                bytes.extend(addr.port.to_le_bytes());
            }
            SocketAddr::Ipv6(addr) => {
                bytes.extend(addr.ip.0.iter().copied().flat_map(u16::to_be_bytes));
                bytes.extend(addr.port.to_le_bytes());
            }
            SocketAddr::Host(addr) => {
                bytes.extend(addr.host.bytes());
                bytes.extend(addr.port.to_le_bytes());
            }
        }
        bytes
    }
}

impl From<([u8; 4], u16)> for SocketAddr {
    fn from(value: ([u8; 4], u16)) -> Self {
        Self::Ipv4(value.into())
    }
}

impl From<([u16; 8], u16)> for SocketAddr {
    fn from(value: ([u16; 8], u16)) -> Self {
        Self::Ipv6(value.into())
    }
}

impl core::str::FromStr for SocketAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = SocketAddrV4::from_str(s) {
            Ok(Self::Ipv4(addr))
        } else if let Ok(addr) = SocketAddrV6::from_str(s) {
            Ok(Self::Ipv6(addr))
        } else {
            Ok(Self::Host(SocketAddrHost::from_str(s)?))
        }
    }
}

#[cfg(feature = "std")]
mod std_compat {
    use std::net::ToSocketAddrs;

    use super::*;

    impl From<Ipv4Addr> for std::net::Ipv4Addr {
        #[inline]
        fn from(other: Ipv4Addr) -> Self {
            let Ipv4Addr([a, b, c, d]) = other;
            std::net::Ipv4Addr::new(a, b, c, d)
        }
    }

    impl From<std::net::Ipv4Addr> for Ipv4Addr {
        #[inline]
        fn from(other: std::net::Ipv4Addr) -> Self {
            Self(other.octets())
        }
    }

    impl From<Ipv6Addr> for std::net::Ipv6Addr {
        #[allow(clippy::many_single_char_names)]
        #[inline]
        fn from(other: Ipv6Addr) -> Self {
            let Ipv6Addr([a, b, c, d, e, f, g, h]) = other;
            std::net::Ipv6Addr::new(a, b, c, d, e, f, g, h)
        }
    }

    impl From<std::net::Ipv6Addr> for Ipv6Addr {
        #[inline]
        fn from(other: std::net::Ipv6Addr) -> Self {
            Self(other.segments())
        }
    }

    impl From<std::net::IpAddr> for IpAddr {
        fn from(value: std::net::IpAddr) -> Self {
            match value {
                std::net::IpAddr::V4(addr) => Self::V4(addr.into()),
                std::net::IpAddr::V6(addr) => Self::V6(addr.into()),
            }
        }
    }

    impl From<IpAddr> for std::net::IpAddr {
        fn from(value: IpAddr) -> Self {
            match value {
                IpAddr::V4(addr) => Self::V4(addr.into()),
                IpAddr::V6(addr) => Self::V6(addr.into()),
            }
        }
    }

    impl From<std::net::SocketAddrV4> for SocketAddrV4 {
        #[inline]
        fn from(other: std::net::SocketAddrV4) -> Self {
            Self {
                ip: (*other.ip()).into(),
                port: other.port(),
            }
        }
    }

    impl From<std::net::SocketAddrV6> for SocketAddrV6 {
        #[inline]
        fn from(other: std::net::SocketAddrV6) -> Self {
            Self {
                ip: (*other.ip()).into(),
                port: other.port(),
            }
        }
    }

    impl From<std::net::SocketAddr> for SocketAddr {
        #[inline]
        fn from(other: std::net::SocketAddr) -> Self {
            match other {
                std::net::SocketAddr::V4(addr) => Self::Ipv4(addr.into()),
                std::net::SocketAddr::V6(addr) => Self::Ipv6(addr.into()),
            }
        }
    }

    impl From<SocketAddrV4> for std::net::SocketAddrV4 {
        #[inline]
        fn from(other: SocketAddrV4) -> Self {
            Self::new(other.ip.into(), other.port)
        }
    }

    impl From<SocketAddrV6> for std::net::SocketAddrV6 {
        #[inline]
        fn from(other: SocketAddrV6) -> Self {
            Self::new(other.ip.into(), other.port, 0, 0)
        }
    }

    impl ToSocketAddrs for SocketAddr {
        type Iter = std::vec::IntoIter<std::net::SocketAddr>;

        fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
            match self {
                SocketAddr::Ipv4(addr) => {
                    Ok(vec![std::net::SocketAddr::V4((*addr).into())].into_iter())
                }
                SocketAddr::Ipv6(addr) => {
                    Ok(vec![std::net::SocketAddr::V6((*addr).into())].into_iter())
                }
                SocketAddr::Host(addr) => (addr.host.as_ref(), addr.port).to_socket_addrs(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn ipv4() {
        assert_eq!(
            Ipv4Addr::from_str("0.0.0.0").unwrap(),
            Ipv4Addr([0, 0, 0, 0])
        );

        assert_eq!(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            Ipv4Addr([127, 0, 0, 1])
        );

        assert_eq!(
            Ipv4Addr::from_str("192.168.1.256").unwrap_err(),
            ParseError::InvalidSegment
        );

        assert_eq!(
            Ipv4Addr::from_str("192.168.1").unwrap_err(),
            ParseError::NotEnoughSegments
        );

        assert_eq!(
            Ipv4Addr::from_str("192.168.1.2.3").unwrap_err(),
            ParseError::TooManySegments
        );
    }

    #[test]
    fn ipv6() {
        assert_eq!(
            Ipv6Addr::from_str("::1").unwrap(),
            Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 1])
        );

        assert_eq!(
            Ipv6Addr::from_str("ff02::1").unwrap(),
            Ipv6Addr([0xff02, 0, 0, 0, 0, 0, 0, 1])
        );

        assert_eq!(
            Ipv6Addr::from_str("2001:0db8::").unwrap(),
            Ipv6Addr([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0])
        );

        assert_eq!(
            Ipv6Addr::from_str("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap(),
            Ipv6Addr([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])
        );

        assert_eq!(
            Ipv6Addr::from_str("2001:0db8::0001").unwrap(),
            Ipv6Addr([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])
        );

        assert_eq!(
            Ipv6Addr::from_str("2001:db8:0:1:2:3:4").unwrap_err(),
            ParseError::NotEnoughSegments
        );

        assert_eq!(
            Ipv6Addr::from_str("2001:db8:0:1:2:3:4:5:6").unwrap_err(),
            ParseError::TooManySegments
        );
    }

    #[test]
    fn socket_v4() {
        assert_eq!(
            SocketAddrV4::from_str("192.168.1.0:9019").unwrap(),
            SocketAddrV4 {
                ip: Ipv4Addr([192, 168, 1, 0]),
                port: 9019
            }
        );

        assert_eq!(
            SocketAddrV4::from_str("192.168.1.1").unwrap_err(),
            ParseError::NoPort
        );

        assert_eq!(
            SocketAddrV4::from_str("192.168.1.1:FOO").unwrap_err(),
            ParseError::InvalidPort
        );
    }

    #[test]
    fn socket_v6() {
        assert_eq!(
            SocketAddrV6::from_str("[2001:0db8::]:9019").unwrap(),
            SocketAddrV6 {
                ip: Ipv6Addr([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                port: 9019
            }
        );

        assert_eq!(
            SocketAddrV6::from_str("[2001:0db8::]").unwrap_err(),
            ParseError::NoPort
        );

        assert_eq!(
            SocketAddrV6::from_str("[2001:0db8::]:FOO").unwrap_err(),
            ParseError::InvalidPort
        );
    }

    #[test]
    fn full_socket() {
        assert_eq!(
            serde_json::from_str::<SocketAddr>("\"192.168.1.0:9019\"").unwrap(),
            SocketAddr::Ipv4(SocketAddrV4 {
                ip: Ipv4Addr([192, 168, 1, 0]),
                port: 9019
            })
        );

        assert_eq!(
            serde_json::from_str::<SocketAddr>("\"[2001:0db8::]:9019\"").unwrap(),
            SocketAddr::Ipv6(SocketAddrV6 {
                ip: Ipv6Addr([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                port: 9019
            })
        );

        assert_eq!(
            serde_json::from_str::<SocketAddr>("\"localhost:9019\"").unwrap(),
            SocketAddr::Host(SocketAddrHost {
                host: "localhost".into(),
                port: 9019
            })
        );
    }

    #[test]
    fn serde_roundtrip() {
        let v4 = SocketAddr::Ipv4(SocketAddrV4 {
            ip: Ipv4Addr([192, 168, 1, 0]),
            port: 9019,
        });

        assert_eq!(
            serde_json::from_str::<SocketAddr>(&serde_json::to_string(&v4).unwrap()).unwrap(),
            v4
        );

        let v6 = SocketAddr::Ipv6(SocketAddrV6 {
            ip: Ipv6Addr([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
            port: 9019,
        });

        let kita = &serde_json::to_string(&v6).unwrap();
        println!("{kita}");
        let kara = serde_json::from_str::<SocketAddr>(kita).unwrap();
        assert_eq!(kara, v6);

        let host = SocketAddr::Host(SocketAddrHost {
            host: "localhost".into(),
            port: 9019,
        });

        assert_eq!(
            serde_json::from_str::<SocketAddr>(&serde_json::to_string(&host).unwrap()).unwrap(),
            host
        );
    }

    #[test]
    fn host() {
        assert_eq!(
            SocketAddrHost::from_str("localhost:9019").unwrap(),
            SocketAddrHost {
                host: "localhost".into(),
                port: 9019
            }
        );
    }
}
