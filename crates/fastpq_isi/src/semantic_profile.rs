//! Typed semantic profile descriptors and their canonical identities.
//!
//! A semantic profile is the complete typed description of one frozen
//! cryptographic construction: a transcript, a native commitment or a digest
//! recomputed inside a relation. Its canonical bytes are one explicit frame of
//! ordered, typed parameters, and its identity is the SHA3-256 digest of those
//! bytes.
//!
//! The identity is committed-profile data. Its only inputs are the parameters
//! a profile declares: no source file, build, toolchain or binary digest
//! enters it. Two builds with the same semantics therefore have the same
//! identity, and a changed parameter always has another one.
//!
//! A recorded measurement names the identity of every profile it depends on.
//! A measurement bound to another identity does not describe the current
//! profile. An identity grants no runtime authority and selects no verifier.
//!
//! The canonical frame is, in order:
//!
//! 1. the 26 bytes of [`SEMANTIC_PROFILE_MAGIC_V1`];
//! 2. the kind label and the profile name, each as a `u32` little-endian byte
//!    length followed by its ASCII bytes;
//! 3. the parameter count as a `u32` little-endian;
//! 4. for each parameter in declared order: the key (length and bytes as
//!    above), one type byte and the value. Type `1` is a `u64` little-endian;
//!    type `2` is UTF-8 text and type `3` is a byte string, each with a `u32`
//!    little-endian length; type `4` is a `u32` little-endian count followed by
//!    that many `u64` little-endian values.
//!
//! Every length is explicit, so no two parameter lists share an encoding.
//! `scripts/zk_semantic_profile_reference.py` implements the same frame
//! independently.

use crate::keccak256::Sha3_256V1;
use core::fmt;

/// Leading bytes of every canonical profile frame, terminator included.
pub const SEMANTIC_PROFILE_MAGIC_V1: &[u8; 26] = b"iroha:semantic-profile:v1\0";
/// Largest number of parameters one profile declares.
pub const SEMANTIC_PROFILE_MAX_PARAMETERS_V1: usize = 255;
/// Longest kind label, profile name or parameter key, in bytes.
pub const SEMANTIC_PROFILE_MAX_LABEL_BYTES_V1: usize = 96;
/// Longest encoded text, byte-string or list value, in bytes.
pub const SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1: usize = 64 * 1024;

const TYPE_U64: u8 = 1;
const TYPE_TEXT: u8 = 2;
const TYPE_BYTES: u8 = 3;
const TYPE_U64_LIST: u8 = 4;

/// What a semantic profile describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SemanticProfileKindV1 {
    /// Fiat-Shamir transcript of a proof backend, with its commitment hash.
    Transcript,
    /// Digest computed natively and never recomputed inside a relation.
    NativeCommitment,
    /// Digest that a relation recomputes.
    InCircuitDigest,
    /// Primitive whose parameters an external standard fixes.
    StandardPrimitive,
    /// Key derivation or keyed function.
    KeyDerivation,
    /// Lattice trapdoor and preimage sampler that no final standard fixes.
    LatticeTrapdoor,
}

impl SemanticProfileKindV1 {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Transcript,
        Self::NativeCommitment,
        Self::InCircuitDigest,
        Self::StandardPrimitive,
        Self::KeyDerivation,
        Self::LatticeTrapdoor,
    ];

    /// Canonical label written into the profile frame.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Transcript => "transcript",
            Self::NativeCommitment => "native-commitment",
            Self::InCircuitDigest => "in-circuit-digest",
            Self::StandardPrimitive => "standard-primitive",
            Self::KeyDerivation => "key-derivation",
            Self::LatticeTrapdoor => "lattice-trapdoor",
        }
    }
}

/// One typed parameter value of a semantic profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticProfileValueV1<'a> {
    /// Unsigned integer.
    U64(u64),
    /// UTF-8 text such as an algorithm or schema identifier.
    Text(&'a str),
    /// Opaque bytes such as a domain tag.
    Bytes(&'a [u8]),
    /// Ordered unsigned integers such as a folding schedule.
    U64List(&'a [u64]),
}

impl SemanticProfileValueV1<'_> {
    /// Copy the value into an owner.
    #[must_use]
    pub fn to_owned_value(self) -> SemanticProfileOwnedValueV1 {
        match self {
            Self::U64(number) => SemanticProfileOwnedValueV1::U64(number),
            Self::Text(text) => SemanticProfileOwnedValueV1::Text(text.to_owned()),
            Self::Bytes(bytes) => SemanticProfileOwnedValueV1::Bytes(bytes.to_vec()),
            Self::U64List(list) => SemanticProfileOwnedValueV1::U64List(list.to_vec()),
        }
    }
}

/// One typed parameter value that owns its data, as decoded from a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticProfileOwnedValueV1 {
    /// Unsigned integer.
    U64(u64),
    /// UTF-8 text.
    Text(String),
    /// Opaque bytes.
    Bytes(Vec<u8>),
    /// Ordered unsigned integers.
    U64List(Vec<u64>),
}

impl SemanticProfileOwnedValueV1 {
    /// Borrow the value in the form [`SemanticProfileV1::new`] takes.
    #[must_use]
    pub fn as_value(&self) -> SemanticProfileValueV1<'_> {
        match self {
            Self::U64(number) => SemanticProfileValueV1::U64(*number),
            Self::Text(text) => SemanticProfileValueV1::Text(text),
            Self::Bytes(bytes) => SemanticProfileValueV1::Bytes(bytes),
            Self::U64List(list) => SemanticProfileValueV1::U64List(list),
        }
    }
}

/// Ordered parameters decoded from one canonical frame.
pub type SemanticProfileParametersV1 = Vec<(String, SemanticProfileOwnedValueV1)>;

/// Why a parameter list is not a canonical semantic profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticProfileErrorV1 {
    /// A name or key is empty, too long or outside the label grammar.
    Label,
    /// Two parameters share a key.
    DuplicateKey,
    /// The profile declares more parameters than the frame admits.
    TooManyParameters,
    /// A text, byte-string or list value exceeds the value ceiling.
    ValueTooLong,
    /// Bytes offered as a profile frame are not the canonical encoding of any profile.
    Noncanonical,
}

impl fmt::Display for SemanticProfileErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Label => "semantic profile label is empty, too long or outside the grammar",
            Self::DuplicateKey => "semantic profile declares one key twice",
            Self::TooManyParameters => "semantic profile declares too many parameters",
            Self::ValueTooLong => "semantic profile value exceeds its byte ceiling",
            Self::Noncanonical => "semantic profile frame is not a canonical encoding",
        })
    }
}

impl std::error::Error for SemanticProfileErrorV1 {}

/// Typed 32-byte identity of one semantic profile.
///
/// It is the SHA3-256 digest of the profile's canonical frame and of nothing
/// else. It is never a source, build or binary hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticProfileIdV1([u8; Self::BYTES]);

impl SemanticProfileIdV1 {
    /// Identity length in bytes.
    pub const BYTES: usize = 32;

    /// Wrap identity bytes that were read from a record.
    ///
    /// The bytes carry no authority; compare them with a computed identity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }
}

impl fmt::LowerHex for SemanticProfileIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Display for SemanticProfileIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::Debug for SemanticProfileIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SemanticProfileIdV1({self:x})")
    }
}

/// Leading bytes of the frame that identifies an ordered set of profiles.
pub const SEMANTIC_PROFILE_SET_MAGIC_V1: &[u8; 30] = b"iroha:semantic-profile-set:v1\0";

/// One identity for the ordered profiles a measurement depends on.
///
/// It is the SHA3-256 digest of [`SEMANTIC_PROFILE_SET_MAGIC_V1`], the profile
/// count as a `u32` little-endian and the 32-byte identities in the given
/// order. A measurement record has one bounded profile field; a workload that
/// depends on several profiles names this identity there. Changing, adding,
/// removing or reordering a profile changes it.
///
/// # Panics
/// Only for a slice of `2^32` or more identities, which no workload has.
#[must_use]
pub fn semantic_profile_set_id_v1(profiles: &[SemanticProfileIdV1]) -> SemanticProfileIdV1 {
    let mut hash = Sha3_256V1::new();
    hash.update(SEMANTIC_PROFILE_SET_MAGIC_V1);
    let count = u32::try_from(profiles.len()).expect("a profile set is far below 2^32 entries");
    hash.update(&count.to_le_bytes());
    for profile in profiles {
        hash.update(profile.as_bytes());
    }
    SemanticProfileIdV1(hash.finalize().into_bytes())
}

/// Canonical frame and identity of one semantic profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticProfileV1 {
    kind: SemanticProfileKindV1,
    name: String,
    bytes: Vec<u8>,
    id: SemanticProfileIdV1,
}

impl SemanticProfileV1 {
    /// Encode `parameters` in the given order and derive the identity.
    ///
    /// # Errors
    /// Rejects a name or key outside the label grammar, a repeated key, more
    /// than [`SEMANTIC_PROFILE_MAX_PARAMETERS_V1`] parameters and a value
    /// longer than [`SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1`].
    pub fn new(
        kind: SemanticProfileKindV1,
        name: &str,
        parameters: &[(&str, SemanticProfileValueV1<'_>)],
    ) -> Result<Self, SemanticProfileErrorV1> {
        if !is_label(name) {
            return Err(SemanticProfileErrorV1::Label);
        }
        if parameters.len() > SEMANTIC_PROFILE_MAX_PARAMETERS_V1 {
            return Err(SemanticProfileErrorV1::TooManyParameters);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SEMANTIC_PROFILE_MAGIC_V1);
        write_bytes(&mut bytes, kind.label().as_bytes())?;
        write_bytes(&mut bytes, name.as_bytes())?;
        write_len(&mut bytes, parameters.len())?;
        for (index, (key, value)) in parameters.iter().enumerate() {
            if !is_label(key) {
                return Err(SemanticProfileErrorV1::Label);
            }
            if parameters[..index]
                .iter()
                .any(|(earlier, _)| earlier == key)
            {
                return Err(SemanticProfileErrorV1::DuplicateKey);
            }
            write_bytes(&mut bytes, key.as_bytes())?;
            match *value {
                SemanticProfileValueV1::U64(number) => {
                    bytes.push(TYPE_U64);
                    bytes.extend_from_slice(&number.to_le_bytes());
                }
                SemanticProfileValueV1::Text(text) => {
                    bytes.push(TYPE_TEXT);
                    write_bytes(&mut bytes, text.as_bytes())?;
                }
                SemanticProfileValueV1::Bytes(opaque) => {
                    bytes.push(TYPE_BYTES);
                    write_bytes(&mut bytes, opaque)?;
                }
                SemanticProfileValueV1::U64List(list) => {
                    if list.len() > SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 / 8 {
                        return Err(SemanticProfileErrorV1::ValueTooLong);
                    }
                    bytes.push(TYPE_U64_LIST);
                    write_len(&mut bytes, list.len())?;
                    for number in list {
                        bytes.extend_from_slice(&number.to_le_bytes());
                    }
                }
            }
        }
        let mut hash = Sha3_256V1::new();
        hash.update(&bytes);
        Ok(Self {
            kind,
            name: name.to_owned(),
            id: SemanticProfileIdV1(hash.finalize().into_bytes()),
            bytes,
        })
    }

    /// Decode a canonical frame and return the profile with its ordered parameters.
    ///
    /// The frame is parsed strictly and then encoded again; only a frame that
    /// equals its own re-encoding is accepted. A wrong magic, an unknown kind
    /// or type byte, a label outside the grammar, a repeated key, text that is
    /// not UTF-8, a length beyond the ceilings, a truncated frame and trailing
    /// bytes are all refused.
    ///
    /// # Errors
    /// Returns [`SemanticProfileErrorV1::Noncanonical`] for every such frame.
    pub fn decode(
        frame: &[u8],
    ) -> Result<(Self, SemanticProfileParametersV1), SemanticProfileErrorV1> {
        let noncanonical = SemanticProfileErrorV1::Noncanonical;
        let mut reader = Reader(frame);
        if reader.take(SEMANTIC_PROFILE_MAGIC_V1.len()) != Some(&SEMANTIC_PROFILE_MAGIC_V1[..]) {
            return Err(noncanonical);
        }
        let label = reader.text().ok_or(noncanonical)?;
        let kind = SemanticProfileKindV1::ALL
            .into_iter()
            .find(|kind| kind.label() == label)
            .ok_or(noncanonical)?;
        let name = reader.text().ok_or(noncanonical)?.to_owned();
        let count = reader.length().ok_or(noncanonical)?;
        if count > SEMANTIC_PROFILE_MAX_PARAMETERS_V1 {
            return Err(noncanonical);
        }
        let mut parameters = Vec::with_capacity(count);
        for _ in 0..count {
            let key = reader.text().ok_or(noncanonical)?.to_owned();
            let value = match reader.take(1).ok_or(noncanonical)?[0] {
                TYPE_U64 => SemanticProfileOwnedValueV1::U64(reader.u64().ok_or(noncanonical)?),
                TYPE_TEXT => {
                    SemanticProfileOwnedValueV1::Text(reader.text().ok_or(noncanonical)?.to_owned())
                }
                TYPE_BYTES => {
                    SemanticProfileOwnedValueV1::Bytes(reader.bytes().ok_or(noncanonical)?.to_vec())
                }
                TYPE_U64_LIST => {
                    let length = reader.length().ok_or(noncanonical)?;
                    if length > SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 / 8 {
                        return Err(noncanonical);
                    }
                    let mut list = Vec::with_capacity(length);
                    for _ in 0..length {
                        list.push(reader.u64().ok_or(noncanonical)?);
                    }
                    SemanticProfileOwnedValueV1::U64List(list)
                }
                _ => return Err(noncanonical),
            };
            parameters.push((key, value));
        }
        if !reader.0.is_empty() {
            return Err(noncanonical);
        }
        let borrowed: Vec<_> = parameters
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_value()))
            .collect();
        let profile = Self::new(kind, &name, &borrowed).map_err(|_| noncanonical)?;
        if profile.bytes != frame {
            return Err(noncanonical);
        }
        Ok((profile, parameters))
    }

    /// Ordered parameters of this profile, decoded from its own frame.
    ///
    /// # Panics
    /// Never: a constructed profile holds a canonical frame.
    #[must_use]
    pub fn parameters(&self) -> SemanticProfileParametersV1 {
        Self::decode(&self.bytes)
            .expect("a constructed profile frame is canonical")
            .1
    }

    /// What this profile describes.
    #[must_use]
    pub const fn kind(&self) -> SemanticProfileKindV1 {
        self.kind
    }

    /// Stable profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Complete canonical frame; a transcript absorbs these bytes in full.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA3-256 identity of the canonical frame.
    #[must_use]
    pub const fn id(&self) -> SemanticProfileIdV1 {
        self.id
    }
}

/// Strict cursor over an offered frame; every read is bounds-checked.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if count > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Some(head)
    }

    fn length(&mut self) -> Option<usize> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(bytes)).ok()
    }

    fn u64(&mut self) -> Option<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let length = self.length()?;
        if length > SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 {
            return None;
        }
        self.take(length)
    }

    fn text(&mut self) -> Option<&'a str> {
        core::str::from_utf8(self.bytes()?).ok()
    }
}

/// Lower-case ASCII words of letters and digits joined by single `.`, `-` or `_`.
fn is_label(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > SEMANTIC_PROFILE_MAX_LABEL_BYTES_V1 {
        return false;
    }
    let mut after_word = false;
    for &byte in bytes {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            after_word = true;
        } else if matches!(byte, b'.' | b'-' | b'_') && after_word {
            after_word = false;
        } else {
            return false;
        }
    }
    after_word
}

fn write_len(target: &mut Vec<u8>, length: usize) -> Result<(), SemanticProfileErrorV1> {
    let length = u32::try_from(length).map_err(|_| SemanticProfileErrorV1::ValueTooLong)?;
    target.extend_from_slice(&length.to_le_bytes());
    Ok(())
}

fn write_bytes(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SemanticProfileErrorV1> {
    if bytes.len() > SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 {
        return Err(SemanticProfileErrorV1::ValueTooLong);
    }
    write_len(target, bytes.len())?;
    target.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[path = "semantic_profile/tests.rs"]
mod tests;
