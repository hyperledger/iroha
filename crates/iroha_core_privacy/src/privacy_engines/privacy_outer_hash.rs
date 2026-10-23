//! Byte-oriented SHA3-384 framing for the privacy STARK outer protocol.
//!
//! This owner never interprets an outer digest as field elements. Private row
//! buffers remain caller-owned; every cloned hash state and partial block is
//! wiped on success, error, and unwind. Independent Poseidon suites are separate.

use sha3::{
    Sha3_384Core,
    digest::{
        Output,
        core_api::{Buffer, FixedOutputCore, UpdateCore},
    },
};
use zeroize::Zeroize;

/// Exact byte width of every outer SHA3-384 commitment.
pub const PRIVACY_OUTER_DIGEST_BYTES_V1: usize = 48;

const FRAME_MAGIC_V1: &[u8] = b"iroha:privacy:stark:sha3-384:frame:v1\0";
/// Maximum number of prepared rows, independent of their payload byte budget.
pub const MAX_PRIVACY_OUTER_BATCH_FRAMES_V1: usize = 4096;
/// Maximum total framed bytes in one bounded preparation batch.
pub const MAX_PRIVACY_OUTER_BATCH_BYTES_V1: usize = 32 * 1024 * 1024;

/// Opaque outer commitment. Every exact 48-byte value is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivacyOuterDigestV1([u8; 48]);
impl PrivacyOuterDigestV1 {
    /// Construct without imposing field canonicality on a byte hash.
    pub(crate) const fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }
    /// Return the exact digest bytes without endian reinterpretation.
    pub(crate) const fn to_bytes(self) -> [u8; 48] {
        self.0
    }
    /// Overwrite a transient digest tile before its allocation is released.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn zeroize_v1(&mut self) {
        self.0.zeroize();
    }
    /// Borrow the exact digest bytes.
    pub(crate) const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}
impl Default for PrivacyOuterDigestV1 {
    fn default() -> Self {
        Self([0; 48])
    }
}

/// Closed proof-family identity within one X509 proof instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyOuterProofFamilyV1 {
    /// Shared MAIN/CA transcript operations.
    Joint = 0,
    /// Original MAIN commitments and local transcript.
    Main = 1,
    /// Original compact-CA commitments and local transcript.
    Ca = 2,
}
/// Public instance coordinates; these bytes are never counted as secret entropy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyOuterProofScopeV1 {
    pub(crate) nonce: [u8; 32],
    pub(crate) family: PrivacyOuterProofFamilyV1,
}
const PROOF_INSTANCE_PROFILE_MARKER_V1: &[u8; 5] = b"\0X5I1";
const PROOF_INSTANCE_PROFILE_SUFFIX_BYTES_V1: usize = 5 + 1 + 32;

/// Exact coordinates of a privacy outer hash frame.
#[derive(Clone, Copy)]
pub struct PrivacyOuterDomainV1<'a> {
    /// Full 32-byte native BLAKE3 commitment to the twelve-protocol catalog.
    pub(crate) catalog: &'a [u8; 32],
    /// Canonical protocol byte label.
    pub(crate) protocol: &'a [u8],
    /// Compiled proof-profile byte label.
    pub(crate) profile: &'a [u8],
    /// Required scope for dynamic X509 proof hashes; absent for fixed metadata.
    pub(crate) proof_scope: Option<PrivacyOuterProofScopeV1>,
    /// Domain-separation role byte label.
    pub(crate) role: &'a [u8],
    /// Protocol-phase byte label.
    pub(crate) phase: &'a [u8],
    /// Merkle level or zero for non-tree operations.
    pub(crate) level: u64,
    /// Row, node, rejection attempt, or nonce coordinate.
    pub(crate) index: u64,
    /// Accepted challenge or query-draw counter.
    pub(crate) counter: u64,
}

/// The dependency's core wipes its permutation state; this owner additionally
/// wipes its whole block buffer, including bytes beyond its current cursor.
#[derive(Clone, Default)]
struct WipingSha3V1 {
    core: Sha3_384Core,
    buffer: Buffer<Sha3_384Core>,
}
impl WipingSha3V1 {
    fn update(&mut self, bytes: &[u8]) {
        let core = &mut self.core;
        self.buffer
            .digest_blocks(bytes, |blocks| core.update_blocks(blocks));
    }
    fn finish(mut self) -> PrivacyOuterDigestV1 {
        let mut output = Output::<Sha3_384Core>::default();
        self.core.finalize_fixed_core(&mut self.buffer, &mut output);
        PrivacyOuterDigestV1::from_bytes(output.into())
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn finish_in_place_v1(&mut self) -> PrivacyOuterDigestV1 {
        let mut output = Output::<Sha3_384Core>::default();
        self.core.finalize_fixed_core(&mut self.buffer, &mut output);
        // Drop the old wiping owner in its original allocation before replacing
        // it. The buffer and dependency core erase in place, without moving a
        // private state into a temporary Vec with uncleared vacated slots.
        *self = Self::default();
        PrivacyOuterDigestV1::from_bytes(output.into())
    }
    fn wipe_buffer(&mut self) {
        self.buffer.pad_with_zeros().as_mut_slice().zeroize();
    }
}
impl Drop for WipingSha3V1 {
    fn drop(&mut self) {
        self.wipe_buffer();
    }
}

fn prefix_bytes_v1(domain: PrivacyOuterDomainV1<'_>) -> Option<usize> {
    let mut bytes = FRAME_MAGIC_V1.len().checked_add(32)?;
    for (index, label) in [domain.protocol, domain.profile, domain.role, domain.phase]
        .into_iter()
        .enumerate()
    {
        if label.is_empty() {
            return None;
        }
        let length = label
            .len()
            .checked_add(if index == 1 && domain.proof_scope.is_some() {
                PROOF_INSTANCE_PROFILE_SUFFIX_BYTES_V1
            } else {
                0
            })?;
        u16::try_from(length).ok()?;
        bytes = bytes.checked_add(2)?.checked_add(length)?;
    }
    bytes.checked_add(24)
}
fn field_bytes_v1(lengths: &[usize]) -> Option<usize> {
    u32::try_from(lengths.len()).ok()?;
    lengths.iter().try_fold(4usize, |bytes, &length| {
        u64::try_from(length).ok()?;
        bytes.checked_add(8)?.checked_add(length)
    })
}
fn write_domain_prefix_v1(state: &mut WipingSha3V1, domain: PrivacyOuterDomainV1<'_>) {
    state.update(FRAME_MAGIC_V1);
    state.update(domain.catalog);
    for (index, label) in [domain.protocol, domain.profile, domain.role, domain.phase]
        .into_iter()
        .enumerate()
    {
        // Construction validates every conversion before any hashing.
        let scope = if index == 1 { domain.proof_scope } else { None };
        let length = label.len() + scope.map_or(0, |_| PROOF_INSTANCE_PROFILE_SUFFIX_BYTES_V1);
        state.update(&(length as u16).to_be_bytes());
        state.update(label);
        if let Some(scope) = scope {
            state.update(PROOF_INSTANCE_PROFILE_MARKER_V1);
            state.update(&[scope.family as u8]);
            state.update(&scope.nonce);
        }
    }
    state.update(&domain.level.to_be_bytes());
}
fn write_fields_v1(state: &mut WipingSha3V1, fields: &[&[u8]]) {
    state.update(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        state.update(&(field.len() as u64).to_be_bytes());
        state.update(field);
    }
}

/// Validated frame borrowing its ordered payload; construction never copies it.
pub struct PrivacyOuterFrameV1<'a> {
    domain: PrivacyOuterDomainV1<'a>,
    fields: &'a [&'a [u8]],
}
impl<'a> PrivacyOuterFrameV1<'a> {
    /// Check all framing lengths and total-size arithmetic before dispatch.
    pub(crate) fn new(domain: PrivacyOuterDomainV1<'a>, fields: &'a [&'a [u8]]) -> Option<Self> {
        let mut total = prefix_bytes_v1(domain)?.checked_add(4)?;
        u32::try_from(fields.len()).ok()?;
        for field in fields {
            u64::try_from(field.len()).ok()?;
            total = total.checked_add(8)?.checked_add(field.len())?;
        }
        let _ = total;
        Some(Self { domain, fields })
    }
    /// Exact framed size for bounded preparation admission, without allocation.
    pub(crate) fn byte_count_for_field_lengths_v1(
        domain: PrivacyOuterDomainV1<'_>,
        lengths: &[usize],
    ) -> Option<usize> {
        prefix_bytes_v1(domain)?.checked_add(field_bytes_v1(lengths)?)
    }
    /// Hash the exact validated frame.
    pub(crate) fn hash(&self) -> PrivacyOuterDigestV1 {
        let mut state = WipingSha3V1::default();
        write_domain_prefix_v1(&mut state, self.domain);
        state.update(&self.domain.index.to_be_bytes());
        state.update(&self.domain.counter.to_be_bytes());
        write_fields_v1(&mut state, self.fields);
        state.finish()
    }
}

/// Cached public framing through level; each digest retains its own coordinates
/// and complete ordered fields. Clones wipe their complete SHA3 state on drop.
#[derive(Clone)]
pub struct PrivacyOuterDomainPrefixV1 {
    state: WipingSha3V1,
    prefix_bytes: usize,
}
impl PrivacyOuterDomainPrefixV1 {
    /// Cache only the public, checked invariant domain prefix.
    pub(crate) fn new(domain: PrivacyOuterDomainV1<'_>) -> Option<Self> {
        let prefix_bytes = prefix_bytes_v1(domain)?;
        let mut state = WipingSha3V1::default();
        write_domain_prefix_v1(&mut state, domain);
        Some(Self {
            state,
            prefix_bytes,
        })
    }
    /// Start an exact final field while reusing only the checked public prefix.
    /// Coordinates and every field length remain freshly bound after the clone.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn last_field_stream_at_with_counter(
        &self,
        index: u64,
        counter: u64,
        prefix_fields: &[&[u8]],
        final_field_len: usize,
    ) -> Result<PrivacyOuterLastFieldStreamV1, PrivacyOuterLastFieldStreamErrorV1> {
        let invalid = PrivacyOuterLastFieldStreamErrorV1::FramingLimitExceeded;
        let count = prefix_fields.len().checked_add(1).ok_or(invalid)?;
        let count = u32::try_from(count).map_err(|_| invalid)?;
        let final_length = u64::try_from(final_field_len).map_err(|_| invalid)?;
        let mut bytes = self.prefix_bytes.checked_add(4).ok_or(invalid)?;
        for field in prefix_fields {
            u64::try_from(field.len()).map_err(|_| invalid)?;
            bytes = bytes
                .checked_add(8)
                .and_then(|n| n.checked_add(field.len()))
                .ok_or(invalid)?;
        }
        bytes
            .checked_add(8)
            .and_then(|n| n.checked_add(final_field_len))
            .ok_or(invalid)?;
        let mut state = self.state.clone();
        state.update(&index.to_be_bytes());
        state.update(&counter.to_be_bytes());
        state.update(&count.to_be_bytes());
        for field in prefix_fields {
            state.update(&(field.len() as u64).to_be_bytes());
            state.update(field);
        }
        state.update(&final_length.to_be_bytes());
        Ok(PrivacyOuterLastFieldStreamV1 {
            state,
            remaining: final_field_len,
        })
    }
    /// Hash one index/counter with the identical scalar framing.
    pub(crate) fn hash_at_with_counter(
        &self,
        index: u64,
        counter: u64,
        fields: &[&[u8]],
    ) -> Option<PrivacyOuterDigestV1> {
        let mut bytes = self.prefix_bytes.checked_add(4)?;
        u32::try_from(fields.len()).ok()?;
        for field in fields {
            u64::try_from(field.len()).ok()?;
            bytes = bytes.checked_add(8)?.checked_add(field.len())?;
        }
        let _ = bytes;
        let mut state = self.state.clone();
        state.update(&index.to_be_bytes());
        state.update(&counter.to_be_bytes());
        write_fields_v1(&mut state, fields);
        Some(state.finish())
    }
}

/// An exact final-field stream must neither overrun nor finalize prematurely.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyOuterLastFieldStreamErrorV1 {
    /// A label, count, length, or total exceeds its exact framing width.
    FramingLimitExceeded,
    /// Input exceeds the declared final field; the owner remains unchanged.
    InputOverrun {
        /// Bytes still required by the declaration.
        remaining: usize,
        /// Bytes supplied by the rejected update.
        supplied: usize,
    },
    /// Finalization preceded the end of the declared final field.
    InputUnderrun {
        /// Bytes missing from the declaration.
        remaining: usize,
    },
}
/// Incremental final-field owner with bounded declared input and wiping state.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct PrivacyOuterLastFieldStreamV1 {
    state: WipingSha3V1,
    remaining: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl PrivacyOuterLastFieldStreamV1 {
    /// Scalar byte oracle for the prefix path; no parallel legacy production owner.
    #[cfg(test)]
    pub(crate) fn new(
        domain: PrivacyOuterDomainV1<'_>,
        prefix_fields: &[&[u8]],
        final_field_len: usize,
    ) -> Result<Self, PrivacyOuterLastFieldStreamErrorV1> {
        let invalid = PrivacyOuterLastFieldStreamErrorV1::FramingLimitExceeded;
        let count = prefix_fields.len().checked_add(1).ok_or(invalid)?;
        let count = u32::try_from(count).map_err(|_| invalid)?;
        let final_length = u64::try_from(final_field_len).map_err(|_| invalid)?;
        let mut bytes = prefix_bytes_v1(domain)
            .ok_or(invalid)?
            .checked_add(4)
            .ok_or(invalid)?;
        for field in prefix_fields {
            u64::try_from(field.len()).map_err(|_| invalid)?;
            bytes = bytes
                .checked_add(8)
                .and_then(|n| n.checked_add(field.len()))
                .ok_or(invalid)?;
        }
        bytes
            .checked_add(8)
            .and_then(|n| n.checked_add(final_field_len))
            .ok_or(invalid)?;
        let mut state = WipingSha3V1::default();
        write_domain_prefix_v1(&mut state, domain);
        state.update(&domain.index.to_be_bytes());
        state.update(&domain.counter.to_be_bytes());
        state.update(&count.to_be_bytes());
        for field in prefix_fields {
            state.update(&(field.len() as u64).to_be_bytes());
            state.update(field);
        }
        state.update(&final_length.to_be_bytes());
        Ok(Self {
            state,
            remaining: final_field_len,
        })
    }
    /// Absorb only within the remaining declared length. Failure changes nothing.
    pub(crate) fn update(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PrivacyOuterLastFieldStreamErrorV1> {
        if self.remaining == usize::MAX {
            return Err(PrivacyOuterLastFieldStreamErrorV1::FramingLimitExceeded);
        }
        if bytes.len() > self.remaining {
            return Err(PrivacyOuterLastFieldStreamErrorV1::InputOverrun {
                remaining: self.remaining,
                supplied: bytes.len(),
            });
        }
        self.state.update(bytes);
        self.remaining -= bytes.len();
        Ok(())
    }
    /// Finalize and wipe in the original row-state slot, then permanently seal it.
    pub(crate) fn finalize_in_place_v1(
        &mut self,
    ) -> Result<PrivacyOuterDigestV1, PrivacyOuterLastFieldStreamErrorV1> {
        if self.remaining != 0 {
            return Err(PrivacyOuterLastFieldStreamErrorV1::InputUnderrun {
                remaining: self.remaining,
            });
        }
        let digest = self.state.finish_in_place_v1();
        // A nonempty checked frame prefix prohibits this declared field size.
        self.remaining = usize::MAX;
        Ok(digest)
    }
    /// Scalar consuming oracle retained only for independent byte-parity tests.
    #[cfg(test)]
    pub(crate) fn finalize(
        self,
    ) -> Result<PrivacyOuterDigestV1, PrivacyOuterLastFieldStreamErrorV1> {
        if self.remaining != 0 {
            return Err(PrivacyOuterLastFieldStreamErrorV1::InputUnderrun {
                remaining: self.remaining,
            });
        }
        Ok(self.state.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_384};

    fn hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |v: u8| match v {
                    b'0'..=b'9' => v - b'0',
                    b'a'..=b'f' => v - b'a' + 10,
                    _ => panic!("invalid fixed test vector"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }
    fn domain(catalog: &[u8; 32]) -> PrivacyOuterDomainV1<'_> {
        PrivacyOuterDomainV1 {
            proof_scope: None,
            catalog,
            protocol: b"protocol",
            profile: b"profile",
            role: b"role",
            phase: b"phase",
            level: 0,
            index: 0,
            counter: 0,
        }
    }

    fn assert_cached_stream_v1(
        domain: PrivacyOuterDomainV1<'_>,
        prefix_fields: &[&[u8]],
        last: &[u8],
        chunk_size: usize,
        expected: PrivacyOuterDigestV1,
    ) {
        let prefix = PrivacyOuterDomainPrefixV1::new(domain).unwrap();
        let mut stream = prefix
            .last_field_stream_at_with_counter(
                domain.index,
                domain.counter,
                prefix_fields,
                last.len(),
            )
            .unwrap();
        for chunk in last.chunks(chunk_size) {
            stream.update(chunk).unwrap();
        }
        assert_eq!(stream.finalize_in_place_v1(), Ok(expected));
        assert!(stream.finalize_in_place_v1().is_err());
        assert!(stream.update(&[]).is_err());
        assert!(stream.state.buffer.get_data().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn scoped_x509_frames_match_independent_bytes_and_all_stream_owners() {
        let catalog = [0x37; 32];
        let mut observed = std::collections::BTreeSet::new();
        for family in [
            PrivacyOuterProofFamilyV1::Joint,
            PrivacyOuterProofFamilyV1::Main,
            PrivacyOuterProofFamilyV1::Ca,
        ] {
            for nonce in [[0; 32], [1; 32], [0xff; 32]] {
                let mut scoped = domain(&catalog);
                scoped.proof_scope = Some(PrivacyOuterProofScopeV1 { nonce, family });
                scoped.level = 7;
                scoped.index = 42;
                scoped.counter = 13;
                // Encode the required effective profile independently of the production writer.
                let mut profile = b"profile".to_vec();
                profile.extend_from_slice(b"\0X5I1");
                profile.push(family as u8);
                profile.extend_from_slice(&nonce);
                for length in [0, 1, 103, 104, 105, 208] {
                    let payload = vec![0x29; length];
                    let fields: [&[u8]; 2] = [b"prefix", &payload];
                    let mut bytes = b"iroha:privacy:stark:sha3-384:frame:v1\0".to_vec();
                    bytes.extend_from_slice(&catalog);
                    for label in [
                        b"protocol".as_slice(),
                        profile.as_slice(),
                        b"role",
                        b"phase",
                    ] {
                        bytes.extend_from_slice(&u16::try_from(label.len()).unwrap().to_be_bytes());
                        bytes.extend_from_slice(label);
                    }
                    for coordinate in [7_u64, 42, 13] {
                        bytes.extend_from_slice(&coordinate.to_be_bytes());
                    }
                    bytes.extend_from_slice(&2_u32.to_be_bytes());
                    for field in fields {
                        bytes.extend_from_slice(&u64::try_from(field.len()).unwrap().to_be_bytes());
                        bytes.extend_from_slice(field);
                    }
                    let expected =
                        PrivacyOuterDigestV1::from_bytes(Sha3_384::digest(&bytes).into());
                    assert_eq!(
                        PrivacyOuterFrameV1::new(scoped, &fields).unwrap().hash(),
                        expected
                    );
                    assert_eq!(
                        PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(scoped, &[6, length]),
                        Some(bytes.len())
                    );
                    assert_eq!(
                        PrivacyOuterDomainPrefixV1::new(scoped)
                            .unwrap()
                            .hash_at_with_counter(42, 13, &fields),
                        Some(expected)
                    );
                    for chunk_size in [1, 7, 104] {
                        assert_cached_stream_v1(
                            scoped,
                            &[b"prefix"],
                            &payload,
                            chunk_size,
                            expected,
                        );
                        let mut stream =
                            PrivacyOuterLastFieldStreamV1::new(scoped, &[b"prefix"], length)
                                .unwrap();
                        for chunk in payload.chunks(chunk_size) {
                            stream.update(chunk).unwrap();
                        }
                        assert_eq!(stream.finalize(), Ok(expected));
                    }
                    assert!(observed.insert(expected));
                    let mut fixed = scoped;
                    fixed.proof_scope = None;
                    assert_ne!(
                        PrivacyOuterFrameV1::new(fixed, &fields).unwrap().hash(),
                        expected
                    );
                    assert_eq!(
                        PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(fixed, &[6, length]),
                        Some(bytes.len() - 38)
                    );
                }
            }
        }
        assert_eq!(observed.len(), 54);
    }

    #[test]
    fn scoped_profile_length_checks_include_the_complete_nonce_suffix() {
        let catalog = [0; 32];
        let maximum = vec![b'x'; usize::from(u16::MAX) - 38];
        let oversized = vec![b'x'; maximum.len() + 1];
        let mut scoped = domain(&catalog);
        scoped.proof_scope = Some(PrivacyOuterProofScopeV1 {
            nonce: [0; 32],
            family: PrivacyOuterProofFamilyV1::Main,
        });
        scoped.profile = &maximum;
        assert!(PrivacyOuterFrameV1::new(scoped, &[]).is_some());
        assert!(PrivacyOuterDomainPrefixV1::new(scoped).is_some());
        scoped.profile = &oversized;
        assert!(PrivacyOuterFrameV1::new(scoped, &[]).is_none());
        assert!(PrivacyOuterDomainPrefixV1::new(scoped).is_none());
        assert!(PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(scoped, &[]).is_none());
        assert!(matches!(
            PrivacyOuterLastFieldStreamV1::new(scoped, &[], 0),
            Err(PrivacyOuterLastFieldStreamErrorV1::FramingLimitExceeded)
        ));
        scoped.proof_scope = None;
        assert!(PrivacyOuterFrameV1::new(scoped, &[]).is_some());
    }

    #[test]
    fn sha3_frame_fourteen_reference_vectors_match_scalar_prefix_and_stream() {
        // Exact inputs and outputs from the independently implemented Python SHA3 specification.
        // This native control must pass on every supported CPU/assembly feature configuration.
        {
            // empty-fields
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("d3003df62b7c5dbbfc26e2a7f48e3d6c8861f911db62f71602a4d4b2273902aae701261984d59b8b4d71a30bba3e405d").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(154)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // empty-field
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("3715b9aa5251505db994dee88d2500f7739c181737d64156c51cd27a343fd94c71da28a258cfd81306662a08db662901").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(162)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // ordered-fields
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("61"), hex("6263")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("f1ba8b26cc6ccd175d33596d569cd5edf6f660c75a4c71ba9486a3f69b823cc20a75bea5f9d13fb6b3257a56e7a0e124").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(173)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // split-fields
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("6162"), hex("63")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("21b1f6a3f682306e8077207697334336cfac6f29d06b9204da24b265202a87b8787c85f148f60ba4a84740fcf1a4297a").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(173)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // protocol
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d763178");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("17405afb280f3fa256c594f69fcc486b3361b697cf7fe285bcb64bfc47e467778a121741ec046a6ed2471bdc914b2409").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(164)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // profile
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c6578");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("a2e4a4a8f296f0852389814c88bc46673760979f4fc60c4374c2f71a16624afc4380562bdcb910d2fcc652d22da34b35").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(164)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // role
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c65616678");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("fffcadaf07d909c27045ee38d6e4dad311bcc6763262a6e5092c76b7834611d7c1cd41c1e48f905b134c2d40e9305220").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(164)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // phase
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f777378");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("7578f54848a309d5e933e8456f03bd01216d6d00cdc47e2386fa3b519d4357ba62a76ee47e20b98547bd0185eafb506a").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(164)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // level
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 81_985_529_216_486_895,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("e36cc4e68e30ff166359a719c8b6785859001f9c855bc555b86f9ca1532d214eab4fa0fb7de23a4a776f03b73e71ee90").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(163)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // index
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 81_985_529_216_486_895,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("dc92778465b80cf0c33033e89238e9be8ee7ad05b838023c6cf4be061f953318c90b543c6df280d6f98f99b4a85d8c44").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(163)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // counter
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 81_985_529_216_486_895,
            };
            let payloads: Vec<Vec<u8>> = vec![hex("78")];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("ac21c3fd93b2069a889575678ea748f0f1a567ad862cc7acc06c327436fcb86e501f141291b5d9e2acc70165359ee91d").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(163)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // binary-payload
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            )];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("666de662f2951da85584bb9c3019f172c53238f60df348f2819e6713ccc2417e6183c64e4aba756f1ecf9949cdbe2e75").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(418)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // sha3-rate-boundary
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex(
                "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
            )];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("265dc93b7db72da79b7b860a0056ee874fa56bdb05cc18217b50af44412e39670cb71106540f885c29d92ea8e6f2aac9").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(266)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
        {
            // large-row
            let catalog = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let protocol = hex("69766d2d707269766174652d6e6f74652d737461726b2d7631");
            let profile = hex("666978747572652d70726f66696c65");
            let role = hex("6c656166");
            let phase = hex("726f7773");
            let catalog: [u8; 32] = catalog.try_into().unwrap();
            let domain = PrivacyOuterDomainV1 {
                proof_scope: None,
                catalog: &catalog,
                protocol: &protocol,
                profile: &profile,
                role: &role,
                phase: &phase,
                level: 0,
                index: 0,
                counter: 0,
            };
            let payloads: Vec<Vec<u8>> = vec![hex(
                "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
            )];
            let fields: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            let expected = PrivacyOuterDigestV1::from_bytes(hex("448d319a867176b89cfbcbfb1a77034d9742af827dc9fa2f73dd7d76f7d94a4dd36603e03cc8d55df48a36dc478a832d").try_into().unwrap());
            assert_eq!(
                PrivacyOuterFrameV1::new(domain, &fields).unwrap().hash(),
                expected
            );
            assert_eq!(
                PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                    domain,
                    &fields.iter().map(|v| v.len()).collect::<Vec<_>>()
                ),
                Some(4610)
            );
            assert_eq!(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .unwrap()
                    .hash_at_with_counter(domain.index, domain.counter, &fields),
                Some(expected)
            );
            if let Some((last, prefix)) = fields.split_last() {
                for chunk_size in [1, 7, 103, 104, 105, 1024] {
                    let mut stream =
                        PrivacyOuterLastFieldStreamV1::new(domain, prefix, last.len()).unwrap();
                    for chunk in last.chunks(chunk_size) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finalize(), Ok(expected));
                    assert_cached_stream_v1(domain, prefix, last, chunk_size, expected);
                }
            }
        }
    }
    #[test]
    fn cached_final_field_prefix_preserves_scalar_bytes_coordinates_and_errors() {
        let catalog = [37; 32];
        let mut domain = domain(&catalog);
        domain.level = 11;
        let prefix = PrivacyOuterDomainPrefixV1::new(domain).unwrap();
        for index in [0, 1, 4_194_303, u64::MAX] {
            for counter in [0, 2, 65_535, u64::MAX] {
                for length in [0, 1, 103, 104, 105, 208, 1024] {
                    let value = vec![29; length];
                    domain.index = index;
                    domain.counter = counter;
                    let expected = PrivacyOuterFrameV1::new(domain, &[b"prefix", &value])
                        .unwrap()
                        .hash();
                    let mut actual = prefix
                        .last_field_stream_at_with_counter(index, counter, &[b"prefix"], length)
                        .unwrap();
                    for chunk in value.chunks(7) {
                        actual.update(chunk).unwrap();
                    }
                    assert_eq!(actual.finalize(), Ok(expected));
                    if index == 1 && counter == 2 && length == 104 {
                        assert_eq!(
                            expected.as_bytes(),
                            &hex(
                                "35c6b73b01d2f1c5fca3cf9df6dd471f9cc2360dd2875bfcc78121e789988c52dc5c668b62a60e078fe6331a02a3ac0a"
                            )[..]
                        );
                    }
                }
            }
        }
        let mut stream = prefix
            .last_field_stream_at_with_counter(1, 2, &[], 8)
            .unwrap();
        assert!(stream.update(&[3; 9]).is_err());
        stream.update(&[3; 8]).unwrap();
        assert_eq!(
            stream.finalize().unwrap(),
            PrivacyOuterFrameV1::new(
                PrivacyOuterDomainV1 {
                    proof_scope: None,
                    index: 1,
                    counter: 2,
                    ..domain
                },
                &[&[3; 8]]
            )
            .unwrap()
            .hash()
        );
        assert!(
            prefix
                .last_field_stream_at_with_counter(1, 2, &[], 8)
                .unwrap()
                .finalize()
                .is_err()
        );
        assert!(
            prefix
                .last_field_stream_at_with_counter(1, 2, &[], usize::MAX)
                .is_err()
        );
        // Prefix clones use the same private buffer-clearing owner as streams.
        let mut cloned = prefix.state.clone();
        cloned.wipe_buffer();
        assert!(cloned.buffer.get_data().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sha3_wiping_owner_matches_standard_digest_and_wipes_cloned_buffers() {
        for length in [0, 1, 103, 104, 105, 207, 208, 4448] {
            let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let mut owner = WipingSha3V1::default();
            for chunk in payload.chunks(7) {
                owner.update(chunk);
            }
            let cloned = owner.clone();
            let expected: [u8; 48] = Sha3_384::digest(&payload).into();
            assert_eq!(owner.finish().to_bytes(), expected);
            assert_eq!(cloned.finish().to_bytes(), expected);
        }
        let mut owner = WipingSha3V1::default();
        owner.update(&[0xa5; 103]);
        let mut cloned = owner.clone();
        owner.wipe_buffer();
        assert!(owner.buffer.pad_with_zeros().iter().all(|byte| *byte == 0));
        assert!(cloned.buffer.get_data().iter().all(|byte| *byte == 0xa5));
        cloned.wipe_buffer();
        assert!(cloned.buffer.pad_with_zeros().iter().all(|byte| *byte == 0));
    }
    #[test]
    fn sha3_framing_rejects_bad_labels_and_checked_size_overflow() {
        let catalog = [0; 32];
        let base = domain(&catalog);
        let too_long = vec![b'x'; usize::from(u16::MAX) + 1];
        for label in [b"".as_slice(), too_long.as_slice()] {
            for position in 0..4 {
                let mut invalid = base;
                match position {
                    0 => invalid.protocol = label,
                    1 => invalid.profile = label,
                    2 => invalid.role = label,
                    _ => invalid.phase = label,
                }
                assert!(PrivacyOuterFrameV1::new(invalid, &[]).is_none());
                assert!(PrivacyOuterDomainPrefixV1::new(invalid).is_none());
                assert!(matches!(
                    PrivacyOuterLastFieldStreamV1::new(invalid, &[], 0),
                    Err(PrivacyOuterLastFieldStreamErrorV1::FramingLimitExceeded)
                ));
            }
        }
        assert_eq!(
            PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(base, &[usize::MAX]),
            None
        );
        assert!(matches!(
            PrivacyOuterLastFieldStreamV1::new(base, &[], usize::MAX),
            Err(PrivacyOuterLastFieldStreamErrorV1::FramingLimitExceeded)
        ));
        let maximum = vec![b'x'; usize::from(u16::MAX)];
        let valid = PrivacyOuterDomainV1 {
            proof_scope: None,
            protocol: &maximum,
            ..base
        };
        assert!(PrivacyOuterFrameV1::new(valid, &[]).is_some());
    }
    #[test]
    fn sha3_stream_overrun_is_unchanged_and_underrun_cannot_finalize() {
        let catalog = [0; 32];
        let domain = domain(&catalog);
        let mut stream = PrivacyOuterLastFieldStreamV1::new(domain, &[b"prefix"], 3).unwrap();
        stream.update(b"a").unwrap();
        assert_eq!(
            stream.update(b"bcd"),
            Err(PrivacyOuterLastFieldStreamErrorV1::InputOverrun {
                remaining: 2,
                supplied: 3
            })
        );
        stream.update(b"bc").unwrap();
        let expected = PrivacyOuterFrameV1::new(domain, &[b"prefix", b"abc"])
            .unwrap()
            .hash();
        assert_eq!(stream.finalize(), Ok(expected));
        let stream = PrivacyOuterLastFieldStreamV1::new(domain, &[], 1).unwrap();
        assert_eq!(
            stream.finalize(),
            Err(PrivacyOuterLastFieldStreamErrorV1::InputUnderrun { remaining: 1 })
        );
        let absent = PrivacyOuterFrameV1::new(domain, &[]).unwrap().hash();
        let empty = PrivacyOuterLastFieldStreamV1::new(domain, &[], 0)
            .unwrap()
            .finalize()
            .unwrap();
        assert_ne!(absent, empty);
        assert_eq!(
            empty,
            PrivacyOuterFrameV1::new(domain, &[b""]).unwrap().hash()
        );
        assert_eq!(
            PrivacyOuterDigestV1::from_bytes([0xff; 48]).to_bytes(),
            [0xff; 48]
        );
    }
}
