//! Canonical original-funded availability evidence and signature checks.
//!
//! The outer codec is the existing semantic Norito `ByteSequence`. Its inner signed-content
//! table is count || ordered row hashes || manifest signature || ordered row signatures.
//! Indices and exact lengths derive from the signed layout and are bound by each signature.
mod author;
pub use author::{AuthoredBody, AuthoringError, PayloadAuthoring};
mod acquisition;
pub use acquisition::{AcquisitionError, PayloadAcquisition};
mod custody;
use super::{MAX_DA_CHUNK_COUNT, MAX_DA_PAYLOAD_SIZE};
use crate::{
    bytes::{ByteDomain, ByteSequence, SharedBytes, SharedDomain},
    crypto::Crypto,
    message::BlockHeader,
    types::{Hash32, HeightConfig, SIGNATURE_LEN, Signature},
};
pub use custody::{
    AvailabilitySource, AvailableBody, BodyRestoration, RestorationError, VerifiedMaterial,
};
use iroha_allocation::AllocationBudget;
use iroha_primitives::erasure::rs16::compact::CompactShape;

/// Maximum exact inner frame; the canonical Norito envelope is additional.
pub const MAX_AVAILABILITY_FRAME_BYTES: usize =
    4 + SIGNATURE_LEN + MAX_DA_CHUNK_COUNT as usize * (32 + SIGNATURE_LEN);
/// Canonical immutable signed availability table domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvailabilityDomain {}
impl ByteDomain for AvailabilityDomain {
    const NAME: &'static str = "AvailabilityFrame";
    const FRAME: &'static str = "iroha_sumeragi::availability::AvailabilityFrame";
}
impl SharedDomain for AvailabilityDomain {
    // Only the separately authenticated result-only genesis certificate accepts empty bytes.
    const MIN: usize = 0;
    const MAX: usize = MAX_AVAILABILITY_FRAME_BYTES;
}
/// One immutable original-funded table retaining ALL original signatures, never shard bodies.
pub type AvailabilityFrame = ByteSequence<SharedBytes<AvailabilityDomain>>;
/// Canonical reconstructed application payload domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadDomain {}
impl ByteDomain for PayloadDomain {
    const NAME: &'static str = "PayloadBytes";
    const FRAME: &'static str = "iroha_sumeragi::availability::PayloadBytes";
}
impl SharedDomain for PayloadDomain {
    const MAX: usize = MAX_DA_PAYLOAD_SIZE;
}
/// One immutable original-funded application payload, separate from availability evidence.
pub type PayloadBytes = ByteSequence<SharedBytes<PayloadDomain>>;

/// Canonical signed row body, whose position/length/hash is authorized by the mandatory frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowDomain {}
impl ByteDomain for RowDomain {
    const NAME: &'static str = "RowBytes";
    const FRAME: &'static str = "iroha_sumeragi::availability::RowBytes";
}
impl SharedDomain for RowDomain {
    const MIN: usize = 2;
    const MAX: usize = super::MAX_DA_CHUNK_SIZE_BYTES as usize;
}
/// Actual original-funded received RS16 row bytes, not a signature-table custody claim.
pub type RowBytes = ByteSequence<SharedBytes<RowDomain>>;
impl AvailabilityFrame {
    /// Check complete mandatory non-genesis table framing before cryptographic admission.
    pub fn has_valid_structure(&self) -> bool {
        let bytes = self.as_slice();
        let Some(count) = bytes.get(..4) else {
            return false;
        };
        let count = u32::from_be_bytes(count.try_into().expect("four bytes")) as usize;
        (2..=MAX_DA_CHUNK_COUNT as usize).contains(&count)
            && bytes.len() == 4 + SIGNATURE_LEN + count * (32 + SIGNATURE_LEN)
    }
}

/// Availability rejection; a resource/source refusal is never evidence of a signed defect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvailabilityError {
    /// Instance, complete epoch, height or author differs from authenticated source.
    Source,
    /// A signed dimension or payload bound is invalid.
    Shape,
    /// Canonical table count or exact byte length is malformed.
    Frame,
    /// Signed content or body digest differs.
    Digest,
    /// An original author signature is invalid.
    Signature,
    /// Original backing is not admitted to the supplied production pool.
    ForeignBudget,
}

/// Borrowed authenticated table. This proves author signatures, NOT received/durable bodies.
/// Only reconstruction from actual shards can establish available payload custody.
pub struct VerifiedManifest<'a> {
    table: VerifiedAvailability<'a>,
    frame: &'a AvailabilityFrame,
    config: &'a HeightConfig,
}
/// Borrowed cryptographic evidence for a portable proof reader. This carries no native pool,
/// received-row count, durable-body claim or method that can construct `AvailableBody`.
/// The caller must first decode the declared canonical Norito `AvailabilityFrame` envelope.
pub struct VerifiedAvailability<'a> {
    header: &'a BlockHeader,
    bytes: &'a [u8],
    shape: CompactShape,
    block_hash: Hash32,
}

fn content_end(chunks: usize) -> usize {
    4 + chunks * 32
}

/// Exact unsigned table bytes, borrowed without decoded-list or payload concatenation.
fn unsigned_content(bytes: &[u8], shape: CompactShape) -> Result<&[u8], AvailabilityError> {
    let chunks = shape.chunk_count();
    let count = bytes.get(..4).ok_or(AvailabilityError::Frame)?;
    if chunks == 0
        || chunks > MAX_DA_CHUNK_COUNT as usize
        || u32::from_be_bytes(count.try_into().expect("four bytes")) as usize != chunks
        || bytes.len() != 4 + SIGNATURE_LEN + chunks * (32 + SIGNATURE_LEN)
    {
        return Err(AvailabilityError::Frame);
    }
    Ok(&bytes[..content_end(chunks)])
}

/// Domain hash of exact canonical ordered content, excluding final block hash and signatures.
pub fn content_digest(crypto: &dyn Crypto, content: &[u8]) -> Hash32 {
    crypto.hash_chunks(&[b"sumeragi/availability/content", content])
}
/// Domain hash of exact actual row bytes; no full-row concatenation allocation.
pub fn row_digest(crypto: &dyn Crypto, row: &[u8]) -> Hash32 {
    crypto.hash_chunks(&[b"sumeragi/availability/row", row])
}

// All fields have fixed widths; no heap allocation or codec-dependent signature preimage.
fn statement(
    header: &BlockHeader,
    bh: Hash32,
    row: Option<(u32, u32, Hash32)>,
) -> ([u8; 224], usize) {
    let mut bytes = [0; 224];
    let mut at = 0;
    let mut put = |part: &[u8]| {
        bytes[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    };
    put(b"sumeragi/availability/sign");
    put(&[u8::from(row.is_some())]);
    put(header.instance.as_bytes());
    put(&header.epoch.epoch.to_be_bytes());
    put(header.epoch.context.as_bytes());
    put(&header.height.to_be_bytes());
    put(&header.origin_view.to_be_bytes());
    put(bh.as_bytes());
    put(header.availability_digest.as_bytes());
    if let Some((index, length, hash)) = row {
        put(&index.to_be_bytes());
        put(&length.to_be_bytes());
        put(hash.as_bytes());
    }
    (bytes, at)
}

/// Verify the complete original signature table under the exact historical authority.
/// This makes no payload/table concatenation copy and never equates table possession with custody.
/// Header hashing still uses the bounded existing header preimage allocation.
/// The caller also applies the existing proposal/header and historical-finality predicates.
///
/// # Errors
/// Rejects foreign funding, mismatched historical authority, invalid geometry or framing,
/// and any content digest or original author signature mismatch.
pub fn verify_manifest<'a>(
    instance: Hash32,
    config: &'a HeightConfig,
    header: &'a BlockHeader,
    frame: &'a AvailabilityFrame,
    budget: &AllocationBudget,
    crypto: &dyn Crypto,
) -> Result<VerifiedManifest<'a>, AvailabilityError> {
    if !frame.admitted_to(budget) {
        return Err(AvailabilityError::ForeignBudget);
    }
    Ok(VerifiedManifest {
        table: verify_availability(instance, config, header, frame.as_slice(), crypto)?,
        frame,
        config,
    })
}

/// Authenticate a borrowed complete signature table against the independently trusted schedule.
/// This grants only evidence authenticity, never native ownership or received/durable custody.
/// All instance, epoch, author, geometry, digest and original-signature checks are shared with
/// native admission. Header hashing retains its existing bounded metadata allocation.
///
/// # Errors
/// Rejects mismatched historical authority, invalid geometry or framing, and any content
/// digest or original author signature mismatch.
pub fn verify_availability<'a>(
    instance: Hash32,
    config: &HeightConfig,
    header: &'a BlockHeader,
    bytes: &'a [u8],
    crypto: &dyn Crypto,
) -> Result<VerifiedAvailability<'a>, AvailabilityError> {
    if header.instance != instance
        || header.epoch != config.epoch.id
        || !config.epoch.contains(header.height)
        || header.payload_len > config.params.max_block_bytes
    {
        return Err(AvailabilityError::Source);
    }
    let author = config
        .committee
        .get(header.proposer)
        .ok_or(AvailabilityError::Source)?;
    let shape = config
        .epoch
        .da_layout
        .shape(u64::from(header.payload_len))
        .map_err(|_| AvailabilityError::Shape)?;
    let content = unsigned_content(bytes, shape)?;
    if content_digest(crypto, content) != header.availability_digest {
        return Err(AvailabilityError::Digest);
    }
    let block_hash = header.hash(crypto);
    let value = VerifiedAvailability {
        header,
        bytes,
        shape,
        block_hash,
    };
    let signature = Signature(
        bytes[content.len()..content.len() + SIGNATURE_LEN]
            .try_into()
            .expect("exact frame"),
    );
    let (bytes, used) = statement(header, block_hash, None);
    if !crypto.verify(author, &bytes[..used], &signature) {
        return Err(AvailabilityError::Signature);
    }
    for index in 0..shape.chunk_count() {
        let (hash, signature) = value.authorization(index).expect("bounded index");
        let length = shape.chunk_range(index).expect("bounded index").len();
        let (bytes, used) = statement(
            header,
            block_hash,
            Some((
                u32::try_from(index).expect("protocol-bounded row index"),
                u32::try_from(length).expect("protocol-bounded row length"),
                hash,
            )),
        );
        if !crypto.verify(author, &bytes[..used], &signature) {
            return Err(AvailabilityError::Signature);
        }
    }
    Ok(value)
}

impl VerifiedAvailability<'_> {
    fn authorization(&self, index: usize) -> Option<(Hash32, Signature)> {
        if index >= self.shape.chunk_count() {
            return None;
        }
        let hash_at = 4 + index * 32;
        let signature_at = content_end(self.shape.chunk_count()) + SIGNATURE_LEN * (index + 1);
        let bytes = self.bytes;
        Some((
            Hash32(
                bytes[hash_at..hash_at + 32]
                    .try_into()
                    .expect("exact frame"),
            ),
            Signature(
                bytes[signature_at..signature_at + SIGNATURE_LEN]
                    .try_into()
                    .expect("exact frame"),
            ),
        ))
    }
    /// Check an actual received row against its original authorization, before counting custody.
    pub fn accepts_row(&self, index: usize, row: &[u8], crypto: &dyn Crypto) -> bool {
        self.shape
            .chunk_range(index)
            .is_some_and(|range| range.len() == row.len())
            && self.authorization(index).is_some_and(|(hash, _)| {
                cfg!(sumeragi_mutation = "MS20") || row_digest(crypto, row) == hash
            })
    }
    /// Exact public geometry, after signed layout and protocol-cap validation. The caller owns
    /// `shape.encoded_bytes()` bytes and `shape.workspace_words()` u16 scratch elements.
    pub fn shape(&self) -> CompactShape {
        self.shape
    }
    /// Verify an actual complete portable payload using caller-owned scratch. Re-encoding
    /// creates the single canonical codeword with terminal zero padding and checks EVERY row
    /// commitment. No payload/table copy, allocation pool or custody capability is created.
    /// Scratch contents on failure are not authenticated output.
    ///
    /// # Errors
    /// Rejects an incorrect payload length or digest, incorrectly sized scratch, codec
    /// failure, or a reconstructed row that differs from its signed commitment.
    pub fn verify_payload(
        &self,
        payload: &[u8],
        codeword: &mut [u8],
        workspace: &mut [u16],
        crypto: &dyn Crypto,
    ) -> Result<(), AvailabilityError> {
        self.check_payload(payload, crypto)?;
        self.shape
            .encode_into(payload, codeword, workspace)
            .map_err(|_| AvailabilityError::Shape)?;
        self.check_codeword(codeword, crypto)
    }
    fn check_payload(&self, payload: &[u8], crypto: &dyn Crypto) -> Result<(), AvailabilityError> {
        if payload.len() != self.shape.payload_bytes()
            || (!cfg!(sumeragi_mutation = "MS20c")
                && crate::preimage::payload_hash(crypto, payload) != self.header.payload_hash)
        {
            return Err(AvailabilityError::Digest);
        }
        Ok(())
    }
    fn check_codeword(
        &self,
        codeword: &[u8],
        crypto: &dyn Crypto,
    ) -> Result<(), AvailabilityError> {
        if codeword.len() != self.shape.encoded_bytes() {
            return Err(AvailabilityError::Shape);
        }
        for index in 0..self.shape.chunk_count() {
            let range = self.shape.chunk_range(index).expect("bounded index");
            if !cfg!(sumeragi_mutation = "MS20e")
                && !self.accepts_row(index, &codeword[range], crypto)
            {
                return Err(AvailabilityError::Digest);
            }
        }
        Ok(())
    }
    /// Exact block identity bound by every original signature.
    pub fn block_hash(&self) -> Hash32 {
        self.block_hash
    }
}
impl VerifiedManifest<'_> {
    /// Check one actual received row before native custody accounting.
    pub fn accepts_row(&self, index: usize, row: &[u8], crypto: &dyn Crypto) -> bool {
        self.table.accepts_row(index, row, crypto)
    }
    /// Exact original authenticated header identity.
    pub fn block_hash(&self) -> Hash32 {
        self.table.block_hash()
    }
}

#[cfg(test)]
mod tests {
    // Signed-table authentication and real RS16 custody controls.
    use super::*;
    use crate::{
        crypto::Signer,
        testing::{FakeValidators, TEST_EPOCH},
        types::{ChainParams, ControlWitness},
    };
    use iroha_primitives::erasure::rs16::compact::{Encoded, encode_funded};

    const INSTANCE: Hash32 = Hash32([0x1a; 32]);

    pub(super) struct Fixture {
        pub(super) keys: FakeValidators,
        pub(super) config: HeightConfig,
        pub(super) header: BlockHeader,
        pub(super) frame: AvailabilityFrame,
        pub(super) encoded: Encoded,
        pub(super) budget: AllocationBudget,
        pub(super) payload: Vec<u8>,
    }
    fn signed_frame(
        header: &mut BlockHeader,
        shape: CompactShape,
        hashes: &[Hash32],
        keys: &FakeValidators,
        budget: &AllocationBudget,
        wrong_row: Option<(usize, u32, u32)>,
    ) -> AvailabilityFrame {
        let n = shape.chunk_count();
        assert_eq!(hashes.len(), n);
        let mut bytes = u32::try_from(n).unwrap().to_be_bytes().to_vec();
        for hash in hashes {
            bytes.extend_from_slice(hash.as_bytes());
        }
        header.availability_digest = content_digest(&keys.crypto, &bytes);
        let bh = header.hash(&keys.crypto);
        let (preimage, used) = statement(header, bh, None);
        bytes.extend_from_slice(&keys.signer(header.proposer).sign(&preimage[..used]).0);
        for (index, hash) in hashes.iter().enumerate() {
            let row = if let Some((selected, declared_index, declared_length)) = wrong_row
                && selected == index
            {
                (declared_index, declared_length, *hash)
            } else {
                (
                    u32::try_from(index).unwrap(),
                    u32::try_from(shape.chunk_range(index).unwrap().len()).unwrap(),
                    *hash,
                )
            };
            let (preimage, used) = statement(header, bh, Some(row));
            bytes.extend_from_slice(&keys.signer(header.proposer).sign(&preimage[..used]).0);
        }
        admit(bytes, budget)
    }
    fn admit(bytes: Vec<u8>, budget: &AllocationBudget) -> AvailabilityFrame {
        let mut frame = AvailabilityFrame::from_untrusted(bytes).unwrap();
        frame.admit(budget).unwrap();
        frame
    }
    impl Fixture {
        pub(super) fn new() -> Self {
            let keys = FakeValidators::new(4, 73, None);
            let mut epoch = TEST_EPOCH;
            epoch.da_layout.chunk_size_bytes = 8;
            epoch.da_layout.data_shards = 2;
            epoch.da_layout.parity_shards = 1;
            epoch.da_layout.max_payload_size_bytes = 64;
            let config = HeightConfig {
                epoch: Box::new(epoch),
                committee: keys.committee.clone(),
                params: ChainParams::default(),
            };
            let payload: Vec<_> = (0..19).map(|x| x * 7 + 3).collect();
            let budget = AllocationBudget::new(1 << 20);
            let shape = config.epoch.da_layout.shape(payload.len() as u64).unwrap();
            let encoded = encode_funded(shape, &payload, &budget).unwrap();
            let mut header = BlockHeader {
                instance: INSTANCE,
                epoch: config.epoch.id,
                height: 7,
                origin_view: 1,
                parent_hash: Hash32([2; 32]),
                parent_result: Hash32([3; 32]),
                payload_hash: crate::preimage::payload_hash(&keys.crypto, &payload),
                availability_digest: Hash32::ZERO,
                payload_len: u32::try_from(payload.len()).unwrap(),
                proposer: 2,
                skipped_leaders: vec![keys.key(0)],
                control_witness: ControlWitness::empty(),
            };
            let hashes: Vec<_> = (0..shape.chunk_count())
                .map(|i| {
                    row_digest(
                        &keys.crypto,
                        &encoded.codeword()[shape.chunk_range(i).unwrap()],
                    )
                })
                .collect();
            let frame = signed_frame(&mut header, shape, &hashes, &keys, &budget, None);
            Self {
                keys,
                config,
                header,
                frame,
                encoded,
                budget,
                payload,
            }
        }
        pub(super) fn verify(&self) -> Result<VerifiedManifest<'_>, AvailabilityError> {
            verify_manifest(
                INSTANCE,
                &self.config,
                &self.header,
                &self.frame,
                &self.budget,
                &self.keys.crypto,
            )
        }
        fn hashes(&self) -> Vec<Hash32> {
            let shape = self.encoded.shape();
            (0..shape.chunk_count())
                .map(|i| {
                    row_digest(
                        &self.keys.crypto,
                        &self.encoded.codeword()[shape.chunk_range(i).unwrap()],
                    )
                })
                .collect()
        }
    }

    #[test]
    fn actual_k_rows_per_stripe_reconstruct_and_preserve_original_pool() {
        let f = Fixture::new();
        let manifest = f.verify().unwrap();
        let shape = f.encoded.shape();
        assert_eq!(shape.chunk_count(), 6);
        assert_eq!(shape.terminal_row_bytes(), 2);
        for missing_first in 0..3 {
            for missing_last in 0..3 {
                let received: Vec<_> = (0..6)
                    .map(|i| {
                        if (i < 3 && i == missing_first) || (i >= 3 && i == 3 + missing_last) {
                            None
                        } else {
                            Some(&f.encoded.codeword()[shape.chunk_range(i).unwrap()])
                        }
                    })
                    .collect();
                let body = manifest
                    .reconstruct(&received, &f.budget, &f.keys.crypto)
                    .unwrap_or_else(|_| panic!("actual signed rows"))
                    .finish(&f.budget)
                    .unwrap_or_else(|_| panic!("original shared custody"));
                assert_eq!(body.payload().as_slice(), f.payload);
                assert!(body.admitted_to(&f.budget));
                assert!(matches!(
                    manifest.reconstruct(
                        &received,
                        &AllocationBudget::new(1 << 20),
                        &f.keys.crypto
                    ),
                    Err(AcquisitionError::Bytes(
                        crate::bytes::ByteAdmissionError::ForeignBudget
                    ))
                ));
            }
        }
        assert_eq!(manifest.block_hash(), f.header.hash(&f.keys.crypto));
    }

    #[test]
    fn signed_table_alone_and_insufficient_received_rows_never_establish_custody() {
        let f = Fixture::new();
        let manifest = f.verify().unwrap();
        let shape = f.encoded.shape();
        for count in [0, 1] {
            let rows: Vec<_> = (0..6)
                .map(|i| {
                    if i % 3 < count {
                        Some(&f.encoded.codeword()[shape.chunk_range(i).unwrap()])
                    } else {
                        None
                    }
                })
                .collect();
            assert!(
                manifest
                    .reconstruct(&rows, &f.budget, &f.keys.crypto)
                    .is_err()
            );
        }
        assert!(!manifest.accepts_row(6, &[1, 2], &f.keys.crypto));
        assert!(!manifest.accepts_row(0, &f.encoded.codeword()[..7], &f.keys.crypto));
        assert!(!manifest.accepts_row(0, &[0; 8], &f.keys.crypto));
    }

    #[test]
    fn acquisition_rejects_corrupt_actual_row_before_counting_custody() {
        use crate::message::{PayloadChunk, PayloadManifest};

        let f = Fixture::new();
        let mut acquisition = PayloadAcquisition::new(
            source(&f),
            PayloadManifest {
                header: f.header.clone(),
                availability: f.frame.clone(),
            },
        );
        acquisition.prepare(&f.budget, &f.keys.crypto).unwrap();
        let shape = f.encoded.shape();
        let original = &f.encoded.codeword()[shape.chunk_range(0).unwrap()];
        for (index, bytes) in [
            (0, {
                let mut bytes = original.to_vec();
                bytes[0] ^= 1;
                bytes
            }),
            (0, original[..original.len() - 1].to_vec()),
            (
                u32::try_from(shape.chunk_count()).unwrap(),
                original.to_vec(),
            ),
        ] {
            let chunk = PayloadChunk {
                instance: INSTANCE,
                height: f.header.height,
                block_hash: f.header.hash(&f.keys.crypto),
                index,
                bytes: RowBytes::from_untrusted(bytes).unwrap(),
            };
            let pointer = chunk.bytes.as_slice().as_ptr();
            let reserved = f.budget.reserved_bytes();
            let (returned, error) = acquisition
                .push(chunk, &f.budget, &f.keys.crypto)
                .expect_err("a corrupt, wrong-length or out-of-range row is not custody");
            assert!(matches!(
                error,
                AcquisitionError::Row(AvailabilityError::Digest)
            ));
            assert!(
                !error.rejects_manifest(),
                "an unsigned bad relay is not a leader fault"
            );
            assert_eq!(acquisition.received_rows(), 0);
            assert_eq!(returned.bytes.as_slice().as_ptr(), pointer);
            assert!(!returned.bytes.admitted_to(&f.budget));
            assert_eq!(f.budget.reserved_bytes(), reserved);
        }
        let chunk = PayloadChunk {
            instance: INSTANCE,
            height: f.header.height,
            block_hash: f.header.hash(&f.keys.crypto),
            index: 0,
            bytes: RowBytes::from_untrusted(original.to_vec()).unwrap(),
        };
        assert!(
            acquisition
                .push(chunk.clone(), &f.budget, &f.keys.crypto)
                .unwrap()
        );
        assert!(!acquisition.push(chunk, &f.budget, &f.keys.crypto).unwrap());
        assert_eq!(acquisition.received_rows(), 1);
    }

    #[test]
    fn every_signature_and_exact_table_boundary_is_mandatory() {
        let f = Fixture::new();
        let n = f.encoded.shape().chunk_count();
        for signature in 0..=n {
            let mut bytes = f.frame.as_slice().to_vec();
            bytes[content_end(n) + signature * SIGNATURE_LEN] ^= 1;
            let frame = admit(bytes, &f.budget);
            assert!(matches!(
                verify_manifest(
                    INSTANCE,
                    &f.config,
                    &f.header,
                    &frame,
                    &f.budget,
                    &f.keys.crypto
                ),
                Err(AvailabilityError::Signature)
            ));
        }
        for len in 0..f.frame.as_slice().len() {
            let frame = admit(f.frame.as_slice()[..len].to_vec(), &f.budget);
            assert!(matches!(
                verify_manifest(
                    INSTANCE,
                    &f.config,
                    &f.header,
                    &frame,
                    &f.budget,
                    &f.keys.crypto
                ),
                Err(AvailabilityError::Frame)
            ));
        }
        let mut bytes = f.frame.as_slice().to_vec();
        bytes.push(0);
        let frame = admit(bytes, &f.budget);
        assert!(matches!(
            verify_manifest(
                INSTANCE,
                &f.config,
                &f.header,
                &frame,
                &f.budget,
                &f.keys.crypto
            ),
            Err(AvailabilityError::Frame)
        ));
        for count in [0u32, 5, 7, u32::MAX] {
            let mut bytes = f.frame.as_slice().to_vec();
            bytes[..4].copy_from_slice(&count.to_be_bytes());
            let frame = admit(bytes, &f.budget);
            assert!(matches!(
                verify_manifest(
                    INSTANCE,
                    &f.config,
                    &f.header,
                    &frame,
                    &f.budget,
                    &f.keys.crypto
                ),
                Err(AvailabilityError::Frame)
            ));
        }
    }

    #[test]
    fn signatures_bind_original_author_epoch_instance_header_index_and_exact_length() {
        let f = Fixture::new();
        for field in 0..9 {
            let mut h = f.header.clone();
            let mut config = f.config.clone();
            match field {
                0 => h.instance.0[0] ^= 1,
                1 => h.epoch.epoch += 1,
                2 => h.epoch.context.0[0] ^= 1,
                3 => h.height += 1,
                4 => h.origin_view += 1,
                5 => h.parent_hash.0[0] ^= 1,
                6 => h.proposer = 1,
                7 => config.committee = FakeValidators::new(4, 74, None).committee,
                _ => config.epoch.last_height = h.height - 1,
            }
            assert!(
                verify_manifest(INSTANCE, &config, &h, &f.frame, &f.budget, &f.keys.crypto)
                    .is_err(),
                "field {field}"
            );
        }
        for wrong in [(0, 1, 8), (0, 0, 6), (3, 3, 8)] {
            let mut header = f.header.clone();
            let frame = signed_frame(
                &mut header,
                f.encoded.shape(),
                &f.hashes(),
                &f.keys,
                &f.budget,
                Some(wrong),
            );
            assert!(matches!(
                verify_manifest(
                    INSTANCE,
                    &f.config,
                    &header,
                    &frame,
                    &f.budget,
                    &f.keys.crypto
                ),
                Err(AvailabilityError::Signature)
            ));
        }
    }

    #[test]
    fn portable_verification_never_grants_native_custody() {
        let f = Fixture::new();
        let wire = norito::encode_canonical(&f.frame).unwrap();
        let frame: AvailabilityFrame = norito::decode_canonical(&wire).unwrap();
        let proof = verify_availability(
            INSTANCE,
            &f.config,
            &f.header,
            frame.as_slice(),
            &f.keys.crypto,
        )
        .unwrap();
        assert_eq!(proof.block_hash(), f.header.hash(&f.keys.crypto));
        assert_eq!(proof.shape(), f.encoded.shape());
        let mut codeword = vec![0; proof.shape().encoded_bytes()];
        let mut scratch = vec![0; proof.shape().workspace_words()];
        assert_eq!(
            proof.verify_payload(&f.payload, &mut codeword, &mut scratch, &f.keys.crypto),
            Ok(())
        );
        assert_eq!(&codeword, f.encoded.codeword());
        assert!(matches!(
            verify_manifest(
                INSTANCE,
                &f.config,
                &f.header,
                &frame,
                &f.budget,
                &f.keys.crypto
            ),
            Err(AvailabilityError::ForeignBudget)
        ));
        let mut wrong = f.payload.clone();
        wrong[0] ^= 1;
        assert_eq!(
            proof.verify_payload(&wrong, &mut codeword, &mut scratch, &f.keys.crypto),
            Err(AvailabilityError::Digest)
        );
        assert_eq!(
            proof.verify_payload(&f.payload, &mut codeword[..1], &mut scratch, &f.keys.crypto),
            Err(AvailabilityError::Shape)
        );
        assert_eq!(
            proof.verify_payload(&f.payload, &mut codeword, &mut scratch[..1], &f.keys.crypto),
            Err(AvailabilityError::Shape)
        );
    }

    #[test]
    fn signed_inconsistent_codeword_and_payload_commitments_are_rejected() {
        let f = Fixture::new();
        let shape = f.encoded.shape();
        let received: Vec<_> = (0..6)
            .map(|i| {
                if i % 3 < 2 {
                    Some(&f.encoded.codeword()[shape.chunk_range(i).unwrap()])
                } else {
                    None
                }
            })
            .collect();
        let mut hashes = f.hashes();
        hashes[5].0[0] ^= 1;
        let mut header = f.header.clone();
        let frame = signed_frame(&mut header, shape, &hashes, &f.keys, &f.budget, None);
        let signed_bad = verify_manifest(
            INSTANCE,
            &f.config,
            &header,
            &frame,
            &f.budget,
            &f.keys.crypto,
        )
        .unwrap();
        assert!(
            signed_bad
                .reconstruct(&received, &f.budget, &f.keys.crypto)
                .is_err()
        );
        let portable = verify_availability(
            INSTANCE,
            &f.config,
            &header,
            frame.as_slice(),
            &f.keys.crypto,
        )
        .unwrap();
        let mut codeword = vec![0; shape.encoded_bytes()];
        let mut scratch = vec![0; shape.workspace_words()];
        assert_eq!(
            portable.verify_payload(&f.payload, &mut codeword, &mut scratch, &f.keys.crypto),
            Err(AvailabilityError::Digest)
        );
        let mut header = f.header.clone();
        header.payload_hash.0[0] ^= 1;
        let frame = signed_frame(&mut header, shape, &f.hashes(), &f.keys, &f.budget, None);
        let signed_bad = verify_manifest(
            INSTANCE,
            &f.config,
            &header,
            &frame,
            &f.budget,
            &f.keys.crypto,
        )
        .unwrap();
        assert!(matches!(
            signed_bad.reconstruct(&received, &f.budget, &f.keys.crypto),
            Err(AcquisitionError::Manifest(AvailabilityError::Digest))
        ));
    }

    #[test]
    fn canonical_norito_frame_remains_untrusted_until_exact_original_pool_admission() {
        let f = Fixture::new();
        let bytes = norito::encode_canonical(&f.frame).unwrap();
        let mut decoded: AvailabilityFrame = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, f.frame);
        assert!(matches!(
            verify_manifest(
                INSTANCE,
                &f.config,
                &f.header,
                &decoded,
                &f.budget,
                &f.keys.crypto
            ),
            Err(AvailabilityError::ForeignBudget)
        ));
        decoded.admit(&f.budget).unwrap();
        assert!(
            verify_manifest(
                INSTANCE,
                &f.config,
                &f.header,
                &decoded,
                &f.budget,
                &f.keys.crypto
            )
            .is_ok()
        );
        assert!(matches!(
            verify_manifest(
                INSTANCE,
                &f.config,
                &f.header,
                &decoded,
                &AllocationBudget::new(1 << 20),
                &f.keys.crypto
            ),
            Err(AvailabilityError::ForeignBudget)
        ));
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(norito::decode_canonical::<AvailabilityFrame>(&corrupt).is_err());
    }
    #[test]
    fn foreign_reconstruction_pool_refuses_without_consuming_received_owners() {
        let f = Fixture::new();
        let shape = f.encoded.shape();
        let pointer = f.encoded.codeword().as_ptr();
        let received: Vec<_> = (0..shape.chunk_count())
            .map(|i| Some(&f.encoded.codeword()[shape.chunk_range(i).unwrap()]))
            .collect();
        let manifest = f.verify().unwrap();
        let foreign = AllocationBudget::new(1 << 20);
        let reserved = f.budget.reserved_bytes();
        assert!(matches!(
            manifest.reconstruct(&received, &foreign, &f.keys.crypto),
            Err(AcquisitionError::Bytes(
                crate::bytes::ByteAdmissionError::ForeignBudget
            ))
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(f.budget.reserved_bytes(), reserved);
        assert_eq!(f.encoded.codeword().as_ptr(), pointer);
        let body = manifest
            .reconstruct(&received, &f.budget, &f.keys.crypto)
            .unwrap_or_else(|_| panic!("original rows and original pool"))
            .finish(&f.budget)
            .unwrap_or_else(|_| panic!("original body custody"));
        assert_eq!(body.payload().as_slice(), f.payload);
        assert!(body.admitted_to(&f.budget));
    }
    struct CountingSigner<'a> {
        inner: &'a dyn Signer,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Signer for CountingSigner<'_> {
        fn public_key(&self) -> &crate::types::PublicKey {
            self.inner.public_key()
        }
        fn sign(&self, bytes: &[u8]) -> Signature {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.sign(bytes)
        }
    }
    fn original_payload(f: &Fixture) -> PayloadBytes {
        let mut bytes = iroha_allocation::ChargedBuffer::new(f.payload.len(), &f.budget).unwrap();
        bytes.append(&f.payload).unwrap();
        PayloadBytes::from_charged(bytes, &f.budget)
            .unwrap_or_else(|(_, error)| panic!("original payload admission: {error}"))
    }
    #[test]
    fn original_author_worker_matches_verified_frame_and_preserves_payload_backing() {
        let f = Fixture::new();
        let payload = original_payload(&f);
        let pointer = payload.as_slice().as_ptr();
        let request = PayloadAuthoring::new(f.header.clone(), payload);
        let output = request
            .complete(
                INSTANCE,
                &f.config,
                &f.budget,
                &f.keys.crypto,
                f.keys.signer(f.header.proposer),
            )
            .unwrap_or_else(|(_, error)| panic!("actual original author worker: {error:?}"));
        assert_eq!(output.body.availability(), &f.frame);
        assert_eq!(output.body.payload().as_slice().as_ptr(), pointer);
        assert_eq!(output.body.header(), &f.header);
        assert_eq!(output.codeword.codeword(), f.encoded.codeword());
        assert!(output.body.admitted_to(&f.budget));
        assert!(output.codeword.belongs_to(&f.budget));
    }
    #[test]
    fn author_worker_retains_completed_signatures_across_control_refusal() {
        let f = Fixture::new();
        let payload = original_payload(&f);
        let pointer = payload.as_slice().as_ptr();
        let signer = CountingSigner {
            inner: f.keys.signer(f.header.proposer),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let available = f.encoded.shape().encoded_bytes() + f.frame.as_slice().len();
        let reserved = f
            .budget
            .try_reserve_bytes((1 << 20) - f.budget.reserved_bytes() - available)
            .unwrap();
        let request = PayloadAuthoring::new(f.header.clone(), payload);
        let (request, error) =
            match request.complete(INSTANCE, &f.config, &f.budget, &f.keys.crypto, &signer) {
                Ok(_) => panic!("shared control must refuse"),
                Err(parts) => parts,
            };
        assert!(matches!(
            error,
            AuthoringError::Bytes(crate::bytes::ByteAdmissionError::ControlAdmission(_))
        ));
        assert_eq!(
            signer.calls.load(std::sync::atomic::Ordering::Relaxed),
            f.encoded.shape().chunk_count() + 1
        );
        assert_eq!(f.budget.reserved_bytes(), 1 << 20);
        drop(reserved);
        let output = request
            .complete(INSTANCE, &f.config, &f.budget, &f.keys.crypto, &signer)
            .unwrap_or_else(|(_, error)| panic!("retry with retained phase owners: {error:?}"));
        assert_eq!(
            signer.calls.load(std::sync::atomic::Ordering::Relaxed),
            f.encoded.shape().chunk_count() + 1,
            "completed table must not be resigned on resource retry"
        );
        assert_eq!(output.body.payload().as_slice().as_ptr(), pointer);
        assert_eq!(output.body.availability(), &f.frame);
    }
    #[test]
    fn author_worker_refuses_foreign_pool_wrong_key_and_mismatched_source() {
        let f = Fixture::new();
        let request = PayloadAuthoring::new(f.header.clone(), original_payload(&f));
        let (request, error) = match request.complete(
            INSTANCE,
            &f.config,
            &AllocationBudget::new(1 << 20),
            &f.keys.crypto,
            f.keys.signer(f.header.proposer),
        ) {
            Ok(_) => panic!("foreign pool"),
            Err(parts) => parts,
        };
        assert!(matches!(
            error,
            AuthoringError::Invalid(AvailabilityError::ForeignBudget)
        ));
        let (request, error) = match request.complete(
            INSTANCE,
            &f.config,
            &f.budget,
            &f.keys.crypto,
            f.keys.signer(0),
        ) {
            Ok(_) => panic!("wrong author"),
            Err(parts) => parts,
        };
        assert!(matches!(
            error,
            AuthoringError::Invalid(AvailabilityError::Source)
        ));
        assert!(
            request
                .complete(
                    INSTANCE,
                    &f.config,
                    &f.budget,
                    &f.keys.crypto,
                    f.keys.signer(f.header.proposer)
                )
                .is_ok()
        );
        let mut header = f.header.clone();
        header.payload_hash.0[0] ^= 1;
        let request = PayloadAuthoring::new(header, original_payload(&f));
        assert!(matches!(
            request.complete(
                INSTANCE,
                &f.config,
                &f.budget,
                &f.keys.crypto,
                f.keys.signer(f.header.proposer)
            ),
            Err((_, AuthoringError::Invalid(AvailabilityError::Digest)))
        ));
    }
    #[test]
    fn stored_body_restoration_checks_actual_codeword_without_resigning_or_copying_payload() {
        let f = Fixture::new();
        let payload = original_payload(&f);
        let pointer = payload.as_slice().as_ptr();
        let original_reserved = f.budget.reserved_bytes();
        let body = BodyRestoration::new(source(&f), f.header.clone(), f.frame.clone(), payload)
            .complete(&f.budget, &f.keys.crypto)
            .unwrap_or_else(|_| panic!("exact persisted original body"));
        assert_eq!(body.source(), &source(&f));
        assert_eq!(body.payload().as_slice().as_ptr(), pointer);
        assert_eq!(
            body.availability().as_slice().as_ptr(),
            f.frame.as_slice().as_ptr()
        );
        assert_eq!(
            f.budget.reserved_bytes(),
            original_reserved,
            "transient re-encoding backing must be released"
        );
        let mut hashes = f.hashes();
        hashes[5].0[0] ^= 1;
        let mut header = f.header.clone();
        let frame = signed_frame(
            &mut header,
            f.encoded.shape(),
            &hashes,
            &f.keys,
            &f.budget,
            None,
        );
        let expected = AvailabilitySource::new(
            INSTANCE,
            header.height,
            header.hash(&f.keys.crypto),
            f.config.clone(),
        )
        .unwrap();
        assert!(matches!(
            BodyRestoration::new(expected, header, frame, body.payload().clone())
                .complete(&f.budget, &f.keys.crypto),
            Err((_, RestorationError::Invalid(AvailabilityError::Digest)))
        ));
    }
    #[test]
    fn restoration_resource_refusal_and_foreign_pool_return_same_job_for_retry() {
        let f = Fixture::new();
        let payload = original_payload(&f);
        let pointer = payload.as_slice().as_ptr();
        let reserve = f
            .budget
            .try_reserve_bytes((1 << 20) - f.budget.reserved_bytes())
            .unwrap();
        let (job, error) =
            BodyRestoration::new(source(&f), f.header.clone(), f.frame.clone(), payload)
                .complete(&f.budget, &f.keys.crypto)
                .unwrap_err();
        assert!(matches!(error, RestorationError::Codec(_)));
        assert_eq!(job.source(), &source(&f));
        let (job, error) = job
            .complete(&AllocationBudget::new(1 << 20), &f.keys.crypto)
            .unwrap_err();
        assert!(matches!(
            error,
            RestorationError::Bytes(crate::bytes::ByteAdmissionError::ForeignBudget)
        ));
        assert_eq!(job.source(), &source(&f));
        drop(reserve);
        let body = job
            .complete(&f.budget, &f.keys.crypto)
            .unwrap_or_else(|_| panic!("same source and payload recover"));
        assert_eq!(body.payload().as_slice().as_ptr(), pointer);
    }
    #[test]
    fn restoration_admits_decoded_inputs_and_rejects_changed_payload_bytes() {
        let f = Fixture::new();
        let payload = PayloadBytes::from_untrusted(f.payload.clone()).unwrap();
        let frame = AvailabilityFrame::from_untrusted(f.frame.as_slice().to_vec()).unwrap();
        assert!(!payload.admitted_to(&f.budget));
        assert!(!frame.admitted_to(&f.budget));
        let body = BodyRestoration::new(source(&f), f.header.clone(), frame, payload)
            .complete(&f.budget, &f.keys.crypto)
            .unwrap_or_else(|_| {
                panic!("decoded inputs admitted and verified by one source-bound job")
            });
        assert!(body.admitted_to(&f.budget));
        for bytes in [
            {
                let mut bytes = f.payload.clone();
                bytes[0] ^= 1;
                bytes
            },
            f.payload[..f.payload.len() - 1].to_vec(),
        ] {
            let payload = PayloadBytes::from_untrusted(bytes).unwrap();
            assert!(matches!(
                BodyRestoration::new(source(&f), f.header.clone(), f.frame.clone(), payload)
                    .complete(&f.budget, &f.keys.crypto),
                Err((_, RestorationError::Invalid(AvailabilityError::Digest)))
            ));
        }
    }
    fn source(f: &Fixture) -> AvailabilitySource {
        AvailabilitySource::new(
            INSTANCE,
            f.header.height,
            f.header.hash(&f.keys.crypto),
            f.config.clone(),
        )
        .unwrap()
    }
    #[test]
    fn source_bound_storage_job_never_confuses_refusal_with_absence_or_rebinds_source() {
        let f = Fixture::new();
        let payload = original_payload(&f);
        let pointer = payload.as_slice().as_ptr();
        let expected = source(&f);
        let request =
            BodyRestoration::new(expected.clone(), f.header.clone(), f.frame.clone(), payload);
        let reserve = f
            .budget
            .try_reserve_bytes((1 << 20) - f.budget.reserved_bytes())
            .unwrap();
        let (request, error) = request.complete(&f.budget, &f.keys.crypto).unwrap_err();
        assert!(error.is_local_refusal());
        assert_eq!(request.source(), &expected);
        drop(reserve);
        let body = request
            .complete(&f.budget, &f.keys.crypto)
            .unwrap_or_else(|_| panic!("same source retained across refusal"));
        assert_eq!(body.payload().as_slice().as_ptr(), pointer);
        assert_eq!(
            body.availability().as_slice().as_ptr(),
            f.frame.as_slice().as_ptr()
        );
        for field in 0..4 {
            let mut config = f.config.clone();
            let mut instance = INSTANCE;
            let mut height = f.header.height;
            let mut hash = f.header.hash(&f.keys.crypto);
            match field {
                0 => instance.0[0] ^= 1,
                1 => height += 1,
                2 => hash.0[0] ^= 1,
                _ => config.epoch.id.context.0[0] ^= 1,
            }
            let expected = AvailabilitySource::new(instance, height, hash, config).unwrap();
            let request = BodyRestoration::new(
                expected,
                f.header.clone(),
                f.frame.clone(),
                body.payload().clone(),
            );
            let (_, error) = request.complete(&f.budget, &f.keys.crypto).unwrap_err();
            assert!(matches!(
                error,
                RestorationError::Invalid(AvailabilityError::Source)
            ));
            assert!(!error.is_local_refusal());
        }
    }
    #[test]
    fn restoration_job_retains_partial_decoded_admission_and_rejects_missing_evidence() {
        let f = Fixture::new();
        let frame = AvailabilityFrame::from_untrusted(f.frame.as_slice().to_vec()).unwrap();
        let payload = PayloadBytes::from_untrusted(f.payload.clone()).unwrap();
        let expected = source(&f);
        let reserve = f
            .budget
            .try_reserve_bytes((1 << 20) - f.budget.reserved_bytes() - f.frame.as_slice().len())
            .unwrap();
        let request = BodyRestoration::new(expected.clone(), f.header.clone(), frame, payload);
        let (request, error) = request.complete(&f.budget, &f.keys.crypto).unwrap_err();
        assert!(error.is_local_refusal());
        assert_eq!(request.source(), &expected);
        drop(reserve);
        assert!(request.complete(&f.budget, &f.keys.crypto).is_ok());
        let request = BodyRestoration::new(
            expected,
            f.header.clone(),
            AvailabilityFrame::from_untrusted(vec![]).unwrap(),
            original_payload(&f),
        );
        let (_, error) = request.complete(&f.budget, &f.keys.crypto).unwrap_err();
        assert!(matches!(
            error,
            RestorationError::Invalid(AvailabilityError::Frame)
        ));
        assert!(!error.is_local_refusal());
        let mut config = f.config.clone();
        config.epoch.last_height = f.header.height - 1;
        assert!(
            AvailabilitySource::new(
                INSTANCE,
                f.header.height,
                f.header.hash(&f.keys.crypto),
                config
            )
            .is_err()
        );
    }
}
