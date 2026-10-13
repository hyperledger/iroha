//! Hash profiles of the State commitment prototypes.
//!
//! Every profile maps a domain tag and its input to four 64-bit words. A
//! digest is encoded as 32 bytes, each word little-endian. For the algebraic
//! profiles each word is a canonical Goldilocks element, so not every 32-byte
//! string is a digest; for the byte profiles the words are the raw 256 output
//! bits and no `iroha_crypto::Hash` marker bit is set or cleared.
//!
//! TODO(G.3): replace by the selected profile in its owner; delete the rest.

use core::{cell::Cell, marker::PhantomData};

use fastpq_isi::poseidon_digest384::{GoldilocksDigestDomainV1, hash_bytes_384_v1};
use iroha_crypto::blake2::{Blake2b, Digest as _, digest::consts::U32};

use super::{poseidon2::Poseidon2Goldilocks12, rescue::RescuePrime64};
use crate::field::{GOLDILOCKS_MODULUS_V1, add_base};

/// Four 64-bit words; 32 bytes when encoded.
pub type Digest = [u64; 4];

/// The all-zero digest: the root of an empty structure and the value digest of
/// a sentinel. No profile is expected to output it.
pub const ZERO_DIGEST: Digest = [0; 4];

/// Encoded size of a digest.
pub const DIGEST_BYTES: usize = 32;

/// Encode a digest as 32 bytes, each word little-endian.
#[must_use]
pub fn digest_to_bytes(digest: &Digest) -> [u8; DIGEST_BYTES] {
    let mut bytes = [0_u8; DIGEST_BYTES];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(digest) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Decode 32 bytes into four words. The words are not checked for canonicity;
/// see [`HashProfile::is_canonical`].
#[must_use]
pub fn digest_from_bytes(bytes: &[u8; DIGEST_BYTES]) -> Digest {
    core::array::from_fn(|index| {
        u64::from_le_bytes(
            bytes[index * 8..index * 8 + 8]
                .try_into()
                .expect("eight-byte digest word"),
        )
    })
}

/// Deterministic work performed by the hash profiles on the calling thread.
///
/// The counts are functions of the inputs alone, so they are identical on every
/// machine; wall time is measured separately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashWork {
    /// Calls of [`HashProfile::hash_bytes`].
    pub byte_hashes: u64,
    /// Bytes given to [`HashProfile::hash_bytes`].
    pub bytes: u64,
    /// Calls of [`HashProfile::compress`].
    pub compressions: u64,
    /// Width-12 permutations of an algebraic sponge, or width-3 permutations
    /// of the six-lane comparator. Zero for byte profiles.
    pub permutations: u64,
}

thread_local! {
    static WORK: Cell<HashWork> = const { Cell::new(HashWork {
        byte_hashes: 0,
        bytes: 0,
        compressions: 0,
        permutations: 0,
    }) };
}

/// Return the calling thread's hash work since the last call and reset it.
pub fn take_hash_work() -> HashWork {
    WORK.with(Cell::take)
}

fn record(update: impl FnOnce(&mut HashWork)) {
    WORK.with(|work| {
        let mut current = work.get();
        update(&mut current);
        work.set(current);
    });
}

/// One hash profile: a byte hash and a domain-separated two-to-one compression.
pub trait HashProfile: 'static {
    /// Stable identity of the profile and its parameters.
    const NAME: &'static str;
    /// Whether the profile is an arithmetization-friendly sponge over Goldilocks.
    const ALGEBRAIC: bool;

    /// Hash a domain tag and a byte string. The byte length is bound.
    fn hash_bytes(domain: u64, bytes: &[u8]) -> Digest;

    /// Compress two digests under a domain tag and one auxiliary word.
    ///
    /// `domain` and `aux` are canonical field elements for algebraic profiles;
    /// every caller passes small constants and bounded counters.
    fn compress(domain: u64, aux: u64, left: &Digest, right: &Digest) -> Digest;

    /// Whether four decoded words can be a digest of this profile.
    fn is_canonical(digest: &Digest) -> bool;
}

/// A 256-bit byte hash a consumer crate supplies.
///
/// The framing of every prototype hash lives in [`ByteProfile`]; an
/// implementation only names the primitive and hashes the concatenated parts.
pub trait ByteHash: 'static {
    /// Stable identity of the primitive and its output length.
    const NAME: &'static str;

    /// Hash the concatenation of `parts` to 32 raw bytes.
    fn digest(parts: &[&[u8]]) -> [u8; DIGEST_BYTES];
}

/// Mode byte of a byte-string hash.
const MODE_BYTES: u8 = 0;
/// Mode byte of a two-to-one compression.
const MODE_COMPRESS: u8 = 1;

/// Hash profile over a raw byte hash.
///
/// `hash_bytes = B(0x00 ‖ le64(domain) ‖ le64(len) ‖ bytes)` and
/// `compress = B(0x01 ‖ le64(domain) ‖ le64(aux) ‖ left ‖ right)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByteProfile<B>(PhantomData<B>);

impl<B: ByteHash> HashProfile for ByteProfile<B> {
    const NAME: &'static str = B::NAME;
    const ALGEBRAIC: bool = false;

    fn hash_bytes(domain: u64, bytes: &[u8]) -> Digest {
        record(|work| {
            work.byte_hashes += 1;
            work.bytes += bytes.len() as u64;
        });
        let length = (bytes.len() as u64).to_le_bytes();
        digest_from_bytes(&B::digest(&[
            &[MODE_BYTES],
            &domain.to_le_bytes(),
            &length,
            bytes,
        ]))
    }

    fn compress(domain: u64, aux: u64, left: &Digest, right: &Digest) -> Digest {
        record(|work| work.compressions += 1);
        digest_from_bytes(&B::digest(&[
            &[MODE_COMPRESS],
            &domain.to_le_bytes(),
            &aux.to_le_bytes(),
            &digest_to_bytes(left),
            &digest_to_bytes(right),
        ]))
    }

    fn is_canonical(_digest: &Digest) -> bool {
        true
    }
}

/// Raw BLAKE2b-256: all 256 output bits, without the marker bit that
/// `iroha_crypto::Hash` sets.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake2b256Raw;

impl ByteHash for Blake2b256Raw {
    const NAME: &'static str = "blake2b-256-raw";

    fn digest(parts: &[&[u8]]) -> [u8; DIGEST_BYTES] {
        let mut hasher = Blake2b::<U32>::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

/// The native-fast profile every construction is measured with.
pub type Blake2bProfile = ByteProfile<Blake2b256Raw>;

/// A width-12 permutation over Goldilocks.
pub trait Permutation12: 'static {
    /// Stable identity of the permutation and its parameters.
    const NAME: &'static str;

    /// Apply the permutation to canonical field elements.
    fn permute(state: &mut [u64; 12]);
}

/// Capacity word 2 of a byte-string sponge.
pub const SPONGE_MODE_BYTES: u64 = 0;
/// Capacity word 2 of a two-to-one compression.
pub const SPONGE_MODE_COMPRESS: u64 = 1;
/// Rate of the sponge in field elements.
pub const SPONGE_RATE: usize = 8;
/// First rate position; positions `0..4` are the capacity.
pub const SPONGE_RATE_START: usize = 4;
/// Bytes packed into one field element.
pub const BYTES_PER_ELEMENT: usize = 7;

/// Pack a byte string into rate blocks.
///
/// The elements are the byte length followed by seven-byte little-endian
/// limbs, padded with zero elements to whole blocks of [`SPONGE_RATE`]. The
/// leading length makes the packing injective, and every element is below
/// `2^56`, so it is canonical.
#[must_use]
pub fn pack_bytes(bytes: &[u8]) -> Vec<[u64; SPONGE_RATE]> {
    let mut elements = Vec::with_capacity(1 + bytes.len().div_ceil(BYTES_PER_ELEMENT));
    elements.push(bytes.len() as u64);
    for limb in bytes.chunks(BYTES_PER_ELEMENT) {
        let mut word = [0_u8; 8];
        word[..limb.len()].copy_from_slice(limb);
        elements.push(u64::from_le_bytes(word));
    }
    elements
        .chunks(SPONGE_RATE)
        .map(|chunk| {
            let mut block = [0_u64; SPONGE_RATE];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

/// Capacity words of the first block of a byte-string sponge.
#[must_use]
pub const fn bytes_capacity(domain: u64) -> [u64; 4] {
    [domain, 0, SPONGE_MODE_BYTES, 0]
}

/// Capacity words of a two-to-one compression.
#[must_use]
pub const fn compress_capacity(domain: u64, aux: u64) -> [u64; 4] {
    [domain, aux, SPONGE_MODE_COMPRESS, 0]
}

/// Sponge profile over a width-12 permutation: capacity 4, rate 8, digest in
/// the first four rate positions.
///
/// `compress` is one permutation of `capacity ‖ left ‖ right`. `hash_bytes`
/// writes the first block of [`pack_bytes`] into the rate, permutes, then adds
/// each further block into the rate and permutes. The in-circuit relation of
/// [`super::circuit`] executes exactly these steps.
#[derive(Clone, Copy, Debug, Default)]
pub struct AlgebraicSponge<P>(PhantomData<P>);

impl<P: Permutation12> HashProfile for AlgebraicSponge<P> {
    const NAME: &'static str = P::NAME;
    const ALGEBRAIC: bool = true;

    fn hash_bytes(domain: u64, bytes: &[u8]) -> Digest {
        let blocks = pack_bytes(bytes);
        record(|work| {
            work.byte_hashes += 1;
            work.bytes += bytes.len() as u64;
            work.permutations += blocks.len() as u64;
        });
        let mut state = [0_u64; 12];
        state[..4].copy_from_slice(&bytes_capacity(domain));
        for (index, block) in blocks.iter().enumerate() {
            for (cell, value) in state[SPONGE_RATE_START..].iter_mut().zip(block) {
                *cell = if index == 0 {
                    *value
                } else {
                    add_base(*cell, *value)
                };
            }
            P::permute(&mut state);
        }
        core::array::from_fn(|index| state[SPONGE_RATE_START + index])
    }

    fn compress(domain: u64, aux: u64, left: &Digest, right: &Digest) -> Digest {
        record(|work| {
            work.compressions += 1;
            work.permutations += 1;
        });
        let mut state = [0_u64; 12];
        state[..4].copy_from_slice(&compress_capacity(domain, aux));
        state[4..8].copy_from_slice(left);
        state[8..].copy_from_slice(right);
        P::permute(&mut state);
        core::array::from_fn(|index| state[SPONGE_RATE_START + index])
    }

    fn is_canonical(digest: &Digest) -> bool {
        digest.iter().all(|word| *word < GOLDILOCKS_MODULUS_V1)
    }
}

/// Poseidon2 sponge profile.
pub type Poseidon2Profile = AlgebraicSponge<Poseidon2Goldilocks12>;
/// Rescue-Prime sponge profile.
pub type RescuePrimeProfile = AlgebraicSponge<RescuePrime64>;

/// The repository's own Goldilocks digest as a native comparator: the six-lane
/// width-3 Poseidon digest of `fastpq_isi::poseidon_digest384`, truncated to
/// its first four lanes so a node keeps the prototype's 32-byte size.
///
/// The truncation is a measurement device, not a proposed construction: the
/// security of the lane composition and of any truncation is task H.1's
/// subject. Only native cost is measured with this profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct Digest384Comparator;

impl Digest384Comparator {
    fn domain(role: &'static [u8], domain: u64, aux: u64) -> GoldilocksDigestDomainV1<'static> {
        GoldilocksDigestDomainV1 {
            catalog: b"iroha:g2:state-commitment-prototypes",
            protocol: b"keyed-state-candidates",
            profile: b"digest384-first-four-lanes",
            role,
            phase: b"measure",
            level: domain,
            index: aux,
            counter: 0,
        }
    }

    fn hash(role: &'static [u8], domain: u64, aux: u64, fields: &[&[u8]]) -> Digest {
        let typed = Self::domain(role, domain, aux);
        let lengths: Vec<usize> = fields.iter().map(|field| field.len()).collect();
        let words = fastpq_isi::poseidon_digest384::GoldilocksDigest384FrameV1::word_count_for_field_lengths_v1(
            typed, &lengths,
        )
        .expect("prototype frames are far below the 32-bit framing ceiling");
        // Every lane absorbs the whole frame two words per permutation.
        record(|work| work.permutations += 6 * (words as u64).div_ceil(2));
        let bytes = hash_bytes_384_v1(typed, fields)
            .expect("prototype frames are far below the 32-bit framing ceiling")
            .to_le_bytes();
        core::array::from_fn(|lane| {
            u64::from_le_bytes(
                bytes[lane * 8..lane * 8 + 8]
                    .try_into()
                    .expect("eight-byte lane"),
            )
        })
    }
}

impl HashProfile for Digest384Comparator {
    const NAME: &'static str = "in-repo-poseidon-x7-w3-digest384-first-four-lanes";
    const ALGEBRAIC: bool = true;

    fn hash_bytes(domain: u64, bytes: &[u8]) -> Digest {
        record(|work| {
            work.byte_hashes += 1;
            work.bytes += bytes.len() as u64;
        });
        Self::hash(b"bytes", domain, 0, &[bytes])
    }

    fn compress(domain: u64, aux: u64, left: &Digest, right: &Digest) -> Digest {
        record(|work| work.compressions += 1);
        Self::hash(
            b"compress",
            domain,
            aux,
            &[&digest_to_bytes(left), &digest_to_bytes(right)],
        )
    }

    fn is_canonical(digest: &Digest) -> bool {
        digest.iter().all(|word| *word < GOLDILOCKS_MODULUS_V1)
    }
}
