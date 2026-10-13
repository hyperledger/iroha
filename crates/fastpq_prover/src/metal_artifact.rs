//! Sole immutable compiled Metal bundle admission, before device or private work.
//!
//! Source and library identity are local integrity checks, not signed provenance,
//! device qualification, measured cost, or ownership of driver allocations.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const ENTRY_POINTS: [&str; 16] = [
    "fastpq_fft_columns",
    "fastpq_lde_columns",
    "fastpq_fft_post_tiling",
    "exact_root_bit_reverse_v1",
    "exact_root_local_tiles_v1",
    "exact_root_global_stage_v1",
    "poseidon_permute",
    "poseidon_hash_rows",
    "poseidon_hash_columns",
    "fastpq_digest384_last_fields",
    "digest384_hash_frames_v1",
    "digest384_indexed_first_coordinate_v1",
    "fastpq_sha3_256_continuations",
    "bn254_fft_columns",
    "bn254_lde_columns",
    "bn254_poseidon_hash_words",
];
const LANGUAGE: &str = "macos-metal2.4";
const SOURCE_SHA256: [u8; 32] = [
    0xd1, 0xd3, 0x32, 0xfc, 0x8d, 0x00, 0x41, 0x8b, 0xe6, 0x29, 0xa7, 0x0f, 0xa3, 0xaf, 0x7b, 0x50,
    0xc2, 0xbf, 0x78, 0x1c, 0x69, 0x06, 0x25, 0x99, 0xf0, 0x91, 0x3c, 0x50, 0x13, 0xf1, 0xd2, 0x92,
];
const SOURCES: [(&str, &[u8]); 8] = [
    (
        "crates/fastpq_prover/metal/include/params.h",
        include_bytes!("../metal/include/params.h"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/field.metal",
        include_bytes!("../metal/kernels/field.metal"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/ntt_stage.metal",
        include_bytes!("../metal/kernels/ntt_stage.metal"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/exact_root.metal",
        include_bytes!("../metal/kernels/exact_root.metal"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/poseidon.metal",
        include_bytes!("../metal/kernels/poseidon.metal"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/digest384.metal",
        include_bytes!("../metal/kernels/digest384.metal"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/keccak256.metal",
        include_bytes!("../metal/kernels/keccak256.metal"),
    ),
    (
        "crates/fastpq_prover/metal/kernels/bn254.metal",
        include_bytes!("../metal/kernels/bn254.metal"),
    ),
];

struct Candidate {
    bytes: &'static [u8],
    source_sha256: [u8; 32],
    target: &'static str,
    language: &'static str,
    producer: &'static str,
    entry_points: &'static [&'static str],
}
struct ReviewedPins {
    library_len: usize,
    library_sha256: [u8; 32],
    source_sha256: [u8; 32],
    target: &'static str,
    language: &'static str,
    producer: &'static str,
    entry_points: &'static [&'static str],
}
struct ApprovedBundle {
    candidate: Candidate,
    pins: ReviewedPins,
}

// TODO: admit genuine compiled bytes and independently reviewed generation pins
// from the sole explicit producer. Its own output metadata is never a trust root.
// Absent authentic approved material means no Metal eligibility in this source cut.
static APPROVED_BUNDLE: Option<ApprovedBundle> = None;
static ADMISSION: OnceLock<Result<AdmittedBundle, ArtifactRefusal>> = OnceLock::new();

/// The exact borrowed immutable bytes whose independent pins were checked.
#[derive(Debug)]
pub struct AdmittedBundle {
    bytes: &'static [u8],
}
impl AdmittedBundle {
    pub(crate) fn bytes(&self) -> &'static [u8] {
        self.bytes
    }
}

/// Operational absence/refusal; never native completion or transaction validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactRefusal {
    Absent,
    SourceIdentity,
    LibraryLength,
    LibraryDigest,
    Target,
    Language,
    Producer,
    Inventory,
}

fn target() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64-apple-darwin"
    } else {
        ""
    }
}

fn source_sha256() -> [u8; 32] {
    let mut hash = Sha256::new();
    // Fixed ordered path length/path/source length/source framing; no temporary
    // concatenation, normalized text, cloned source or runtime path access.
    for (path, bytes) in SOURCES {
        let path_len = u32::try_from(path.len()).expect("fixed Metal source paths fit u32");
        hash.update(path_len.to_le_bytes());
        hash.update(path.as_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

fn inspect(approved: Option<&ApprovedBundle>) -> Result<AdmittedBundle, ArtifactRefusal> {
    let approved = approved.ok_or(ArtifactRefusal::Absent)?;
    let candidate = &approved.candidate;
    let pins = &approved.pins;
    if source_sha256() != SOURCE_SHA256
        || pins.source_sha256 != SOURCE_SHA256
        || candidate.source_sha256 != pins.source_sha256
    {
        return Err(ArtifactRefusal::SourceIdentity);
    }
    if pins.library_len == 0 || candidate.bytes.len() != pins.library_len {
        return Err(ArtifactRefusal::LibraryLength);
    }
    if <[u8; 32]>::from(Sha256::digest(candidate.bytes)) != pins.library_sha256 {
        return Err(ArtifactRefusal::LibraryDigest);
    }
    if target().is_empty() || pins.target != target() || candidate.target != pins.target {
        return Err(ArtifactRefusal::Target);
    }
    if pins.language != LANGUAGE || candidate.language != pins.language {
        return Err(ArtifactRefusal::Language);
    }
    if pins.producer.is_empty() || candidate.producer != pins.producer {
        return Err(ArtifactRefusal::Producer);
    }
    if pins.entry_points != ENTRY_POINTS || candidate.entry_points != pins.entry_points {
        return Err(ArtifactRefusal::Inventory);
    }
    Ok(AdmittedBundle {
        bytes: candidate.bytes,
    })
}

/// Borrow the sole admission result; refused results cannot refresh from a path,
/// environment variable, caller-selected pin, or a cached backend selection.
pub fn admitted_bundle() -> Result<&'static AdmittedBundle, ArtifactRefusal> {
    ADMISSION
        .get_or_init(|| inspect(APPROVED_BUNDLE.as_ref()))
        .as_ref()
        .map_err(|error| *error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Public synthetic bytes are rejection inputs only, never a compiled library,
    // shipping approval, accepted bundle, or successful device observation.
    fn rejection_input() -> ApprovedBundle {
        ApprovedBundle {
            candidate: Candidate {
                bytes: b"public rejection input, not Metal output",
                source_sha256: SOURCE_SHA256,
                target: target(),
                language: LANGUAGE,
                producer: "public negative process-policy fixture",
                entry_points: &ENTRY_POINTS,
            },
            pins: ReviewedPins {
                library_len: 0,
                library_sha256: [0; 32],
                source_sha256: SOURCE_SHA256,
                target: target(),
                language: LANGUAGE,
                producer: "public negative process-policy fixture",
                entry_points: &ENTRY_POINTS,
            },
        }
    }
    fn refuse_without_native_access(input: Option<&ApprovedBundle>, expected: ArtifactRefusal) {
        let reached = Cell::new(false);
        let result = inspect(input).map(|bundle| {
            let _ = bundle.bytes();
            reached.set(true);
        });
        assert_eq!(result, Err(expected));
        assert!(
            !reached.get(),
            "no device, pipeline or private staging callback"
        );
    }

    #[test]
    fn ordered_eight_source_identity_and_complete_sixteen_kernel_inventory_are_pinned() {
        assert_eq!(SOURCES.len(), 8);
        assert_eq!(source_sha256(), SOURCE_SHA256);
        assert_eq!(ENTRY_POINTS.len(), 16);
        for (index, entry) in ENTRY_POINTS.iter().enumerate() {
            assert!(!ENTRY_POINTS[..index].contains(entry));
            let needle = format!("kernel void {entry}(");
            assert_eq!(
                SOURCES
                    .iter()
                    .map(|(_, bytes)| std::str::from_utf8(bytes).unwrap().matches(&needle).count())
                    .sum::<usize>(),
                1
            );
        }
    }

    #[test]
    fn absent_authentic_bundle_cannot_reach_device_or_private_staging() {
        refuse_without_native_access(None, ArtifactRefusal::Absent);
        assert!(matches!(admitted_bundle(), Err(ArtifactRefusal::Absent)));
        assert!(matches!(admitted_bundle(), Err(ArtifactRefusal::Absent)));
    }

    #[test]
    fn independent_source_length_and_digest_pins_refuse_synthetic_inputs() {
        let mut input = rejection_input();
        input.candidate.source_sha256[0] ^= 1;
        refuse_without_native_access(Some(&input), ArtifactRefusal::SourceIdentity);
        input = rejection_input();
        input.pins.source_sha256[0] ^= 1;
        refuse_without_native_access(Some(&input), ArtifactRefusal::SourceIdentity);
        input = rejection_input();
        refuse_without_native_access(Some(&input), ArtifactRefusal::LibraryLength);
        input.pins.library_len = input.candidate.bytes.len() + 1;
        refuse_without_native_access(Some(&input), ArtifactRefusal::LibraryLength);
        input.pins.library_len = input.candidate.bytes.len();
        refuse_without_native_access(Some(&input), ArtifactRefusal::LibraryDigest);
    }

    #[test]
    fn target_language_producer_and_inventory_refuse_before_native_access() {
        for refusal in [
            ArtifactRefusal::Target,
            ArtifactRefusal::Language,
            ArtifactRefusal::Producer,
            ArtifactRefusal::Inventory,
        ] {
            let mut input = rejection_input();
            input.pins.library_len = input.candidate.bytes.len();
            input.pins.library_sha256 = Sha256::digest(input.candidate.bytes).into();
            match refusal {
                ArtifactRefusal::Target => input.candidate.target = "wrong-target",
                ArtifactRefusal::Language => input.candidate.language = "wrong-language",
                ArtifactRefusal::Producer => input.candidate.producer = "self-selected-producer",
                ArtifactRefusal::Inventory => input.candidate.entry_points = &ENTRY_POINTS[..15],
                _ => unreachable!(),
            }
            refuse_without_native_access(Some(&input), refusal);
        }
    }

    #[test]
    fn cached_refusal_does_not_acquire_credit_or_refresh_identity() {
        let cache = OnceLock::new();
        let attempts = Cell::new(0);
        for _ in 0..2 {
            let result = cache.get_or_init(|| {
                attempts.set(attempts.get() + 1);
                inspect(None)
            });
            assert!(matches!(result, Err(ArtifactRefusal::Absent)));
        }
        assert_eq!(attempts.get(), 1);
    }
}
