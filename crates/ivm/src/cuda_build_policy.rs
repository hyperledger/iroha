//! Sole source-owned CUDA bundle approval and exact production source inventory.
//!
//! Ordinary builds admit genuine absence. Supplied material never selects its
//! own trust root or becomes an unsigned/generated fallback.

/// Independently reviewed raw Ed25519 key and complete canonical manifest pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReviewedCudaBundlePins {
    pub(crate) public_key_sha256: &'static str,
    pub(crate) manifest_sha256: &'static str,
}

// TODO: Admit Some only after genuine ten-family production bytes, signed
// provenance and independent review of both exact identities are available.
pub(crate) const REVIEWED_CUDA_BUNDLE_PINS: Option<ReviewedCudaBundlePins> = None;

/// One unchanged production family and its exact reviewed source bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CudaSource {
    pub(crate) stem: &'static str,
    pub(crate) sha256: &'static str,
}
pub(crate) const CUDA_SOURCES: [CudaSource; 10] = [
    CudaSource {
        stem: "aes",
        sha256: "2b6c3d9a022f9b80c261f3da4e2d8779625e0f7af71cd088df518b99fae42deb",
    },
    CudaSource {
        stem: "bitonic_sort",
        sha256: "38dfed94c7fc0db57b02dc836c44f19c8aec1a1b28d50b0b0436f9d98fc1d869",
    },
    CudaSource {
        stem: "bn254",
        sha256: "b8750ba2e3649a42a6e29fd930927cd5a48a4800797b6f5b98615ebfd4b518e2",
    },
    CudaSource {
        stem: "poseidon",
        sha256: "b99103d848880b501639624409bcb33b60a6be4c8a86cc551dcccabde10c0da8",
    },
    CudaSource {
        stem: "sha256",
        sha256: "2b396800a4973838c4485f7e6762201fe83fd4d9197fbd52b2d0fb60973ad12d",
    },
    CudaSource {
        stem: "sha256_leaves",
        sha256: "01477b00d5a6fc6dc147a26debf1f611ff6dda6791230371ed8fe4cb7529f905",
    },
    CudaSource {
        stem: "sha256_pairs_reduce",
        sha256: "6ca14898afe92652cd270277463ed2a40ffde4c2ee6dbb9e8838eea6e18aadd7",
    },
    CudaSource {
        stem: "sha3",
        sha256: "aa6c98001a9c68021c874acfa0b6630935a9e660b03ba816d397e56467a16a59",
    },
    CudaSource {
        stem: "signature",
        sha256: "75d70ad41d5b7b0581c95aa2ebbc94c0291e49b355db1bdd320efd0f57c4a2bb",
    },
    CudaSource {
        stem: "vector",
        sha256: "d98fe451f593e70ad4e81f1275b9bb312266a08d00204e5f9c9034356950bbcb",
    },
];
pub(crate) const fn cuda_stems() -> [&'static str; 10] {
    let mut stems = [""; 10];
    let mut index = 0;
    while index < stems.len() {
        stems[index] = CUDA_SOURCES[index].stem;
        index += 1;
    }
    stems
}

#[cfg(feature = "cuda")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PtxRefusal {
    Utf8(std::str::Utf8Error),
    Directive(&'static str),
    InteriorNul,
}
/// Keep the original exact four-token PTX structural checks and CStr relation.
/// Passing this pure structure check certifies no native kernel or completion.
#[cfg(feature = "cuda")]
pub(crate) fn validate_ptx(bytes: &[u8]) -> Result<(), PtxRefusal> {
    let text = std::str::from_utf8(bytes).map_err(PtxRefusal::Utf8)?;
    for directive in [".version", ".target", ".address_size", ".entry"] {
        if !text
            .split_ascii_whitespace()
            .any(|token| token == directive)
        {
            return Err(PtxRefusal::Directive(directive));
        }
    }
    if bytes.contains(&0) {
        return Err(PtxRefusal::InteriorNul);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cuda_bundle_files::{BundlePresence, PresenceRefusal, bundle_presence};

    // Direct successors of the retired mode parser and generated-release
    // controls: builds have one source approval and no caller-selected mode.
    #[test]
    fn only_genuine_absence_admits_an_unreviewed_bundle() {
        assert_eq!(REVIEWED_CUDA_BUNDLE_PINS, None);
        assert_eq!(
            (bundle_presence(false, &[false; 13])).expect("expected successful fixture result"),
            BundlePresence::Absent
        );
        assert_eq!(
            bundle_presence(false, &[true; 13]),
            Err(PresenceRefusal::UnreviewedMaterial)
        );
        for index in 0..13 {
            let mut present = [false; 13];
            present[index] = true;
            assert_eq!(
                bundle_presence(false, &present),
                Err(PresenceRefusal::UnreviewedMaterial)
            );
        }
    }
    #[test]
    fn source_review_requires_complete_material_in_every_profile() {
        assert_eq!(
            (bundle_presence(true, &[true; 13])).expect("expected successful fixture result"),
            BundlePresence::Complete
        );
        assert_eq!(
            bundle_presence(true, &[false; 13]),
            Err(PresenceRefusal::IncompleteReviewedMaterial)
        );
        for index in 0..13 {
            let mut present = [true; 13];
            present[index] = false;
            assert_eq!(
                bundle_presence(true, &present),
                Err(PresenceRefusal::IncompleteReviewedMaterial)
            );
        }
    }
    #[test]
    fn sole_catalog_has_exact_ten_distinct_integer_and_field_families() {
        let stems = cuda_stems();
        assert_eq!(
            stems,
            [
                "aes",
                "bitonic_sort",
                "bn254",
                "poseidon",
                "sha256",
                "sha256_leaves",
                "sha256_pairs_reduce",
                "sha3",
                "signature",
                "vector"
            ]
        );
        for (index, source) in CUDA_SOURCES.iter().enumerate() {
            assert_eq!(source.sha256.len(), 64);
            assert!(
                source
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert!(!stems[..index].contains(&source.stem));
        }
        assert!(!stems.contains(&"float_diagnostic"));
    }
}
