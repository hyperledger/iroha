//! Signed, byte-exact admission of the ten bundled CUDA PTX families.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const MANIFEST_HEADER: &str = "ivm-cuda-ptx-provenance-v1";
const GENERATION_DOMAIN: &[u8] = b"ivm-cuda-ptx-generation-v1\0";
pub(super) const MAX_MANIFEST_BYTES: usize = 16 * 1024;
pub(super) const MAX_PTX_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn canonical_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with(' ')
        && !value.ends_with(' ')
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

/// Canonical refusal storage stays on the stack; build diagnostics format the
/// same original vocabulary without adding runtime field-name/hex buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProvenanceRefusal {
    TrustedFingerprint,
    PublicKeyLength,
    SignatureLength,
    PublicKeyFingerprint,
    PublicKeyEncoding,
    Signature,
    ManifestText,
    ManifestUtf8,
    Header,
    MissingField(&'static str),
    ExpectedField(&'static str),
    InvalidDigest(&'static str),
    ArtifactField {
        stem: &'static str,
        source: bool,
        missing: bool,
    },
    ArtifactDigest {
        stem: &'static str,
        source: bool,
    },
    Flags,
    Target,
    DigestMismatch(&'static str),
    PtxLimit(&'static str),
    Trailing,
    Generation,
    ManifestPin,
    Traversal,
}
impl std::fmt::Display for ProvenanceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrustedFingerprint => f.write_str(
                "CUDA trusted public-key fingerprint must be a reviewed lowercase SHA-256",
            ),
            Self::PublicKeyLength => f.write_str("CUDA provenance public key must be 32 raw bytes"),
            Self::SignatureLength => f.write_str("CUDA provenance signature must be 64 raw bytes"),
            Self::PublicKeyFingerprint => {
                f.write_str("CUDA provenance public key differs from the reviewed fingerprint")
            }
            Self::PublicKeyEncoding => {
                f.write_str("CUDA provenance public key is not canonical Ed25519")
            }
            Self::Signature => f.write_str("CUDA provenance signature does not verify"),
            Self::ManifestText => {
                f.write_str("CUDA provenance must be canonical LF text with a final LF")
            }
            Self::ManifestUtf8 => f.write_str("CUDA provenance must be UTF-8"),
            Self::Header => f.write_str("CUDA provenance has an unknown V1 header"),
            Self::MissingField(name) => write!(f, "CUDA provenance missing {name}"),
            Self::ExpectedField(name) => {
                write!(f, "CUDA provenance expected {name} in fixed order")
            }
            Self::InvalidDigest(name) => write!(
                f,
                "CUDA provenance {name} must be a nonzero lowercase SHA-256"
            ),
            Self::ArtifactField {
                stem,
                source,
                missing,
            } => {
                let suffix = if *source {
                    "source_sha256"
                } else {
                    "ptx_sha256"
                };
                if *missing {
                    write!(f, "CUDA provenance missing artifact.{stem}.{suffix}")
                } else {
                    write!(
                        f,
                        "CUDA provenance expected artifact.{stem}.{suffix} in fixed order"
                    )
                }
            }
            Self::ArtifactDigest { stem, source } => write!(
                f,
                "CUDA provenance artifact.{stem}.{} must be a nonzero lowercase SHA-256",
                if *source {
                    "source_sha256"
                } else {
                    "ptx_sha256"
                }
            ),
            Self::Flags => f.write_str("CUDA provenance has invalid exact nvcc flags"),
            Self::Target => f.write_str("CUDA provenance has invalid or unbound target profile"),
            Self::DigestMismatch(stem) => {
                write!(f, "CUDA provenance source/PTX digest mismatch for {stem}")
            }
            Self::PtxLimit(stem) => write!(f, "CUDA PTX {stem} exceeds its byte limit"),
            Self::Trailing => f.write_str("CUDA provenance has an unexpected trailing field"),
            Self::Generation => {
                f.write_str("CUDA provenance two-run generation digests differ from bundled PTX")
            }
            Self::ManifestPin => f.write_str(
                "CUDA provenance manifest differs from the source-owned reviewed fingerprint",
            ),
            Self::Traversal => f.write_str("CUDA provenance original row traversal is incomplete"),
        }
    }
}
impl std::error::Error for ProvenanceRefusal {}

fn field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &'static str,
) -> Result<&'a str, ProvenanceRefusal> {
    let line = lines.next().ok_or(ProvenanceRefusal::MissingField(name))?;
    line.strip_prefix(name)
        .and_then(|value| value.strip_prefix('='))
        .ok_or(ProvenanceRefusal::ExpectedField(name))
}
fn digest_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &'static str,
) -> Result<&'a str, ProvenanceRefusal> {
    let value = field(lines, name)?;
    if !is_lower_sha256(value) {
        return Err(ProvenanceRefusal::InvalidDigest(name));
    }
    Ok(value)
}
fn artifact_digest_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    stem: &'static str,
    source: bool,
) -> Result<&'a str, ProvenanceRefusal> {
    let line = lines.next().ok_or(ProvenanceRefusal::ArtifactField {
        stem,
        source,
        missing: true,
    })?;
    let suffix = if source {
        ".source_sha256="
    } else {
        ".ptx_sha256="
    };
    let value = line
        .strip_prefix("artifact.")
        .and_then(|line| line.strip_prefix(stem))
        .and_then(|line| line.strip_prefix(suffix))
        .ok_or(ProvenanceRefusal::ArtifactField {
            stem,
            source,
            missing: false,
        })?;
    if !is_lower_sha256(value) {
        return Err(ProvenanceRefusal::ArtifactDigest { stem, source });
    }
    Ok(value)
}
/// Compare a borrowed canonical hex digest using only a stack digest.
pub(super) fn matches_sha256(bytes: &[u8], expected: &str) -> bool {
    let digest = Sha256::digest(bytes);
    digest_matches(&digest, expected)
}
fn digest_matches(digest: &[u8], expected: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let expected = expected.as_bytes();
    expected.len() == 64
        && digest.iter().enumerate().all(|(index, byte)| {
            expected[2 * index] == HEX[(byte >> 4) as usize]
                && expected[2 * index + 1] == HEX[(byte & 0x0f) as usize]
        })
}
fn update_generation(hasher: &mut Sha256, stem: &str, bytes: &[u8]) {
    hasher.update((stem.len() as u16).to_le_bytes());
    hasher.update(stem.as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
#[derive(Clone, Copy, Debug)]
pub(super) struct BorrowedCudaMetadata<'a> {
    pub cuda_image_sha256: &'a str,
    pub nvcc_version_sha256: &'a str,
    pub nvcc_flags: &'a str,
    pub target_profile: &'a str,
}
#[derive(Clone, Copy)]
struct RowDigests<'a> {
    source: &'a str,
    ptx: &'a str,
}
/// The sole authenticated fixed-order reader. Expected row fields precede the
/// adapter's original file reads; borrowed bytes never escape their actual owner.
pub(super) struct BorrowedCudaReader<'a> {
    manifest: &'a [u8],
    stems: &'a [&'static str],
    lines: std::str::SplitTerminator<'a, char>,
    metadata: BorrowedCudaMetadata<'a>,
    first_generation: &'a str,
    second_generation: &'a str,
    generation: Sha256,
    index: usize,
    pending: Option<RowDigests<'a>>,
}
impl<'a> BorrowedCudaReader<'a> {
    pub(super) fn new(
        manifest: &'a [u8],
        public_key: &[u8],
        signature: &[u8],
        stems: &'a [&'static str],
        trusted_key_sha256: &str,
    ) -> Result<Self, ProvenanceRefusal> {
        if !is_lower_sha256(trusted_key_sha256) {
            return Err(ProvenanceRefusal::TrustedFingerprint);
        }
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err(ProvenanceRefusal::ManifestText);
        }
        let public_key: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| ProvenanceRefusal::PublicKeyLength)?;
        let signature: &[u8; 64] = signature
            .try_into()
            .map_err(|_| ProvenanceRefusal::SignatureLength)?;
        if !matches_sha256(public_key, trusted_key_sha256) {
            return Err(ProvenanceRefusal::PublicKeyFingerprint);
        }
        let verifier = VerifyingKey::from_bytes(public_key)
            .map_err(|_| ProvenanceRefusal::PublicKeyEncoding)?;
        verifier
            .verify_strict(manifest, &Signature::from_bytes(signature))
            .map_err(|_| ProvenanceRefusal::Signature)?;
        if !manifest.ends_with(b"\n") || manifest.contains(&b'\r') || manifest.contains(&b'\0') {
            return Err(ProvenanceRefusal::ManifestText);
        }
        let text = std::str::from_utf8(manifest).map_err(|_| ProvenanceRefusal::ManifestUtf8)?;
        let mut lines = text.split_terminator('\n');
        if lines.next() != Some(MANIFEST_HEADER) {
            return Err(ProvenanceRefusal::Header);
        }
        // These private slots are not published until every original phase passes.
        let mut metadata = BorrowedCudaMetadata {
            cuda_image_sha256: "",
            nvcc_version_sha256: "",
            nvcc_flags: "",
            target_profile: "",
        };
        metadata.cuda_image_sha256 = field(&mut lines, "cuda_image_sha256")?;
        if !is_lower_sha256(metadata.cuda_image_sha256) {
            return Err(ProvenanceRefusal::InvalidDigest("cuda_image_sha256"));
        }
        metadata.nvcc_version_sha256 = field(&mut lines, "nvcc_version_sha256")?;
        if !is_lower_sha256(metadata.nvcc_version_sha256) {
            return Err(ProvenanceRefusal::InvalidDigest("nvcc_version_sha256"));
        }
        metadata.nvcc_flags = field(&mut lines, "nvcc_flags")?;
        if !canonical_text(metadata.nvcc_flags, 512)
            || !metadata.nvcc_flags.starts_with("-ptx -std=c++14 ")
        {
            return Err(ProvenanceRefusal::Flags);
        }
        metadata.target_profile = field(&mut lines, "target_profile")?;
        if !canonical_text(metadata.target_profile, 128)
            || !metadata.target_profile.starts_with("arch=compute_")
            || !metadata.target_profile.contains(",code=sm_")
            || !metadata.nvcc_flags.contains(metadata.target_profile)
        {
            return Err(ProvenanceRefusal::Target);
        }
        let first_generation = digest_field(&mut lines, "generation_1_sha256")?;
        let second_generation = digest_field(&mut lines, "generation_2_sha256")?;
        let mut generation = Sha256::new();
        generation.update(GENERATION_DOMAIN);
        Ok(Self {
            manifest,
            stems,
            lines,
            metadata,
            first_generation,
            second_generation,
            generation,
            index: 0,
            pending: None,
        })
    }
    pub(super) fn next_row(&mut self) -> Result<&'static str, ProvenanceRefusal> {
        if self.pending.is_some() || self.index >= self.stems.len() {
            return Err(ProvenanceRefusal::Traversal);
        }
        let stem = self.stems[self.index];
        let source = artifact_digest_field(&mut self.lines, stem, true)?;
        let ptx = artifact_digest_field(&mut self.lines, stem, false)?;
        self.pending = Some(RowDigests { source, ptx });
        Ok(stem)
    }
    pub(super) fn accept_row(
        &mut self,
        source: &[u8],
        ptx: &[u8],
    ) -> Result<(), ProvenanceRefusal> {
        let digests = self.pending.ok_or(ProvenanceRefusal::Traversal)?;
        let stem = self.stems[self.index];
        if ptx.len() > MAX_PTX_BYTES {
            return Err(ProvenanceRefusal::PtxLimit(stem));
        }
        if !matches_sha256(source, digests.source) || !matches_sha256(ptx, digests.ptx) {
            return Err(ProvenanceRefusal::DigestMismatch(stem));
        }
        update_generation(&mut self.generation, stem, ptx);
        self.index += 1;
        self.pending = None;
        Ok(())
    }
    pub(super) fn finish(
        mut self,
        manifest_sha256: &str,
    ) -> Result<BorrowedCudaMetadata<'a>, ProvenanceRefusal> {
        if self.index != self.stems.len() || self.pending.is_some() {
            return Err(ProvenanceRefusal::Traversal);
        }
        if self.lines.next().is_some() {
            return Err(ProvenanceRefusal::Trailing);
        }
        if self.first_generation != self.second_generation
            || !digest_matches(&self.generation.finalize(), self.first_generation)
        {
            return Err(ProvenanceRefusal::Generation);
        }
        if !is_lower_sha256(manifest_sha256) || !matches_sha256(self.manifest, manifest_sha256) {
            return Err(ProvenanceRefusal::ManifestPin);
        }
        Ok(self.metadata)
    }
}

#[cfg(test)]
fn generation_sha256(stems: &[&str], artifacts: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GENERATION_DOMAIN);
    for (stem, bytes) in stems.iter().zip(artifacts) {
        update_generation(&mut hasher, stem, bytes);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cuda_bundle_files::{
        MANIFEST_NAME, MANIFEST_PUBLIC_KEY_NAME, MANIFEST_SIGNATURE_NAME, VerifiedCudaBundle,
        open_regular_file, read_regular_file, same_regular_inode, verify_bundle,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        fmt::Write as _,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const STEMS: [&str; 2] = ["aes", "vector"];
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
        trusted_fingerprint: String,
        signing_key: SigningKey,
        manifest: String,
        artifacts: Vec<Vec<u8>>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "ivm-cuda-provenance-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).expect("unique private fixture directory");
            let signing_key = SigningKey::from_bytes(&[0x42; 32]);
            let public_key = signing_key.verifying_key().to_bytes();
            let trusted_fingerprint = sha256_hex(&public_key);
            let artifacts = STEMS
                .iter()
                .map(|stem| {
                    format!(
                        ".version 7.8\n.target sm_86\n.address_size 64\n.visible .entry {stem}() {{ ret; }}\n"
                    )
                    .into_bytes()
                })
                .collect::<Vec<_>>();
            let generation = generation_sha256(&STEMS, &artifacts);
            let mut manifest = format!(
                "{MANIFEST_HEADER}\n\
                 cuda_image_sha256={}\n\
                 nvcc_version_sha256={}\n\
                 nvcc_flags=-ptx -std=c++14 -gencode arch=compute_86,code=sm_86\n\
                 target_profile=arch=compute_86,code=sm_86\n\
                 generation_1_sha256={generation}\n\
                 generation_2_sha256={generation}\n",
                sha256_hex(b"pinned CUDA image"),
                sha256_hex(b"nvcc --version output"),
            );
            for (stem, ptx) in STEMS.iter().zip(&artifacts) {
                let source = format!("// source for {stem}\n");
                fs::write(directory.join(format!("{stem}.cu")), &source).expect("source fixture");
                fs::write(directory.join(format!("{stem}.ptx")), ptx).expect("PTX fixture");
                writeln!(
                    &mut manifest,
                    "artifact.{stem}.source_sha256={}",
                    sha256_hex(source.as_bytes())
                )
                .expect("manifest string");
                writeln!(
                    &mut manifest,
                    "artifact.{stem}.ptx_sha256={}",
                    sha256_hex(ptx)
                )
                .expect("manifest string");
            }
            let mut fixture = Self {
                directory,
                trusted_fingerprint,
                signing_key,
                manifest,
                artifacts,
            };
            fixture.resign();
            fixture
        }
        fn resign(&mut self) {
            fs::write(self.directory.join(MANIFEST_NAME), &self.manifest)
                .expect("manifest fixture");
            fs::write(
                self.directory.join(MANIFEST_PUBLIC_KEY_NAME),
                self.signing_key.verifying_key().to_bytes(),
            )
            .expect("public key fixture");
            fs::write(
                self.directory.join(MANIFEST_SIGNATURE_NAME),
                self.signing_key.sign(self.manifest.as_bytes()).to_bytes(),
            )
            .expect("signature fixture");
        }
        fn verify(&self) -> Result<VerifiedCudaBundle, String> {
            verify_bundle(
                &self.directory,
                &STEMS,
                &self.trusted_fingerprint,
                &sha256_hex(self.manifest.as_bytes()),
            )
        }
    }

    #[test]
    fn signed_bundle_binds_exact_source_ptx_and_toolchain_fields() {
        let fixture = Fixture::new();
        let verified = fixture.verify().expect("signed fixture");
        assert_eq!(verified.artifacts, fixture.artifacts);
        assert_eq!(verified.cuda_image_sha256, sha256_hex(b"pinned CUDA image"));
        assert_eq!(
            verified.nvcc_version_sha256,
            sha256_hex(b"nvcc --version output")
        );
        assert_eq!(verified.target_profile, "arch=compute_86,code=sm_86");
        assert_eq!(
            verified.nvcc_flags,
            "-ptx -std=c++14 -gencode arch=compute_86,code=sm_86"
        );
    }

    #[test]
    fn signed_bundle_accepts_large_source_trivia_and_preserves_exact_hashes() {
        let mut fixture = Fixture::new();
        let source = format!("//{}\n", "x".repeat(1024 * 1024));
        let path = fixture.directory.join("vector.cu");
        fs::write(&path, &source).expect("large source fixture");
        let original = format!(
            "artifact.vector.source_sha256={}",
            sha256_hex(b"// source for vector\n")
        );
        assert_eq!(fixture.manifest.matches(&original).count(), 1);
        fixture.manifest = fixture.manifest.replacen(
            &original,
            &format!(
                "artifact.vector.source_sha256={}",
                sha256_hex(source.as_bytes())
            ),
            1,
        );
        fixture.resign();
        assert_eq!(
            fixture.verify().expect("large signed source").artifacts,
            fixture.artifacts
        );
        assert_eq!(
            read_regular_file(&path, None).expect("exact source"),
            source.as_bytes()
        );
        assert!(
            read_regular_file(&path, Some(64))
                .unwrap_err()
                .contains("byte limit")
        );
        fs::write(path, format!("{source}// mutation\n")).expect("source mutation");
        assert!(fixture.verify().unwrap_err().contains("digest mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn source_reader_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let source = fixture.directory.join("vector.cu");
        let alias = fixture.directory.join("alias.cu");
        symlink(source, &alias).expect("source alias fixture");
        assert!(open_regular_file(&alias).is_err());
        assert!(
            read_regular_file(&alias, None)
                .unwrap_err()
                .contains("regular file")
        );
    }

    #[test]
    fn source_reader_requires_the_original_regular_inode() {
        let fixture = Fixture::new();
        let source = fixture.directory.join("vector.cu");
        let before = fs::symlink_metadata(&source).expect("source metadata");
        let opened = open_regular_file(&source).expect("direct source");
        assert!(same_regular_inode(
            &before,
            &opened.metadata().expect("retained inode")
        ));
        fs::rename(&source, fixture.directory.join("original.cu")).expect("move source");
        fs::write(&source, b"// source for vector\n").expect("same-byte replacement");
        #[cfg(unix)]
        assert!(!same_regular_inode(
            &before,
            &fs::symlink_metadata(&source).expect("replacement metadata")
        ));
        let retained = opened.metadata().expect("original retained inode");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(before.dev(), retained.dev());
            assert_eq!(before.ino(), retained.ino());
        }
        assert_eq!(before.len(), retained.len());
    }

    #[test]
    fn bundle_rejects_unsigned_or_unreviewed_mutations() {
        let fixture = Fixture::new();
        let ptx_path = fixture.directory.join("aes.ptx");
        fs::write(&ptx_path, b"different PTX").expect("mutate PTX");
        assert!(fixture.verify().unwrap_err().contains("digest mismatch"));
        fs::write(&ptx_path, &fixture.artifacts[0]).expect("restore PTX");

        let source_path = fixture.directory.join("vector.cu");
        fs::write(&source_path, b"different source").expect("mutate source");
        assert!(fixture.verify().unwrap_err().contains("digest mismatch"));
        fs::write(&source_path, b"// source for vector\n").expect("restore source");

        let signature_path = fixture.directory.join(MANIFEST_SIGNATURE_NAME);
        fs::write(&signature_path, [0_u8; 64]).expect("mutate signature");
        assert!(
            fixture
                .verify()
                .unwrap_err()
                .contains("signature does not verify")
        );
        assert!(
            verify_bundle(
                &fixture.directory,
                &STEMS,
                &sha256_hex(b"unreviewed key"),
                &sha256_hex(fixture.manifest.as_bytes())
            )
            .unwrap_err()
            .contains("reviewed fingerprint")
        );
    }

    #[test]
    fn signed_manifest_rejects_false_two_run_claim_and_extra_fields() {
        let mut fixture = Fixture::new();
        let recorded = format!(
            "generation_2_sha256={}",
            generation_sha256(&STEMS, &fixture.artifacts)
        );
        fixture.manifest = fixture.manifest.replacen(
            &recorded,
            &format!("generation_2_sha256={}", sha256_hex(b"different run")),
            1,
        );
        fixture.resign();
        assert!(
            fixture
                .verify()
                .unwrap_err()
                .contains("generation digests differ")
        );

        let mut fixture = Fixture::new();
        fixture.manifest.push_str("unexpected=field\n");
        fixture.resign();
        assert!(
            fixture
                .verify()
                .unwrap_err()
                .contains("unexpected trailing field")
        );
    }
    fn borrowed_fixture<'a>(
        fixture: &'a Fixture,
        manifest_pin: &str,
    ) -> Result<BorrowedCudaMetadata<'a>, ProvenanceRefusal> {
        let public_key = fixture.signing_key.verifying_key().to_bytes();
        let signature = fixture
            .signing_key
            .sign(fixture.manifest.as_bytes())
            .to_bytes();
        let mut reader = BorrowedCudaReader::new(
            fixture.manifest.as_bytes(),
            &public_key,
            &signature,
            &STEMS,
            &fixture.trusted_fingerprint,
        )?;
        for (index, stem) in STEMS.iter().enumerate() {
            assert_eq!(reader.next_row()?, *stem);
            let source = fs::read(fixture.directory.join(format!("{stem}.cu"))).unwrap();
            reader.accept_row(&source, &fixture.artifacts[index])?;
        }
        reader.finish(manifest_pin)
    }

    #[test]
    fn original_file_and_borrowed_adapters_share_exact_canonical_metadata_and_inputs() {
        // This original synthetic signed fixture exercises only the canonical
        // relation. It never enters the production source-owned artifact owner.
        let fixture = Fixture::new();
        let pin = sha256_hex(fixture.manifest.as_bytes());
        let file = fixture.verify().unwrap();
        let borrowed = borrowed_fixture(&fixture, &pin).unwrap();
        assert_eq!(file.manifest, fixture.manifest.as_bytes());
        assert_eq!(
            file.public_key,
            fixture.signing_key.verifying_key().to_bytes()
        );
        assert_eq!(
            file.signature,
            fixture
                .signing_key
                .sign(fixture.manifest.as_bytes())
                .to_bytes()
        );
        assert_eq!(borrowed.cuda_image_sha256, file.cuda_image_sha256);
        assert_eq!(borrowed.nvcc_version_sha256, file.nvcc_version_sha256);
        assert_eq!(borrowed.nvcc_flags, file.nvcc_flags);
        assert_eq!(borrowed.target_profile, file.target_profile);
        let original = fixture.manifest.as_bytes().as_ptr_range();
        for field in [
            borrowed.cuda_image_sha256,
            borrowed.nvcc_version_sha256,
            borrowed.nvcc_flags,
            borrowed.target_profile,
        ] {
            assert!(original.contains(&field.as_ptr()));
            assert!(field.as_bytes().as_ptr_range().end <= original.end);
        }
        for (index, stem) in STEMS.iter().enumerate() {
            assert_eq!(
                file.sources[index],
                format!("// source for {stem}\n").as_bytes()
            );
            assert_eq!(file.artifacts[index], fixture.artifacts[index]);
        }
    }

    #[test]
    fn exact_manifest_approval_cannot_be_selected_by_resigning_or_rehashing_material() {
        let mut fixture = Fixture::new();
        let original_pin = sha256_hex(fixture.manifest.as_bytes());
        let original_flags = "nvcc_flags=-ptx -std=c++14 -gencode arch=compute_86,code=sm_86";
        fixture.manifest = fixture.manifest.replacen(
            original_flags,
            "nvcc_flags=-ptx -std=c++14 -O3 -gencode arch=compute_86,code=sm_86",
            1,
        );
        fixture.resign();
        assert_eq!(
            borrowed_fixture(&fixture, &original_pin).unwrap_err(),
            ProvenanceRefusal::ManifestPin
        );
        assert!(
            verify_bundle(
                &fixture.directory,
                &STEMS,
                &fixture.trusted_fingerprint,
                &original_pin
            )
            .unwrap_err()
            .contains("source-owned reviewed fingerprint")
        );
        // Original semantic refusals precede the new final approval comparison.
        fixture.manifest.push_str("unexpected=field\n");
        fixture.resign();
        assert_eq!(
            borrowed_fixture(&fixture, &original_pin).unwrap_err(),
            ProvenanceRefusal::Trailing
        );
        assert!(
            verify_bundle(
                &fixture.directory,
                &STEMS,
                &fixture.trusted_fingerprint,
                &original_pin
            )
            .unwrap_err()
            .contains("unexpected trailing field")
        );
        fs::write(fixture.directory.join("aes.cu"), b"changed original source").unwrap();
        assert_eq!(
            borrowed_fixture(&fixture, &original_pin).unwrap_err(),
            ProvenanceRefusal::DigestMismatch("aes")
        );
        assert!(
            verify_bundle(
                &fixture.directory,
                &STEMS,
                &fixture.trusted_fingerprint,
                &original_pin
            )
            .unwrap_err()
            .contains("digest mismatch")
        );
    }

    #[test]
    fn original_row_order_traversal_and_authentication_refuse_before_any_partial_owner() {
        let fixture = Fixture::new();
        let public_key = fixture.signing_key.verifying_key().to_bytes();
        let signature = fixture
            .signing_key
            .sign(fixture.manifest.as_bytes())
            .to_bytes();
        let new_reader = || {
            BorrowedCudaReader::new(
                fixture.manifest.as_bytes(),
                &public_key,
                &signature,
                &STEMS,
                &fixture.trusted_fingerprint,
            )
        };
        assert_eq!(
            new_reader()
                .unwrap()
                .finish(&sha256_hex(fixture.manifest.as_bytes()))
                .unwrap_err(),
            ProvenanceRefusal::Traversal
        );
        let mut reader = new_reader().unwrap();
        assert_eq!(
            reader.accept_row(&[], &[]),
            Err(ProvenanceRefusal::Traversal)
        );
        assert_eq!(
            (reader.next_row()).expect("expected successful fixture result"),
            "aes"
        );
        assert_eq!(reader.next_row(), Err(ProvenanceRefusal::Traversal));
        assert_eq!(
            reader
                .finish(&sha256_hex(fixture.manifest.as_bytes()))
                .unwrap_err(),
            ProvenanceRefusal::Traversal
        );
        assert!(matches!(
            BorrowedCudaReader::new(
                fixture.manifest.as_bytes(),
                &public_key[..31],
                &signature,
                &STEMS,
                &fixture.trusted_fingerprint
            ),
            Err(ProvenanceRefusal::PublicKeyLength)
        ));
        assert!(matches!(
            BorrowedCudaReader::new(
                fixture.manifest.as_bytes(),
                &public_key,
                &signature[..63],
                &STEMS,
                &fixture.trusted_fingerprint
            ),
            Err(ProvenanceRefusal::SignatureLength)
        ));
        let wrong = sha256_hex(b"unreviewed fixture key");
        assert!(matches!(
            BorrowedCudaReader::new(
                fixture.manifest.as_bytes(),
                &public_key,
                &signature,
                &STEMS,
                &wrong
            ),
            Err(ProvenanceRefusal::PublicKeyFingerprint)
        ));
        assert!(matches!(
            BorrowedCudaReader::new(
                fixture.manifest.as_bytes(),
                &public_key,
                &[0; 64],
                &STEMS,
                &fixture.trusted_fingerprint
            ),
            Err(ProvenanceRefusal::Signature)
        ));
        assert_eq!(
            borrowed_fixture(&fixture, &"0".repeat(64)).unwrap_err(),
            ProvenanceRefusal::ManifestPin
        );
        let mut reordered = fixture;
        let first = "artifact.aes.source_sha256=";
        reordered.manifest =
            reordered
                .manifest
                .replacen(first, "artifact.vector.source_sha256=", 1);
        reordered.resign();
        assert_eq!(
            borrowed_fixture(&reordered, &sha256_hex(reordered.manifest.as_bytes())).unwrap_err(),
            ProvenanceRefusal::ArtifactField {
                stem: "aes",
                source: true,
                missing: false
            }
        );
    }

    #[test]
    fn shared_walk_preserves_canonical_text_truncation_and_original_byte_limits() {
        let mut fixture = Fixture::new();
        fixture.manifest = fixture.manifest.replacen("\n", "\r\n", 1);
        fixture.resign();
        assert_eq!(
            borrowed_fixture(&fixture, &sha256_hex(fixture.manifest.as_bytes())).unwrap_err(),
            ProvenanceRefusal::ManifestText
        );
        let mut fixture = Fixture::new();
        let offset = fixture
            .manifest
            .find("artifact.vector.ptx_sha256=")
            .unwrap();
        fixture.manifest.truncate(offset);
        fixture.resign();
        assert_eq!(
            borrowed_fixture(&fixture, &sha256_hex(fixture.manifest.as_bytes())).unwrap_err(),
            ProvenanceRefusal::ArtifactField {
                stem: "vector",
                source: false,
                missing: true
            }
        );
        let mut fixture = Fixture::new();
        fixture.manifest.push_str(&"x".repeat(MAX_MANIFEST_BYTES));
        fixture.resign();
        assert_eq!(
            borrowed_fixture(&fixture, &sha256_hex(fixture.manifest.as_bytes())).unwrap_err(),
            ProvenanceRefusal::ManifestText
        );
        let fixture = Fixture::new();
        let public_key = fixture.signing_key.verifying_key().to_bytes();
        let signature = fixture
            .signing_key
            .sign(fixture.manifest.as_bytes())
            .to_bytes();
        let mut reader = BorrowedCudaReader::new(
            fixture.manifest.as_bytes(),
            &public_key,
            &signature,
            &STEMS,
            &fixture.trusted_fingerprint,
        )
        .unwrap();
        assert_eq!(
            (reader.next_row()).expect("expected successful fixture result"),
            "aes"
        );
        let oversized = vec![0; MAX_PTX_BYTES + 1];
        assert_eq!(
            reader.accept_row(b"// source for aes\n", &oversized),
            Err(ProvenanceRefusal::PtxLimit("aes"))
        );
        assert!(matches!(
            reader.accept_row(b"// source for aes\n", &fixture.artifacts[0]),
            Ok(())
        ));
        assert_eq!(
            (reader.next_row()).expect("expected successful fixture result"),
            "vector"
        );
        assert!(matches!(
            reader.accept_row(b"// source for vector\n", &fixture.artifacts[1]),
            Ok(())
        ));
        assert_eq!(reader.next_row(), Err(ProvenanceRefusal::Traversal));
        assert!(
            reader
                .finish(&sha256_hex(fixture.manifest.as_bytes()))
                .is_ok()
        );
    }
    #[test]
    fn file_adapter_retains_every_admitted_original_input() {
        let fixture = Fixture::new();
        let original_sources: Vec<_> = STEMS
            .iter()
            .map(|stem| fs::read(fixture.directory.join(format!("{stem}.cu"))).unwrap())
            .collect();
        let original_artifacts: Vec<_> = STEMS
            .iter()
            .map(|stem| fs::read(fixture.directory.join(format!("{stem}.ptx"))).unwrap())
            .collect();
        let original_manifest = fs::read(fixture.directory.join(MANIFEST_NAME)).unwrap();
        let original_key = fs::read(fixture.directory.join(MANIFEST_PUBLIC_KEY_NAME)).unwrap();
        let original_signature = fs::read(fixture.directory.join(MANIFEST_SIGNATURE_NAME)).unwrap();
        assert_eq!(original_manifest, fixture.manifest.as_bytes());
        assert_eq!(original_key, fixture.signing_key.verifying_key().to_bytes());
        assert_eq!(
            original_signature,
            fixture.signing_key.sign(&original_manifest).to_bytes()
        );
        for (index, stem) in STEMS.iter().enumerate() {
            assert_eq!(
                original_sources[index],
                format!("// source for {stem}\n").as_bytes()
            );
            assert_eq!(original_artifacts[index], fixture.artifacts[index]);
        }
        let verified = fixture.verify().expect("actual signed private originals");
        // Replace every admitted pathname after admission. The returned owner
        // must still contain all original bytes, not a later pathname read.
        for stem in STEMS {
            fs::write(
                fixture.directory.join(format!("{stem}.cu")),
                b"replaced source",
            )
            .unwrap();
            fs::write(
                fixture.directory.join(format!("{stem}.ptx")),
                b"replaced PTX",
            )
            .unwrap();
        }
        for name in [
            MANIFEST_NAME,
            MANIFEST_PUBLIC_KEY_NAME,
            MANIFEST_SIGNATURE_NAME,
        ] {
            fs::write(fixture.directory.join(name), b"replaced authentic input").unwrap();
        }
        assert_eq!(verified.sources, original_sources);
        assert_eq!(verified.artifacts, original_artifacts);
        assert_eq!(verified.manifest, original_manifest);
        assert_eq!(verified.public_key.as_slice(), original_key);
        assert_eq!(verified.signature.as_slice(), original_signature);
        assert_eq!(verified.cuda_image_sha256, sha256_hex(b"pinned CUDA image"));
        assert_eq!(
            verified.nvcc_version_sha256,
            sha256_hex(b"nvcc --version output")
        );
        assert_eq!(
            verified.nvcc_flags,
            "-ptx -std=c++14 -gencode arch=compute_86,code=sm_86"
        );
        assert_eq!(verified.target_profile, "arch=compute_86,code=sm_86");
    }

    #[test]
    fn borrowed_metadata_preserves_original_first_fault_order_and_values() {
        let fixture = Fixture::new();
        let pin = sha256_hex(fixture.manifest.as_bytes());
        let metadata = borrowed_fixture(&fixture, &pin).expect("actual signed private metadata");
        assert_eq!(metadata.cuda_image_sha256, sha256_hex(b"pinned CUDA image"));
        assert_eq!(
            metadata.nvcc_version_sha256,
            sha256_hex(b"nvcc --version output")
        );
        assert_eq!(
            metadata.nvcc_flags,
            "-ptx -std=c++14 -gencode arch=compute_86,code=sm_86"
        );
        assert_eq!(metadata.target_profile, "arch=compute_86,code=sm_86");

        let image = format!("cuda_image_sha256={}\n", sha256_hex(b"pinned CUDA image"));
        let version = format!(
            "nvcc_version_sha256={}\n",
            sha256_hex(b"nvcc --version output")
        );
        let flags = "nvcc_flags=-ptx -std=c++14 -gencode arch=compute_86,code=sm_86\n";
        let target = "target_profile=arch=compute_86,code=sm_86\n";
        let zero = "0".repeat(64);
        let cases = [
            (
                format!("cuda_image_sha256={zero}\n"),
                ProvenanceRefusal::InvalidDigest("cuda_image_sha256"),
            ),
            (
                image.clone(),
                ProvenanceRefusal::MissingField("nvcc_version_sha256"),
            ),
            (
                format!("{image}nvcc_version_sha256={zero}\n"),
                ProvenanceRefusal::InvalidDigest("nvcc_version_sha256"),
            ),
            (
                format!("{image}{version}"),
                ProvenanceRefusal::MissingField("nvcc_flags"),
            ),
            (
                format!("{image}{version}nvcc_flags=invalid\n"),
                ProvenanceRefusal::Flags,
            ),
            (
                format!("{image}{version}{flags}"),
                ProvenanceRefusal::MissingField("target_profile"),
            ),
            (
                format!("{image}{version}{flags}target_profile=invalid\n"),
                ProvenanceRefusal::Target,
            ),
            (
                format!("{image}{version}{flags}{target}"),
                ProvenanceRefusal::MissingField("generation_1_sha256"),
            ),
        ];
        for (prefix, expected) in cases {
            let mut fixture = Fixture::new();
            fixture.manifest = format!("ivm-cuda-ptx-provenance-v1\n{prefix}");
            fixture.resign();
            let pin = sha256_hex(fixture.manifest.as_bytes());
            assert_eq!(borrowed_fixture(&fixture, &pin).unwrap_err(), expected);
        }
    }
}
