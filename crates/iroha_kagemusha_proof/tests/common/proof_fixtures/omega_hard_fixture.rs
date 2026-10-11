//! Shared test-only canonical Omega fixture codec and bounded immutable DATA intake.
//! Explicit schema names are identical in library and integration-test modules.

use ff::PrimeField;
use iroha_pasta::Fp;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

/// Fixed roles, never caller-selected paths.
pub(crate) const NAMES: [&str; 6] = [
    "omega.descriptor.norito",
    "omega.vk",
    "omega.proof",
    "public18.bin",
    "pallas.accumulator",
    "vesta.accumulator",
];
/// Current bounded importer limits, followed by exact fixed public/claim extents.
pub(crate) const CAPS: [usize; 6] = [1 << 20, 256 << 10, 10_000, 18 * 32, 17 * 32, 17 * 32];
/// Stable root-frame identity, independent of the compiling crate/module path.
pub(crate) const MANIFEST_SCHEMA: &str = "iroha.kagemusha.test.omega_hard_fixture.manifest.v1";

/// Exact original identity. It grants DATA integrity, not proof or source authority.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.test.omega_hard_fixture.file_pin.v1")]
pub(crate) struct FilePin {
    pub(crate) bytes: u64,
    pub(crate) sha256: [u8; 32],
}
/// One canonical cross-binary manifest; no path aliases or alternate decoder.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.test.omega_hard_fixture.manifest.v1")]
pub(crate) struct FixtureManifest {
    pub(crate) version: u8,
    pub(crate) producer_receipt_sha256: [u8; 32],
    pub(crate) files: [FilePin; 6],
}

/// SHA-256 of exact original bytes.
pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
/// Canonical lowercase hash/word formatting.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// An independently selected exact hash, with no default identity.
pub(crate) fn pin(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}
fn validate(manifest: &FixtureManifest) {
    assert_eq!(manifest.version, 1);
    assert_ne!(manifest.producer_receipt_sha256, [0; 32]);
    for (index, (selected, cap)) in manifest.files.iter().zip(CAPS).enumerate() {
        assert!(selected.bytes > 0 && selected.bytes <= cap as u64);
        assert_ne!(selected.sha256, [0; 32]);
        if index >= 3 {
            assert_eq!(selected.bytes, cap as u64);
        }
    }
}
/// The sole fixture encoder; caller provenance remains independently admitted.
pub(crate) fn encode_manifest(manifest: &FixtureManifest) -> Vec<u8> {
    validate(manifest);
    let bytes = norito::encode_canonical(manifest).unwrap();
    assert!(bytes.len() <= 8192);
    bytes
}
/// Exact canonical decode with fixed bounds and declared schema identity.
pub(crate) fn decode_manifest(bytes: &[u8]) -> FixtureManifest {
    assert!(!bytes.is_empty() && bytes.len() <= 8192);
    let manifest: FixtureManifest =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    validate(&manifest);
    assert_eq!(encode_manifest(&manifest), bytes);
    manifest
}
/// Bounded cooperative local read; input hashes separately enforce exact originals.
pub(crate) fn bounded(path: &Path, cap: usize) -> Vec<u8> {
    let before = fs::symlink_metadata(path).expect("required retained fixture; no fallback");
    assert!(before.file_type().is_file());
    let file = File::open(path).unwrap();
    assert_eq!(before.len(), file.metadata().unwrap().len());
    assert!(before.len() > 0 && before.len() <= cap as u64);
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap());
    file.take(cap as u64 + 1).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}
/// Retain one create-new, synced original in an owner-only output directory.
pub(crate) fn retain(output: &Path, name: &str, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(output.join(name)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
/// Canonical little-endian field words, without a second framing convention.
pub(crate) fn words_bytes(words: &[Fp]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_repr()).collect()
}

/// Exact externally selected fixture plus a retained cooperative directory lock.
pub(crate) struct LoadedFixture {
    root: PathBuf,
    _guard: File,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) manifest: FixtureManifest,
    pub(crate) producer_receipt: Vec<u8>,
    pub(crate) originals: [Vec<u8>; 6],
}
impl LoadedFixture {
    /// Verify that the original inputs still match after the consuming diagnostic.
    pub(crate) fn recheck(&self) {
        for ((name, cap), bytes) in NAMES.iter().zip(CAPS).zip(&self.originals) {
            assert_eq!(bounded(&self.root.join(name), cap), *bytes);
        }
        assert_eq!(
            bounded(&self.root.join("fixture.norito"), 8192),
            self.manifest_bytes
        );
        assert_eq!(
            bounded(&self.root.join("producer-receipt.json"), 65_536),
            self.producer_receipt
        );
    }
}
/// Read only exact selected identities; no hardcoded historical or alternate keys.
pub(crate) fn load_selected(
    root: &Path,
    manifest_sha: [u8; 32],
    descriptor_sha: [u8; 32],
    key_sha: [u8; 32],
) -> LoadedFixture {
    assert!(fs::symlink_metadata(root).unwrap().file_type().is_dir());
    let guard = File::open(root).unwrap();
    guard
        .try_lock()
        .expect("immutable separate fixture; never live cache");
    let manifest_bytes = bounded(&root.join("fixture.norito"), 8192);
    assert_eq!(sha(&manifest_bytes), manifest_sha);
    let manifest = decode_manifest(&manifest_bytes);
    assert_eq!(
        manifest.files[0].sha256, descriptor_sha,
        "independently selected descriptor identity"
    );
    assert_eq!(
        manifest.files[1].sha256, key_sha,
        "independently selected verifier-key identity"
    );
    let producer_receipt = bounded(&root.join("producer-receipt.json"), 65_536);
    assert_eq!(sha(&producer_receipt), manifest.producer_receipt_sha256);
    let originals = core::array::from_fn(|i| {
        let bytes = bounded(&root.join(NAMES[i]), CAPS[i]);
        assert_eq!(bytes.len() as u64, manifest.files[i].bytes);
        assert_eq!(sha(&bytes), manifest.files[i].sha256);
        bytes
    });
    LoadedFixture {
        root: root.to_path_buf(),
        _guard: guard,
        manifest_bytes,
        manifest,
        producer_receipt,
        originals,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    fn data() -> [Vec<u8>; 6] {
        [
            b"unrelated descriptor DATA".to_vec(),
            b"key DATA".to_vec(),
            b"proof DATA".to_vec(),
            vec![3; 576],
            vec![4; 544],
            vec![5; 544],
        ]
    }
    fn manifest(values: &[Vec<u8>; 6]) -> FixtureManifest {
        FixtureManifest {
            version: 1,
            producer_receipt_sha256: sha(b"test DATA provenance"),
            files: values.each_ref().map(|v| FilePin {
                bytes: v.len() as u64,
                sha256: sha(v),
            }),
        }
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/qualification")
                .join(format!(
                    "omega-codec-test-{}-{}-{}",
                    module_path!().replace("::", "-"),
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn stable_schema_and_canonical_roundtrip() {
        use norito::NoritoSchema as _;
        assert_eq!(FixtureManifest::nominal_name(), MANIFEST_SCHEMA);
        assert_eq!(FixtureManifest::frame_name(), MANIFEST_SCHEMA);
        assert_eq!(
            FilePin::nominal_name(),
            "iroha.kagemusha.test.omega_hard_fixture.file_pin.v1"
        );
        let value = manifest(&data());
        let bytes = encode_manifest(&value);
        assert_eq!(decode_manifest(&bytes), value);
        assert_eq!(encode_manifest(&decode_manifest(&bytes)), bytes);
        let alternate =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _guard = norito::core::DecodeFlagsGuard::enter(alternate);
        assert_eq!(encode_manifest(&value), bytes);
        assert_eq!(decode_manifest(&bytes), value);
        assert_eq!(norito::core::effective_decode_flags(), Some(alternate));
    }
    #[test]
    fn manifest_refuses_version_extent_and_trailing_bytes() {
        let value = manifest(&data());
        for change in 0..4 {
            let mut bad = value.clone();
            match change {
                0 => bad.version = 2,
                1 => bad.files[0].bytes = (CAPS[0] + 1) as u64,
                2 => bad.files[3].bytes = 575,
                _ => bad.producer_receipt_sha256 = [0; 32],
            };
            assert!(std::panic::catch_unwind(|| encode_manifest(&bad)).is_err());
        }
        let mut bytes = encode_manifest(&value);
        bytes.push(0);
        assert!(std::panic::catch_unwind(|| decode_manifest(&bytes)).is_err());
        assert!(std::panic::catch_unwind(|| pin(&"G".repeat(64))).is_err());
    }
    #[test]
    fn intake_requires_all_three_pins_and_every_original() {
        let dir = Temp::new();
        let values = data();
        let value = manifest(&values);
        let bytes = encode_manifest(&value);
        retain(&dir.0, "fixture.norito", &bytes);
        retain(&dir.0, "producer-receipt.json", b"test DATA provenance");
        for (name, raw) in NAMES.iter().zip(&values) {
            retain(&dir.0, name, raw);
        }
        let pins = [sha(&bytes), value.files[0].sha256, value.files[1].sha256];
        let read = load_selected(&dir.0, pins[0], pins[1], pins[2]);
        read.recheck();
        assert_eq!(read.originals, values);
        assert_eq!(read.manifest, value);
        drop(read);
        for i in 0..3 {
            let mut wrong = pins;
            wrong[i][0] ^= 1;
            assert!(
                std::panic::catch_unwind(|| load_selected(&dir.0, wrong[0], wrong[1], wrong[2]))
                    .is_err()
            );
        }
        fs::write(dir.0.join(NAMES[2]), b"changed").unwrap();
        assert!(
            std::panic::catch_unwind(|| load_selected(&dir.0, pins[0], pins[1], pins[2])).is_err()
        );
        fs::remove_file(dir.0.join(NAMES[2])).unwrap();
        assert!(
            std::panic::catch_unwind(|| load_selected(&dir.0, pins[0], pins[1], pins[2])).is_err()
        );
    }
    #[test]
    #[ignore = "two copied binaries exchange this unrelated canonical DATA vector; explicit write/read role and fresh path required"]
    fn shared_fixture_codec_cross_binary_handoff() {
        let path = PathBuf::from(
            std::env::var_os("KAGEMUSHA_OMEGA_CODEC_VECTOR").expect("explicit DATA vector path"),
        );
        let value = manifest(&data());
        let expected = encode_manifest(&value);
        match std::env::var("KAGEMUSHA_OMEGA_CODEC_ROLE").as_deref() {
            Ok("write") => retain(
                path.parent().unwrap(),
                path.file_name().unwrap().to_str().unwrap(),
                &expected,
            ),
            Ok("read") => {
                let bytes = bounded(&path, 8192);
                assert_eq!(decode_manifest(&bytes), value);
                assert_eq!(bytes, expected);
            }
            _ => panic!("explicit write or read role"),
        }
        eprintln!(
            "OMEGA_FIXTURE_CODEC schema={} sha256={} bytes={} native_authority=false",
            MANIFEST_SCHEMA,
            hex(&sha(&expected)),
            expected.len()
        );
    }
}
