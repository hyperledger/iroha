//! Explicit full-route wallet source construction from independently pinned genesis.
//! Generated artifacts undergo ordinary signed source admission; this engineering
//! harness grants no deployment authority and requires no finality proof artifacts.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use iroha_data_model::{
    block::decode_framed_signed_block,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, authenticated_genesis},
};
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk_gadgets::p256::native::{Affine, words_from_be};
use p256::ecdsa::SigningKey;

use super::*;

#[path = "full_catalog/acceptance.rs"]
mod acceptance;
#[path = "full_catalog/reuse.rs"]
mod reuse;
#[path = "full_catalog/transport.rs"]
mod transport;
pub(crate) use acceptance::{
    open_pinned_engineering_finality_sources, open_pinned_engineering_wallet_sources,
};

const OUTPUT_BYTES: u64 = 128 << 30;

fn pin(name: &str) -> [u8; 32] {
    let encoded = std::env::var(name).expect("independently recorded exact SHA-256 pin");
    let bytes: [u8; 32] = hex::decode(encoded).unwrap().try_into().unwrap();
    assert_ne!(bytes, [0; 32]);
    bytes
}
fn regular_directory(path: &Path) -> Result<(), Error> {
    if !fs::symlink_metadata(path)
        .map_err(|_| Error::Inventory)?
        .file_type()
        .is_dir()
    {
        return Err(Error::Inventory);
    }
    Ok(())
}
fn bounded_file(path: &Path, cap: usize) -> Result<Vec<u8>, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Inventory)?;
    let length = usize::try_from(metadata.len()).map_err(|_| Error::Inventory)?;
    if !metadata.file_type().is_file() || length == 0 || length > cap {
        return Err(Error::Inventory);
    }
    let file = File::open(path).map_err(|_| Error::Inventory)?;
    if file.metadata().map_err(|_| Error::Inventory)?.len() != metadata.len() {
        return Err(Error::Inventory);
    }
    let mut bytes = Vec::with_capacity(length);
    file.take(u64::try_from(cap).map_err(|_| Error::Inventory)? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Inventory)?;
    if bytes.len() != length {
        return Err(Error::Inventory);
    }
    Ok(bytes)
}
fn pinned_file(path: &Path, cap: usize, expected: [u8; 32]) -> Result<Vec<u8>, Error> {
    if expected == [0; 32] {
        return Err(Error::Inventory);
    }
    let bytes = bounded_file(path, cap)?;
    if BlobV1::of(&bytes).sha256 != expected {
        return Err(Error::Inventory);
    }
    Ok(bytes)
}
fn pinned_genesis_fixture() -> Vec<u8> {
    let path = PathBuf::from(
        std::env::var_os("KAGEMUSHA_SIGNED_GENESIS_FIXTURE").expect("selected genesis fixture"),
    );
    pinned_file(
        &path,
        1 << 20,
        pin("KAGEMUSHA_SIGNED_GENESIS_FIXTURE_SHA256"),
    )
    .unwrap()
}
fn native_finality(fixture: &[u8]) -> SumeragiFinalityVerifier {
    let capture: norito::json::Value = norito::json::from_slice(fixture).unwrap();
    let wire = hex::decode(capture["signed_genesis_wire_hex"].as_str().unwrap()).unwrap();
    let genesis = decode_framed_signed_block(&wire).unwrap();
    let epoch = authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let roster = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    SumeragiFinalityVerifier::new(&genesis, capture["chain_id"].as_str().unwrap(), roster).unwrap()
}
fn fixture_scope() -> SourceScopeV1 {
    // Public engineering root only; the same scalar and compiled provider are
    // used by the test authority owner. No production signing material is read.
    let root = SigningKey::from_bytes((&[0x11; 32]).into()).unwrap();
    let point = root.verifying_key().to_encoded_point(false);
    let sec1 = point.as_bytes();
    let provider = kagemusha_wallet_provider_contract_v1();
    SourceScopeV1::new(
        [
            u128::from_le_bytes(provider[..16].try_into().unwrap()),
            u128::from_le_bytes(provider[16..].try_into().unwrap()),
        ],
        Affine {
            x: words_from_be(sec1[1..33].try_into().unwrap()),
            y: words_from_be(sec1[33..65].try_into().unwrap()),
        },
    )
    .unwrap()
}
fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = path.parent().ok_or(Error::Inventory)?;
    let temporary = root.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| Error::Unavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::Unavailable)?;
    fs::hard_link(&temporary, path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Inventory
        } else {
            Error::Unavailable
        }
    })?;
    fs::remove_file(temporary).map_err(|_| Error::Unavailable)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Unavailable)
}

struct Originals {
    root: PathBuf,
    bytes: u64,
    count: usize,
}
impl OriginalSourceV1 for Originals {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        let path = self.root.join(hex::encode(digest));
        if !fs::symlink_metadata(&path)
            .map_err(|_| Error::Inventory)?
            .file_type()
            .is_file()
        {
            return Err(Error::Inventory);
        }
        Ok(Box::new(File::open(path).map_err(|_| Error::Inventory)?))
    }
}
impl OriginalSinkV1 for Originals {
    fn store(&mut self, identity: BlobV1, bytes: &[u8]) -> Result<(), Error> {
        if BlobV1::of(bytes) != identity {
            return Err(Error::Inventory);
        }
        let path = self.root.join(hex::encode(identity.sha256));
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if pinned_file(&path, bytes.len(), identity.sha256)? != bytes {
                    return Err(Error::Inventory);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let total = self
                    .bytes
                    .checked_add(identity.bytes)
                    .filter(|n| *n <= OUTPUT_BYTES)
                    .ok_or(Error::Inventory)?;
                // Durable hard-link publication never replaces an existing address.
                publish(&path, bytes)?;
                self.bytes = total;
                self.count += 1;
                if bytes.len() > 1 << 20 {
                    eprintln!(
                        "WALLET_SOURCE_ORIGINAL count={} stored_bytes={}",
                        self.count, self.bytes
                    );
                }
            }
            Err(_) => return Err(Error::Inventory),
        }
        Ok(())
    }
}

#[test]
#[ignore = "explicit complete wallet source construction from pinned native genesis"]
fn complete_wallet_catalog_from_pinned_genesis() {
    let output = PathBuf::from(
        std::env::var_os("KAGEMUSHA_WALLET_CATALOG_OUTPUT")
            .expect("fresh exclusive compiler output"),
    );
    let compiler_sources = pin("KAGEMUSHA_WALLET_SOURCE_SHA256");
    let fixture = pinned_genesis_fixture();
    let native = native_finality(&fixture);
    fs::create_dir(&output).expect("fresh output; no replacement or implicit resume");
    fs::create_dir(output.join("originals")).unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut reader = File::open(executable).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 16_384];
    loop {
        let length = reader.read(&mut buffer).unwrap();
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    publish(&output.join("binary.sha256"), &hash.finalize()).unwrap();
    publish(&output.join("source.sha256"), &compiler_sources).unwrap();
    publish(
        &output.join("input-pins.norito"),
        &norito::to_bytes(&BlobV1::of(&fixture)).unwrap(),
    )
    .unwrap();
    let scope = fixture_scope();
    publish(
        &output.join("source-policy.norito"),
        &norito::to_bytes(&(scope.provider(), scope.root().x, scope.root().y)).unwrap(),
    )
    .unwrap();
    let mut originals = Originals {
        root: output.join("originals"),
        bytes: 0,
        count: 0,
    };
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    eprintln!(
        "WALLET_SOURCE_PHASE all52_route_compilation_started signed=false wallet_grant=false"
    );
    let candidates = reuse::intake(&mut originals).unwrap();
    let mut compiler = OfflineCompilerV1::new(scope, &mut originals, config, OUTPUT_BYTES).unwrap();
    for (index, original) in candidates.into_iter().enumerate() {
        compiler.index_original(original).unwrap();
        eprintln!(
            "WALLET_SOURCE_REUSE indexed={} selected_sources=0 grant=false",
            index + 1
        );
    }
    let draft = compiler
        .wallet_pack(*native.initial_epoch().network_id.as_bytes())
        .unwrap();
    let bytes = draft.producer_inventory();
    let inventory: ProducerInventoryV1 =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    inventory.validate().unwrap();
    publish(&output.join("producer-inventory.norito"), bytes).unwrap();
    publish(
        &output.join("producer-inventory.sha256"),
        &BlobV1::of(&bytes).sha256,
    )
    .unwrap();
    assert_eq!(inventory.routes.len(), compiled_routes().len());
    eprintln!(
        "WALLET_SOURCE_CATALOG routes={} programs={} terminal_keys={} originals={} stored_bytes={} signed=false qualified_wallet=false actual_receipt_proof=false",
        inventory.routes.len(),
        inventory.operations.len(),
        inventory.terminals.len(),
        inventory.originals.len(),
        originals.bytes
    );
    let (_installed, _qualified) =
        acceptance::accept(&output, draft, &mut originals, &native, config);
}

#[test]
fn pinned_reader_rejects_substitution_trailing_oversized_and_absent_originals() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    assert!(bounded_file(&path, 3).is_err());
    fs::write(&path, [1, 2, 3]).unwrap();
    let pin = BlobV1::of(&[1, 2, 3]).sha256;
    assert_eq!(pinned_file(&path, 3, pin).unwrap(), [1, 2, 3]);
    assert!(pinned_file(&path, 2, pin).is_err());
    assert!(pinned_file(&path, 3, [0; 32]).is_err());
    assert!(pinned_file(&path, 3, [1; 32]).is_err());
    fs::write(&path, [1, 2, 3, 4]).unwrap();
    assert!(pinned_file(&path, 4, pin).is_err());
    assert!(bounded_file(directory.path(), 4).is_err());
}

#[test]
fn output_preserves_exact_content_and_refuses_changed_address_or_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let mut originals = Originals {
        root: directory.path().to_owned(),
        bytes: 0,
        count: 0,
    };
    let original = [1, 2, 3];
    let identity = BlobV1::of(&original);
    originals.store(identity, &original).unwrap();
    originals.store(identity, &original).unwrap();
    assert_eq!((originals.bytes, originals.count), (3, 1));
    assert!(originals.store(identity, &[3, 2, 1]).is_err());
    fs::write(
        directory.path().join(hex::encode(identity.sha256)),
        [3, 2, 1],
    )
    .unwrap();
    assert!(originals.store(identity, &original).is_err());
    assert_eq!(
        fs::read(directory.path().join(hex::encode(identity.sha256))).unwrap(),
        [3, 2, 1]
    );
}

#[test]
fn native_finality_binds_each_supplied_signed_genesis_without_repository_substitution() {
    use iroha_data_model::{
        block::consensus::SumeragiGenesisContextParameters, isi::Log, level::Level,
        sumeragi_finality::test_fixtures::NativeFinalityFixture,
    };

    let select = |original: &NativeFinalityFixture| {
        let input = norito::json::to_vec(&norito::json!({
            "chain_id": (original.chain_id()),
            "signed_genesis_wire_hex": (hex::encode(original.genesis().encode_wire().unwrap())),
        }))
        .unwrap();
        let selected = native_finality(&input);
        assert_eq!(
            selected.initial_epoch(),
            original.verifier().initial_epoch()
        );
        assert_eq!(selected.initial_epoch().network_id, original.network_id());
        assert_eq!(selected.chain_id(), original.chain_id());
        assert_eq!(selected.instance(), original.verifier().instance());
        selected
    };
    let alpha = NativeFinalityFixture::start_with_explicit_parameters("catalog-pinned-alpha");
    let beta = NativeFinalityFixture::start_with_explicit_parameters("catalog-pinned-beta");
    let selected_alpha = select(&alpha);
    let selected_beta = select(&beta);
    // The chain label is bound by the consensus instance, not by the fixture's
    // deterministic signed genesis. Distinct labels must not be mistaken for
    // distinct genesis-derived epoch contexts.
    assert_eq!(alpha.genesis().hash(), beta.genesis().hash());
    assert_eq!(
        selected_alpha.initial_epoch(),
        selected_beta.initial_epoch()
    );
    assert_ne!(selected_alpha.instance(), selected_beta.instance());

    // A different signed instruction changes the actual genesis root while the
    // selected chain label stays fixed. Both roots pass through the same parser
    // and must retain their own exact epoch, network and consensus instance.
    let distinct = NativeFinalityFixture::start_with_genesis_extension(
        alpha.chain_id(),
        SumeragiGenesisContextParameters::recommended().nexus_amx_context_hash,
        vec![Log::new(Level::INFO, "catalog distinct signed genesis".into()).into()],
    );
    let selected_distinct = select(&distinct);
    assert_ne!(alpha.genesis().hash(), distinct.genesis().hash());
    assert_ne!(
        selected_alpha.initial_epoch(),
        selected_distinct.initial_epoch()
    );
    assert_ne!(selected_alpha.instance(), selected_distinct.instance());
}

#[path = "full_catalog/diagnostic.rs"]
mod diagnostic;
