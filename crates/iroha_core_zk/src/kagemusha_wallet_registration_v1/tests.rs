//! Native certificate transport tests; success outputs are synthetic, not executed ledger state.
//! Actual Core registration execution is qualified separately through the same Model extractor.
use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId},
    block::{BlockSignatures, builder::BlockBuilder},
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    kagemusha::{
        KagemushaDevicePublicKeyV1, KagemushaWalletAssetScopeV1,
        kagemusha_wallet_provider_contract_v1,
    },
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use std::{fs, io::Write as _};
struct Fixture {
    _temp: tempfile::TempDir,
    source: RegistrationSourceV1,
    genesis: SumeragiFinalityVerifier,
    scheme: KagemushaWalletSchemeV1,
    asset: KagemushaWalletAssetScopeV1,
    entries: Vec<RegistrationEntryV1>,
    committed: CommittedTransaction,
}
fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
    norito::encode_canonical(value).unwrap()
}
fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
fn put(root: &str, bytes: &[u8]) -> BlobV1 {
    let blob = BlobV1::of(bytes);
    let directory = PrivateDirectory::open_exact(root).unwrap();
    let name = hex::encode(blob.sha256);
    if Path::new(root).join(&name).exists() {
        return blob;
    }
    let mut writer = directory
        .create_retained_private(name, REGISTRATION_PROOF_MAX_BYTES_V1)
        .unwrap();
    writer.write_all(bytes).unwrap();
    writer.seal_read_only().unwrap();
    blob
}
fn install_entries(f: &mut Fixture) {
    let mut next = None;
    for entry in f.entries.iter_mut().rev() {
        entry.next = next;
        next = Some(put(&f.source.originals_root, &encode(entry)));
    }
    f.source.inventory.first = next.unwrap();
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = temp.path().canonicalize().unwrap().join("originals");
    private_dir(&root);
    let mut native = NativeFinalityFixture::start("universal-registration-source");
    let genesis = native.verifier();
    let mut proofs = vec![native.genesis_proof().clone()];
    let log = native.block_with_submitted_work(native.next_header());
    proofs.push(native.certify(log));
    let p256 = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *native.network_id().as_bytes(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            p256.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let asset = KagemushaWalletAssetScopeV1 {
        version: 1,
        asset: AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .unwrap(),
        asset_incarnation: *Hash::new(b"registered source incarnation").as_ref(),
        scale: 2,
    };
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let reserve = AccountId::new(key.public_key().clone());
    let instruction = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Register {
            scheme: scheme.to_canonical_bytes().unwrap(),
            asset: encode(&asset),
            reserve: reserve.clone(),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let header = native.next_header();
    let mut tx = TransactionBuilder::new(
        native.network_id(),
        reserve,
        FeePaymentIntent::authority(vec![], None),
    );
    tx.set_creation_time(std::time::Duration::from_millis(
        header.creation_time_ms - 1,
    ));
    let tx = tx.with_instructions([instruction]).sign(key.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(tx);
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(vec![])]);
    let proof = native.certify(block);
    proofs.push(proof.clone());
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    let block = verified.block();
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (output_index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    };
    let path = root.to_str().unwrap().to_owned();
    let entries = proofs
        .iter()
        .enumerate()
        .map(|(index, proof)| RegistrationEntryV1 {
            version: 1,
            ordinal: index as u64 + 1,
            proof: put(&path, &encode(proof)),
            next: None,
        })
        .collect();
    let receipt = put(&path, &encode(&committed));
    let mut result = Fixture {
        _temp: temp,
        genesis,
        scheme,
        asset: asset.clone(),
        entries,
        committed,
        source: RegistrationSourceV1 {
            version: 1,
            originals_root: path,
            inventory: RegistrationInventoryV1 {
                version: 1,
                asset_digest: asset.asset_digest(),
                instruction_index: 0,
                committed: receipt,
                first: receipt,
                proof_count: 3,
            },
        },
    };
    install_entries(&mut result);
    result
}
fn run(f: &Fixture) -> Result<FinalizedKagemushaWalletRegistrationV1, RegistrationErrorV1> {
    verify_registration_source_v1(&f.source, &f.genesis, &f.scheme, || false)
}
#[test]
fn genuine_native_prefix_selects_exact_registered_asset_and_codec_bounds() {
    let f = fixture();
    let raw = f.source.encode_canonical().unwrap();
    assert_eq!(
        RegistrationSourceV1::decode_canonical(&raw).unwrap(),
        f.source
    );
    let mut trailing = raw;
    trailing.push(0);
    assert!(RegistrationSourceV1::decode_canonical(&trailing).is_err());
    assert!(
        RegistrationSourceV1::decode_canonical(&vec![0; REGISTRATION_SOURCE_MAX_BYTES_V1 + 1])
            .is_err()
    );
    let selected = run(&f).unwrap();
    assert_eq!(selected.scheme(), &f.scheme);
    assert_eq!(selected.asset(), &f.asset);
    assert_eq!(selected.height(), 3);
    assert_eq!(selected.block_hash(), *f.committed.block_hash().as_ref());
}
#[test]
fn inventory_count_terminal_order_asset_and_receipt_substitutions_refuse() {
    for variant in 0..7 {
        let mut f = fixture();
        match variant {
            0 => f.source.inventory.proof_count = 2,
            1 => f.source.inventory.proof_count = 4,
            2 => {
                f.entries[1].ordinal = 3;
                install_entries(&mut f);
            }
            3 => {
                f.entries[2].next = Some(f.source.inventory.first);
                let changed = put(&f.source.originals_root, &encode(&f.entries[2]));
                f.entries[1].next = Some(changed);
                let changed = put(&f.source.originals_root, &encode(&f.entries[1]));
                f.entries[0].next = Some(changed);
                f.source.inventory.first = put(&f.source.originals_root, &encode(&f.entries[0]));
            }
            4 => f.source.inventory.asset_digest[0] ^= 1,
            5 => f.source.inventory.instruction_index = 1,
            _ => {
                f.committed.block_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"wrong committed block"));
                f.source.inventory.committed = put(&f.source.originals_root, &encode(&f.committed));
            }
        }
        assert!(run(&f).is_err(), "variant={variant}");
    }
}
#[test]
fn missing_first_or_middle_original_is_distinct_from_truncated_or_substituted() {
    for index in [0, 1] {
        let f = fixture();
        fs::remove_file(
            Path::new(&f.source.originals_root).join(hex::encode(f.entries[index].proof.sha256)),
        )
        .unwrap();
        assert!(matches!(run(&f), Err(RegistrationErrorV1::Absent)));
    }
    for truncate in [false, true] {
        let f = fixture();
        let blob = f.entries[1].proof;
        let path = Path::new(&f.source.originals_root).join(hex::encode(blob.sha256));
        fs::remove_file(&path).unwrap();
        let mut bytes = vec![0; usize::try_from(blob.bytes).unwrap()];
        if truncate {
            bytes.pop();
        }
        let directory = PrivateDirectory::open_exact(&f.source.originals_root).unwrap();
        let mut writer = directory
            .create_retained_private(hex::encode(blob.sha256), REGISTRATION_PROOF_MAX_BYTES_V1)
            .unwrap();
        writer.write_all(&bytes).unwrap();
        writer.seal_read_only().unwrap();
        assert!(matches!(run(&f), Err(RegistrationErrorV1::Custody(_))));
    }
}
#[test]
fn foreign_native_genesis_is_not_a_content_address_authority() {
    let mut f = fixture();
    // Changing only the fixture's chain label leaves its genesis bytes identical. Include
    // explicit native parameters to construct a genuinely different signed genesis original.
    let foreign =
        NativeFinalityFixture::start_with_explicit_parameters("foreign-registration-chain");
    assert_ne!(f.genesis.initial_epoch().network_id, foreign.network_id());
    f.entries[0].proof = put(&f.source.originals_root, &encode(foreign.genesis_proof()));
    install_entries(&mut f);
    assert!(matches!(run(&f), Err(RegistrationErrorV1::Finality(_))));
}
#[test]
fn same_genesis_foreign_chain_certificate_is_not_selected_instance_authority() {
    let mut f = fixture();
    let mut foreign = NativeFinalityFixture::start("foreign-registration-chain");
    // H1 has no chain label. The H2 certificate carries the independently selected instance.
    assert_eq!(f.genesis.initial_epoch().network_id, foreign.network_id());
    assert_ne!(f.genesis.instance(), foreign.verifier().instance());
    assert_eq!(
        f.entries[0].proof,
        BlobV1::of(&encode(foreign.genesis_proof()))
    );
    let block = foreign.block_with_submitted_work(foreign.next_header());
    f.entries[1].proof = put(&f.source.originals_root, &encode(&foreign.certify(block)));
    install_entries(&mut f);
    let result = run(&f);
    assert!(
        matches!(result, Err(RegistrationErrorV1::Finality(_))),
        "{result:?}"
    );
}
#[test]
fn cancellation_at_multiple_progress_points_emits_no_capability_and_allows_fresh_retry() {
    let f = fixture();
    for stop in [1, 3, 6, 9] {
        let mut calls = 0;
        let result = verify_registration_source_v1(&f.source, &f.genesis, &f.scheme, || {
            calls += 1;
            calls == stop
        });
        assert!(
            matches!(result, Err(RegistrationErrorV1::Cancelled)),
            "stop={stop}, calls={calls}"
        );
        assert_eq!(run(&f).unwrap().asset(), &f.asset);
    }
}
#[test]
fn retained_directory_replacement_fails_even_with_identical_transport_names() {
    let f = fixture();
    let old = Path::new(&f.source.originals_root);
    let moved = old.with_file_name("retained-old");
    let directory = PrivateDirectory::open_exact(old).unwrap();
    let mut changed = false;
    let result = read_original(
        &directory,
        f.source.inventory.first,
        REGISTRATION_ENTRY_MAX_BYTES_V1,
        &mut || {
            if !changed {
                fs::rename(old, &moved).unwrap();
                private_dir(old);
                changed = true;
            }
            false
        },
    );
    assert!(matches!(result, Err(RegistrationErrorV1::Custody(_))));
}
#[test]
fn native_io_classification_never_turns_lost_retained_custody_into_initial_absence() {
    assert!(matches!(
        storage(io::ErrorKind::NotFound.into()),
        RegistrationErrorV1::Custody(_)
    ));
    assert!(matches!(
        storage(io::Error::other("retained identity changed")),
        RegistrationErrorV1::Custody(_)
    ));
    #[cfg(unix)]
    {
        assert!(matches!(
            storage(io::Error::from_raw_os_error(
                rustix::io::Errno::IO.raw_os_error()
            )),
            RegistrationErrorV1::Unavailable(_)
        ));
        for errno in [rustix::io::Errno::LOOP, rustix::io::Errno::NOTDIR] {
            assert!(matches!(
                storage(errno.into()),
                RegistrationErrorV1::Custody(_)
            ));
        }
    }
}

#[cfg(unix)]
#[test]
fn root_and_selected_child_symlinks_are_custody_failures() {
    use std::os::unix::fs::symlink;
    let mut f = fixture();
    let selected = f.source.originals_root.clone();
    let alias = f._temp.path().canonicalize().unwrap().join("alias");
    symlink(&selected, &alias).unwrap();
    f.source.originals_root = alias.to_str().unwrap().to_owned();
    assert!(matches!(run(&f), Err(RegistrationErrorV1::Custody(_))));
    f.source.originals_root = selected;
    let name =
        Path::new(&f.source.originals_root).join(hex::encode(f.source.inventory.first.sha256));
    let original = f
        ._temp
        .path()
        .canonicalize()
        .unwrap()
        .join("original-entry");
    fs::rename(&name, &original).unwrap();
    symlink(original, name).unwrap();
    assert!(matches!(run(&f), Err(RegistrationErrorV1::Custody(_))));
}

#[test]
fn checkpoint_read_preserves_allocation_refusal_and_allows_unrestricted_retry() {
    let native = NativeFinalityFixture::start("registration-checkpoint-allocation");
    let genesis = native.verifier();
    let checkpoint = genesis.export_checkpoint(native.genesis_proof()).unwrap();
    let original = checkpoint.encode_canonical().unwrap();
    let restore = || -> Result<SumeragiFinalityVerifier, RegistrationErrorV1> {
        Ok(SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &native.network_id(),
            genesis.chain_id(),
        )?)
    };
    let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let error = norito::with_decode_limits_scope(no_allocation, restore).unwrap_err();
    let RegistrationErrorV1::Finality(FinalityReadError::DecodeResource(cause)) = error else {
        panic!("checkpoint resource refusal was reclassified: {error:?}");
    };
    assert_eq!(
        cause.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(matches!(
        cause.into_error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 })
            if attempted > 0
    ));
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
    assert_eq!(
        restore()
            .unwrap()
            .export_checkpoint(native.genesis_proof())
            .unwrap(),
        checkpoint
    );
}

#[test]
fn completed_finality_verdict_remains_distinct_from_unfinished_reads() {
    let cause = FinalityError("foreign registration network".into());
    let error = RegistrationErrorV1::from(cause.clone());
    assert!(matches!(
        error,
        RegistrationErrorV1::Finality(FinalityReadError::Invalid(actual)) if actual == cause
    ));
}

#[test]
fn publisher_authenticates_lazy_readers_and_emits_deterministic_inventory() {
    let f = fixture();
    let parent = PrivateDirectory::open_exact(f._temp.path().canonicalize().unwrap()).unwrap();
    let selection = RegistrationSelectionV1 {
        genesis: &f.genesis,
        scheme: &f.scheme,
        asset_digest: f.asset.asset_digest(),
        instruction_index: 0,
    };
    let publish = |name: &str| {
        publish_registration_source_v1(
            &parent,
            name,
            selection,
            std::io::Cursor::new(encode(&f.committed)),
            f.entries.iter().map(|entry| {
                fs::File::open(
                    Path::new(&f.source.originals_root).join(hex::encode(entry.proof.sha256)),
                )
            }),
            || false,
        )
    };
    let (first, registration) = publish("one").unwrap();
    let (second, _) = publish("two").unwrap();
    assert_eq!(registration.asset(), &f.asset);
    assert_eq!(first.inventory, second.inventory);
    assert_eq!(first.inventory, f.source.inventory);
    assert_ne!(first.originals_root, second.originals_root);
    let original = fs::read(parent.path().join("one/registration-source.norito")).unwrap();
    assert_eq!(
        RegistrationSourceV1::decode_canonical(&original).unwrap(),
        first
    );
    assert!(publish("one").is_err());
    assert_eq!(
        fs::read(parent.path().join("one/registration-source.norito")).unwrap(),
        original
    );
}
struct Declared<I> {
    inner: I,
    count: usize,
}
impl<I: Iterator> Iterator for Declared<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}
impl<I: DoubleEndedIterator> DoubleEndedIterator for Declared<I> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}
impl<I: ExactSizeIterator> ExactSizeIterator for Declared<I> {
    fn len(&self) -> usize {
        self.count
    }
}
#[test]
fn publisher_refuses_false_counts_foreign_registration_and_cancel_without_manifest() {
    let f = fixture();
    let parent = PrivateDirectory::open_exact(f._temp.path().canonicalize().unwrap()).unwrap();
    for (name, count, asset, cancel) in [
        ("short", 4, f.asset.asset_digest(), false),
        ("excess", 2, f.asset.asset_digest(), false),
        ("foreign", 3, [42; 32], false),
        ("cancel", 3, f.asset.asset_digest(), true),
    ] {
        let selection = RegistrationSelectionV1 {
            genesis: &f.genesis,
            scheme: &f.scheme,
            asset_digest: asset,
            instruction_index: 0,
        };
        let readers = Declared {
            count,
            inner: f.entries.iter().map(|entry| {
                fs::File::open(
                    Path::new(&f.source.originals_root).join(hex::encode(entry.proof.sha256)),
                )
            }),
        };
        let mut calls = 0;
        assert!(
            publish_registration_source_v1(
                &parent,
                name,
                selection,
                std::io::Cursor::new(encode(&f.committed)),
                readers,
                || {
                    calls += 1;
                    cancel && calls == 4
                }
            )
            .is_err()
        );
        assert!(parent.path().join(name).is_dir());
        assert!(
            !parent
                .path()
                .join(name)
                .join("registration-source.norito")
                .exists()
        );
    }
}
