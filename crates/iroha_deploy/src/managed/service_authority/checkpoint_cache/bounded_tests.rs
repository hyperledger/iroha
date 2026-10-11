//! Genuine paid checkpoint cuts exercise bounded FIFO reuse and fresh enclosing admission.

use super::{
    tests::{assert_entry, assert_refused, attempts},
    *,
};
use crate::managed::{
    LocalnetPorts,
    native_operation::{
        checkpoint_bytes, decode_checkpoint,
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, quote_instructions},
        },
    },
    service_authority::NetworkPurpose,
};
use iroha_data_model::isi::{InstructionBox, Log};
use iroha_fs::PublishMode;
use norito::core::DecodeBudgetContext;

#[test]
fn retained_import_envelope_accounts_separate_graphs_and_native_merkle_layout() {
    // Exercise the real serialized-leaf decoder across empty, power-of-two and padded
    // geometries; the independently reconstructed node array is not a Norito charge.
    for leaves in [0usize, 1, 2, 3, 31, 32, 33, 1025] {
        let tree: iroha_crypto::MerkleTree<ExecutionOutputV1> = (0..leaves)
            .map(|index| {
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    index.to_le_bytes(),
                ))
            })
            .collect();
        let wire = norito::encode_canonical(&tree).unwrap();
        let decoded: iroha_crypto::MerkleTree<ExecutionOutputV1> =
            norito::decode_canonical(&wire).unwrap();
        assert_eq!(decoded, tree);
        assert!(
            decoded.allocated_bytes()
                <= 4 * leaves * size_of::<Option<iroha_crypto::HashOf<ExecutionOutputV1>>>()
        );
        assert!(wire.len() / iroha_crypto::Hash::LENGTH >= leaves);
        assert!(retained_import_envelope(wire.len()).unwrap() >= decoded.allocated_bytes());
    }
    assert!(
        size_of::<Option<iroha_crypto::HashOf<ExecutionOutputV1>>>() > iroha_crypto::Hash::LENGTH
    );
    assert!(retained_import_envelope(MAX_CHECKPOINT_BYTES + 1).is_none());
    let mut empty = Entries::default();
    let ceiling = retained_import_envelope(MAX_CHECKPOINT_BYTES).unwrap();
    assert!(empty.make_room(MAX_CHECKPOINT_BYTES, ceiling));
    assert!(!empty.make_room(MAX_CHECKPOINT_BYTES + 1, ceiling));
    assert!(!empty.make_room(0, ceiling + 1));
    assert!(empty.is_empty());
}

#[test]
fn three_paid_originals_reuse_fifo_without_caching_source_or_outer_admission() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "checkpoint-three-originals",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let mut originals = Vec::new();
    let mut images = Vec::new();
    let mut transactions = Vec::new();
    for index in 0..4 {
        let transaction = quote_instructions(
            &native,
            &authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                format!("fixed FIFO paid original {index}"),
            ))],
        );
        assert_eq!(native.chain.commit(vec![transaction.clone()]), vec![true]);
        let original = native.observe(&authority);
        assert_eq!(original.checkpoint().height(), index + 2);
        let bytes = checkpoint_bytes(&original).unwrap();
        originals.push(original);
        images.push(bytes);
        transactions.push(transaction);
    }
    drop(ports);
    let unavailable = UnavailablePeers::start(&prepared);
    let mut imported = Vec::new();
    for index in 0..3 {
        let original = authority.decode_checkpoint(&images[index]).unwrap();
        assert_eq!(original, originals[index]);
        imported.push(original);
    }
    assert_eq!(attempts(&authority), 3);
    for turn in 0..12 {
        let index = turn % 3;
        let hit = authority.decode_checkpoint(&images[index]).unwrap();
        assert_eq!(hit, originals[index]);
        assert!(std::ptr::eq(hit.checkpoint(), imported[index].checkpoint()));
        assert!(std::ptr::eq(
            hit.verified_tip_ref().unwrap(),
            imported[index].verified_tip_ref().unwrap(),
        ));
        assert_entry(&authority, &images[index]);
    }
    assert_eq!(attempts(&authority), 3);
    let fourth = authority.decode_checkpoint(&images[3]).unwrap();
    assert_eq!(fourth, originals[3]);
    assert_eq!(attempts(&authority), 4);
    {
        let selected = authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap();
        assert_eq!(selected.len, SLOTS);
        assert!(
            selected
                .slots
                .iter()
                .flatten()
                .all(|entry| entry.bytes != images[0])
        );
        for offset in 0..SLOTS {
            assert_eq!(
                selected.slots[(selected.first + offset) % SLOTS]
                    .as_ref()
                    .unwrap()
                    .bytes,
                images[offset + 1]
            );
        }
    }
    for image in &images[1..] {
        authority.decode_checkpoint(image).unwrap();
    }
    assert_eq!(attempts(&authority), 4);
    let first_again = authority.decode_checkpoint(&images[0]).unwrap();
    assert_eq!(first_again, originals[0]);
    assert_eq!(attempts(&authority), 5);
    assert!(!std::ptr::eq(
        first_again.checkpoint(),
        imported[0].checkpoint()
    ));
    let mut malformed = images[0].clone();
    malformed.push(0);
    assert_refused(&authority, &malformed, 2);
    assert_refused(&authority, &malformed, 1);
    let mut validation = EpochValidationScope::new();
    let mut imports = CheckpointImports::new(&authority, Some(&mut validation));
    for image in &images[..3] {
        imports.decode(image).unwrap();
    }
    let original_error = decode_checkpoint(
        &malformed,
        authority.config.network_id,
        authority.config.chain.as_str(),
    )
    .unwrap_err()
    .to_string();
    let before = attempts(&authority);
    assert_eq!(
        imports.decode(&malformed).unwrap_err().to_string(),
        original_error
    );
    assert_eq!(attempts(&authority), before + 2);
    assert!(
        authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap()
            .is_empty()
    );
    assert_eq!(imports.decode(&images[0]).unwrap(), originals[0]);
    drop(imports);
    drop(validation);

    // All three warm owners are discarded before the original cumulative admission. The
    // cap-one refusal is real; exact positive success uses the original measured charge.
    fn limits(allocation: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            allocation,
            64,
        )
    }
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let expected = baseline
        .with(|| {
            decode_checkpoint(
                &images[0],
                authority.config.network_id,
                authority.config.chain.as_str(),
            )
        })
        .unwrap();
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 1 && charge < 64 * 1024 * 1024);
    for cap in [0, 1, usize::try_from(charge).unwrap()] {
        for image in &images[..3] {
            authority.decode_checkpoint(image).unwrap();
        }
        let expected_budget = DecodeBudgetContext::new(limits(cap));
        let expected_result = expected_budget.with(|| {
            decode_checkpoint(
                &images[0],
                authority.config.network_id,
                authority.config.chain.as_str(),
            )
        });
        let actual_budget = DecodeBudgetContext::new(limits(cap));
        let before = attempts(&authority);
        let actual_result = actual_budget.with(|| authority.decode_checkpoint(&images[0]));
        assert_eq!(attempts(&authority), before + 1);
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
        match (actual_result, expected_result) {
            (Ok(actual), Ok(original)) => {
                assert_eq!(actual, original);
                assert_eq!(actual, expected);
                assert_eq!(actual_budget.consumed_allocated_bytes(), charge);
            }
            (Err(actual), Err(original)) => assert_eq!(actual.to_string(), original.to_string()),
            other => panic!("original active admission must match: {other:?}"),
        }
        assert!(
            authority
                .effective_checkpoint_cache()
                .entry
                .try_lock()
                .unwrap()
                .is_empty()
        );
    }
    let retry = authority.decode_checkpoint(&images[0]).unwrap();
    assert_eq!(retry, originals[0]);
    authority
        .directory
        .write_atomic("carrier.nrt", &images[0], PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        authority
            .retained_finality(&authority.directory, &transactions[0])
            .unwrap()
            .unwrap()
            .height,
        2
    );
    std::fs::remove_file(authority.directory.path().join("carrier.nrt")).unwrap();
    assert!(
        authority
            .retained_finality(&authority.directory, &transactions[0])
            .unwrap()
            .is_none()
    );
    authority
        .directory
        .write_atomic("carrier.nrt", &malformed, PublishMode::CreateNew)
        .unwrap();
    assert!(
        authority
            .retained_finality(&authority.directory, &transactions[0])
            .is_err()
    );
    authority
        .directory
        .write_atomic("carrier.nrt", &images[0], PublishMode::Replace)
        .unwrap();
    assert_eq!(
        authority
            .retained_finality(&authority.directory, &transactions[0])
            .unwrap()
            .unwrap()
            .height,
        2
    );
    // A maximum incoming envelope evicts the actual small memo owners before decode;
    // escaped caller Arcs remain caller-owned and cannot be claimed as released memory.
    {
        let mut selected = authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap();
        assert!(!selected.is_empty());
        let ceiling = retained_import_envelope(MAX_CHECKPOINT_BYTES).unwrap();
        assert!(selected.make_room(MAX_CHECKPOINT_BYTES, ceiling));
        assert!(selected.is_empty());
    }
    assert_eq!(checkpoint_bytes(&retry).unwrap(), images[0]);
    assert!(unavailable.requests.lock().unwrap().is_empty());
    assert_eq!(native.chain.height(), 5);
}
