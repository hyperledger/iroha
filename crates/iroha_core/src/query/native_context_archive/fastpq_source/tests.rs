//! Genuine Worker publication, restart, complete-source tamper and finite-custody controls.

use super::*;
use crate::{
    state::World,
    sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
use std::sync::Arc;

fn fixture() -> (CertifiedTestChain, AssetId) {
    let domain_id = DomainId::try_new("fastpq-durable", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "principal".parse().unwrap());
    let definition = AssetDefinition::new(
        definition_id.clone(),
        "Durable source principal",
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let asset = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let world = World::with_assets(
        [domain],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [definition],
        [
            Asset::new(asset.clone(), Quantity::from(100_u32)),
            Asset::new(
                AssetId::new(definition_id, BOB_ID.clone()),
                Quantity::from(10_u32),
            ),
        ],
        [],
    );
    (
        CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap(),
        asset,
    )
}
fn transfer(chain: &mut CertifiedTestChain, asset: &AssetId, time: u64) {
    let transaction = chain.sign(
        &ALICE_KEYPAIR,
        [Transfer::asset_quantity(asset.clone(), 3_u32, BOB_ID.clone()).into()],
        time - 1,
    );
    assert_eq!(chain.commit_at(time, vec![transaction]), [true]);
}
fn limits() -> SourceReadLimits {
    SourceReadLimits {
        max_entries: 64,
        max_statements: 64,
        max_effects_per_statement: 128,
    }
}
fn reader(
    chain: &CertifiedTestChain,
    height: u64,
    pool: &AllocationBudget,
) -> NativeFastpqSourceRead {
    let view = chain.state().view();
    let native = CertifiedChain::new(&view)
        .unwrap()
        .authenticated_execution(height)
        .unwrap();
    NativeFastpqSourceRead::new(Arc::clone(chain.kura()), native, pool.clone(), limits())
}
fn complete(
    read: &mut NativeFastpqSourceRead,
) -> Result<AuthenticatedRecoveredFastpqSource, SourceReadError> {
    for _ in 0..64 {
        if let Some(source) = read.poll()? {
            return Ok(source);
        }
    }
    panic!("bounded fixture source did not complete");
}
fn source_file(chain: &CertifiedTestChain, height: u64) -> File {
    let root = chain.kura().native_context_archive_root().unwrap();
    let directory =
        open_archive_directory_named(&root, Kura::fastpq_source_namespace(), false).unwrap();
    open_named_record(
        &directory,
        &RecordName::fastpq(height, chain.committed(height).block_hash(), false),
    )
    .unwrap()
}
#[cfg(unix)]
fn rewrite_source(chain: &CertifiedTestChain, height: u64, bytes: &[u8]) {
    use rustix::fs::{Mode, OFlags};
    let root = chain.kura().native_context_archive_root().unwrap();
    let directory =
        open_archive_directory_named(&root, Kura::fastpq_source_namespace(), false).unwrap();
    let name = RecordName::fastpq(height, chain.committed(height).block_hash(), false);
    let mut file = File::from(
        rustix::fs::openat(
            &directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap(),
    );
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn actual_worker_persists_complete_tape_and_recovers_historical_source_after_next_payment() {
    let (mut chain, asset) = fixture();
    transfer(&mut chain, &asset, 2_000);
    transfer(&mut chain, &asset, 3_000);
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut read = reader(&chain, 2, &pool);
    let source = complete(&mut read).unwrap();
    assert_eq!(source.native().committed().height(), 2);
    assert_eq!(
        source.native().committed().block_hash(),
        chain.committed(2).block_hash()
    );
    assert_eq!(source.manifest().statement_count, 1);
    assert_eq!(source.leaves().len(), 1);
    assert_eq!(source.entry(0).unwrap().0.context.source.height, 2);
    assert!(source.pool().same_pool(&pool));
    assert!(read.poll().is_err(), "completed opaque source moves once");
    drop(read);
    assert_eq!(
        pool.reserved_bytes(),
        match &source.contents {
            SourceContents::Complete(funded) => funded.allocation_bytes().unwrap(),
            SourceContents::Empty(_) => panic!("actual paid source is nonempty"),
        },
        "every retained array, controller and Quantity retains its exact original charge"
    );
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_certified_final_tip_replay_recreates_tapes_without_successor() {
    let (mut original, asset) = fixture();
    transfer(&mut original, &asset, 2_000);
    let (mut restarted, _) = fixture();
    assert_eq!(original.network_id(), restarted.network_id());
    restarted.replay_from(&original).unwrap();
    let hash = original.committed(2).block_hash();
    drop(original);
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let source = complete(&mut reader(&restarted, 2, &pool)).unwrap();
    assert_eq!(source.native().committed().block_hash(), hash);
    assert_eq!(source.entry(0).unwrap().0.context.source.height, 2);
    assert_eq!(
        restarted.height(),
        2,
        "proof recovery cannot require another payment"
    );
}

#[test]
fn complete_source_rejects_tape_inventory_context_and_effect_tampering() {
    let (mut chain, asset) = fixture();
    transfer(&mut chain, &asset, 2_000);
    let mut original = Vec::new();
    source_file(&chain, 2).read_to_end(&mut original).unwrap();
    for mutation in 0..5 {
        let mut record: SourceRecord = norito::decode_canonical(&original).unwrap();
        match mutation {
            0 => record.tapes.clear(),
            1 => record.entries.clear(),
            2 => record.tapes[0].context.source.height += 1,
            3 => record.tapes[0].effects[0].ordinal += 1,
            _ => {
                record.carrier =
                    HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"another carrier"))
            }
        }
        rewrite_source(&chain, 2, &norito::to_bytes(&record).unwrap());
        let pool = AllocationBudget::new(16 * 1024 * 1024);
        let mut read = reader(&chain, 2, &pool);
        assert!(
            complete(&mut read).is_err(),
            "tampered transport must never become opaque source: {mutation}"
        );
        assert!(
            complete(&mut read).is_err(),
            "failed source cannot skip or advance after retry"
        );
        drop(read);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    rewrite_source(&chain, 2, &original);
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    complete(&mut reader(&chain, 2, &pool)).unwrap();
}

#[test]
fn source_capacity_refusal_retains_same_context_descriptor_and_resumes_without_reselection() {
    let (mut chain, asset) = fixture();
    transfer(&mut chain, &asset, 2_000);
    let pool = AllocationBudget::new(0);
    let mut read = reader(&chain, 2, &pool);
    let cause = match read.poll() {
        Err(cause) => cause,
        Ok(_) => panic!("zero pool must refuse"),
    };
    assert!(matches!(
        cause,
        SourceReadError::Archive(NativeContextArchiveError::Allocation(_))
    ));
    assert!(read.context_read.as_ref().unwrap().has_pinned_source());
    pool.set_limit_bytes(16 * 1024 * 1024);
    let source = complete(&mut read).unwrap();
    assert_eq!(source.native().committed().height(), 2);
    drop((source, read));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn concrete_source_backing_refusal_keeps_original_bytes_and_cannot_be_relabelled_as_invalidity() {
    let (mut chain, asset) = fixture();
    transfer(&mut chain, &asset, 2_000);
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut read = reader(&chain, 2, &pool);
    while read.tape_bytes.is_none() {
        assert!(read.poll().unwrap().is_none());
    }
    let original_pointer = read.tape_bytes.as_ref().unwrap().as_slice().as_ptr();
    let used = pool.reserved_bytes();
    let blocker = pool.try_reserve_bytes(16 * 1024 * 1024 - used).unwrap();
    let cause = match read.poll() {
        Err(cause) => cause,
        Ok(_) => panic!("graph admission must refuse"),
    };
    assert!(matches!(
        cause,
        SourceReadError::Buffer(ChargedBufferError::Admission(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert!(
        read.destination.is_some(),
        "retain the exact original partial destination"
    );
    assert!(read.decoded.is_none());
    assert_eq!(
        read.tape_bytes.as_ref().unwrap().as_slice().as_ptr(),
        original_pointer
    );
    drop(blocker);
    let source = complete(&mut read).unwrap();
    drop((source, read));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn absent_original_tape_stays_unresolved_until_the_same_record_is_available() {
    use rustix::fs::{AtFlags, Mode, OFlags};
    let (mut chain, asset) = fixture();
    transfer(&mut chain, &asset, 2_000);
    let root = chain.kura().native_context_archive_root().unwrap();
    let directory =
        open_archive_directory_named(&root, Kura::fastpq_source_namespace(), false).unwrap();
    let name = RecordName::fastpq(2, chain.committed(2).block_hash(), false);
    let mut original = Vec::new();
    source_file(&chain, 2).read_to_end(&mut original).unwrap();
    rustix::fs::unlinkat(&directory, name.as_str(), AtFlags::empty()).unwrap();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut read = reader(&chain, 2, &pool);
    for _ in 0..2 {
        let cause = match complete(&mut read) {
            Err(cause) => cause,
            Ok(_) => panic!("absent tape cannot become completion or durable cursor advance"),
        };
        assert!(
            matches!(cause, SourceReadError::Archive(NativeContextArchiveError::Io(ref error))
            if error.kind() == io::ErrorKind::NotFound)
        );
        assert_eq!(read.native.as_ref().unwrap().committed().height(), 2);
        assert!(
            read.manifest.is_some(),
            "the authenticated complete D7 remains retained"
        );
        assert!(read.decoded.is_none());
    }
    let mut file = File::from(
        rustix::fs::openat(
            &directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .unwrap(),
    );
    file.write_all(&original).unwrap();
    file.sync_all().unwrap();
    directory.sync_all().unwrap();
    let source = complete(&mut read).unwrap();
    assert_eq!(source.native().committed().height(), 2);
    assert_eq!(
        chain.height(),
        2,
        "source recovery must not synthesize a successor"
    );
    drop((source, read));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
#[cfg(unix)]
fn optional_artifact_store_refusal_cannot_strand_actual_paid_native_publication() {
    let (mut chain, asset) = fixture();
    // Occupy one canonical source file beyond its local artifact object cap. The
    // existing aggregate inventory owner must refuse further optional storage.
    // Native context storage and the actual signed payment remain unchanged.
    let root = chain.kura().native_context_archive_root().unwrap();
    let directory =
        open_archive_directory_named(&root, Kura::fastpq_source_namespace(), false).unwrap();
    let name = RecordName::fastpq(1, chain.committed(1).block_hash(), false);
    let file = open_named_record(&directory, &name).unwrap();
    // Reopen the existing genuine file for the explicit local-disk fault injection.
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let writable = File::from(
            rustix::fs::openat(
                &directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
        );
        writable
            .set_len(chain.kura().fastpq_object_max_bytes().get() as u64 + 1)
            .unwrap();
        writable.sync_all().unwrap();
    }
    drop(file);
    assert!(
        chain
            .kura()
            .validate_fastpq_artifact_inventory_on_startup()
            .is_err()
    );
    transfer(&mut chain, &asset, 2_000);
    assert_eq!(
        chain.state().view().height(),
        2,
        "optional proof transport did not strand publication"
    );
    let view = chain.state().view();
    let native = CertifiedChain::new(&view)
        .unwrap()
        .authenticated_execution(2)
        .unwrap();
    assert_eq!(native.committed().result(), chain.committed(2).result());
    assert_eq!(native.block().as_ref().failed_outputs().count(), 0);
    assert!(
        source_file_if_present(&chain, 2).is_err(),
        "no fake source or cursor was emitted"
    );
}

fn source_file_if_present(chain: &CertifiedTestChain, height: u64) -> io::Result<File> {
    let root = chain
        .kura()
        .native_context_archive_root()
        .map_err(io::Error::other)?;
    let directory = open_archive_directory_named(&root, Kura::fastpq_source_namespace(), false)?;
    open_named_record(
        &directory,
        &RecordName::fastpq(height, chain.committed(height).block_hash(), false),
    )
}

#[test]
#[cfg(unix)]
fn actual_empty_genesis_manifest_advances_without_optional_tape() {
    use rustix::fs::AtFlags;
    let (mut chain, asset) = fixture();
    transfer(&mut chain, &asset, 2_000);
    let root = chain.kura().native_context_archive_root().unwrap();
    let directory =
        open_archive_directory_named(&root, Kura::fastpq_source_namespace(), false).unwrap();
    let name = RecordName::fastpq(1, chain.committed(1).block_hash(), false);
    rustix::fs::unlinkat(&directory, name.as_str(), AtFlags::empty()).unwrap();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut read = reader(&chain, 1, &pool);
    let source = complete(&mut read).unwrap();
    assert_eq!(source.native().committed().height(), 1);
    assert_eq!(
        source.native().committed().result(),
        chain.committed(1).result()
    );
    assert_eq!(source.manifest().statement_count, 0);
    assert!(source.leaves().is_empty() && source.entry(0).is_none());
    assert!(
        read.tape_read.is_none(),
        "complete empty D7 needs no optional tape advertisement"
    );
    assert!(read.poll().is_err(), "actual source authority moves once");
    drop((source, read));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(chain.height(), 2, "no unrelated traffic or empty block");
}
