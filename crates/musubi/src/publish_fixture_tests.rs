// Publication sidecar, compact-envelope, and journal transition tests.
use super::*;
use iroha::{
    crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf},
    data_model::{
        NetworkId,
        account::{MultisigMember, MultisigPolicy},
        block::BlockHeader,
        musubi::{
            MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1, MUSUBI_MAX_ARCHIVE_LOCATIONS_V1,
            MUSUBI_MAX_LOCATION_PROVIDERS_V1, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1,
            MusubiArchiveAvailabilityV1, MusubiArtifactGovernanceStateV1, MusubiArtifactTakedownV1,
            MusubiGovernanceActionDigestV1, MusubiKotodamaEditionV1, MusubiPackageIdV1,
            MusubiPackageScopeV1, MusubiPageRequestV1, MusubiProviderBundleVerificationApprovalV1,
            MusubiProviderBundleVerificationAttestationV1,
            MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
            MusubiReasonV1, MusubiReleaseIdV1, MusubiReleaseManifestV1, MusubiReleaseMetadataV1,
            MusubiReleaseRevisionsV1, MusubiReleaseSelectionStateV1, MusubiReleaseYankV1,
            MusubiResolutionProofV1, MusubiResolverIndexQueryV1,
            MusubiSeedIngressReceiptApprovalV1, MusubiSeedIngressReceiptPayloadV1,
            MusubiStorageAvailabilityV1, MusubiVerificationLockV1, MusubiVersionV1,
            musubi_provider_bundle_attestation_set_digest_v1, validate_musubi_account_id_v1,
        },
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        sorafs::pin_registry::{
            ChunkerProfileHandle, ManifestRootCid, ProviderIngestCompletionAuthorityV1,
            ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    },
};
use iroha_model_base::topology::DataSpaceId;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::{collections::VecDeque, io::Cursor};
use std::{fs::OpenOptions, io::Write as _};
use tempfile::tempdir;
fn publication_file_snapshot(path: &Path) -> FileSnapshot {
    RetainedFile::open_private(path)
        .expect("retain private fixture")
        .snapshot()
        .expect("private fixture snapshot")
}
fn publication_test_network_id(marker: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([marker; 32]),
    ))
}
struct BytesSource(Vec<u8>);
impl PublicationCarSource for BytesSource {
    fn open_car(&self) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(Cursor::new(self.0.as_slice())))
    }
    fn car_plan(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> io::Result<MusubiSeedIngressCarPlanV1> {
        MusubiSeedIngressCarPlanV1::from_car_build_plan(&publication_fixture_car_plan(), commitment)
            .map_err(|_| invalid_plan_source("test publication plan differs from the commitment"))
    }
}
#[test]
fn staged_car_source_reopens_only_the_exact_operation_file() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let operation_id = "0101010101010101010101010101010101010101010101010101010101010101"
        .parse()
        .expect("operation id");
    let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, 4);
    store
        .directory
        .write_atomic(
            source.path().file_name().unwrap(),
            b"car!",
            PublishMode::CreateNew,
        )
        .expect("stage private fixture CAR");
    let mut bytes = Vec::new();
    source
        .open_car()
        .expect("open exact CAR")
        .read_to_end(&mut bytes)
        .expect("read exact CAR");
    assert_eq!(bytes, b"car!");
    let wrong_size = PublicationStagedCarSourceV1::new(state.path(), operation_id, 5);
    assert_eq!(
        wrong_size
            .open_car()
            .err()
            .expect("wrong length must fail")
            .kind(),
        io::ErrorKind::InvalidData
    );
}
#[cfg(unix)]
#[test]
fn staged_car_reader_rejects_hard_links_and_in_place_growth() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let operation_id = "0404040404040404040404040404040404040404040404040404040404040404"
        .parse()
        .expect("operation id");
    let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, 4);
    store
        .directory
        .write_atomic(
            source.path().file_name().unwrap(),
            b"car!",
            PublishMode::CreateNew,
        )
        .expect("stage private fixture CAR");
    let linked = state.path().join("linked.car");
    fs::hard_link(source.path(), &linked).expect("create hard link");
    assert_eq!(
        source
            .open_car()
            .err()
            .expect("hard-linked source rejected")
            .kind(),
        io::ErrorKind::InvalidData
    );
    fs::remove_file(linked).expect("remove fixture hard link");
    let mut reader = source.open_car().expect("open exact CAR");
    let mut prefix = [0_u8; 2];
    reader.read_exact(&mut prefix).expect("read prefix");
    OpenOptions::new()
        .append(true)
        .open(source.path())
        .expect("open source for mutation")
        .write_all(b"x")
        .expect("grow source");
    let mut remainder = Vec::new();
    let error = reader
        .read_to_end(&mut remainder)
        .expect_err("in-place growth rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
#[test]
fn staged_car_bytes_are_commitment_checked_and_idempotent() {
    let state = tempdir().expect("state root");
    let _store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let operation_id = "0202020202020202020202020202020202020202020202020202020202020202"
        .parse()
        .expect("operation id");
    let (plan, bytes, commitment) = publication_fixture_canonical_car();
    let source = PublicationStagedCarSourceV1::stage_bytes(
        state.path(),
        operation_id,
        &commitment,
        &plan,
        &bytes,
    )
    .expect("stage committed CAR");
    let car_before = publication_file_snapshot(source.path());
    let plan_before = publication_file_snapshot(source.plan_path());
    PublicationStagedCarSourceV1::stage_bytes(
        state.path(),
        operation_id,
        &commitment,
        &plan,
        &bytes,
    )
    .expect("identical retry reuses staged CAR and plan");
    assert_eq!(car_before, publication_file_snapshot(source.path()));
    assert_eq!(plan_before, publication_file_snapshot(source.plan_path()));
    assert_eq!(
        source.car_plan(&commitment).expect("reopen exact plan"),
        MusubiSeedIngressCarPlanV1::from_car_build_plan(&plan, &commitment).expect("wire plan")
    );
    fs::write(source.path(), vec![0xA5; bytes.len()]).expect("substitute same-length fixture");
    assert!(matches!(
        PublicationStagedCarSourceV1::stage_bytes(
            state.path(),
            operation_id,
            &commitment,
            &plan,
            &bytes,
        ),
        Err(PublicationError::JournalWrite(ref error))
            if error.code() == crate::atomic_io::AtomicWriteErrorCode::ImmutableConflict
    ));
    let other_id = "0303030303030303030303030303030303030303030303030303030303030303"
        .parse()
        .expect("other operation id");
    let mut wrong_commitment = commitment.clone();
    wrong_commitment.car_digest = MusubiContentDigestV1::new([9; 32]);
    assert!(matches!(
        PublicationStagedCarSourceV1::stage_bytes(
            state.path(),
            other_id,
            &wrong_commitment,
            &plan,
            &bytes,
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::Validation,
            ..
        })
    ));
    assert!(
        !PublicationStagedCarSourceV1::new(state.path(), other_id, commitment.car_size)
            .path()
            .exists()
    );
}
#[test]
fn staged_car_rejects_a_different_file_inventory_before_install() {
    let state = tempdir().expect("state root");
    let _store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let operation_id = "2929292929292929292929292929292929292929292929292929292929292929"
        .parse()
        .expect("operation id");
    let (mut substituted_plan, bytes, commitment) = publication_fixture_canonical_car();
    let source_file = substituted_plan
        .files
        .iter_mut()
        .find(|file| file.path.iter().map(String::as_str).eq(["src", "lib.ko"]))
        .expect("fixture source file");
    source_file.path = vec!["src".to_owned(), "renamed.ko".to_owned()];
    substituted_plan
        .validate()
        .expect("substituted inventory remains a valid SoraFS plan");
    MusubiSeedIngressCarPlanV1::from_car_build_plan(&substituted_plan, &commitment)
        .expect("scalar commitment fields do not bind the file inventory");
    assert!(matches!(
        PublicationStagedCarSourceV1::stage_bytes(
            state.path(),
            operation_id,
            &commitment,
            &substituted_plan,
            &bytes,
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::Validation,
            ..
        })
    ));
    let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, commitment.car_size);
    assert!(!source.path().exists());
    assert!(!source.plan_path().exists());
}
#[test]
fn detached_begin_persists_the_recovery_anchor_before_sidecar_failure() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (request, _) = request();
    let operation_id = request.operation_id();
    let expected_size = request.archive_commitment.car_size;
    assert!(matches!(
        engine.begin_detached_with_car(
            request.clone(),
            &publication_fixture_car_plan(),
            b"not the committed canonical CAR",
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::Validation,
            ..
        })
    ));
    assert_eq!(
        store
            .load(operation_id)
            .expect("durable recovery anchor")
            .request,
        request
    );
    let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, expected_size);
    assert!(!source.path().exists());
    assert!(!source.plan_path().exists());
}
#[test]
fn detached_begin_idempotently_reuses_sidecars_while_the_journal_is_pristine() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment);
    let expected_operation_id = request.operation_id();
    let (operation_id, source) = engine
        .begin_detached_with_car(request.clone(), &plan, &car)
        .expect("begin detached publication");
    assert_eq!(operation_id, expected_operation_id);
    let journal_before = store.load(operation_id).expect("pristine journal");
    assert_eq!(journal_before.phase, PublicationPhaseV1::Validation);
    assert_eq!(journal_before.revision, 1);
    let car_before = publication_file_snapshot(source.path());
    let plan_before = publication_file_snapshot(source.plan_path());
    let (retried_operation_id, retried_source) = engine
        .begin_detached_with_car(request, &plan, &car)
        .expect("idempotently recover pristine detached publication");
    assert_eq!(retried_operation_id, operation_id);
    assert_eq!(car_before, publication_file_snapshot(retried_source.path()));
    assert_eq!(
        plan_before,
        publication_file_snapshot(retried_source.plan_path())
    );
    assert_eq!(
        store
            .load(operation_id)
            .expect("unchanged pristine journal"),
        journal_before
    );
}
#[test]
fn detached_begin_rejects_an_advanced_journal_that_must_resume() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment);
    let (operation_id, source) = engine
        .begin_detached_with_car(request.clone(), &plan, &car)
        .expect("begin detached publication");
    let pristine = store.load(operation_id).expect("pristine journal");
    let mut next = pristine.clone();
    next.validation = Some(validation_evidence(&request));
    next.phase = PublicationPhaseV1::SeedIngress;
    let advanced = store
        .transition(&pristine, next)
        .expect("advance fixture journal");
    let car_before = fs::read(source.path()).expect("read staged CAR");
    let plan_before = fs::read(source.plan_path()).expect("read staged plan");
    assert!(matches!(
        engine.begin_detached_with_car(request, &plan, &car),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("pristine validation revision")
    ));
    assert_eq!(
        store
            .load(operation_id)
            .expect("unchanged advanced journal"),
        advanced
    );
    assert_eq!(
        fs::read(source.path()).expect("reread staged CAR"),
        car_before
    );
    assert_eq!(
        fs::read(source.plan_path()).expect("reread staged plan"),
        plan_before
    );
}
#[test]
fn pristine_pre_ingress_recovery_installs_and_idempotently_reuses_exact_sidecars() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment.clone());
    let journal = store
        .create(request.clone())
        .expect("persist pristine recovery anchor");
    let journal_path = state
        .path()
        .join(journal_relative_path(journal.operation_id));
    let journal_before = fs::read(&journal_path).expect("read pristine journal");
    let source = engine
        .recover_pre_ingress_sidecars(&journal, &request.publication, &commitment, &plan, &car)
        .expect("recover exact sidecars");
    let car_before = publication_file_snapshot(source.path());
    let plan_before = publication_file_snapshot(source.plan_path());
    assert_eq!(
        store.load(journal.operation_id).expect("unchanged journal"),
        journal
    );
    assert_eq!(
        source.car_plan(&commitment).expect("reopen recovered plan"),
        MusubiSeedIngressCarPlanV1::from_car_build_plan(&plan, &commitment)
            .expect("canonical wire plan")
    );
    let retried = engine
        .recover_pre_ingress_sidecars(&journal, &request.publication, &commitment, &plan, &car)
        .expect("idempotently recover exact sidecars");
    assert_eq!(car_before, publication_file_snapshot(retried.path()));
    assert_eq!(plan_before, publication_file_snapshot(retried.plan_path()));
    assert_eq!(
        fs::read(journal_path).expect("reread pristine journal"),
        journal_before
    );
}
#[test]
fn pristine_pre_ingress_recovery_repairs_a_car_only_partial_install() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment.clone());
    let journal = store
        .create(request.clone())
        .expect("persist pristine recovery anchor");
    store
        .root
        .install_immutable(&staged_car_relative_path(journal.operation_id), &car)
        .expect("install exact CAR-only crash fixture");
    let source =
        PublicationStagedCarSourceV1::new(state.path(), journal.operation_id, commitment.car_size);
    let car_before = publication_file_snapshot(source.path());
    assert!(!source.plan_path().exists());
    let repaired = engine
        .recover_pre_ingress_sidecars(&journal, &request.publication, &commitment, &plan, &car)
        .expect("repair missing plan sidecar");
    assert_eq!(car_before, publication_file_snapshot(repaired.path()));
    assert!(repaired.plan_path().exists());
    assert_eq!(
        store.load(journal.operation_id).expect("unchanged journal"),
        journal
    );
}
#[test]
fn pristine_pre_ingress_recovery_repairs_a_plan_only_partial_install() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment.clone());
    let journal = store
        .create(request.clone())
        .expect("persist pristine recovery anchor");
    let plan_bytes = MusubiSeedIngressCarPlanV1::from_car_build_plan(&plan, &commitment)
        .and_then(|plan| plan.canonical_bytes())
        .expect("canonical plan sidecar");
    store
        .root
        .install_immutable(
            &staged_plan_relative_path(journal.operation_id),
            &plan_bytes,
        )
        .expect("install exact plan-only crash fixture");
    let source =
        PublicationStagedCarSourceV1::new(state.path(), journal.operation_id, commitment.car_size);
    let plan_before = publication_file_snapshot(source.plan_path());
    assert!(!source.path().exists());
    let repaired = engine
        .recover_pre_ingress_sidecars(&journal, &request.publication, &commitment, &plan, &car)
        .expect("repair missing CAR sidecar");
    assert_eq!(plan_before, publication_file_snapshot(repaired.plan_path()));
    assert!(repaired.path().exists());
    assert_eq!(
        store.load(journal.operation_id).expect("unchanged journal"),
        journal
    );
}
#[test]
fn pre_ingress_recovery_rejects_mismatch_stale_and_advanced_journals_before_install() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment.clone());
    let journal = store
        .create(request.clone())
        .expect("persist pristine recovery anchor");
    let source =
        PublicationStagedCarSourceV1::new(state.path(), journal.operation_id, commitment.car_size);
    let mut substituted_publication = request.publication.clone();
    substituted_publication.manifest.interface_digest = MusubiContentDigestV1::new([0xA5; 32]);
    assert!(matches!(
        engine.recover_pre_ingress_sidecars(
            &journal,
            &substituted_publication,
            &commitment,
            &plan,
            &car,
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::Validation,
            ..
        })
    ));
    assert!(!source.path().exists());
    assert!(!source.plan_path().exists());
    let mut next = journal.clone();
    next.validation = Some(validation_evidence(&request));
    next.phase = PublicationPhaseV1::SeedIngress;
    let advanced = store
        .transition(&journal, next)
        .expect("advance fixture journal");
    assert!(matches!(
        engine.recover_pre_ingress_sidecars(
            &journal,
            &request.publication,
            &commitment,
            &plan,
            &car,
        ),
        Err(PublicationError::ConcurrentJournalUpdate)
    ));
    assert!(matches!(
        engine.recover_pre_ingress_sidecars(
            &advanced,
            &request.publication,
            &commitment,
            &plan,
            &car,
        ),
        Err(PublicationError::InvalidJournal(_))
    ));
    assert!(!source.path().exists());
    assert!(!source.plan_path().exists());
}
#[test]
fn validation_requires_the_exact_plan_before_calling_the_backend() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let engine = PublicationEngine::new(&store);
    let (_plan, car, commitment) = publication_fixture_canonical_car();
    let (request, broker) = request_with_archive_commitment(commitment.clone());
    let journal = store
        .create(request.clone())
        .expect("persist pristine recovery anchor");
    store
        .root
        .install_immutable(&staged_car_relative_path(journal.operation_id), &car)
        .expect("install exact CAR-only crash fixture");
    let source =
        PublicationStagedCarSourceV1::new(state.path(), journal.operation_id, commitment.car_size);
    let mut backend = EarlyBackend {
        broker,
        fail_validation_once: true,
        substitute_receipt: false,
        now_ms: 1_500,
        receipt_window: None,
        prepare_calls: 0,
    };
    assert!(matches!(
        engine.advance_once(journal.operation_id, &source, &mut backend),
        Err(PublicationError::CarSource(_))
    ));
    assert!(
        backend.fail_validation_once,
        "backend validation was not called"
    );
    assert_eq!(
        store.load(journal.operation_id).expect("unchanged journal"),
        journal
    );
}
#[test]
fn staged_plan_missing_corrupt_or_hard_linked_fails_closed() {
    let state = tempdir().expect("state root");
    let _store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let (plan, bytes, commitment) = publication_fixture_canonical_car();
    for (id_byte, mutation) in [(0x31, "missing"), (0x32, "corrupt"), (0x33, "linked")] {
        let operation_id =
            PublicationOperationIdV1::from_str(&hex::encode([id_byte; 32])).expect("operation id");
        let source = PublicationStagedCarSourceV1::stage_bytes(
            state.path(),
            operation_id,
            &commitment,
            &plan,
            &bytes,
        )
        .expect("stage fixture");
        let linked = state.path().join(format!("{mutation}.plan"));
        match mutation {
            "missing" => fs::remove_file(source.plan_path()).expect("remove plan sidecar"),
            "corrupt" => {
                let mut noncanonical =
                    fs::read(source.plan_path()).expect("read canonical sidecar");
                noncanonical.push(0);
                fs::write(source.plan_path(), noncanonical).expect("append trailing sidecar byte");
            }
            "linked" => fs::hard_link(source.plan_path(), linked).expect("hard-link sidecar"),
            _ => unreachable!("closed fixture mutation"),
        }
        assert!(source.car_plan(&commitment).is_err());
    }
}
#[test]
fn staged_plan_substitution_fails_commitment_validation() {
    let state = tempdir().expect("state root");
    let _store = PublicationJournalStore::open(state.path()).expect("private journal store");
    let operation_id = "3434343434343434343434343434343434343434343434343434343434343434"
        .parse()
        .expect("operation id");
    let (expected_plan, bytes, expected_commitment) = publication_fixture_canonical_car();
    let source = PublicationStagedCarSourceV1::stage_bytes(
        state.path(),
        operation_id,
        &expected_commitment,
        &expected_plan,
        &bytes,
    )
    .expect("stage fixture");
    let mut substituted_plan = expected_plan.clone();
    let source_file = substituted_plan
        .files
        .iter_mut()
        .find(|file| file.path.iter().map(String::as_str).eq(["src", "lib.ko"]))
        .expect("fixture source file");
    source_file.path = vec!["src".to_owned(), "renamed.ko".to_owned()];
    substituted_plan
        .validate()
        .expect("substituted inventory remains structurally valid");
    let substituted_commitment = expected_commitment.clone();
    let substituted_wire =
        MusubiSeedIngressCarPlanV1::from_car_build_plan(&substituted_plan, &substituted_commitment)
            .expect("substituted wire plan");
    assert!(matches!(
        PublicationStagedCarSourceV1::stage_bytes(
            state.path(),
            operation_id,
            &substituted_commitment,
            &substituted_plan,
            &bytes,
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::Validation,
            ..
        })
    ));
    assert!(source.path().exists());
    assert!(source.plan_path().exists());
    fs::write(
        source.plan_path(),
        substituted_wire
            .canonical_bytes()
            .expect("encode substituted plan"),
    )
    .expect("substitute sidecar bytes");
    assert_eq!(
        source
            .car_plan(&expected_commitment)
            .expect_err("substituted plan must fail")
            .kind(),
        io::ErrorKind::InvalidData
    );
}
#[cfg(unix)]
#[test]
fn journal_load_rejects_a_fifo_substitution_without_blocking() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("journal store");
    let (request, _) = request();
    let operation_id = request.operation_id();
    store.create(request).expect("create canonical journal");
    TEST_PUBLICATION_READ_FIFO_SUBSTITUTIONS.with(|remaining| remaining.set(1));
    assert!(matches!(
        store.load(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
    let path = state.path().join(journal_relative_path(operation_id));
    assert!(
        fs::symlink_metadata(path)
            .expect("substituted FIFO metadata")
            .file_type()
            .is_fifo()
    );
    TEST_PUBLICATION_READ_FIFO_SUBSTITUTIONS.with(|remaining| assert_eq!(remaining.get(), 0));
}
#[test]
fn journal_decode_rejects_trailing_bare_and_oversized_frames() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("journal store");
    let (request, _) = request();
    let operation_id = request.operation_id();
    let journal = store.create(request).expect("create canonical journal");
    let path = state.path().join(journal_relative_path(operation_id));
    let canonical = fs::read(&path).expect("read canonical journal");
    assert_eq!(
        decode_publication_journal(&canonical).expect("decode canonical journal"),
        journal
    );
    OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open journal for trailing-byte injection")
        .write_all(&[0])
        .expect("append trailing byte");
    assert!(matches!(
        store.load(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
    store
        .root
        .replace(&journal_relative_path(operation_id), &journal.encode())
        .expect("replace with legacy bare encoding");
    assert!(matches!(
        store.load(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
    let oversized = vec![0_u8; MAX_JOURNAL_BYTES_USIZE + 1];
    assert!(matches!(
        decode_publication_journal(&oversized),
        Err(PublicationError::InvalidJournal(_))
    ));
}
#[test]
fn compact_release_envelope_reconstructs_exact_wire_and_detects_proof_substitution() {
    let (request, broker) = request();
    let (_, preparation) = release_preparation_fixture(&request, &broker);
    let signed = signed_release_transaction(&request, 1);
    let envelope =
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(&request, &signed)
            .expect("extract compact release envelope");
    let reconstructed = envelope
        .reconstruct_signed_transaction(&request)
        .expect("reconstruct compact release transaction");
    assert_eq!(reconstructed, signed);
    let wire = release_signed_transaction_wire_v1(&signed).expect("release V1 wire");
    assert_eq!(
        wire,
        signed
            .encode_wire_v1()
            .expect("data-model fixed V1 transaction wire")
    );
    let intent = PublicationReleaseSubmissionIntentV1::try_new(
        request.operation_id(),
        &request,
        preparation,
        &signed,
    )
    .expect("compact release intent");
    let encoded = norito::encode_canonical(&intent).expect("encode compact release intent");
    let decoded: PublicationReleaseSubmissionIntentV1 =
        norito::decode_canonical(&encoded).expect("decode compact release intent");
    assert_eq!(decoded, intent);
    assert_eq!(
        decoded
            .reconstruct_signed_transaction(request.operation_id(), &request)
            .expect("validate decoded compact intent"),
        signed
    );
    let other = signed_release_transaction(&request, 2);
    let forged = TransactionBuilder::from_payload(signed.payload().clone())
        .expect("valid original payload")
        .build_with_signature(other.signature().payload().clone());
    assert_eq!(forged.hash(), signed.hash());
    let forged_wire = release_signed_transaction_wire_v1(&forged).expect("forged release V1 wire");
    assert_ne!(forged_wire, wire);
    assert_ne!(
        domain_hash(RELEASE_SIGNED_TRANSACTION_DOMAIN, &forged_wire),
        intent.signed_transaction_digest
    );
    let mut substituted = intent;
    substituted.envelope.signature = forged.signature().clone();
    assert!(matches!(
        substituted.validate_for(request.operation_id(), &request),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::ReleaseSubmission,
            ..
        })
    ));
}
#[test]
fn compact_release_envelope_distinguishes_valid_authorization_bundles() {
    let (mut request, _) = request();
    let signer_a = KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::Ed25519)
        .expect("first multisig fixture key");
    let signer_b = KeyPair::try_from_seed(vec![0xB2; 32], Algorithm::Ed25519)
        .expect("second multisig fixture key");
    request.publisher = AccountId::new_multisig(
        MultisigPolicy::new(
            1,
            vec![
                MultisigMember::new(signer_a.public_key().clone(), 1)
                    .expect("first multisig member"),
                MultisigMember::new(signer_b.public_key().clone(), 1)
                    .expect("second multisig member"),
            ],
        )
        .expect("one-of-two multisig policy"),
    );
    let mut builder = TransactionBuilder::new(
        request.network_id(),
        request.publisher.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([request.publish_instruction()]);
    builder.set_creation_time(std::time::Duration::from_millis(2_500));
    builder.set_nonce(NonZeroU32::new(1).expect("fixture nonce"));
    let transaction_a = builder.clone().sign_multisig([signer_a.private_key()]);
    let transaction_b = builder.sign_multisig([signer_b.private_key()]);
    assert_eq!(transaction_a.payload(), transaction_b.payload());
    assert_eq!(transaction_a.hash(), transaction_b.hash());
    transaction_a.verify_signature().expect("first valid proof");
    transaction_b
        .verify_signature()
        .expect("second valid proof");
    let wire_a = release_signed_transaction_wire_v1(&transaction_a).expect("first exact wire");
    let wire_b = release_signed_transaction_wire_v1(&transaction_b).expect("second exact wire");
    assert_ne!(wire_a, wire_b);
    assert_ne!(
        domain_hash(RELEASE_SIGNED_TRANSACTION_DOMAIN, &wire_a),
        domain_hash(RELEASE_SIGNED_TRANSACTION_DOMAIN, &wire_b)
    );
    let envelope_a =
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(&request, &transaction_a)
            .expect("first compact authorization");
    let envelope_b =
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(&request, &transaction_b)
            .expect("second compact authorization");
    assert_ne!(envelope_a, envelope_b);
    assert_eq!(
        envelope_a
            .reconstruct_signed_transaction(&request)
            .expect("first reconstruction"),
        transaction_a
    );
    assert_eq!(
        envelope_b
            .reconstruct_signed_transaction(&request)
            .expect("second reconstruction"),
        transaction_b
    );
}
#[test]
fn compact_release_envelope_rejects_omitted_and_noncanonical_payload_fields() {
    let (request, _) = request();
    let signed = signed_release_transaction(&request, 1);
    let (_, publisher_keypair) = account(20);
    let mut metadata_payload = signed.payload().clone();
    metadata_payload
        .metadata
        .insert("unexpected".parse().expect("metadata key"), "not allowed");
    let metadata_transaction = TransactionBuilder::from_payload(metadata_payload)
        .expect("metadata fixture payload")
        .sign(publisher_keypair.private_key());
    assert!(
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(
            &request,
            &metadata_transaction
        )
        .is_err()
    );
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "release-vk"),
    );
    let attachments = vec![attachment];
    let attachment_transaction = TransactionBuilder::from_payload(signed.payload().clone())
        .expect("attachment fixture payload")
        .with_proof_attachments(attachments)
        .expect("valid proof carriers")
        .sign(publisher_keypair.private_key());
    assert!(
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(
            &request,
            &attachment_transaction
        )
        .is_err()
    );
    let mut overflow_payload = signed.payload().clone();
    overflow_payload.creation_time_ms = u64::MAX;
    overflow_payload.time_to_live_ms = NonZeroU64::new(1);
    let overflow_transaction = TransactionBuilder::from_payload(overflow_payload)
        .expect("overflow fixture payload")
        .sign(publisher_keypair.private_key());
    assert!(
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(
            &request,
            &overflow_transaction
        )
        .is_err()
    );
    let mut wrong_network_payload = signed.payload().clone();
    wrong_network_payload.domain = iroha_data_model::transaction::TransactionDomain::Network(
        publication_test_network_id(0xFF),
    );
    let wrong_network_transaction = TransactionBuilder::from_payload(wrong_network_payload)
        .expect("wrong-network fixture payload")
        .sign(publisher_keypair.private_key());
    assert!(
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(
            &request,
            &wrong_network_transaction
        )
        .is_err()
    );
}
#[test]
fn compact_release_envelope_preserves_maximum_canonical_multisig_bundle() {
    let (request, _) = request();
    let (request, signed) = maximum_multisig_release_transaction(request);
    assert_eq!(signed.signature_count(), MUSUBI_MAX_RELEASE_SIGNATURES_V1);
    let envelope =
        PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(&request, &signed)
            .expect("maximum canonical multisig envelope");
    assert_eq!(
        envelope
            .reconstruct_signed_transaction(&request)
            .expect("maximum multisig reconstruction"),
        signed
    );
    let mut reordered = envelope;
    reordered
        .multisig_signatures
        .as_mut()
        .expect("multisig bundle")
        .signatures
        .swap(0, 1);
    assert!(reordered.reconstruct_signed_transaction(&request).is_err());
}
#[test]
fn compact_final_checkpoint_covers_the_maximum_admitted_release_signers() {
    let (request, _) = request();
    let (request, _) = maximum_multisig_release_transaction(request);
    let evidence = final_evidence(&request);
    let submission = PublicationAmxSubmissionV1::new(
        request.operation_id(),
        &request.publish_instruction(),
        [0xA5; 32],
        evidence.snapshot.finalized_height,
    );
    let checkpoint = PublicationFinalCheckpointV1::from_verified(&request, &submission, &evidence)
        .expect("compact verified final checkpoint");
    ensure_release_component_budget(
        &checkpoint,
        MAX_RELEASE_FINAL_CHECKPOINT_CANONICAL_BYTES,
        "maximum-admitted-signer final checkpoint",
        PublicationPhaseV1::FinalVerification,
    )
    .expect("maximum admitted release signers fit the compact checkpoint reserve");
    assert!(
        canonical_encoded_len(&checkpoint).expect("encode compact final checkpoint")
            < canonical_encoded_len(&evidence).expect("encode full final evidence")
    );
    assert_eq!(checkpoint.release, request.publication.manifest.release);
    assert_ne!(checkpoint.home_release_digest, [0; 32]);
    assert_ne!(checkpoint.universal_release_digest, [0; 32]);
    let encoded = norito::encode_canonical(&checkpoint).expect("encode final checkpoint");
    let decoded: PublicationFinalCheckpointV1 =
        norito::decode_canonical(&encoded).expect("decode final checkpoint");
    assert_eq!(decoded, checkpoint);
    assert_eq!(
        decoded.checkpoint_digest,
        decoded.digest().expect("checkpoint digest")
    );
    let mut different_operation = request.clone();
    different_operation.nonce[0] ^= 1;
    assert_ne!(different_operation.operation_id(), request.operation_id());
    assert!(
        checkpoint
            .validate_for(&different_operation, &submission)
            .is_err()
    );
    let mut foreign_network = request.clone();
    // Two deployments may reuse the same human-facing ChainName. Their distinct
    // genesis-derived identities must still separate operation and checkpoint replay.
    foreign_network.network_id = publication_test_network_id(0xA7);
    foreign_network
        .validate()
        .expect("foreign genesis-derived identity remains structurally valid");
    assert_ne!(foreign_network.operation_id(), request.operation_id());
    assert!(
        checkpoint
            .validate_for(&foreign_network, &submission)
            .is_err()
    );
    let mut substituted_submission = submission;
    substituted_submission.operation_id = different_operation.operation_id();
    assert!(
        checkpoint
            .validate_for(&request, &substituted_submission)
            .is_err()
    );
    let mut substituted = checkpoint;
    substituted.home_release_digest[0] ^= 1;
    assert!(substituted.validate_for(&request, &submission).is_err());
}
#[test]
fn compact_final_checkpoint_accepts_later_paired_yank_and_storage_projection() {
    let (request, _) = request();
    let mut evidence = final_evidence(&request);
    let (changed_by, _) = account(0xD1);
    let yank = MusubiReleaseYankV1 {
        release: request.publication.manifest.release.clone(),
        yanked: true,
        reason: MusubiReasonV1::new("post-publication policy change").expect("reason"),
        changed_by,
        changed_at_height: 90,
        revision: 2,
    };
    evidence.home_release.yank = yank.clone();
    evidence.home_release.revisions.yank = yank.revision;
    evidence.universal_release.selection.yank = yank;
    let governance = MusubiArtifactGovernanceStateV1::TakenDown(MusubiArtifactTakedownV1 {
        action_digest: MusubiGovernanceActionDigestV1::new([0xD3; 32]),
        reason: MusubiReasonV1::new("post-publication governed takedown").expect("reason"),
        applied_at_height: 91,
    });
    evidence.home_release.artifact_governance = governance.clone();
    evidence.home_release.revisions.artifact_governance = 2;
    evidence.universal_release.selection.governance = governance;
    evidence.universal_release.selection.storage.availability =
        MusubiStorageAvailabilityV1::BelowQuorum;
    evidence
        .universal_release
        .selection
        .storage
        .healthy_replicas = 1;
    assert!(!evidence.universal_release.selection.fresh_selectable());
    let submission = PublicationAmxSubmissionV1::new(
        request.operation_id(),
        &request.publish_instruction(),
        [0xD2; 32],
        81,
    );
    let checkpoint = PublicationFinalCheckpointV1::from_verified(&request, &submission, &evidence)
        .expect("later paired projections still prove the immutable release claim");
    checkpoint
        .validate_for(&request, &submission)
        .expect("compact checkpoint remains request-bound");
}
#[test]
fn compact_final_checkpoint_decouples_near_limit_governance_account() {
    let (request, _) = request();
    let submission = PublicationAmxSubmissionV1::new(
        request.operation_id(),
        &request.publish_instruction(),
        [0xD4; 32],
        81,
    );
    let ordinary_evidence = final_evidence(&request);
    let ordinary_checkpoint =
        PublicationFinalCheckpointV1::from_verified(&request, &submission, &ordinary_evidence)
            .expect("ordinary compact checkpoint");
    let changed_by = maximum_legal_musubi_account();
    let changed_by_size = norito::to_bytes(&changed_by)
        .expect("near-limit account has canonical Norito bytes")
        .len();
    assert!(changed_by_size <= MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1);
    assert!(changed_by_size > MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1 - 256);
    validate_musubi_account_id_v1(&changed_by).expect("near-limit account is legal in Musubi");
    let mut large_evidence = ordinary_evidence.clone();
    let yank = MusubiReleaseYankV1 {
        release: request.publication.manifest.release.clone(),
        yanked: true,
        reason: MusubiReasonV1::new("post-publication owner change").expect("reason"),
        changed_by,
        changed_at_height: 90,
        revision: 2,
    };
    large_evidence.home_release.yank = yank.clone();
    large_evidence.home_release.revisions.yank = yank.revision;
    large_evidence.universal_release.selection.yank = yank;
    let large_checkpoint =
        PublicationFinalCheckpointV1::from_verified(&request, &submission, &large_evidence)
            .expect("near-limit governance projection compacts");
    let ordinary_evidence_size =
        canonical_encoded_len(&ordinary_evidence).expect("ordinary final evidence size");
    let large_evidence_size =
        canonical_encoded_len(&large_evidence).expect("large final evidence size");
    let ordinary_checkpoint_size =
        canonical_encoded_len(&ordinary_checkpoint).expect("ordinary final checkpoint size");
    let large_checkpoint_size =
        canonical_encoded_len(&large_checkpoint).expect("large final checkpoint size");
    assert!(large_evidence_size > ordinary_evidence_size + changed_by_size);
    assert_eq!(large_checkpoint_size, ordinary_checkpoint_size);
    assert!(large_checkpoint_size <= MAX_RELEASE_FINAL_CHECKPOINT_CANONICAL_BYTES);
    assert_ne!(
        large_checkpoint.home_release_digest,
        ordinary_checkpoint.home_release_digest
    );
    assert_ne!(
        large_checkpoint.universal_release_digest,
        ordinary_checkpoint.universal_release_digest
    );
}
#[test]
fn release_component_canonical_budget_accepts_boundary_and_rejects_plus_one() {
    fn bytes_with_canonical_size(target: usize) -> Vec<u8> {
        let mut lower = 0_usize;
        let mut upper = target;
        while lower <= upper {
            let length = lower + (upper - lower) / 2;
            let value = vec![0_u8; length];
            match norito::encode_canonical(&value)
                .expect("encode boundary fixture")
                .len()
                .cmp(&target)
            {
                std::cmp::Ordering::Less => lower = length + 1,
                std::cmp::Ordering::Equal => return value,
                std::cmp::Ordering::Greater => {
                    let Some(next) = length.checked_sub(1) else {
                        break;
                    };
                    upper = next;
                }
            }
        }
        panic!("canonical byte-vector encoding could not represent exact size {target}");
    }
    let at_limit = bytes_with_canonical_size(MAX_RELEASE_INTENT_CANONICAL_BYTES);
    ensure_release_component_budget(
        &at_limit,
        MAX_RELEASE_INTENT_CANONICAL_BYTES,
        "boundary fixture",
        PublicationPhaseV1::ReleaseSubmission,
    )
    .expect("exact canonical boundary is admitted");
    let above_limit = bytes_with_canonical_size(MAX_RELEASE_INTENT_CANONICAL_BYTES + 1);
    assert!(matches!(
        ensure_release_component_budget(
            &above_limit,
            MAX_RELEASE_INTENT_CANONICAL_BYTES,
            "boundary fixture",
            PublicationPhaseV1::ReleaseSubmission,
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::ReleaseSubmission,
            ..
        })
    ));
    assert!(matches!(
        ensure_release_component_budget(
            &[0_u8],
            0,
            "final verification fixture",
            PublicationPhaseV1::FinalVerification,
        ),
        Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::FinalVerification,
            ..
        })
    ));
}
#[test]
fn release_absence_requires_exact_empty_same_snapshot_retention_evidence() {
    let (request, broker) = request();
    let (_, floor) = release_preparation_fixture(&request, &broker);
    let signed = signed_release_transaction(&request, 1);
    let intent = PublicationReleaseSubmissionIntentV1::try_new(
        request.operation_id(),
        &request,
        floor,
        &signed,
    )
    .expect("release intent");
    let deadline = release_submission_valid_until_ms(&intent).expect("release deadline");
    let absence = release_absence_evidence(&request, 80, deadline + 1);
    absence
        .validate_for(&request)
        .expect("exact synchronized absence");
    PublicationReleaseSubmissionTerminalV1::finalized_validity_window_elapsed(
        &intent,
        absence.clone(),
    )
    .validate_for(&request, &intent)
    .expect("consensus-time terminal proof");
    let mut unknown = absence.clone();
    unknown.retention_page.items[0].disposition =
        MusubiArchiveRetentionDispositionV1::RetainUnknown;
    unknown.retention_page.items[0].storage = None;
    assert!(unknown.validate_for(&request).is_err());
    let mut wrong_snapshot = absence.clone();
    wrong_snapshot.retention_page.snapshot.finalized_height += 1;
    wrong_snapshot.retention_page.snapshot.finalized_block_hash = [0xD2; 32];
    assert!(wrong_snapshot.validate_for(&request).is_err());
    let mut future_storage = absence.clone();
    future_storage.retention_page.items[0]
        .storage
        .as_mut()
        .expect("known archive storage")
        .finalized_height = future_storage.retention_page.snapshot.finalized_height + 1;
    assert!(future_storage.validate_for(&request).is_err());
    let mut non_exact = absence.clone();
    non_exact.resolver_page.query.requirement = Some("*".parse().expect("wildcard"));
    assert!(non_exact.validate_for(&request).is_err());
    let at_deadline = release_absence_evidence(&request, 80, deadline);
    assert!(
        PublicationReleaseSubmissionTerminalV1::finalized_validity_window_elapsed(
            &intent,
            at_deadline,
        )
        .validate_for(&request, &intent)
        .is_err()
    );
}
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the test verifies every boundary and append-only mutation of the bounded release journal"
)]
fn release_attempt_journal_is_append_only_bounded_and_durable() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("journal store");
    let (request, broker) = request();
    let operation_id = request.operation_id();
    let mut journal = release_ready_journal(&request, &broker);
    let mut attempts = Vec::new();
    for generation in 1..=MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1 {
        let offset = u64::try_from((generation - 1) * 3).expect("fixture offset");
        let registration = registration(&request, &broker);
        let replication =
            replication_checkpoint_with_journal_max_shape(&request, &registration, offset);
        let floor = release_preparation_for_registration(&request, &registration, replication);
        let signed =
            signed_release_transaction(&request, u32::try_from(generation).expect("fixture nonce"));
        let intent =
            PublicationReleaseSubmissionIntentV1::try_new(operation_id, &request, floor, &signed)
                .expect("bounded release intent");
        let mut attempt = PublicationReleaseSubmissionAttemptV1::new(
            u8::try_from(generation).expect("fixture generation"),
            intent,
        );
        if generation < MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1 {
            let preparation_height = attempt
                .intent
                .preparation
                .replication
                .finalized_page
                .snapshot
                .finalized_height;
            let absence = release_absence_evidence(
                &request,
                preparation_height + 1,
                release_submission_valid_until_ms(&attempt.intent).expect("release deadline") + 1,
            );
            attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::Terminal(
                PublicationReleaseSubmissionTerminalV1::registry_expired(
                    &attempt.intent,
                    preparation_height + 1,
                    absence,
                ),
            ));
        }
        attempts.push(attempt);
    }
    let live_floor = attempts
        .last()
        .expect("live bounded attempt")
        .intent
        .preparation
        .clone();
    journal.replication = Some(live_floor.replication);
    journal.readbacks = live_floor.readbacks;
    journal.release_submission_attempts = attempts;
    journal.validate().expect("maximum legal release history");
    let encoded = norito::encode_canonical(&journal).expect("encode maximum release history");
    let (maximum_authority_request, maximum_signed) =
        maximum_multisig_release_transaction(request.clone());
    let maximum_envelope = PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(
        &maximum_authority_request,
        &maximum_signed,
    )
    .expect("maximum authorization envelope");
    let maximum_envelope_size =
        canonical_encoded_len(&maximum_envelope).expect("encode maximum envelope");
    let conservative_authorization_projection = encoded
        .len()
        .checked_add(
            maximum_envelope_size
                .checked_mul(MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1)
                .expect("bounded envelope projection"),
        )
        .expect("bounded journal projection");
    assert!(conservative_authorization_projection <= MAX_JOURNAL_BYTES_USIZE);
    assert!(encoded.len() <= MAX_JOURNAL_BYTES_USIZE);
    store
        .write(&journal)
        .expect("persist maximum release history");
    let persisted_len = fs::metadata(state.path().join(journal_relative_path(operation_id)))
        .expect("maximum release journal metadata")
        .len();
    assert_eq!(
        persisted_len,
        u64::try_from(encoded.len()).expect("length fits u64")
    );
    assert!(persisted_len <= MAX_JOURNAL_BYTES);
    assert_eq!(
        store.load(operation_id).expect("reload release history"),
        journal
    );
    let mut completed = journal.clone();
    let last_attempt = completed
        .release_submission_attempts
        .last_mut()
        .expect("eighth live release attempt");
    let applied_height = last_attempt
        .intent
        .preparation
        .replication
        .finalized_page
        .snapshot
        .finalized_height
        + 1;
    let submission = PublicationAmxSubmissionV1::new(
        operation_id,
        &request.publish_instruction(),
        last_attempt.intent.transaction_hash,
        applied_height,
    );
    last_attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::applied(
        &last_attempt.intent,
        submission,
    ));
    completed.phase = PublicationPhaseV1::FinalVerification;
    completed.submission = Some(submission);
    completed.completion = Some(
        PublicationFinalCheckpointV1::from_verified(
            &request,
            &submission,
            &final_evidence(&request),
        )
        .expect("compact exact final checkpoint"),
    );
    let completed = store
        .transition(&journal, completed)
        .expect("persist applied outcome and compact final checkpoint with maximum history");
    let completed_len = fs::metadata(state.path().join(journal_relative_path(operation_id)))
        .expect("completed maximum release journal metadata")
        .len();
    assert!(completed_len <= MAX_JOURNAL_BYTES);
    assert_eq!(
        store
            .load(operation_id)
            .expect("reload completed maximum release history"),
        completed
    );
    let mut rewritten_completion = completed.clone();
    let rewritten_checkpoint = rewritten_completion
        .completion
        .as_mut()
        .expect("completed journal checkpoint");
    rewritten_checkpoint.home_release_digest[0] ^= 1;
    rewritten_checkpoint.checkpoint_digest = rewritten_checkpoint
        .digest()
        .expect("alternate checkpoint digest");
    rewritten_checkpoint
        .validate_for(&request, &submission)
        .expect("self-consistent alternate checkpoint shape");
    assert!(matches!(
        store.transition(&completed, rewritten_completion),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("compact final checkpoint is not append-only")
    ));
    let mut immutable_rewrite = journal.clone();
    let first_terminal = match immutable_rewrite.release_submission_attempts[0]
        .outcome
        .as_mut()
        .expect("first terminal outcome")
    {
        PublicationReleaseSubmissionOutcomeV1::Terminal(terminal) => terminal,
        PublicationReleaseSubmissionOutcomeV1::Applied { .. } => {
            panic!("first outcome must be terminal")
        }
    };
    first_terminal.signed_transaction_digest[0] ^= 1;
    assert!(!release_submission_attempts_are_append_only(
        &journal.release_submission_attempts,
        &immutable_rewrite.release_submission_attempts,
    ));
    let mut ninth = journal;
    let last = ninth
        .release_submission_attempts
        .last_mut()
        .expect("eighth release attempt");
    let preparation_height = last
        .intent
        .preparation
        .replication
        .finalized_page
        .snapshot
        .finalized_height;
    last.outcome = Some(PublicationReleaseSubmissionOutcomeV1::Terminal(
        PublicationReleaseSubmissionTerminalV1::registry_expired(
            &last.intent,
            preparation_height + 1,
            release_absence_evidence(
                &request,
                preparation_height + 1,
                release_submission_valid_until_ms(&last.intent).expect("release deadline") + 1,
            ),
        ),
    ));
    let (_, ninth_floor) = release_preparation_fixture_with_offset(&request, &broker, 24);
    let ninth_signed = signed_release_transaction(&request, 9);
    let ninth_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        ninth_floor.clone(),
        &ninth_signed,
    )
    .expect("ninth release intent shape");
    ninth
        .release_submission_attempts
        .push(PublicationReleaseSubmissionAttemptV1::new(9, ninth_intent));
    ninth.replication = Some(ninth_floor.replication);
    ninth.readbacks = ninth_floor.readbacks;
    assert!(matches!(
        ninth.validate(),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("release-submission attempt bound")
    ));
}
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the test exercises each forbidden direct release-attempt transition in one coherent state history"
)]
fn release_attempt_transition_persists_live_intent_before_any_outcome() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("journal store");
    let (request, broker) = request();
    let operation_id = request.operation_id();
    let mut previous = release_ready_journal(&request, &broker);
    let mut illegal_empty_submission = previous.clone();
    illegal_empty_submission.release_submission_attempts.clear();
    assert!(matches!(
        illegal_empty_submission.validate(),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("persist-before-send exact intent")
    ));
    previous.phase = PublicationPhaseV1::Readback;
    previous.readbacks.clear();
    previous.release_submission_attempts.clear();
    previous.validate().expect("pre-intent readback journal");
    store
        .write(&previous)
        .expect("persist release-ready journal");
    let (_, floor) = release_preparation_fixture(&request, &broker);
    let signed = signed_release_transaction(&request, 1);
    let intent =
        PublicationReleaseSubmissionIntentV1::try_new(operation_id, &request, floor, &signed)
            .expect("first release intent");
    let submission = PublicationAmxSubmissionV1::new(
        operation_id,
        &request.publish_instruction(),
        intent.transaction_hash,
        80,
    );
    let mut direct_applied = previous.clone();
    let mut applied_attempt = PublicationReleaseSubmissionAttemptV1::new(1, intent.clone());
    applied_attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::applied(
        &applied_attempt.intent,
        submission,
    ));
    direct_applied.phase = PublicationPhaseV1::FinalVerification;
    direct_applied.readbacks = intent.preparation.readbacks.clone();
    direct_applied.release_submission_attempts = vec![applied_attempt];
    direct_applied.submission = Some(submission);
    assert!(matches!(
        store.transition(&previous, direct_applied),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("release-submission attempt history is not append-only")
    ));
    let preparation_height = intent
        .preparation
        .replication
        .finalized_page
        .snapshot
        .finalized_height;
    let absence = release_absence_evidence(
        &request,
        preparation_height + 1,
        release_submission_valid_until_ms(&intent).expect("release deadline") + 1,
    );
    let terminal = PublicationReleaseSubmissionTerminalV1::registry_expired(
        &intent,
        preparation_height + 1,
        absence,
    );
    let mut direct_terminal = previous.clone();
    direct_terminal.phase = PublicationPhaseV1::ReleaseSubmission;
    direct_terminal.readbacks = intent.preparation.readbacks.clone();
    let mut terminal_attempt = PublicationReleaseSubmissionAttemptV1::new(1, intent.clone());
    terminal_attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::Terminal(
        terminal.clone(),
    ));
    direct_terminal.release_submission_attempts = vec![terminal_attempt];
    assert!(matches!(
        store.transition(&previous, direct_terminal),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("release-submission attempt history is not append-only")
    ));
    let mut live = previous.clone();
    live.phase = PublicationPhaseV1::ReleaseSubmission;
    live.readbacks = intent.preparation.readbacks.clone();
    live.release_submission_attempts = vec![PublicationReleaseSubmissionAttemptV1::new(1, intent)];
    let live = store
        .transition(&previous, live)
        .expect("persist first live intent");
    let mut terminal_history = live.clone();
    terminal_history.release_submission_attempts[0].outcome =
        Some(PublicationReleaseSubmissionOutcomeV1::Terminal(terminal));
    let terminal_history = store
        .transition(&live, terminal_history)
        .expect("append terminal outcome separately");
    let (_, refreshed_floor) = release_preparation_fixture_with_offset(&request, &broker, 1);
    let refreshed_signed = signed_release_transaction(&request, 2);
    let refreshed_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        refreshed_floor,
        &refreshed_signed,
    )
    .expect("second release intent");
    let mut direct_successor_outcome = terminal_history.clone();
    let mut second_attempt = PublicationReleaseSubmissionAttemptV1::new(2, refreshed_intent);
    second_attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::Terminal(
        PublicationReleaseSubmissionTerminalV1::registry_expired(
            &second_attempt.intent,
            second_attempt
                .intent
                .preparation
                .replication
                .finalized_page
                .snapshot
                .finalized_height
                + 1,
            release_absence_evidence(
                &request,
                second_attempt
                    .intent
                    .preparation
                    .replication
                    .finalized_page
                    .snapshot
                    .finalized_height
                    + 1,
                release_submission_valid_until_ms(&second_attempt.intent).expect("second deadline")
                    + 1,
            ),
        ),
    ));
    direct_successor_outcome
        .release_submission_attempts
        .push(second_attempt);
    assert!(matches!(
        store.transition(&terminal_history, direct_successor_outcome),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("release-submission attempt history is not append-only")
    ));
}
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the test keeps applied binding and rejected-successor invariants in one exact release history"
)]
fn release_attempt_applied_binding_and_rejected_successor_are_exact() {
    let (request, broker) = request();
    let operation_id = request.operation_id();
    let mut applied_journal = release_ready_journal(&request, &broker);
    let (_, applied_floor) = release_preparation_fixture(&request, &broker);
    let applied_signed = signed_release_transaction(&request, 1);
    let applied_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        applied_floor,
        &applied_signed,
    )
    .expect("applied release intent");
    let submission = PublicationAmxSubmissionV1::new(
        operation_id,
        &request.publish_instruction(),
        applied_intent.transaction_hash,
        80,
    );
    let mut applied_attempt = PublicationReleaseSubmissionAttemptV1::new(1, applied_intent);
    applied_attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::applied(
        &applied_attempt.intent,
        submission,
    ));
    applied_journal.phase = PublicationPhaseV1::FinalVerification;
    applied_journal.release_submission_attempts = vec![applied_attempt];
    applied_journal.submission = Some(submission);
    applied_journal.validate().expect("exact applied binding");
    applied_journal
        .submission
        .as_mut()
        .expect("submission")
        .transaction_hash[0] ^= 1;
    assert!(applied_journal.validate().is_err());
    let mut successor_journal = release_ready_journal(&request, &broker);
    let (first_registration, first_floor) = release_preparation_fixture(&request, &broker);
    let first_signed = signed_release_transaction(&request, 1);
    let first_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        first_floor.clone(),
        &first_signed,
    )
    .expect("first rejected intent");
    let (_, refreshed_floor) = release_preparation_fixture_with_offset(&request, &broker, 1);
    let covering_snapshot = refreshed_floor.replication.finalized_page.snapshot;
    let mut rejection_absence = release_absence_evidence(
        &request,
        covering_snapshot.finalized_height,
        release_submission_valid_until_ms(&first_intent).expect("deadline") + 1,
    );
    rejection_absence.resolver_page.snapshot = covering_snapshot;
    rejection_absence.retention_query.expected_snapshot = Some(covering_snapshot);
    rejection_absence.retention_page.snapshot = covering_snapshot;
    let mut first_attempt = PublicationReleaseSubmissionAttemptV1::new(1, first_intent);
    first_attempt.outcome = Some(PublicationReleaseSubmissionOutcomeV1::Terminal(
        PublicationReleaseSubmissionTerminalV1::registry_rejected(
            &first_attempt.intent,
            covering_snapshot.finalized_height,
            rejection_absence,
        ),
    ));
    let second_signed = signed_release_transaction(&request, 2);
    let second_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        refreshed_floor.clone(),
        &second_signed,
    )
    .expect("refreshed release intent");
    successor_journal.release_submission_attempts = vec![
        first_attempt.clone(),
        PublicationReleaseSubmissionAttemptV1::new(2, second_intent),
    ];
    successor_journal.replication = Some(refreshed_floor.replication);
    successor_journal.readbacks = refreshed_floor.readbacks;
    successor_journal
        .validate()
        .expect("higher same-location revision permits rejected successor");
    let mut covering_replication =
        replication_checkpoint_with_directory_advance(&request, &first_registration);
    covering_replication.finalized_page.snapshot = covering_snapshot;
    let covering_floor =
        release_preparation_for_registration(&request, &first_registration, covering_replication);
    let unchanged_signed = signed_release_transaction(&request, 2);
    let unchanged_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        covering_floor.clone(),
        &unchanged_signed,
    )
    .expect("covering unchanged-location successor shape");
    successor_journal.release_submission_attempts = vec![
        first_attempt.clone(),
        PublicationReleaseSubmissionAttemptV1::new(2, unchanged_intent),
    ];
    successor_journal.replication = Some(covering_floor.replication);
    successor_journal.readbacks = covering_floor.readbacks;
    assert!(matches!(
        successor_journal.validate(),
        Err(PublicationError::InvalidJournal(ref reason))
            if reason.contains("did not refresh or replace its location")
    ));
    let mut replacement_journal = release_ready_journal(&request, &broker);
    let registered = replacement_journal
        .registered_archive
        .as_ref()
        .expect("registered archive")
        .clone();
    let retirement = retired_location_terminal(&first_registration);
    assert!(
        retirement.finalized_page.snapshot.finalized_height >= covering_snapshot.finalized_height
    );
    let mut second_registration =
        location_registration_generation(operation_id, &request, &registered, 2);
    second_registration.intent.prepared_page = retirement.finalized_page.clone();
    second_registration = finalized_location_registration(&request, &second_registration.intent);
    let second_replication = replication_checkpoint(&request, &second_registration, 3);
    let second_floor =
        release_preparation_for_registration(&request, &second_registration, second_replication);
    let replacement_signed = signed_release_transaction(&request, 2);
    let replacement_intent = PublicationReleaseSubmissionIntentV1::try_new(
        operation_id,
        &request,
        second_floor.clone(),
        &replacement_signed,
    )
    .expect("replacement-location release intent");
    let mut retired_first_location = replacement_journal.archive_location_attempts[0].clone();
    retired_first_location.terminal = Some(retirement);
    retired_first_location.terminal_floor = Some(
        PublicationArchiveLocationTerminalFloorV1::Replication(first_floor.replication.clone()),
    );
    replacement_journal.archive_location_attempts = vec![
        retired_first_location,
        PublicationArchiveLocationAttemptV1 {
            generation: 2,
            intent: second_registration.intent.clone(),
            registration: Some(second_registration),
            terminal: None,
            terminal_floor: None,
        },
    ];
    replacement_journal.release_submission_attempts = vec![
        first_attempt,
        PublicationReleaseSubmissionAttemptV1::new(2, replacement_intent),
    ];
    replacement_journal.replication = Some(second_floor.replication);
    replacement_journal.readbacks = second_floor.readbacks;
    replacement_journal
        .validate()
        .expect("retirement covering rejection permits a later location generation");
}
#[cfg(unix)]
#[test]
fn operation_lock_is_private_exclusive_and_rejects_hard_links() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("journal store");
    let (request, _) = request();
    let operation_id = request.operation_id();
    store.create(request).expect("create journal");
    let lock_path = state
        .path()
        .join(operation_lock_relative_path(operation_id));
    let metadata = fs::symlink_metadata(&lock_path).expect("operation lock metadata");
    assert_eq!(metadata.len(), 0);
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    let held = store
        .lock_operation(operation_id)
        .expect("hold operation lock");
    let second = PublicationJournalStore::open(state.path()).expect("second journal store");
    assert!(matches!(
        second.lock_operation(operation_id),
        Err(PublicationError::ConcurrentJournalUpdate)
    ));
    held.finish(Ok(())).expect("release operation lock");
    let hard_link = state.path().join("operation-lock-hard-link");
    fs::hard_link(&lock_path, &hard_link).expect("link operation lock");
    assert!(matches!(
        store.lock_operation(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
    fs::remove_file(hard_link).expect("remove fixture hard link");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o4600))
        .expect("add set-user-ID bit to operation lock");
    assert!(matches!(
        store.lock_operation(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
        .expect("restore operation lock permissions");
}
#[test]
fn concurrent_transition_cas_has_exactly_one_winner() {
    use std::sync::{Arc, Barrier};
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("journal store");
    let (request, _) = request();
    let operation_id = request.operation_id();
    let previous = store.create(request).expect("create journal");
    let barrier = Arc::new(Barrier::new(2));
    let root = state.path().to_path_buf();
    let workers = [(), ()].map(|()| {
        let barrier = Arc::clone(&barrier);
        let root = root.clone();
        let previous = previous.clone();
        std::thread::spawn(move || {
            let store = PublicationJournalStore::open(&root).expect("worker journal store");
            barrier.wait();
            store.transition(&previous, previous.clone())
        })
    });
    let results = workers.map(|worker| worker.join().expect("transition worker"));
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PublicationError::ConcurrentJournalUpdate)))
            .count(),
        1
    );
    assert_eq!(
        store.load(operation_id).expect("winning journal").revision,
        2
    );
}

#[test]
fn native_journal_reopen_retains_exact_bytes_and_exclusive_lock() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("native journal store");
    let (request, _) = request();
    let operation_id = request.operation_id();
    let original = store.create(request).expect("original journal");
    let held = store
        .lock_operation(operation_id)
        .expect("hold operation lock");
    let reopened = PublicationJournalStore::open(state.path()).expect("reopen journal store");
    assert_eq!(
        reopened.load(operation_id).expect("exact reopened journal"),
        original
    );
    assert!(matches!(
        reopened.lock_operation(operation_id),
        Err(PublicationError::ConcurrentJournalUpdate)
    ));
    held.finish(Ok(())).expect("release lock");
    let held = reopened
        .lock_operation(operation_id)
        .expect("acquire after release");
    held.validate().expect("retained private lock identity");
    held.finish(Ok(())).expect("release reopened lock");
    let lock_path = state
        .path()
        .join(operation_lock_relative_path(operation_id));
    fs::hard_link(&lock_path, state.path().join("linked-lock")).expect("link lock fixture");
    assert!(matches!(
        reopened.lock_operation(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
    fs::remove_file(state.path().join("linked-lock")).expect("remove alias");
    fs::write(lock_path, b"not-empty").expect("nonempty lock fixture");
    assert!(matches!(
        reopened.lock_operation(operation_id),
        Err(PublicationError::InvalidJournal(_))
    ));
}

#[test]
fn native_journal_refuses_linked_oversized_or_misnamed_frames() {
    for mutation in ["linked", "oversized", "misnamed"] {
        let state = tempdir().expect("state root");
        let store = PublicationJournalStore::open(state.path()).expect("native journal store");
        let (request, _) = request();
        let operation_id = request.operation_id();
        store.create(request).expect("original journal");
        let path = state.path().join(journal_relative_path(operation_id));
        let load_id = match mutation {
            "linked" => {
                fs::hard_link(&path, state.path().join("journal-alias")).expect("hard link");
                operation_id
            }
            "oversized" => {
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("fixture journal")
                    .set_len(MAX_JOURNAL_BYTES + 1)
                    .expect("oversized extent");
                operation_id
            }
            "misnamed" => {
                let other = PublicationOperationIdV1([0xFA; 32]);
                store
                    .directory
                    .write_atomic(
                        format!("{other}.{JOURNAL_EXTENSION}"),
                        &fs::read(path).expect("canonical bytes"),
                        PublishMode::CreateNew,
                    )
                    .expect("copy exact frame under wrong operation id");
                other
            }
            _ => unreachable!("closed fixture mutations"),
        };
        assert!(
            matches!(
                store.load(load_id),
                Err(PublicationError::InvalidJournal(_))
            ),
            "must reject {mutation}"
        );
    }
}

#[test]
fn native_staged_car_rejects_shared_links_and_allocation_before_length_validation() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("native journal store");
    let operation_id = PublicationOperationIdV1([0xF1; 32]);
    let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, 4);
    store
        .directory
        .write_atomic(
            source.path().file_name().unwrap(),
            b"car!",
            PublishMode::CreateNew,
        )
        .expect("private fixture CAR");
    fs::hard_link(source.path(), state.path().join("car-alias")).expect("link fixture CAR");
    assert_eq!(
        source.open_car().err().expect("shared CAR rejected").kind(),
        io::ErrorKind::InvalidData
    );
    for length in [0, MUSUBI_MAX_CAR_BYTES_V1 + 1, u64::MAX] {
        let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, length);
        assert_eq!(
            source
                .load_car_bytes_for_plan()
                .expect_err("reject before allocation")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[cfg(windows)]
#[test]
fn native_staged_car_retains_non_delete_sharing_ancestors_and_file() {
    let state = tempdir().expect("state root");
    let store = PublicationJournalStore::open(state.path()).expect("native journal store");
    let operation_id = PublicationOperationIdV1([0xF2; 32]);
    let source = PublicationStagedCarSourceV1::new(state.path(), operation_id, 4);
    store
        .directory
        .write_atomic(
            source.path().file_name().unwrap(),
            b"car!",
            PublishMode::CreateNew,
        )
        .expect("private fixture CAR");
    let mut reader = source.open_car().expect("retained CAR reader");
    assert!(fs::rename(source.path(), state.path().join("moved.car")).is_err());
    assert!(OpenOptions::new().write(true).open(source.path()).is_err());
    assert!(fs::rename(store.directory.path(), state.path().join("moved-directory")).is_err());
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .expect("exact retained bytes");
    assert_eq!(bytes, b"car!");
}

#[test]
fn original_client_journal_loss_cannot_reopen_real_detached_engine_history() {
    let temporary = tempdir().expect("original client custody");
    let state = temporary.path().join("operations");
    let outer = PrivateDirectory::open_or_create(&state).expect("unpublished outer");
    let original = publication_client_journal::initialize(outer.path()).expect("original inner");
    let inner_identity = original.identity().expect("original inner identity");
    drop(original);
    let (plan, car, commitment) = publication_fixture_canonical_car();
    let (request, _) = request_with_archive_commitment(commitment);
    let operation_id = request.operation_id();
    {
        let store = PublicationJournalStore::open_existing(&state).expect("preinitialized store");
        assert_eq!(store.directory.identity().unwrap(), inner_identity);
        let engine = PublicationEngine::new(&store);
        let (created, source) = engine
            .begin_detached_with_car(request.clone(), &plan, &car)
            .expect("real engine journal and canonical CAR sidecars");
        assert_eq!(created, operation_id);
        let journal = store.load(operation_id).expect("actual retained journal");
        assert_eq!(journal.request, request);
        assert_eq!(journal.revision, 1);
        assert_eq!(journal.phase, PublicationPhaseV1::Validation);
        assert_eq!(std::fs::read(source.path()).unwrap(), car);
        assert!(source.plan_path().is_file());
    }
    let reopened = PublicationJournalStore::open_existing(&state).expect("original reopen");
    assert_eq!(reopened.load(operation_id).unwrap().request, request);
    drop(reopened);
    // Only client operation history is lost; the original outer remains owner-held.
    std::fs::remove_dir_all(state.join(publication_client_journal::DIRECTORY_NAME)).unwrap();
    assert!(PublicationJournalStore::open_existing(&state).is_err());
    assert!(outer.entries(1).unwrap().is_empty());
    assert!(
        !state
            .join(publication_client_journal::DIRECTORY_NAME)
            .exists()
    );
    // Losing the complete outer must likewise never authorize generated reconstruction.
    drop(outer);
    std::fs::remove_dir(&state).unwrap();
    assert!(PublicationJournalStore::open_existing(&state).is_err());
    assert!(!state.exists());
}
