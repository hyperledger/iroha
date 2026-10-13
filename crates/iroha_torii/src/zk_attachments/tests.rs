//! Attachment sanitization, persistence, and quota tests.

use super::{
    AttachmentHashes, AttachmentMeta, AttachmentProvenance, AttachmentSanitizerMode,
    AttachmentSanitizerVerdict, SanitizeRejectReason, SanitizerConfig, ZK1_MAX_TLV_COUNT, json,
    parse_zk1_tags, sanitize_attachment_id, sanitize_attachment_sync,
};
use axum::http::HeaderMap;
use axum::{http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt as _;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::account::AccountId;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, ffi::OsStr, fs, path::PathBuf, process::Command};
use std::{
    io,
    io::Write as _,
    sync::{Arc, Once},
    time::{Duration, Instant},
};
#[test]
fn attachment_config_lock_remains_usable_after_writer_panic() {
    let panic = std::thread::spawn(|| {
        let _guard = super::attach_cfg().write();
        panic!("intentional attachment-config writer panic");
    })
    .join();
    assert!(panic.is_err());
    let _guard = super::attach_cfg().read();
}
#[cfg(windows)]
#[test]
fn exact_file_removal_unlinks_read_only_name_while_identity_handle_is_retained() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let path = tmp.path().join("retained-read-only.bin");
    fs::write(&path, b"attachment").expect("write attachment");
    let mut permissions = fs::metadata(&path)
        .expect("attachment metadata")
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).expect("mark attachment read-only");
    let retained = crate::secure_file_metadata::from_path(&path)
        .expect("retain delete-sharing identity handle");

    assert!(
        super::remove_direct_regular_file_if_present(&path)
            .expect("remove exact read-only attachment")
    );
    let error = crate::secure_file_metadata::from_path(&path)
        .expect_err("POSIX disposition must immediately unlink the file name");
    assert_eq!(error.kind(), io::ErrorKind::NotFound);

    drop(retained);
}
#[cfg(windows)]
#[test]
fn exact_directory_removal_unlinks_name_while_identity_handle_is_retained() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let path = tmp.path().join("retained-empty-directory");
    fs::create_dir(&path).expect("create empty directory");
    let retained = crate::secure_file_metadata::from_path(&path)
        .expect("retain delete-sharing identity handle");

    assert!(
        super::remove_direct_empty_directory_if_present(&path)
            .expect("remove exact empty directory")
    );
    let error = crate::secure_file_metadata::from_path(&path)
        .expect_err("POSIX disposition must immediately unlink the directory name");
    assert_eq!(error.kind(), io::ErrorKind::NotFound);

    drop(retained);
}
#[cfg(windows)]
#[test]
fn exact_directory_removal_preserves_nonempty_directory() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let path = tmp.path().join("nonempty-directory");
    fs::create_dir(&path).expect("create directory");
    fs::write(path.join("entry"), b"attachment").expect("write directory entry");

    let error = super::remove_direct_empty_directory_if_present(&path)
        .expect_err("nonempty directory must not be removed");
    assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty);
    assert_eq!(
        fs::read(path.join("entry")).expect("nonempty directory remains readable"),
        b"attachment"
    );
}
#[test]
fn persistence_preflight_retries_after_directory_creation_failure() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let root = super::attachments_root_dir();
    fs::write(&root, b"blocks attachment directory").expect("write root blocker");

    assert!(super::init_persistence().is_err());

    fs::remove_file(&root).expect("remove root blocker");
    super::init_persistence().expect("preflight must retry instead of caching failure");
    super::verify_direct_directory(&root).expect("verified direct attachment root");
}
#[test]
fn persistence_preflight_removes_crash_temps_and_unaccounted_orphan_bodies() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let orphan_id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let tenant_temp = super::attachments_dir(&tenant).join(".tmpABC123");
    fs::write(&tenant_temp, b"partial attachment").expect("write attachment temp");
    let orphan_body = super::bin_path(&tenant, &orphan_id);
    fs::write(&orphan_body, b"unaccounted body").expect("write orphan body");
    super::ensure_attachment_mutation_transaction_dir_durable()
        .expect("create transaction directory");
    let transaction_temp = super::attachment_mutation_transaction_dir().join(".tmpXYZ789");
    fs::write(&transaction_temp, b"partial journal").expect("write journal temp");
    let processing_temp = super::prover_processing_state_dir()
        .join(&orphan_id)
        .join(".tmpRST456");
    fs::create_dir_all(processing_temp.parent().expect("processing temp parent"))
        .expect("create processing state directory");
    fs::write(&processing_temp, b"partial receipt").expect("write processing temp");

    super::init_persistence().expect("recover attachment persistence");

    assert!(!tenant_temp.exists());
    assert!(!orphan_body.exists());
    assert!(!transaction_temp.exists());
    assert!(!processing_temp.exists());
}
#[test]
fn persistence_preflight_rejects_metadata_without_a_body() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"missing":"body"}"#;
    let meta = canonical_test_meta(&tenant, body);
    super::ensure_dirs(&tenant).expect("create tenant directory");
    fs::write(
        super::meta_path(&tenant, &meta.id),
        json::to_json_pretty(&meta).expect("encode metadata"),
    )
    .expect("write orphan metadata");

    let error = super::init_persistence()
        .expect_err("metadata without its body must fail startup recovery");
    assert!(error.to_string().contains("metadata has no body"));
}
#[test]
fn persistence_preflight_rejects_unknown_mutation_namespace_entries() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    super::ensure_root_dir().expect("create attachment root");
    super::ensure_attachment_mutation_transaction_dir_durable()
        .expect("create mutation transaction directory");
    fs::write(
        super::attachment_mutation_transaction_dir().join("unexpected.json"),
        b"{}",
    )
    .expect("write unexpected mutation entry");

    let error = super::init_persistence()
        .expect_err("unknown mutation namespace entries must fail startup recovery");
    assert!(error.to_string().contains("unexpected entry"));
}
#[test]
fn persistence_preflight_rejects_corrupt_processing_receipts() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"processing":true}"#, 1);
    fs::write(
        super::prover_processing_receipt_path(&meta.id),
        b"{not json",
    )
    .expect("write corrupt processing receipt");

    let error = super::init_persistence()
        .expect_err("corrupt processing receipts must fail startup recovery");
    assert!(
        error
            .to_string()
            .contains("decode ZK prover processing receipt")
    );
}
#[cfg(unix)]
#[test]
fn persistence_preflight_rejects_symlinked_attachment_root() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tempfile::tempdir().expect("symlink target");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let root = super::attachments_root_dir();
    std::os::unix::fs::symlink(target.path(), &root).expect("symlink attachment root");

    let error = super::init_persistence().expect_err("symlinked root must fail preflight");

    assert!(error.to_string().contains("not a direct directory"));
}
#[cfg(unix)]
#[test]
fn persistence_preflight_rejects_symlinked_prover_ancestor_before_cleanup() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tempfile::tempdir().expect("symlink target");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    super::ensure_root_dir().expect("create attachment root");
    let id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let external_entry = target
        .path()
        .join(format!(
            "processing_{}",
            super::ZK_PROVER_PROCESSING_STATE_VERSION
        ))
        .join(id);
    fs::create_dir_all(&external_entry).expect("create external processing entry");
    let external_temp = external_entry.join(".tmpABC123");
    fs::write(&external_temp, b"external data").expect("write external temp-shaped file");
    std::os::unix::fs::symlink(target.path(), super::base_dir().join("zk_prover"))
        .expect("symlink prover ancestor");

    let error = super::init_persistence()
        .expect_err("a symlinked prover ancestor must fail before cleanup");
    assert!(
        error.to_string().contains("not a direct directory")
            || matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR),
        "unexpected ancestor refusal: {error}"
    );
    assert!(
        external_temp.exists(),
        "preflight must not delete through a symlinked ancestor"
    );
}
#[tokio::test]
async fn gc_worker_reports_shutdown_and_storage_failure() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    super::init_persistence().expect("attachment preflight");

    let clean_shutdown = super::ShutdownSignal::new();
    let clean_worker = super::start_gc_worker(clean_shutdown.clone()).expect("start GC worker");
    clean_shutdown.send();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), clean_worker)
            .await
            .expect("GC worker observes shutdown")
            .expect("GC worker joins"),
        crate::ToriiCriticalWorkerExit::StoppedByShutdown
    );

    let invalid_tenant = super::attachments_root_dir().join("a".repeat(super::TENANT_KEY_HEX_LEN));
    fs::write(&invalid_tenant, b"not a tenant directory").expect("write tenant blocker");
    let failure_shutdown = super::ShutdownSignal::new();
    let failed_worker =
        super::start_gc_worker(failure_shutdown).expect("root preflight still succeeds");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), failed_worker)
            .await
            .expect("GC storage failure is visible")
            .expect("GC worker joins"),
        crate::ToriiCriticalWorkerExit::UnexpectedExit
    );

    fs::remove_file(invalid_tenant).expect("remove tenant blocker");
    let tenant_dir = super::attachments_root_dir().join("b".repeat(super::TENANT_KEY_HEX_LEN));
    fs::create_dir(&tenant_dir).expect("create tenant directory");
    fs::write(
        tenant_dir.join(format!("{}.json", "c".repeat(super::ATTACHMENT_ID_HEX_LEN))),
        b"{not valid metadata",
    )
    .expect("write malformed canonical metadata");
    let failure_shutdown = super::ShutdownSignal::new();
    let failed_worker =
        super::start_gc_worker(failure_shutdown).expect("root preflight still succeeds");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), failed_worker)
            .await
            .expect("GC metadata failure is visible")
            .expect("GC worker joins"),
        crate::ToriiCriticalWorkerExit::UnexpectedExit
    );
}
#[tokio::test]
async fn ttl_collection_fails_closed_on_fresh_metadata_without_a_body() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"fresh":true}"#, 1);
    super::init_persistence().expect("initialize attachment persistence");
    fs::remove_file(super::bin_path(&tenant, &meta.id)).expect("remove persisted body");

    let error =
        super::collect_expired_attachments_once(&super::ShutdownSignal::new(), Duration::MAX)
            .await
            .expect_err("a metadata-only pair must stop TTL collection");
    assert!(error.to_string().contains("metadata has no body"));
}
#[tokio::test]
async fn ttl_collection_reconciles_unaccounted_body_only_entries() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    super::init_persistence().expect("initialize attachment persistence");
    let tenant = super::AttachmentTenant::anonymous();
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let body_path = super::bin_path(&tenant, &id);
    fs::write(&body_path, b"unaccounted body").expect("write body-only entry");

    super::collect_expired_attachments_once(&super::ShutdownSignal::new(), Duration::MAX)
        .await
        .expect("body-only entries are durably reconciled");
    assert!(!body_path.exists());
    assert!(!super::attachments_dir(&tenant).exists());
}
#[cfg(any(unix, windows))]
#[tokio::test]
async fn ttl_collection_rejects_hard_linked_attachment_entries() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    super::init_persistence().expect("initialize attachment persistence");
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"hard_link":"rejected"}"#;
    let meta = persist_canonical_test_attachment(&tenant, body, 1);
    let body_path = super::bin_path(&tenant, &meta.id);
    let hard_link_source = tmp.path().join("hard-link-source");
    fs::write(&hard_link_source, body).expect("write hard-link source");
    fs::remove_file(&body_path).expect("remove canonical body before replacement");
    fs::hard_link(&hard_link_source, &body_path).expect("install hard-linked body");

    let error =
        super::collect_expired_attachments_once(&super::ShutdownSignal::new(), Duration::MAX)
            .await
            .expect_err("hard-linked bodies must stop TTL collection");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
#[test]
fn quota_scan_entry_bound_counts_every_raw_entry() {
    let mut scanned = 0_u64;
    assert!(super::quota_scan_entry_within_limit(&mut scanned, 2));
    assert!(super::quota_scan_entry_within_limit(&mut scanned, 2));
    assert!(!super::quota_scan_entry_within_limit(&mut scanned, 2));
    assert_eq!(scanned, 3);
}
#[test]
fn attachment_sanitizer_stdout_reader_retains_admission_until_eof() {
    struct BlockingReader {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl std::io::Read for BlockingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            self.entered
                .send(())
                .expect("signal blocked sanitizer stdout read");
            self.release
                .recv()
                .expect("release blocked sanitizer stdout read");
            Ok(0)
        }
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .try_acquire_owned()
        .expect("acquire sanitizer admission");
    let admission = crate::ProofBodyAdmissionLease::new(permit);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let result = super::spawn_sanitizer_stdout_reader(
        BlockingReader {
            entered: entered_tx,
            release: release_rx,
        },
        16,
        Some(admission),
    );
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("sanitizer stdout reader must block");
    assert_eq!(
        semaphore.available_permits(),
        0,
        "a detached stdout reader must retain physical admission"
    );
    release_tx
        .send(())
        .expect("release sanitizer stdout reader");
    assert_eq!(
        result
            .recv_timeout(Duration::from_secs(1))
            .expect("sanitizer stdout result")
            .expect("sanitizer stdout read"),
        Vec::<u8>::new()
    );
    assert_eq!(semaphore.available_permits(), 1);
}
#[test]
fn attachment_sanitizer_stdout_reader_contains_panic_and_releases_admission() {
    struct PanickingReader {
        dropped: Option<std::sync::mpsc::Sender<bool>>,
    }
    impl std::io::Read for PanickingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                iroha_panic_hook::is_suppressed(),
                "the physical stdout-reader thread must suppress the shutdown hook"
            );
            panic!("injected sanitizer stdout-reader panic");
        }
    }
    impl Drop for PanickingReader {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(iroha_panic_hook::is_suppressed());
            }
        }
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .try_acquire_owned()
        .expect("acquire sanitizer admission");
    let admission = crate::ProofBodyAdmissionLease::new(permit);
    let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
    let result = super::spawn_sanitizer_stdout_reader(
        PanickingReader {
            dropped: Some(dropped_tx),
        },
        16,
        Some(admission),
    );

    assert_eq!(
        result
            .recv_timeout(Duration::from_secs(1))
            .expect("panicking sanitizer reader must report a terminal result")
            .expect_err("reader panic must become an opaque sanitizer error"),
        "attachment sanitizer stdout reader panicked"
    );
    assert_eq!(
        semaphore.available_permits(),
        1,
        "the physical reader must release admission after a panic"
    );
    assert!(
        !dropped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("panicking reader must be dropped on its physical thread"),
        "thread-local shutdown-hook suppression must clear after recovery"
    );
}
#[test]
fn quota_child_entry_budget_is_aggregate_across_tenants() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let first = super::AttachmentTenant("a".repeat(super::TENANT_KEY_HEX_LEN));
    let second = super::AttachmentTenant("b".repeat(super::TENANT_KEY_HEX_LEN));
    super::ensure_dirs(&first).expect("create first tenant directory");
    super::ensure_dirs(&second).expect("create second tenant directory");
    for (tenant, prefix) in [(&first, "first"), (&second, "second")] {
        for index in 0..2 {
            fs::write(
                super::attachments_dir(tenant).join(format!("{prefix}-{index}.noise")),
                b"noise",
            )
            .expect("write raw tenant entry");
        }
    }

    let mut scan = super::AttachmentQuotaScanBudget::new(3);
    assert!(
        super::quota_metas_for_tenant(&first, &mut scan)
            .expect("first tenant fits aggregate child-entry budget")
            .is_empty()
    );
    let error = super::quota_metas_for_tenant(&second, &mut scan)
        .expect_err("second tenant must share the first tenant's scan budget");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        scan.child_entries, 2,
        "the remaining aggregate budget must bound enumeration before a whole extra directory is admitted"
    );
}
#[cfg(unix)]
#[test]
fn quota_scan_rejects_canonical_metadata_symlink() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let target = tmp.path().join("outside-metadata.json");
    fs::write(&target, b"{}").expect("write symlink target");
    symlink(&target, super::meta_path(&tenant, &id)).expect("create metadata symlink");
    let mut scan = super::AttachmentQuotaScanBudget::new(10);

    let error = super::quota_metas_for_tenant(&tenant, &mut scan)
        .expect_err("canonical metadata symlink must not be skipped");
    assert!(
        error.kind() == io::ErrorKind::InvalidData
            || matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR),
        "unexpected symlink refusal: {error}"
    );
}
#[cfg(unix)]
#[test]
fn global_quota_scan_rejects_canonical_tenant_symlink() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("temp dir");
    let outside = tempfile::tempdir().expect("outside tenant");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    super::ensure_root_dir().expect("create attachment root");
    let tenant_key = "a".repeat(super::TENANT_KEY_HEX_LEN);
    symlink(
        outside.path(),
        super::attachments_root_dir().join(&tenant_key),
    )
    .expect("create tenant symlink");
    let submitting = super::AttachmentTenant("b".repeat(super::TENANT_KEY_HEX_LEN));
    let mut scan = super::AttachmentQuotaScanBudget::new(10);

    let error = super::other_tenants_quota_usage(&submitting, &mut scan)
        .expect_err("canonical tenant symlink must not be skipped");
    assert!(
        error.kind() == io::ErrorKind::InvalidData
            || matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR),
        "unexpected symlink refusal: {error}"
    );
}
fn test_sanitizer_config(max_expanded_bytes: u64, max_archive_depth: u32) -> SanitizerConfig {
    SanitizerConfig {
        allowed_mime_types: vec![
            super::NORITO_MIME_TYPE.to_string(),
            super::JSON_MIME_TYPE.to_string(),
            super::ZK1_MIME_TYPE.to_string(),
        ],
        max_expanded_bytes,
        max_archive_depth,
        timeout: std::time::Duration::from_millis(100),
        mode: AttachmentSanitizerMode::InProcess,
    }
}
fn gzip_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).expect("write gzip input");
    encoder.finish().expect("finish gzip")
}
fn canonical_test_meta(tenant: &super::AttachmentTenant, body: &[u8]) -> AttachmentMeta {
    let id = hex::encode::<[u8; 32]>(Hash::new(body).into());
    AttachmentMeta {
        id: id.clone(),
        content_type: super::JSON_MIME_TYPE.to_owned(),
        size: body.len() as u64,
        created_ms: 1_700_000_000_000,
        tenant: Some(tenant.as_str().to_owned()),
        provenance: Some(AttachmentProvenance {
            declared_type: Some(super::JSON_MIME_TYPE.to_owned()),
            sniffed_type: super::JSON_MIME_TYPE.to_owned(),
            hashes: AttachmentHashes {
                blake2b_256: id,
                sha256: hex::encode(Sha256::digest(body)),
            },
            sanitizer: AttachmentSanitizerVerdict {
                verdict: "accepted".to_owned(),
                expanded_bytes: body.len() as u64,
                archive_depth: 0,
                sandboxed: false,
            },
        }),
        zk1_tags: None,
    }
}
fn quota_transaction(
    tenant: &super::AttachmentTenant,
    incoming_meta: AttachmentMeta,
    previous_meta: Option<AttachmentMeta>,
    victim_ids: Vec<String>,
) -> super::AttachmentQuotaTransaction {
    super::AttachmentQuotaTransaction {
        version: super::ATTACHMENT_QUOTA_TRANSACTION_VERSION,
        tenant: tenant.as_str().to_owned(),
        incoming_meta,
        previous_meta,
        victim_ids,
    }
}
fn delete_transaction(
    tenant: &super::AttachmentTenant,
    id: impl Into<String>,
) -> super::AttachmentDeleteTransaction {
    super::AttachmentDeleteTransaction {
        version: super::ATTACHMENT_DELETE_TRANSACTION_VERSION,
        tenant: tenant.as_str().to_owned(),
        id: id.into(),
    }
}
fn persist_canonical_test_attachment(
    tenant: &super::AttachmentTenant,
    body: &[u8],
    created_ms: u64,
) -> AttachmentMeta {
    let mut meta = canonical_test_meta(tenant, body);
    meta.created_ms = created_ms;
    super::persist_body(tenant, &meta.id, body).expect("persist canonical attachment body");
    super::save_meta(tenant, &meta).expect("persist canonical attachment metadata");
    meta
}
fn padded_json_body(tenant: &str, index: usize, target_len: usize) -> Vec<u8> {
    let prefix = format!(r#"{{"tenant":"{tenant}","index":{index},"padding":""#);
    let suffix = r#""}"#;
    assert!(prefix.len() + suffix.len() <= target_len);
    let mut body = prefix;
    body.push_str(&"x".repeat(target_len - body.len() - suffix.len()));
    body.push_str(suffix);
    assert_eq!(body.len(), target_len);
    body.into_bytes()
}
fn load_fixture_base64(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("attachments")
        .join(name);
    let encoded = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
    let mut joined = String::new();
    for line in encoded.lines() {
        joined.push_str(line.trim());
    }
    BASE64_STANDARD
        .decode(joined.as_bytes())
        .unwrap_or_else(|err| panic!("failed to decode fixture {}: {err}", path.display()))
}
fn ensure_test_config() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        super::configure(
            60,
            1024,
            10,
            4096,
            20,
            8192,
            vec![
                super::NORITO_MIME_TYPE.to_string(),
                super::JSON_MIME_TYPE.to_string(),
                super::ZK1_MIME_TYPE.to_string(),
            ],
            4096,
            1,
            AttachmentSanitizerMode::InProcess,
            500,
            None,
            crate::routing::MaybeTelemetry::disabled(),
        );
    });
    // Each scoped data directory is a new store and must perform node startup
    // recovery before serving requests, including after an earlier fault test.
    super::init_persistence().expect("initialize the scoped attachment store");
}
fn checked_attachment_ed25519_keypair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("test attachment fixture key derivation should succeed")
}
fn checked_attachment_account(seed: u8) -> AccountId {
    AccountId::new(
        checked_attachment_ed25519_keypair(seed)
            .public_key()
            .clone(),
    )
}
#[test]
fn checked_attachment_ed25519_keypair_uses_fallible_seed_derivation() {
    assert_eq!(
        checked_attachment_ed25519_keypair(0x40).algorithm(),
        Algorithm::Ed25519
    );
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
    assert_ne!(
        checked_attachment_account(0x41),
        checked_attachment_account(0x42)
    );
}
#[test]
fn attachment_meta_norito_roundtrip() {
    let meta = AttachmentMeta {
        id: "deadbeef".repeat(4),
        content_type: "application/json".to_string(),
        size: 512,
        created_ms: 1_700_000_000_000,
        tenant: Some("a".repeat(64)),
        provenance: None,
        zk1_tags: None,
    };
    let encoded = json::to_json_pretty(&meta).expect("serialize metadata");
    let decoded: AttachmentMeta = json::from_json(&encoded).expect("deserialize metadata");
    assert_eq!(meta, decoded);
}
#[test]
fn load_meta_rejects_oversized_persisted_metadata() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    fs::write(
        super::meta_path(&tenant, &id),
        vec![b' '; super::ATTACHMENT_META_FILE_MAX_BYTES as usize + 1],
    )
    .expect("write oversized persisted metadata");
    super::try_load_meta(&tenant, &id)
        .expect_err("metadata beyond the 64-KiB persistence contract must be rejected");
}
#[test]
fn save_meta_rejects_records_beyond_the_persistence_contract() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let id = "c".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let meta = AttachmentMeta {
        id: id.clone(),
        content_type: "x".repeat(super::ATTACHMENT_META_FILE_MAX_BYTES as usize),
        size: 0,
        created_ms: 0,
        tenant: Some(tenant.as_str().to_owned()),
        provenance: None,
        zk1_tags: None,
    };
    let error =
        super::save_meta(&tenant, &meta).expect_err("oversized metadata must not be persisted");
    assert!(error.to_string().contains("persistence limit"));
    assert!(!super::meta_path(&tenant, &id).exists());
}
#[test]
fn save_and_load_meta_require_canonical_provenance() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"valid":true}"#;
    let meta = canonical_test_meta(&tenant, body);
    super::persist_body(&tenant, &meta.id, body).expect("persist canonical body");
    super::save_meta(&tenant, &meta).expect("persist canonical metadata");
    assert_eq!(
        super::try_load_meta(&tenant, &meta.id).expect("load canonical metadata"),
        Some(meta.clone()),
        "canonical metadata must round-trip"
    );
    let mut missing = meta.clone();
    missing.provenance = None;
    assert!(
        super::save_meta(&tenant, &missing)
            .expect_err("missing provenance must reject")
            .to_string()
            .contains("provenance is required")
    );
    let mut rejected = meta.clone();
    rejected
        .provenance
        .as_mut()
        .expect("canonical provenance")
        .sanitizer
        .verdict = "rejected".to_owned();
    assert!(
        super::save_meta(&tenant, &rejected)
            .expect_err("non-accepted sanitizer verdict must reject")
            .to_string()
            .contains("verdict")
    );
    let mut wrong_expanded_size = meta;
    wrong_expanded_size
        .provenance
        .as_mut()
        .expect("canonical provenance")
        .sanitizer
        .expanded_bytes += 1;
    assert!(
        super::save_meta(&tenant, &wrong_expanded_size)
            .expect_err("expanded-size mismatch must reject")
            .to_string()
            .contains("expanded size")
    );
}
#[cfg(unix)]
#[test]
fn load_meta_rejects_a_symlink_entry() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let id = "b".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let target = tmp.path().join("outside-metadata.json");
    fs::write(&target, b"{}").expect("write symlink target");
    symlink(&target, super::meta_path(&tenant, &id)).expect("create metadata symlink");
    super::try_load_meta(&tenant, &id)
        .expect_err("metadata readers must not follow attachment-store symlinks");
}
#[test]
fn attachment_tenant_is_derived_from_signed_account() {
    let alice = checked_attachment_account(0x43);
    let bob = checked_attachment_account(0x44);
    assert_eq!(
        super::AttachmentTenant::from_account(&alice),
        super::AttachmentTenant::from_account(&alice)
    );
    assert_ne!(
        super::AttachmentTenant::from_account(&alice),
        super::AttachmentTenant::from_account(&bob)
    );
}
#[test]
fn prover_processing_receipt_json_requires_complete_v1_schema() {
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: "a".repeat(super::ATTACHMENT_ID_HEX_LEN),
        processed_ms: 1,
        terminal: true,
        retry_not_before_ms: None,
        retry_count: 0,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    let canonical = json::to_value(&receipt).expect("encode exact processing receipt");
    assert!(
        canonical
            .get("retry_not_before_ms")
            .is_some_and(norito::json::Value::is_null),
        "terminal retry deadline must be present as explicit null"
    );
    assert!(
        canonical
            .get("completed_proof_indices")
            .and_then(norito::json::Value::as_array)
            .is_some_and(Vec::is_empty),
        "terminal completed-proof cache must be present as an empty array"
    );
    assert!(
        canonical
            .get("processing_context_hash")
            .is_some_and(norito::json::Value::is_null),
        "terminal processing-context hash must be present as explicit null"
    );
    assert_eq!(
        json::from_value::<super::ProverProcessingReceipt>(canonical.clone())
            .expect("decode exact processing receipt"),
        receipt
    );
    for field in [
        "version",
        "id",
        "processed_ms",
        "terminal",
        "retry_not_before_ms",
        "retry_count",
        "completed_proof_indices",
        "processing_context_hash",
    ] {
        let mut omitted = canonical.clone();
        omitted
            .as_object_mut()
            .expect("processing receipt object")
            .remove(field);
        assert!(
            json::from_value::<super::ProverProcessingReceipt>(omitted).is_err(),
            "omitted processing receipt field `{field}` must not default"
        );
    }
}
#[test]
fn corrupt_prover_processing_receipt_is_not_treated_as_missing() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"receipt":true}"#, 1);
    fs::write(
        super::prover_processing_receipt_path(&meta.id),
        b"{not json",
    )
    .expect("write corrupt processing receipt");

    assert_eq!(
        super::try_load_prover_processing_receipt(&meta.id)
            .expect_err("corrupt receipt must be a storage failure")
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        super::try_prover_processing_decision(&meta.id, u64::MAX)
            .expect_err("corrupt receipt must not become Missing")
            .kind(),
        io::ErrorKind::InvalidData
    );
}
#[test]
fn prover_processing_receipt_lives_until_the_last_attachment_reference_is_deleted() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let first = super::AttachmentTenant("1".repeat(super::TENANT_KEY_HEX_LEN));
    let second = super::AttachmentTenant("2".repeat(super::TENANT_KEY_HEX_LEN));
    let id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    for tenant in [&first, &second] {
        super::ensure_dirs(tenant).expect("create tenant directory");
        fs::write(super::meta_path(tenant, &id), b"metadata").expect("write metadata marker");
        fs::write(super::bin_path(tenant, &id), b"body").expect("write body marker");
        super::ensure_prover_processing_reference(tenant.as_str(), &id)
            .expect("register live attachment reference");
    }
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: id.clone(),
        processed_ms: 1,
        terminal: true,
        retry_not_before_ms: None,
        retry_count: 0,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&receipt)
            .expect("persist terminal receipt")
    );
    assert_eq!(
        super::prover_processing_decision(&id, 1),
        super::ProverProcessingDecision::Suppress
    );
    super::delete_attachment_files(&first, &id).expect("delete first attachment copy");
    assert_eq!(
        super::prover_processing_decision(&id, 1),
        super::ProverProcessingDecision::Suppress,
        "one live duplicate must retain the global receipt"
    );
    super::delete_attachment_files(&second, &id).expect("delete final attachment copy");
    assert_eq!(
        super::prover_processing_decision(&id, 1),
        super::ProverProcessingDecision::Missing,
        "the last attachment deletion must reclaim the receipt"
    );
    assert!(
        super::ensure_prover_processing_reference(second.as_str(), &id).is_err(),
        "a stale discovery entry must not recreate a reference after deletion"
    );
}
#[test]
fn startup_replays_every_durable_attachment_delete_boundary() {
    for boundary in 0_u8..5 {
        let tmp = tempfile::tempdir().expect("temp dir");
        let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
        let tenant = super::AttachmentTenant::anonymous();
        let body = format!(r#"{{"delete_boundary":{boundary}}}"#).into_bytes();
        let meta = persist_canonical_test_attachment(&tenant, &body, 1);
        let receipt = super::ProverProcessingReceipt {
            version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
            id: meta.id.clone(),
            processed_ms: 1,
            terminal: true,
            retry_not_before_ms: None,
            retry_count: 0,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        };
        assert!(
            super::persist_prover_processing_receipt_if_referenced(&receipt)
                .expect("persist terminal receipt")
        );
        super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
            .expect("persist delete intent");
        match boundary {
            0 => {}
            1 => {
                fs::remove_file(super::meta_path(&tenant, &meta.id))
                    .expect("simulate crash after metadata unlink");
            }
            2 => {
                fs::remove_file(super::meta_path(&tenant, &meta.id))
                    .expect("simulate crash after metadata unlink");
                fs::remove_file(super::bin_path(&tenant, &meta.id))
                    .expect("simulate crash after body unlink");
            }
            3 => {
                fs::remove_file(super::meta_path(&tenant, &meta.id))
                    .expect("simulate crash after metadata unlink");
                fs::remove_file(super::bin_path(&tenant, &meta.id))
                    .expect("simulate crash after body unlink");
                let _processing_guard = super::prover_processing_state_lock().lock();
                super::remove_prover_processing_reference_locked(tenant.as_str(), &meta.id)
                    .expect("simulate crash after reference reclamation");
            }
            4 => {
                super::apply_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
                    .expect("simulate crash after delete application but before journal clear");
            }
            _ => unreachable!(),
        }

        assert!(super::attachment_mutation_transaction_path().is_file());
        assert!(
            super::try_load_meta(&tenant, &meta.id)
                .expect("pending delete lookup")
                .is_none(),
            "a pending delete must be invisible before replay"
        );
        super::init_persistence().expect("replay durable delete intent at startup");

        assert!(!super::meta_path(&tenant, &meta.id).exists());
        assert!(!super::bin_path(&tenant, &meta.id).exists());
        assert!(!super::attachment_mutation_transaction_path().exists());
        assert_eq!(
            super::prover_processing_decision(&meta.id, 1),
            super::ProverProcessingDecision::Missing
        );
    }
}
#[test]
fn delete_replay_recovers_after_a_malformed_sibling_reference_is_repaired() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let first = super::AttachmentTenant("7".repeat(super::TENANT_KEY_HEX_LEN));
    let second = super::AttachmentTenant("8".repeat(super::TENANT_KEY_HEX_LEN));
    let body = br#"{"shared":"delete-replay"}"#;
    let first_meta = persist_canonical_test_attachment(&first, body, 1);
    let second_meta = persist_canonical_test_attachment(&second, body, 1);
    assert_eq!(first_meta.id, second_meta.id);
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: first_meta.id.clone(),
        processed_ms: 1,
        terminal: true,
        retry_not_before_ms: None,
        retry_count: 0,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&receipt)
            .expect("persist shared terminal receipt")
    );
    super::persist_attachment_delete_transaction(&delete_transaction(&first, &first_meta.id))
        .expect("persist delete intent");
    let malformed = super::prover_processing_reference_dir(&first_meta.id).join("malformed");
    fs::write(&malformed, b"not a reference").expect("write malformed sibling reference");

    super::recover_attachment_mutation_transaction()
        .expect_err("malformed sibling must keep delete recovery fail-closed");
    assert!(super::attachment_mutation_transaction_path().is_file());
    assert!(super::meta_path(&first, &first_meta.id).is_file());
    assert!(
        !super::attachment_pair_exists(first.as_str(), &first_meta.id)
            .expect("pending delete visibility"),
        "the durable delete intent must hide a physically complete pair"
    );

    fs::remove_file(malformed).expect("repair malformed sibling reference");
    assert!(super::recover_attachment_mutation_transaction().expect("replay repaired delete"));
    assert!(!super::meta_path(&first, &first_meta.id).exists());
    assert!(!super::bin_path(&first, &first_meta.id).exists());
    assert!(super::meta_path(&second, &second_meta.id).is_file());
    assert!(super::bin_path(&second, &second_meta.id).is_file());
    assert_eq!(
        super::prover_processing_decision(&first_meta.id, 1),
        super::ProverProcessingDecision::Suppress,
        "the surviving tenant reference must retain the shared receipt"
    );
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[cfg(unix)]
#[test]
fn delete_replay_rejects_symlinked_processing_entry_without_touching_target() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let external = tempfile::tempdir().expect("external processing target");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"delete":"symlink"}"#, 1);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
        .expect("persist delete intent");
    let processing_entry = super::prover_processing_state_dir().join(&meta.id);
    fs::remove_dir_all(&processing_entry).expect("remove real processing entry");
    let sentinel = external.path().join("sentinel");
    fs::write(&sentinel, b"must remain").expect("write external sentinel");
    std::os::unix::fs::symlink(external.path(), &processing_entry)
        .expect("replace processing entry with symlink");

    super::recover_attachment_mutation_transaction()
        .expect_err("delete replay must reject a symlinked processing entry");
    assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"must remain");
    assert!(super::meta_path(&tenant, &meta.id).is_file());
    assert!(super::bin_path(&tenant, &meta.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());
}
#[cfg(unix)]
#[test]
fn delete_replay_rejects_a_missing_attachment_root_until_it_is_restored() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"delete":"root-move"}"#, 1);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
        .expect("persist delete intent");
    let root = super::attachments_root_dir();
    let detached = super::base_dir().join("zk_attachments.detached");
    fs::rename(&root, &detached).expect("detach attachment root");

    super::recover_attachment_mutation_transaction()
        .expect_err("delete replay must reject a missing attachment root");
    assert!(
        detached
            .join(tenant.as_str())
            .join(format!("{}.json", meta.id))
            .is_file()
    );
    assert!(
        detached
            .join(tenant.as_str())
            .join(format!("{}.bin", meta.id))
            .is_file()
    );
    assert!(super::attachment_mutation_transaction_path().is_file());

    fs::rename(&detached, &root).expect("restore attachment root");
    assert!(super::recover_attachment_mutation_transaction().expect("replay restored delete"));
    assert!(!super::meta_path(&tenant, &meta.id).exists());
    assert!(!super::bin_path(&tenant, &meta.id).exists());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn delete_replay_rejects_a_missing_processing_root_for_a_complete_pair() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"delete":"processing-move"}"#, 1);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
        .expect("persist delete intent");
    let root = super::base_dir().join("zk_prover");
    let detached = super::base_dir().join("zk_prover.detached");
    fs::rename(&root, &detached).expect("detach processing root");

    super::recover_attachment_mutation_transaction()
        .expect_err("a complete pair must retain its processing reference until deletion");
    assert!(super::meta_path(&tenant, &meta.id).is_file());
    assert!(super::bin_path(&tenant, &meta.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());

    fs::rename(&detached, &root).expect("restore processing root");
    assert!(super::recover_attachment_mutation_transaction().expect("replay restored delete"));
    assert!(!super::meta_path(&tenant, &meta.id).exists());
    assert!(!super::bin_path(&tenant, &meta.id).exists());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[cfg(unix)]
#[test]
fn delete_replay_resyncs_an_already_unlinked_file_in_a_nonempty_tenant() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let target = persist_canonical_test_attachment(&tenant, br#"{"delete":"target"}"#, 1);
    let sibling = persist_canonical_test_attachment(&tenant, br#"{"delete":"sibling"}"#, 2);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &target.id))
        .expect("persist delete intent");
    let _failure = super::fail_next_directory_sync(&super::attachments_dir(&tenant));

    super::recover_attachment_mutation_transaction()
        .expect_err("injected metadata-unlink sync failure must retain the delete intent");
    assert!(!super::meta_path(&tenant, &target.id).exists());
    assert!(super::bin_path(&tenant, &target.id).is_file());
    assert!(super::meta_path(&tenant, &sibling.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());

    let _replay_failure = super::fail_next_directory_sync(&super::attachments_dir(&tenant));
    super::recover_attachment_mutation_transaction()
        .expect_err("replay must resync the absent metadata entry before unlinking the body");
    assert!(
        super::bin_path(&tenant, &target.id).is_file(),
        "the replay sync must precede the remaining body unlink"
    );
    assert!(super::attachment_mutation_transaction_path().is_file());

    assert!(super::recover_attachment_mutation_transaction().expect("replay file unlink"));
    assert!(!super::meta_path(&tenant, &target.id).exists());
    assert!(!super::bin_path(&tenant, &target.id).exists());
    assert!(super::meta_path(&tenant, &sibling.id).is_file());
    assert!(super::bin_path(&tenant, &sibling.id).is_file());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[cfg(unix)]
#[test]
fn delete_replay_resyncs_an_already_unlinked_reference_with_a_sibling() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let first = super::AttachmentTenant("3".repeat(super::TENANT_KEY_HEX_LEN));
    let second = super::AttachmentTenant("4".repeat(super::TENANT_KEY_HEX_LEN));
    let body = br#"{"delete":"shared-reference"}"#;
    let first_meta = persist_canonical_test_attachment(&first, body, 1);
    let second_meta = persist_canonical_test_attachment(&second, body, 2);
    assert_eq!(first_meta.id, second_meta.id);
    super::persist_attachment_delete_transaction(&delete_transaction(&first, &first_meta.id))
        .expect("persist delete intent");
    let reference_dir = super::prover_processing_reference_dir(&first_meta.id);
    let _failure = super::fail_next_directory_sync(&reference_dir);

    super::recover_attachment_mutation_transaction()
        .expect_err("injected reference-unlink sync failure must retain the delete intent");
    assert!(!super::prover_processing_reference_path(first.as_str(), &first_meta.id).exists());
    assert!(super::prover_processing_reference_path(second.as_str(), &second_meta.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());

    let _replay_failure = super::fail_next_directory_sync(&reference_dir);
    super::recover_attachment_mutation_transaction()
        .expect_err("replay must resync the absent target reference");
    assert!(super::attachment_mutation_transaction_path().is_file());

    assert!(super::recover_attachment_mutation_transaction().expect("replay reference unlink"));
    assert!(super::meta_path(&second, &second_meta.id).is_file());
    assert!(super::bin_path(&second, &second_meta.id).is_file());
    assert!(super::prover_processing_reference_path(second.as_str(), &second_meta.id).is_file());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[cfg(unix)]
#[test]
fn delete_replay_resyncs_an_already_removed_tenant_directory() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"delete":"tenant"}"#, 1);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
        .expect("persist delete intent");
    let _failure = super::fail_next_directory_sync(&super::attachments_root_dir());

    super::recover_attachment_mutation_transaction()
        .expect_err("injected tenant-removal sync failure must retain the delete intent");
    assert!(!super::attachments_dir(&tenant).exists());
    assert!(super::attachment_mutation_transaction_path().is_file());

    let _replay_failure = super::fail_next_directory_sync(&super::attachments_root_dir());
    super::recover_attachment_mutation_transaction()
        .expect_err("replay must resync the absent tenant entry");
    assert!(super::attachment_mutation_transaction_path().is_file());

    assert!(super::recover_attachment_mutation_transaction().expect("replay tenant removal"));
    assert!(!super::attachments_dir(&tenant).exists());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn journal_absence_is_resynced_before_it_is_trusted_after_clear_failure() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"delete":"journal"}"#, 1);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
        .expect("persist delete intent");
    let _failure = super::fail_next_directory_sync(&super::attachment_mutation_transaction_dir());

    super::recover_attachment_mutation_transaction()
        .expect_err("injected journal-clear sync failure must remain observable");
    assert!(!super::attachment_mutation_transaction_path().exists());
    assert!(super::ATTACHMENT_MUTATION_DIRECTORY_DIRTY.load(std::sync::atomic::Ordering::Acquire));

    let _replay_failure =
        super::fail_next_directory_sync(&super::attachment_mutation_transaction_dir());
    super::load_attachment_mutation_transaction()
        .expect_err("absent journal must be resynced before it is trusted");
    assert!(super::ATTACHMENT_MUTATION_DIRECTORY_DIRTY.load(std::sync::atomic::Ordering::Acquire));

    assert!(
        super::load_attachment_mutation_transaction()
            .expect("resync absent journal")
            .is_none()
    );
    assert!(!super::ATTACHMENT_MUTATION_DIRECTORY_DIRTY.load(std::sync::atomic::Ordering::Acquire));
}
#[cfg(unix)]
#[test]
fn delete_replay_rejects_symlinked_tenant_without_touching_target() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let external = tempfile::tempdir().expect("external tenant target");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let meta = persist_canonical_test_attachment(&tenant, br#"{"delete":"tenant-link"}"#, 1);
    super::persist_attachment_delete_transaction(&delete_transaction(&tenant, &meta.id))
        .expect("persist delete intent");
    let tenant_dir = super::attachments_dir(&tenant);
    fs::remove_dir_all(&tenant_dir).expect("remove real tenant directory");
    let external_meta = external.path().join(format!("{}.json", meta.id));
    let external_body = external.path().join(format!("{}.bin", meta.id));
    fs::write(&external_meta, b"external metadata").expect("write external metadata");
    fs::write(&external_body, b"external body").expect("write external body");
    std::os::unix::fs::symlink(external.path(), &tenant_dir).expect("replace tenant with symlink");

    super::recover_attachment_mutation_transaction()
        .expect_err("delete replay must reject a symlinked tenant");
    assert_eq!(
        fs::read(&external_meta).expect("read external metadata"),
        b"external metadata"
    );
    assert_eq!(
        fs::read(&external_body).expect("read external body"),
        b"external body"
    );
    assert!(super::attachment_mutation_transaction_path().is_file());
}
#[test]
fn attachment_deletion_preserves_files_when_reference_unlink_fails() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant("4".repeat(super::TENANT_KEY_HEX_LEN));
    let id = "c".repeat(super::ATTACHMENT_ID_HEX_LEN);
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let meta_path = super::meta_path(&tenant, &id);
    let body_path = super::bin_path(&tenant, &id);
    fs::write(&meta_path, b"metadata").expect("write metadata marker");
    fs::write(&body_path, b"body").expect("write body marker");
    super::ensure_prover_processing_reference(tenant.as_str(), &id)
        .expect("register live attachment reference");
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: id.clone(),
        processed_ms: 1,
        terminal: true,
        retry_not_before_ms: None,
        retry_count: 0,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&receipt)
            .expect("persist terminal receipt")
    );
    let reference_path = super::prover_processing_reference_path(tenant.as_str(), &id);
    fs::remove_file(&reference_path).expect("remove reference fixture");
    fs::create_dir(&reference_path).expect("replace reference with an undeletable directory");

    super::delete_attachment_files(&tenant, &id)
        .expect_err("reference transition failure must abort attachment deletion");
    assert!(meta_path.is_file());
    assert!(body_path.is_file());
    assert_eq!(
        super::prover_processing_decision(&id, 1),
        super::ProverProcessingDecision::Suppress,
        "the receipt must survive an incomplete reference transition"
    );
}
#[test]
fn attachment_deletion_preserves_files_when_reference_enumeration_fails() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant("5".repeat(super::TENANT_KEY_HEX_LEN));
    let id = "d".repeat(super::ATTACHMENT_ID_HEX_LEN);
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let meta_path = super::meta_path(&tenant, &id);
    let body_path = super::bin_path(&tenant, &id);
    fs::write(&meta_path, b"metadata").expect("write metadata marker");
    fs::write(&body_path, b"body").expect("write body marker");
    super::ensure_prover_processing_reference(tenant.as_str(), &id)
        .expect("register live attachment reference");
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: id.clone(),
        processed_ms: 1,
        terminal: true,
        retry_not_before_ms: None,
        retry_count: 0,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&receipt)
            .expect("persist terminal receipt")
    );
    let reference_dir = super::prover_processing_reference_dir(&id);
    fs::remove_dir_all(&reference_dir).expect("remove reference-directory fixture");
    fs::write(&reference_dir, b"not a directory").expect("replace reference directory with a file");
    assert!(
        super::processing_reference_dir_has_shards(&id).is_err(),
        "reference enumeration errors must remain distinguishable from an empty directory"
    );

    super::delete_attachment_files(&tenant, &id)
        .expect_err("reference enumeration failure must abort attachment deletion");
    assert!(meta_path.is_file());
    assert!(body_path.is_file());
    assert_eq!(
        super::prover_processing_decision(&id, 1),
        super::ProverProcessingDecision::Suppress,
        "the receipt must survive an unreadable reference directory"
    );
}
#[test]
fn attachment_deletion_cleans_crash_left_processing_temp_files() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant("6".repeat(super::TENANT_KEY_HEX_LEN));
    let id = "e".repeat(super::ATTACHMENT_ID_HEX_LEN);
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let meta_path = super::meta_path(&tenant, &id);
    let body_path = super::bin_path(&tenant, &id);
    fs::write(&meta_path, b"metadata").expect("write metadata marker");
    fs::write(&body_path, b"body").expect("write body marker");
    super::ensure_prover_processing_reference(tenant.as_str(), &id)
        .expect("register live attachment reference");
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: id.clone(),
        processed_ms: 1,
        terminal: true,
        retry_not_before_ms: None,
        retry_count: 0,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&receipt)
            .expect("persist terminal receipt")
    );
    let state_entry_dir = super::prover_processing_state_dir().join(&id);
    let reference_dir = super::prover_processing_reference_dir(&id);
    fs::write(
        reference_dir.join(format!("{}ABC123", super::ZK_PROVER_PROCESSING_TEMP_PREFIX)),
        b"partial reference",
    )
    .expect("write crash-left reference temporary file");
    fs::write(
        state_entry_dir.join(format!("{}DEF456", super::ZK_PROVER_PROCESSING_TEMP_PREFIX)),
        b"partial receipt",
    )
    .expect("write crash-left receipt temporary file");

    super::delete_attachment_files(&tenant, &id)
        .expect("crash-left processing temporary files must not wedge deletion");
    assert!(!meta_path.exists());
    assert!(!body_path.exists());
    assert!(!state_entry_dir.exists());
    assert_eq!(
        super::prover_processing_decision(&id, 1),
        super::ProverProcessingDecision::Missing
    );
}
#[test]
fn prover_processing_retry_receipt_suppresses_until_its_deadline() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant("3".repeat(super::TENANT_KEY_HEX_LEN));
    let id = "b".repeat(super::ATTACHMENT_ID_HEX_LEN);
    super::ensure_dirs(&tenant).expect("create tenant directory");
    fs::write(super::meta_path(&tenant, &id), b"metadata").expect("write metadata marker");
    fs::write(super::bin_path(&tenant, &id), b"body").expect("write body marker");
    super::ensure_prover_processing_reference(tenant.as_str(), &id)
        .expect("register live attachment reference");
    let receipt = super::ProverProcessingReceipt {
        version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
        id: id.clone(),
        processed_ms: 10,
        terminal: false,
        retry_not_before_ms: Some(1_000),
        retry_count: 3,
        completed_proof_indices: Vec::new(),
        processing_context_hash: None,
    };
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&receipt)
            .expect("persist retry receipt")
    );
    assert_eq!(
        super::prover_processing_decision(&id, 999),
        super::ProverProcessingDecision::Suppress
    );
    assert_eq!(
        super::prover_processing_decision(&id, 1_000),
        super::ProverProcessingDecision::Due { retry_count: 3 }
    );
}
#[test]
fn sanitize_attachment_id_rejects_bad_inputs() {
    assert!(sanitize_attachment_id("../etc/passwd").is_none());
    assert!(sanitize_attachment_id("not-hex").is_none());
    assert!(sanitize_attachment_id(&"g".repeat(super::ATTACHMENT_ID_HEX_LEN)).is_none());
    let upper = "A".repeat(super::ATTACHMENT_ID_HEX_LEN);
    assert_eq!(
        sanitize_attachment_id(&upper),
        Some("a".repeat(super::ATTACHMENT_ID_HEX_LEN))
    );
}
#[tokio::test]
async fn get_attachment_rejects_invalid_id() {
    let response = super::handle_get_attachment(
        super::AttachmentTenant::anonymous(),
        axum::extract::Path("../bad".to_string()),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn attachment_read_apis_report_corrupt_metadata_as_storage_failure() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    super::ensure_dirs(&tenant).expect("create tenant directory");
    let id = "a".repeat(super::ATTACHMENT_ID_HEX_LEN);
    fs::write(super::meta_path(&tenant, &id), b"{not valid metadata")
        .expect("write corrupt metadata");

    let list = super::handle_list_attachments(tenant.clone())
        .await
        .into_response();
    assert_eq!(list.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let count = super::handle_count_attachments(
        tenant.clone(),
        crate::NoritoQuery(super::AttachmentListQuery::default()),
    )
    .await
    .into_response();
    assert_eq!(count.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let get = super::handle_get_attachment(tenant, axum::extract::Path(id))
        .await
        .into_response();
    assert_eq!(get.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[tokio::test]
async fn get_attachment_rejects_same_size_body_substitution() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"valid":true}"#;
    let substituted = br#"{"valid":null}"#;
    assert_eq!(body.len(), substituted.len());
    let meta = canonical_test_meta(&tenant, body);
    super::persist_body(&tenant, &meta.id, body).expect("persist canonical body");
    super::save_meta(&tenant, &meta).expect("persist canonical metadata");
    fs::write(super::bin_path(&tenant, &meta.id), substituted).expect("substitute same-size body");
    let response = super::handle_get_attachment(tenant, axum::extract::Path(meta.id))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn sanitizer_accepts_norito_magic() {
    let cfg = test_sanitizer_config(1024, 1);
    let body = b"NRT0test";
    let outcome = sanitize_attachment_sync(None, body, &cfg).expect("sanitized");
    assert_eq!(outcome.summary.sniffed_type, super::NORITO_MIME_TYPE);
    assert_eq!(outcome.summary.expanded_bytes, body.len() as u64);
}
#[test]
fn sanitizer_rejects_declared_mismatch() {
    let cfg = test_sanitizer_config(1024, 1);
    let body = b"NRT0test";
    let err = sanitize_attachment_sync(Some(super::JSON_MIME_TYPE), body, &cfg)
        .expect_err("mismatch rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Type);
}
#[test]
fn sanitizer_accepts_plus_json_declared_type() {
    let cfg = test_sanitizer_config(1024, 1);
    let body = br#"{"hello":"world"}"#;
    let outcome = sanitize_attachment_sync(Some("application/ld+json"), body, &cfg)
        .expect("plus-json should be accepted");
    assert_eq!(outcome.summary.sniffed_type, super::JSON_MIME_TYPE);
}
#[test]
fn sanitizer_rejects_expansion_limit() {
    let cfg = test_sanitizer_config(8, 2);
    let body = b"{\"hello\":\"world\"}";
    let gz = gzip_compress(body);
    let err = sanitize_attachment_sync(None, &gz, &cfg).expect_err("expansion rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Expansion);
}
#[test]
fn sanitizer_rejects_archive_depth() {
    let cfg = test_sanitizer_config(1024, 1);
    let body = b"{\"hello\":\"world\"}";
    let once = gzip_compress(body);
    let twice = gzip_compress(&once);
    let err = sanitize_attachment_sync(None, &twice, &cfg).expect_err("depth rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Expansion);
}
#[test]
fn sanitizer_limit_helpers_round_up() {
    assert_eq!(
        super::sanitizer_cpu_limit_secs(std::time::Duration::from_millis(1)),
        1
    );
    assert_eq!(
        super::sanitizer_cpu_limit_secs(std::time::Duration::from_millis(1001)),
        2
    );
    let min_limit = super::sanitizer_memory_limit_bytes(0);
    assert!(min_limit >= 64 * 1024 * 1024);
    let scaled_limit = super::sanitizer_memory_limit_bytes(16 * 1024 * 1024);
    assert!(scaled_limit > min_limit);
}
#[test]
fn sanitizer_executable_override_prefers_explicit_path() {
    let override_path = PathBuf::from("attachment_sanitizer_stub");
    let resolved = super::sanitizer_executable_with_override(Some(override_path.clone()))
        .expect("override path");
    assert_eq!(resolved, override_path);
}
#[test]
fn sanitizer_executable_defaults_to_dedicated_sibling() {
    let resolved = super::sanitizer_executable_with_override(None).expect("sanitizer path");
    let current = std::env::current_exe().expect("current exe");
    assert_ne!(resolved, current);
    assert_eq!(
        resolved,
        current.parent().expect("binary directory").join(format!(
            "{}{}",
            super::ATTACHMENT_SANITIZER_BINARY_STEM,
            std::env::consts::EXE_SUFFIX
        ))
    );
}
#[test]
fn validate_sanitizer_executable_rejects_missing_non_file_or_node_path() {
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("missing-sanitizer");
    let err = super::validate_sanitizer_executable(&missing).expect_err("missing path rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("attachment sanitizer spawn failed"));
    let err =
        super::validate_sanitizer_executable(temp.path()).expect_err("directory path rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("is not a file"));
    let current = std::env::current_exe().expect("current executable");
    let err = super::validate_sanitizer_executable(&current)
        .expect_err("node executable must be rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("dedicated executable"));
}
#[test]
fn sanitizer_command_environment_is_an_explicit_allowlist() {
    let mut cmd = Command::new("attachment_sanitizer");
    cmd.env("PRIVATE_KEY", "must-not-survive");
    super::set_clean_sanitizer_environment(&mut cmd, "4096");
    let envs: Vec<_> = cmd.get_envs().collect();
    assert_eq!(envs.len(), 3);
    assert!(
        envs.iter()
            .all(|(key, _)| *key != OsStr::new("PRIVATE_KEY"))
    );
    assert!(envs.iter().any(|(key, value)| {
        *key == OsStr::new(super::ATTACHMENT_SANITIZER_ENV) && *value == Some(OsStr::new("1"))
    }));
    assert!(envs.iter().any(|(key, value)| {
        *key == OsStr::new(super::ATTACHMENT_SANITIZER_MAX_INPUT_ENV)
            && *value == Some(OsStr::new("4096"))
    }));
    assert!(envs.iter().any(|(key, value)| {
        *key == OsStr::new(super::ATTACHMENT_SANITIZER_SANDBOXED_ENV)
            && *value == Some(OsStr::new("1"))
    }));
}
#[test]
fn sandboxed_sanitizer_command_fails_closed_without_wrapper_in_search_path() {
    let exe = PathBuf::from("attachment_sanitizer");
    let err = super::sandboxed_sanitizer_command_for_search_path(
        &exe,
        "4096",
        Some(OsStr::new("/definitely/missing")),
    )
    .expect_err("missing sandbox wrapper must reject");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("OS sandbox unavailable"));
}
#[cfg(target_os = "macos")]
#[test]
fn sandboxed_sanitizer_command_uses_sandbox_exec_on_macos() {
    let temp = tempfile::tempdir().expect("temp dir");
    let sandbox_exec = temp.path().join("sandbox-exec");
    fs::write(&sandbox_exec, "").expect("write fake sandbox-exec");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(&sandbox_exec)
            .expect("sandbox-exec metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&sandbox_exec, permissions).expect("make sandbox-exec executable");
    }
    let exe = PathBuf::from("attachment_sanitizer");
    let cmd = super::sandboxed_sanitizer_command_for_search_path(
        &exe,
        "4096",
        Some(temp.path().as_os_str()),
    )
    .expect("sandbox command");
    assert_eq!(cmd.get_program(), sandbox_exec.as_os_str());
    let args: Vec<_> = cmd.get_args().collect();
    assert_eq!(args.first().copied(), Some(OsStr::new("-p")));
    assert!(
        args.get(1)
            .and_then(|arg| arg.to_str())
            .is_some_and(|profile| profile.contains("(deny network*)")
                && profile.contains("(allow sysctl-read)")
                && !profile.contains("(allow file-read*)"))
    );
    assert_eq!(args.last().copied(), Some(exe.as_os_str()));
    let envs: Vec<_> = cmd.get_envs().collect();
    assert!(envs.iter().any(|(key, value)| {
        *key == OsStr::new(super::ATTACHMENT_SANITIZER_ENV) && *value == Some(OsStr::new("1"))
    }));
    assert!(envs.iter().any(|(key, value)| {
        *key == OsStr::new(super::ATTACHMENT_SANITIZER_SANDBOXED_ENV)
            && *value == Some(OsStr::new("1"))
    }));
}
#[cfg(target_os = "linux")]
#[test]
fn sandboxed_sanitizer_command_uses_bwrap_from_search_path() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bubblewrap = temp.path().join("bwrap");
    fs::write(&bubblewrap, "").expect("write fake bwrap");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(&bubblewrap)
            .expect("bwrap metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&bubblewrap, permissions).expect("make bwrap executable");
    }
    let exe = PathBuf::from("attachment_sanitizer");
    let cmd = super::sandboxed_sanitizer_command_for_search_path(
        &exe,
        "4096",
        Some(temp.path().as_os_str()),
    )
    .expect("sandbox command");
    assert_eq!(cmd.get_program(), bubblewrap.as_os_str());
    let args: Vec<_> = cmd.get_args().collect();
    assert!(
        args.iter()
            .any(|arg| *arg == OsStr::new("--die-with-parent"))
    );
    assert!(args.iter().any(|arg| *arg == OsStr::new("--clearenv")));
    assert!(args.iter().any(|arg| *arg == OsStr::new("--setenv")));
    assert_eq!(
        args.last().copied(),
        Some(OsStr::new("/attachment_sanitizer"))
    );
    assert!(
        !args.windows(3).any(|window| {
            window == [OsStr::new("--ro-bind"), OsStr::new("/"), OsStr::new("/")]
        }),
        "the sandbox must not expose the host root"
    );
}
#[test]
fn sanitizer_stdout_reader_rejects_oversized_response() {
    let mut within_limit = io::Cursor::new(b"1234".as_slice());
    assert_eq!(
        super::read_sanitizer_stdout_limited(&mut within_limit, 4).expect("bounded output"),
        b"1234"
    );
    let mut oversized = io::Cursor::new(b"12345".as_slice());
    let err = super::read_sanitizer_stdout_limited(&mut oversized, 4)
        .expect_err("oversized output rejected");
    assert!(err.contains("output exceeds 4 bytes"));
}
struct AlwaysErrReader;
impl io::Read for AlwaysErrReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
}
#[test]
fn read_limited_rejects_expired_deadline_before_read() {
    let err = super::read_limited(
        io::Cursor::new(b"hello".as_slice()),
        16,
        Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("one millisecond before the fixture clock"),
    )
    .expect_err("expired deadline");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert_eq!(err.message, "attachment sanitize timeout exceeded");
}
#[test]
fn read_limited_wraps_reader_error_as_checksum() {
    let err = super::read_limited(
        AlwaysErrReader,
        16,
        Instant::now() + Duration::from_millis(100),
    )
    .expect_err("reader error");
    assert_eq!(err.reason, SanitizeRejectReason::Checksum);
    assert!(err.message.contains("attachment decompress failed"));
}
#[test]
fn read_limited_rejects_oversized_output() {
    let err = super::read_limited(
        io::Cursor::new(b"hello".as_slice()),
        4,
        Instant::now() + Duration::from_millis(100),
    )
    .expect_err("oversized output");
    assert_eq!(err.reason, SanitizeRejectReason::Expansion);
    assert_eq!(
        err.message,
        "attachment expanded beyond max bytes (>4 bytes)"
    );
}
fn encode_sanitizer_response(response: &super::SanitizerResponse) -> Vec<u8> {
    crate::frame_test_support::assert_current_frame(
        response,
        "iroha_torii::zk_attachments::SanitizerResponse",
    )
}
fn canonical_sanitizer_request() -> super::SanitizerRequest {
    super::SanitizerRequest {
        declared_type: Some(super::JSON_MIME_TYPE.to_owned()),
        body: br#"{"hello":"world"}"#.to_vec(),
        allowed_mime_types: vec![super::JSON_MIME_TYPE.to_owned()],
        max_expanded_bytes: 1024,
        max_archive_depth: 1,
        timeout_ms: 500,
    }
}
#[test]
fn decode_sanitizer_request_bytes_accepts_exact_canonical_frame() {
    let expected = canonical_sanitizer_request();
    let bytes = crate::frame_test_support::assert_current_frame(
        &expected,
        "iroha_torii::zk_attachments::SanitizerRequest",
    );
    let decoded = super::decode_sanitizer_request_bytes(&bytes).expect("decode request");
    assert_eq!(decoded.declared_type, expected.declared_type);
    assert_eq!(decoded.body, expected.body);
    assert_eq!(decoded.allowed_mime_types, expected.allowed_mime_types);
    assert_eq!(decoded.max_expanded_bytes, expected.max_expanded_bytes);
    assert_eq!(decoded.max_archive_depth, expected.max_archive_depth);
    assert_eq!(decoded.timeout_ms, expected.timeout_ms);
}
#[test]
fn decode_sanitizer_request_bytes_rejects_truncated_frame() {
    let mut bytes =
        norito::encode_canonical(&canonical_sanitizer_request()).expect("encode canonical request");
    bytes.pop().expect("request frame is non-empty");
    let err = super::decode_sanitizer_request_bytes(&bytes)
        .expect_err("truncated request must fail closed");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("request decode failed"));
}
#[test]
fn decode_sanitizer_response_bytes_propagates_type_error() {
    let err = super::decode_sanitizer_response_bytes(&encode_sanitizer_response(
        &super::SanitizerResponse::Rejected {
            error: super::SanitizeErrorWire {
                reason: "type".to_string(),
                message: "unsupported attachment format".to_string(),
            },
        },
    ))
    .expect_err("type reject");
    assert_eq!(err.reason, SanitizeRejectReason::Type);
    assert_eq!(err.message, "unsupported attachment format");
}
#[test]
fn decode_sanitizer_response_bytes_accepts_success_response() {
    let outcome = super::decode_sanitizer_response_bytes(&encode_sanitizer_response(
        &super::SanitizerResponse::Accepted {
            summary: super::SanitizerSummary {
                sniffed_type: super::JSON_MIME_TYPE.to_string(),
                expanded_bytes: 17,
                archive_depth: 1,
                sandboxed: true,
            },
            sanitized_body: br#"{"hello":"world"}"#.to_vec(),
        },
    ))
    .expect("successful decode");
    assert_eq!(outcome.summary.sniffed_type, super::JSON_MIME_TYPE);
    assert_eq!(outcome.summary.expanded_bytes, 17);
    assert_eq!(outcome.summary.archive_depth, 1);
    assert!(outcome.summary.sandboxed);
    assert_eq!(outcome.sanitized_body, br#"{"hello":"world"}"#.to_vec());
}
#[test]
fn decode_sanitizer_response_bytes_maps_unknown_reason_to_sandbox() {
    let err = super::decode_sanitizer_response_bytes(&encode_sanitizer_response(
        &super::SanitizerResponse::Rejected {
            error: super::SanitizeErrorWire {
                reason: "mystery".to_string(),
                message: "unexpected failure".to_string(),
            },
        },
    ))
    .expect_err("unknown reject");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert_eq!(err.message, "unexpected failure");
}
#[test]
fn decode_sanitizer_response_bytes_rejects_truncated_frame() {
    let mut bytes = encode_sanitizer_response(&super::SanitizerResponse::Rejected {
        error: super::SanitizeErrorWire {
            reason: "sandbox".to_owned(),
            message: "rejected".to_owned(),
        },
    });
    bytes.pop().expect("response frame is non-empty");
    let err = super::decode_sanitizer_response_bytes(&bytes)
        .expect_err("truncated response must fail closed");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("response decode failed"));
}
#[test]
fn decode_sanitizer_response_bytes_rejects_well_framed_unknown_variant() {
    let frame = encode_sanitizer_response(&super::SanitizerResponse::Rejected {
        error: super::SanitizeErrorWire {
            reason: "sandbox".to_owned(),
            message: "rejected".to_owned(),
        },
    });
    let view = norito::core::from_bytes_view(&frame).expect("inspect canonical response");
    let flags = view.flags();
    let mut payload = view.as_bytes().to_vec();
    payload[..core::mem::size_of::<u32>()].copy_from_slice(&u32::MAX.to_le_bytes());
    let forged =
        norito::core::frame_bare_with_header_flags::<super::SanitizerResponse>(&payload, flags)
            .expect("frame response with an unknown variant");
    let err = super::decode_sanitizer_response_bytes(&forged)
        .expect_err("unknown response variants must fail closed");
    assert_eq!(err.reason, SanitizeRejectReason::Sandbox);
    assert!(err.message.contains("response decode failed"));
}
#[test]
fn sanitizer_rejects_fixture_gzip_bomb() {
    let cfg = test_sanitizer_config(64 * 1024, 2);
    let gz = load_fixture_base64("gzip_bomb_1m.b64");
    let err = sanitize_attachment_sync(None, &gz, &cfg).expect_err("expansion rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Expansion);
}
#[test]
fn sanitizer_rejects_fixture_zstd_nested_depth() {
    let cfg = test_sanitizer_config(4 * 1024 * 1024, 1);
    let payload = load_fixture_base64("zstd_nested_depth2.b64");
    let err = sanitize_attachment_sync(None, &payload, &cfg).expect_err("depth rejected");
    assert_eq!(err.reason, SanitizeRejectReason::Expansion);
}
#[test]
fn zk1_extract_tags_collects_tlv_tags() {
    let mut bytes = b"ZK1\0".to_vec();
    bytes.extend_from_slice(b"PROF");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(b"IPAK");
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    let tags = parse_zk1_tags(&bytes).expect("zk1 tags");
    assert_eq!(tags, vec!["PROF".to_string(), "IPAK".to_string()]);
}
#[test]
fn zk1_attachment_tag_extraction_rejects_excess_tlvs_without_partial_metadata() {
    let mut bytes = b"ZK1\0".to_vec();
    for _ in 0..ZK1_MAX_TLV_COUNT {
        bytes.extend_from_slice(b"PROF");
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(parse_zk1_tags(&bytes), Ok(vec!["PROF".to_owned()]));
    bytes.extend_from_slice(b"IPAK");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    assert!(parse_zk1_tags(&bytes).is_err());
}
#[test]
fn attachment_meta_tag_filter_requires_the_ingest_index() {
    let tenant = super::AttachmentTenant::anonymous();
    let mut meta = AttachmentMeta {
        id: "deadbeef".repeat(8),
        content_type: super::ZK1_MIME_TYPE.to_string(),
        size: 8,
        created_ms: 1_700_000_000_000,
        tenant: Some(tenant.as_str().to_string()),
        provenance: None,
        zk1_tags: None,
    };
    assert!(!super::attachment_meta_has_tag(&meta, "PROF"));
    meta.zk1_tags = Some(vec!["PROF".to_string()]);
    assert!(super::attachment_meta_has_tag(&meta, "PROF"));
    assert!(!super::attachment_meta_has_tag(&meta, "IPAK"));
}
#[test]
fn needs_export_sanitization_flags_missing_or_nested() {
    let base = AttachmentMeta {
        id: "deadbeef".repeat(4),
        content_type: super::JSON_MIME_TYPE.to_string(),
        size: 8,
        created_ms: 1_700_000_000_000,
        tenant: None,
        provenance: None,
        zk1_tags: None,
    };
    assert!(super::needs_export_sanitization(&base));
    let mut meta = base;
    meta.provenance = Some(AttachmentProvenance {
        declared_type: Some(super::JSON_MIME_TYPE.to_string()),
        sniffed_type: super::JSON_MIME_TYPE.to_string(),
        hashes: AttachmentHashes {
            blake2b_256: "a".repeat(64),
            sha256: "b".repeat(64),
        },
        sanitizer: AttachmentSanitizerVerdict {
            verdict: "accepted".to_string(),
            expanded_bytes: 8,
            archive_depth: 1,
            sandboxed: false,
        },
    });
    assert!(super::needs_export_sanitization(&meta));
    if let Some(provenance) = meta.provenance.as_mut() {
        provenance.sanitizer.archive_depth = 0;
    }
    assert!(!super::needs_export_sanitization(&meta));
}
#[tokio::test]
async fn post_attachment_records_provenance() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    let body = axum::body::Bytes::from_static(br#"{"hello":"world"}"#);
    let response =
        super::handle_post_attachment(super::AttachmentTenant::anonymous(), headers, body)
            .await
            .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);
    let meta_bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let meta_text = std::str::from_utf8(&meta_bytes).expect("utf8");
    let meta: AttachmentMeta = json::from_json(meta_text).expect("meta");
    assert_eq!(meta.content_type, super::JSON_MIME_TYPE);
    let provenance = meta.provenance.expect("provenance");
    assert_eq!(provenance.sniffed_type, super::JSON_MIME_TYPE);
    assert_eq!(
        provenance.declared_type.as_deref(),
        Some(super::JSON_MIME_TYPE)
    );
    assert_eq!(provenance.sanitizer.verdict, "accepted");
    assert_eq!(provenance.sanitizer.archive_depth, 0);
}
#[tokio::test]
async fn compressed_attachment_cannot_expand_beyond_per_item_storage_cap() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let tenant = super::AttachmentTenant::anonymous();
    let expanded = format!(r#"{{"padding":"{}"}}"#, "x".repeat(2_000)).into_bytes();
    assert!(expanded.len() > super::max_bytes_cfg());
    assert!(expanded.len() as u64 <= super::max_expanded_bytes_cfg());
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&expanded)
        .expect("compress oversized canonical attachment");
    let compressed = encoder.finish().expect("finish attachment compression");
    assert!(compressed.len() <= super::max_bytes_cfg());

    let response = super::handle_post_attachment(
        tenant.clone(),
        HeaderMap::new(),
        axum::body::Bytes::from(compressed),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        super::list_all_ids(&tenant).is_empty(),
        "an expanded body above the per-item cap must not be persisted"
    );
    assert!(
        !super::attachments_dir(&tenant).exists(),
        "a rejected expanded body must not leave a tenant directory"
    );
}
#[test]
fn quota_transaction_validation_rejects_duplicate_and_unbounded_victim_sets() {
    let tenant = super::AttachmentTenant("a".repeat(super::TENANT_KEY_HEX_LEN));
    let incoming = canonical_test_meta(&tenant, br#"{"incoming":true}"#);
    let victim = "b".repeat(super::ATTACHMENT_ID_HEX_LEN);
    let no_eviction = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::validate_attachment_quota_transaction(&no_eviction)
        .expect("every write is journaled even when it has no eviction victims");
    let duplicate = quota_transaction(
        &tenant,
        incoming.clone(),
        None,
        vec![victim.clone(), victim.clone()],
    );
    assert_eq!(
        super::validate_attachment_quota_transaction(&duplicate)
            .expect_err("duplicate victims must be rejected")
            .kind(),
        io::ErrorKind::InvalidData
    );

    let too_many = quota_transaction(
        &tenant,
        incoming,
        None,
        vec![
            victim;
            usize::try_from(super::ATTACHMENT_META_SCAN_MAX_FILES)
                .expect("test scan bound fits usize")
                + 1
        ],
    );
    assert_eq!(
        super::validate_attachment_quota_transaction(&too_many)
            .expect_err("unbounded victim sets must be rejected")
            .kind(),
        io::ErrorKind::InvalidData
    );
}
#[test]
fn mutation_journal_rejects_a_second_operation_kind() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let incoming = canonical_test_meta(&tenant, br#"{"journal":"write"}"#);
    let write = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::persist_attachment_quota_transaction(&write).expect("persist write mutation");

    let error =
        super::persist_attachment_delete_transaction(&delete_transaction(&tenant, incoming.id))
            .expect_err("one mutation journal cannot contain an ambiguous second operation");
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert!(matches!(
        super::load_attachment_mutation_transaction().expect("load retained mutation"),
        Some(super::AttachmentMutationTransaction::Write(retained)) if *retained == write
    ));
    super::clear_attachment_mutation_transaction().expect("clear test mutation");
}
#[tokio::test]
async fn pending_write_is_hidden_until_processing_reference_publication_completes() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"journal":"hidden-write"}"#;
    let incoming = canonical_test_meta(&tenant, body);
    let write = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::persist_attachment_quota_transaction(&write).expect("persist write mutation");
    super::persist_body(&tenant, &incoming.id, body).expect("persist incoming body");
    super::ensure_direct_directory(&super::prover_processing_state_dir())
        .expect("create processing state directory");
    let reference_obstruction = super::prover_processing_state_dir().join(&incoming.id);
    fs::write(&reference_obstruction, b"blocks processing entry")
        .expect("obstruct reference publication");

    super::save_meta(&tenant, &incoming)
        .expect_err("processing-reference failure must retain the write mutation");
    assert_eq!(
        super::try_load_meta_raw(&tenant, &incoming.id).expect("load raw committed metadata"),
        Some(incoming.clone())
    );
    assert!(
        super::try_load_meta(&tenant, &incoming.id)
            .expect("load public metadata")
            .is_none(),
        "the uncommitted write must not be publicly visible"
    );
    assert!(
        !super::attachment_pair_exists(tenant.as_str(), &incoming.id)
            .expect("resolve prover visibility"),
        "the prover must not discover an uncommitted write"
    );
    assert!(super::attachment_mutation_transaction_path().is_file());

    let list = super::handle_list_attachments(tenant.clone())
        .await
        .into_response();
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = list
        .into_body()
        .collect()
        .await
        .expect("collect attachment list")
        .to_bytes();
    let listed: Vec<AttachmentMeta> = json::from_slice(&list_body).expect("decode attachment list");
    assert!(listed.is_empty(), "list must hide the pending write");

    let count = super::handle_count_attachments(
        tenant.clone(),
        crate::NoritoQuery(super::AttachmentListQuery::default()),
    )
    .await
    .into_response();
    assert_eq!(count.status(), StatusCode::OK);
    let count_body = count
        .into_body()
        .collect()
        .await
        .expect("collect attachment count")
        .to_bytes();
    let counted: json::Value = json::from_slice(&count_body).expect("decode attachment count");
    assert_eq!(counted.get("count").and_then(json::Value::as_u64), Some(0));

    let get =
        super::handle_get_attachment(tenant.clone(), axum::extract::Path(incoming.id.clone()))
            .await
            .into_response();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);

    fs::remove_file(reference_obstruction).expect("repair reference publication");
    assert!(super::recover_attachment_quota_transaction().expect("complete repaired write"));
    assert_eq!(
        super::try_load_meta(&tenant, &incoming.id).expect("load committed metadata"),
        Some(incoming)
    );
    assert!(
        super::attachment_pair_exists(tenant.as_str(), &write.incoming_meta.id)
            .expect("resolve committed prover visibility")
    );
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn write_replay_resyncs_metadata_publication_before_clearing_the_journal() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"journal":"metadata-sync"}"#;
    let incoming = canonical_test_meta(&tenant, body);
    let write = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::persist_attachment_quota_transaction(&write).expect("persist write mutation");
    super::persist_body(&tenant, &incoming.id, body).expect("persist incoming body");
    let _failure = super::fail_next_directory_sync(&super::attachments_dir(&tenant));

    super::save_meta(&tenant, &incoming)
        .expect_err("injected metadata-publication sync failure must retain the journal");
    assert!(super::meta_path(&tenant, &incoming.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());

    let _replay_failure = super::fail_next_directory_sync(&super::attachments_dir(&tenant));
    super::recover_attachment_quota_transaction()
        .expect_err("replay must resync the complete incoming pair");
    assert!(super::attachment_mutation_transaction_path().is_file());

    assert!(super::recover_attachment_quota_transaction().expect("replay metadata publish"));
    assert_eq!(
        super::try_load_meta(&tenant, &incoming.id).expect("load committed metadata"),
        Some(incoming)
    );
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn write_replay_resyncs_existing_processing_marker_before_clearing_the_journal() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"journal":"reference-sync"}"#;
    let incoming = canonical_test_meta(&tenant, body);
    let write = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::persist_attachment_quota_transaction(&write).expect("persist write mutation");
    super::persist_body(&tenant, &incoming.id, body).expect("persist incoming body");
    let _failure =
        super::fail_next_directory_sync(&super::prover_processing_reference_dir(&incoming.id));

    super::save_meta(&tenant, &incoming)
        .expect_err("injected reference-publication sync failure must retain the journal");
    assert!(super::prover_processing_reference_path(tenant.as_str(), &incoming.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());

    let _replay_failure =
        super::fail_next_directory_sync(&super::prover_processing_reference_dir(&incoming.id));
    super::recover_attachment_quota_transaction()
        .expect_err("replay must resync the existing processing marker");
    assert!(super::attachment_mutation_transaction_path().is_file());

    assert!(super::recover_attachment_quota_transaction().expect("replay reference publish"));
    assert_eq!(
        super::try_load_meta(&tenant, &incoming.id).expect("load committed metadata"),
        Some(incoming)
    );
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn quota_recovery_rejects_oversized_journal_without_mutating_attachments() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(0x57));
    let victim = persist_canonical_test_attachment(&tenant, br#"{"victim":"untouched"}"#, 1);
    super::ensure_attachment_mutation_transaction_dir_durable()
        .expect("create durable transaction directory");
    fs::write(
        super::attachment_mutation_transaction_path(),
        vec![
            b'x';
            usize::try_from(super::ATTACHMENT_MUTATION_TRANSACTION_MAX_BYTES)
                .expect("test journal bound fits usize")
                + 1
        ],
    )
    .expect("write oversized quota journal");

    assert!(super::recover_attachment_quota_transaction().is_err());
    assert!(
        super::init_persistence().is_err(),
        "startup recovery failure must be visible to worker orchestration"
    );
    assert!(super::meta_path(&tenant, &victim.id).is_file());
    assert!(super::bin_path(&tenant, &victim.id).is_file());
    assert!(super::attachment_mutation_transaction_path().is_file());
}
#[test]
fn quota_recovery_rolls_back_partial_incoming_and_preserves_victims() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(0x54));
    let victim_body = br#"{"victim":"preserved"}"#;
    let victim = persist_canonical_test_attachment(&tenant, victim_body, 1);
    let incoming_body = br#"{"incoming":"partial"}"#;
    let incoming = canonical_test_meta(&tenant, incoming_body);
    let transaction = quota_transaction(&tenant, incoming.clone(), None, vec![victim.id.clone()]);
    super::persist_attachment_quota_transaction(&transaction)
        .expect("persist quota transaction intent");
    super::persist_body(&tenant, &incoming.id, incoming_body)
        .expect("persist only the incoming body phase");

    assert!(super::recover_attachment_quota_transaction().expect("recover partial transaction"));
    assert!(super::meta_path(&tenant, &victim.id).is_file());
    assert!(super::bin_path(&tenant, &victim.id).is_file());
    assert!(!super::meta_path(&tenant, &incoming.id).exists());
    assert!(!super::bin_path(&tenant, &incoming.id).exists());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn write_recovery_removes_partial_body_without_eviction_victims() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"ordinary":"partial-write"}"#;
    let incoming = canonical_test_meta(&tenant, body);
    let transaction = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::persist_attachment_quota_transaction(&transaction)
        .expect("persist ordinary write intent");
    super::persist_body(&tenant, &incoming.id, body).expect("persist body phase only");

    assert!(super::recover_attachment_quota_transaction().expect("recover ordinary partial write"));
    assert!(!super::meta_path(&tenant, &incoming.id).exists());
    assert!(!super::bin_path(&tenant, &incoming.id).exists());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn quota_recovery_restores_previous_metadata_for_partial_repost() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(0x55));
    let victim =
        persist_canonical_test_attachment(&tenant, br#"{"victim":"preserved-on-repost"}"#, 1);
    let incoming_body = br#"{"incoming":"same-id-repost"}"#;
    let previous = persist_canonical_test_attachment(&tenant, incoming_body, 2);
    let mut replacement = previous.clone();
    replacement.created_ms = 3;
    let transaction = quota_transaction(
        &tenant,
        replacement,
        Some(previous.clone()),
        vec![victim.id.clone()],
    );
    super::persist_attachment_quota_transaction(&transaction)
        .expect("persist repost quota transaction intent");
    super::persist_body(&tenant, &previous.id, incoming_body)
        .expect("persist repost body phase only");

    assert!(super::recover_attachment_quota_transaction().expect("recover partial repost"));
    assert_eq!(
        super::try_load_meta(&tenant, &previous.id).expect("load restored metadata"),
        Some(previous)
    );
    assert!(super::meta_path(&tenant, &victim.id).is_file());
    assert!(super::bin_path(&tenant, &victim.id).is_file());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn quota_recovery_finalizes_evictions_after_complete_incoming_commit() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(0x56));
    let victim = persist_canonical_test_attachment(&tenant, br#"{"victim":"evicted"}"#, 1);
    let incoming_body = br#"{"incoming":"complete"}"#;
    let incoming = canonical_test_meta(&tenant, incoming_body);
    let transaction = quota_transaction(&tenant, incoming.clone(), None, vec![victim.id.clone()]);
    super::persist_attachment_quota_transaction(&transaction)
        .expect("persist quota transaction intent");
    super::persist_body(&tenant, &incoming.id, incoming_body).expect("persist incoming body");
    super::save_meta(&tenant, &incoming).expect("persist incoming metadata");

    assert!(super::recover_attachment_quota_transaction().expect("recover complete transaction"));
    assert!(super::meta_path(&tenant, &incoming.id).is_file());
    assert!(super::bin_path(&tenant, &incoming.id).is_file());
    assert!(!super::meta_path(&tenant, &victim.id).exists());
    assert!(!super::bin_path(&tenant, &victim.id).exists());
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[test]
fn write_recovery_retains_intent_when_committed_body_is_corrupt() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"incoming":"complete"}"#;
    let incoming = canonical_test_meta(&tenant, body);
    let transaction = quota_transaction(&tenant, incoming.clone(), None, Vec::new());
    super::persist_attachment_quota_transaction(&transaction).expect("persist write intent");
    super::persist_body(&tenant, &incoming.id, body).expect("persist body");
    super::save_meta(&tenant, &incoming).expect("persist metadata");
    let mut corrupt = body.to_vec();
    corrupt[0] ^= 1;
    fs::write(super::bin_path(&tenant, &incoming.id), corrupt).expect("corrupt body");

    assert!(super::recover_attachment_quota_transaction().is_err());
    assert!(
        super::attachment_mutation_transaction_path().is_file(),
        "corruption must leave the durable recovery intent pending"
    );
}
#[tokio::test]
async fn global_count_quota_evicts_only_the_submitting_tenant() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let first = super::AttachmentTenant::from_account(&checked_attachment_account(0x51));
    let second = super::AttachmentTenant::from_account(&checked_attachment_account(0x52));
    let third = super::AttachmentTenant::from_account(&checked_attachment_account(0x53));

    let mut first_oldest = None;
    for index in 0..10 {
        let body = format!(r#"{{"tenant":"first","index":{index}}}"#).into_bytes();
        let meta = persist_canonical_test_attachment(
            &first,
            &body,
            u64::try_from(index).expect("test index fits u64") + 1,
        );
        if index == 0 {
            first_oldest = Some(meta.id);
        }
    }
    for index in 0..10 {
        let body = format!(r#"{{"tenant":"second","index":{index}}}"#).into_bytes();
        persist_canonical_test_attachment(
            &second,
            &body,
            u64::try_from(index).expect("test index fits u64") + 100,
        );
    }
    let second_before = super::list_all_ids(&second)
        .into_iter()
        .collect::<BTreeSet<_>>();

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = super::handle_post_attachment(
        first.clone(),
        headers.clone(),
        axum::body::Bytes::from_static(br#"{"tenant":"first","index":10}"#),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(super::list_all_ids(&first).len(), 10);
    assert!(
        !super::meta_path(&first, &first_oldest.expect("oldest first-tenant id")).exists(),
        "the submitting tenant's oldest entry should make room"
    );
    assert_eq!(
        super::list_all_ids(&second)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        second_before,
        "same-tenant replacement must not evict another tenant"
    );
    let first_before_rejection = super::list_all_ids(&first)
        .into_iter()
        .collect::<BTreeSet<_>>();

    let response = super::handle_post_attachment(
        third.clone(),
        headers,
        axum::body::Bytes::from_static(br#"{"tenant":"third","index":0}"#),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(super::list_all_ids(&third).is_empty());
    assert_eq!(
        super::list_all_ids(&first)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        first_before_rejection,
        "global exhaustion must reject before deleting another tenant's data"
    );
    assert_eq!(
        super::list_all_ids(&second)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        second_before,
        "global exhaustion must preserve all non-submitting tenants"
    );
}
#[tokio::test]
async fn quota_victims_survive_incoming_persistence_failure() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(0x5a));
    for index in 0..10 {
        let body = format!(r#"{{"retained":{index}}}"#).into_bytes();
        persist_canonical_test_attachment(
            &tenant,
            &body,
            u64::try_from(index).expect("test index fits u64") + 1,
        );
    }
    let retained_before = super::list_all_ids(&tenant)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let incoming = br#"{"incoming":"must-fail-before-eviction"}"#;
    let incoming_id = canonical_test_meta(&tenant, incoming).id;
    let _failure = super::fail_next_directory_sync(&super::attachments_dir(&tenant));
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    let response = super::handle_post_attachment(
        tenant.clone(),
        headers,
        axum::body::Bytes::from_static(incoming),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        super::list_all_ids(&tenant)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        retained_before,
        "a failed incoming write must not delete any planned quota victim"
    );
    assert!(!super::meta_path(&tenant, &incoming_id).exists());
    assert!(
        !super::bin_path(&tenant, &incoming_id).exists(),
        "the incomplete incoming write must be rolled back"
    );
    assert!(!super::attachment_mutation_transaction_path().exists());
}
#[tokio::test]
async fn quota_eviction_failure_returns_error_and_retains_recovery_intent() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(0x5b));
    let mut oldest = None;
    for index in 0..10 {
        let body = format!(r#"{{"retained":{index}}}"#).into_bytes();
        let meta = persist_canonical_test_attachment(
            &tenant,
            &body,
            u64::try_from(index).expect("test index fits u64") + 1,
        );
        if index == 0 {
            oldest = Some(meta.id);
        }
    }
    let oldest = oldest.expect("oldest quota victim");
    // Fail only during victim removal, after the incoming pair and recovery
    // intent are durable. A malformed victim would be rejected at admission.
    let _failure =
        super::fail_next_directory_sync(&super::prover_processing_reference_dir(&oldest));
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let incoming = br#"{"incoming":"durable-before-eviction"}"#;
    let incoming_id = canonical_test_meta(&tenant, incoming).id;

    let response = super::handle_post_attachment(
        tenant.clone(),
        headers,
        axum::body::Bytes::from_static(incoming),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(super::meta_path(&tenant, &incoming_id).is_file());
    assert!(super::bin_path(&tenant, &incoming_id).is_file());
    assert!(
        super::attachment_mutation_transaction_path().is_file(),
        "failed eviction must retain its durable recovery intent"
    );

    assert!(
        super::recover_attachment_quota_transaction()
            .expect("retry durable quota eviction after fault repair")
    );
    assert!(!super::attachment_mutation_transaction_path().exists());
    assert!(!super::meta_path(&tenant, &oldest).exists());
    assert!(!super::bin_path(&tenant, &oldest).exists());
    assert_eq!(super::list_all_ids(&tenant).len(), 10);
}
#[tokio::test]
async fn global_byte_quota_rejects_cross_tenant_growth_without_eviction() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let first = super::AttachmentTenant::from_account(&checked_attachment_account(0x61));
    let second = super::AttachmentTenant::from_account(&checked_attachment_account(0x62));
    let third = super::AttachmentTenant::from_account(&checked_attachment_account(0x63));
    for index in 0..4 {
        let body = padded_json_body("first", index, 1_000);
        persist_canonical_test_attachment(
            &first,
            &body,
            u64::try_from(index).expect("test index fits u64") + 1,
        );
        let body = padded_json_body("second", index, 1_000);
        persist_canonical_test_attachment(
            &second,
            &body,
            u64::try_from(index).expect("test index fits u64") + 100,
        );
    }
    let first_before = super::list_all_ids(&first)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let second_before = super::list_all_ids(&second)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = super::handle_post_attachment(
        third.clone(),
        headers,
        axum::body::Bytes::from(padded_json_body("third", 0, 300)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(super::list_all_ids(&third).is_empty());
    assert_eq!(
        super::list_all_ids(&first)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        first_before
    );
    assert_eq!(
        super::list_all_ids(&second)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        second_before
    );
}
#[tokio::test]
async fn obstructed_delete_latches_mutations_until_recovery_succeeds() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let tenant = super::AttachmentTenant::anonymous();
    let original = br#"{"delete":"partial"}"#;
    let original_meta = persist_canonical_test_attachment(&tenant, original, 1);
    let body_path = super::bin_path(&tenant, &original_meta.id);
    fs::remove_file(&body_path).expect("replace body with deletion obstruction");
    fs::create_dir(&body_path).expect("create body deletion obstruction");
    let obstruction = body_path.join("still-present");
    fs::write(&obstruction, b"block deletion").expect("populate deletion obstruction");

    let response = super::handle_delete_attachment(
        tenant.clone(),
        axum::extract::Path(original_meta.id.clone()),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        super::meta_path(&tenant, &original_meta.id).is_file(),
        "prevalidation must retain the safe half of an obstructed pair"
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let replacement = axum::body::Bytes::from_static(br#"{"delete":"recovered"}"#);
    let blocked =
        super::handle_post_attachment(tenant.clone(), headers.clone(), replacement.clone())
            .await
            .into_response();
    assert_eq!(
        blocked.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "an obstructed delete must keep later mutations fail-closed"
    );

    fs::remove_file(&obstruction).expect("remove obstruction contents");
    fs::remove_dir(&body_path).expect("remove obstruction directory");
    let recovered = super::handle_post_attachment(tenant, headers, replacement)
        .await
        .into_response();
    assert_eq!(recovered.status(), StatusCode::CREATED);
}
#[tokio::test]
async fn attachment_tenant_churn_does_not_leave_empty_quota_directories() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    ensure_test_config();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    for index in 0_u8..32 {
        let tenant = super::AttachmentTenant::from_account(&checked_attachment_account(
            index.saturating_add(0x80),
        ));
        let body = format!(r#"{{"tenant_churn":{index}}}"#).into_bytes();
        let id = canonical_test_meta(&tenant, &body).id;
        let response = super::handle_post_attachment(
            tenant.clone(),
            headers.clone(),
            axum::body::Bytes::from(body),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(super::attachments_dir(&tenant).is_dir());

        let response = super::handle_delete_attachment(tenant.clone(), axum::extract::Path(id))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            !super::attachments_dir(&tenant).exists(),
            "deleted tenant {index} left an empty quota directory"
        );
    }
    assert_eq!(
        fs::read_dir(super::attachments_root_dir())
            .expect("read attachment root after churn")
            .count(),
        0,
        "tenant churn must not accumulate unaccounted root entries"
    );
}
#[tokio::test]
async fn same_id_repost_at_quota_preserves_processing_receipt() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::anonymous();
    let mut target: Option<(AttachmentMeta, Vec<u8>)> = None;
    for index in 0..10 {
        let body = format!(r#"{{"attachment":{index}}}"#).into_bytes();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let response = super::handle_post_attachment(
            tenant.clone(),
            headers,
            axum::body::Bytes::from(body.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let meta_bytes = response
            .into_body()
            .collect()
            .await
            .expect("attachment response")
            .to_bytes();
        let meta: AttachmentMeta =
            json::from_json(std::str::from_utf8(&meta_bytes).expect("attachment metadata UTF-8"))
                .expect("attachment metadata JSON");
        if index == 0 {
            target = Some((meta, body));
        }
    }
    let (mut target_meta, target_body) = target.expect("target attachment");
    target_meta.created_ms = 0;
    super::save_meta(&tenant, &target_meta).expect("make target the oldest quota entry");
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&super::ProverProcessingReceipt {
            version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
            id: target_meta.id.clone(),
            processed_ms: 1,
            terminal: true,
            retry_not_before_ms: None,
            retry_count: 0,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        })
        .expect("persist terminal processing receipt")
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = super::handle_post_attachment(
        tenant.clone(),
        headers,
        axum::body::Bytes::from(target_body),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(super::list_all_ids(&tenant).len(), 10);
    assert_eq!(
        super::prover_processing_decision(&target_meta.id, u64::MAX),
        super::ProverProcessingDecision::Suppress,
        "reposting identical content must not evict its durable processing state"
    );
}
#[tokio::test]
async fn gc_rechecks_expiry_after_waiting_for_a_repost() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let tenant = super::AttachmentTenant::anonymous();
    let body = br#"{"attachment":"gc-race"}"#.to_vec();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response =
        super::handle_post_attachment(tenant.clone(), headers, axum::body::Bytes::from(body))
            .await
            .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);
    let meta_bytes = response
        .into_body()
        .collect()
        .await
        .expect("attachment response")
        .to_bytes();
    let mut meta: AttachmentMeta =
        json::from_json(std::str::from_utf8(&meta_bytes).expect("attachment metadata UTF-8"))
            .expect("attachment metadata JSON");
    meta.created_ms = 0;
    super::save_meta(&tenant, &meta).expect("mark attachment as initially expired");
    assert!(
        super::persist_prover_processing_receipt_if_referenced(&super::ProverProcessingReceipt {
            version: super::ZK_PROVER_PROCESSING_STATE_VERSION,
            id: meta.id.clone(),
            processed_ms: 1,
            terminal: true,
            retry_not_before_ms: None,
            retry_count: 0,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        })
        .expect("persist terminal processing receipt")
    );

    let mutation_guard = super::quota_lock().lock().await;
    let gc_tenant = tenant.clone();
    let gc_id = meta.id.clone();
    let (before_lock_tx, before_lock_rx) = tokio::sync::oneshot::channel();
    let gc = tokio::spawn(async move {
        super::delete_attachment_if_expired_with_before_lock(
            &gc_tenant,
            &gc_id,
            Duration::from_secs(60),
            move || {
                let _ = before_lock_tx.send(());
            },
        )
        .await
    });
    before_lock_rx
        .await
        .expect("GC task reaches the shared mutation lock");
    meta.created_ms = crate::utils::unix_now_ms();
    super::save_meta(&tenant, &meta).expect("refresh attachment metadata during repost");
    drop(mutation_guard);

    assert!(
        !gc.await
            .expect("GC task joins")
            .expect("GC recheck succeeds"),
        "GC must not delete content refreshed while it waited for the mutation lock"
    );
    assert!(super::meta_path(&tenant, &meta.id).is_file());
    assert!(super::bin_path(&tenant, &meta.id).is_file());
    assert_eq!(
        super::prover_processing_decision(&meta.id, u64::MAX),
        super::ProverProcessingDecision::Suppress
    );
}
#[tokio::test]
async fn post_attachment_rejects_over_cardinality_zk1_before_persistence() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    let mut envelope = b"ZK1\0".to_vec();
    for _ in 0..=ZK1_MAX_TLV_COUNT {
        envelope.extend_from_slice(b"PROF");
        envelope.extend_from_slice(&0u32.to_le_bytes());
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-zk1"),
    );
    let response = super::handle_post_attachment(
        super::AttachmentTenant::anonymous(),
        headers,
        axum::body::Bytes::from(envelope),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        super::list_all_ids(&super::AttachmentTenant::anonymous()).is_empty(),
        "a rejected envelope must not create attachment state"
    );
}
#[tokio::test]
async fn get_attachment_resanitizes_compressed_exports() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let _guard = crate::data_dir::OverrideGuard::new(tmp.path());
    ensure_test_config();
    super::init_persistence().expect("attachment persistence preflight");
    let payload = br#"{"hello":"world"}"#;
    let compressed = gzip_compress(payload);
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = super::handle_post_attachment(
        super::AttachmentTenant::anonymous(),
        headers,
        axum::body::Bytes::from(compressed),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);
    let meta_bytes = response
        .into_body()
        .collect()
        .await
        .expect("meta body")
        .to_bytes();
    let meta_text = std::str::from_utf8(&meta_bytes).expect("utf8 meta");
    let meta: AttachmentMeta = json::from_json(meta_text).expect("meta");
    let expected_id = hex::encode::<[u8; 32]>(Hash::new(payload).into());
    assert_eq!(meta.id, expected_id);
    assert_eq!(meta.size, payload.len() as u64);
    let provenance = meta.provenance.expect("provenance");
    assert!(provenance.sanitizer.archive_depth > 0);
    let response = super::handle_get_attachment(
        super::AttachmentTenant::anonymous(),
        axum::extract::Path(meta.id.clone()),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("body bytes")
        .to_bytes();
    assert_eq!(body_bytes.as_ref(), payload);
}
