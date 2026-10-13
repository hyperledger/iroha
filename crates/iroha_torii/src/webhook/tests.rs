//! Webhook persistence, delivery, and network policy tests.

use super::*;
use crate::test_utils::TestDataDirGuard;
use http_body_util::BodyExt as _;
use iroha_crypto::Hash;
use iroha_data_model::events::{
    EventBox,
    pipeline::{TransactionEvent, TransactionStatus},
};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use std::sync::{Barrier, MutexGuard};
use std::{
    collections::HashSet,
    convert::TryFrom,
    fs,
    sync::{Arc, Mutex},
};
use tokio::{
    runtime::Runtime,
    time::{Duration, sleep},
};
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn write_private_test_file(path: &Path, bytes: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create private test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .expect("set private test-file permissions");
    }
    file.write_all(bytes).expect("write private test file");
    file.sync_all().expect("sync private test file");
}
fn registry_entry(id: u64, url: String) -> WebhookEntry {
    WebhookEntry {
        id,
        url,
        active: true,
        secret: None,
        filter: None,
    }
}
fn test_webhook_generation(id: u64) -> [u8; WEBHOOK_GENERATION_BYTES] {
    let mut generation = [0_u8; WEBHOOK_GENERATION_BYTES];
    generation[WEBHOOK_GENERATION_BYTES - core::mem::size_of::<u64>()..]
        .copy_from_slice(&id.to_be_bytes());
    generation
}
fn registered_registry_entry(id: u64, url: String) -> RegisteredWebhook {
    RegisteredWebhook {
        entry: registry_entry(id, url),
        generation: test_webhook_generation(id),
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn persisted_registry_document(
    next_id: u64,
    entries: Vec<norito::json::Value>,
) -> norito::json::Value {
    let mut document = norito::json::Map::new();
    document.insert(
        "version".into(),
        norito::json::Value::from(WEBHOOK_REGISTRY_FORMAT_VERSION),
    );
    document.insert("next_id".into(), norito::json::Value::from(next_id));
    document.insert("entries".into(), norito::json::Value::Array(entries));
    norito::json::Value::Object(document)
}
fn proof_verified_event(backend: &str, call_hash: Option<[u8; 32]>) -> EventBox {
    use iroha_data_model::events::data::proof::{ProofEvent, ProofVerified};

    EventBox::Data(iroha_data_model::events::SharedDataEvent::from(
        DataEvent::Proof(ProofEvent::Verified(ProofVerified {
            id: iroha_data_model::proof::ProofId {
                backend: backend.to_owned(),
                proof_hash: [0xA1; 32],
            },
            vk_ref: None,
            vk_commitment: None,
            call_hash,
            envelope_hash: None,
        })),
    ))
}
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
#[test]
fn webhook_persistence_fails_closed_without_private_storage_support() {
    let _env = TestDataDirGuard::new();
    let error = init_persistence()
        .expect_err("webhook persistence must not fall back to pathname-only storage");

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("owner-private"));
}
#[test]
fn webhook_registry_rejects_entry_and_count_overflow() {
    let mut registry = RegistryInner::default();
    let oversized = registered_registry_entry(1, "x".repeat(WEBHOOK_ENTRY_MAX_BYTES));
    assert!(!registry_can_retain(&registry, &oversized));
    let compact = registered_registry_entry(1, "http://example.com/hook".to_string());
    for id in 0..WEBHOOK_REGISTRY_MAX_ENTRIES {
        registry
            .items
            .insert(u64::try_from(id).expect("id fits"), compact.clone());
    }
    assert!(!registry_can_retain(&registry, &compact));
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn persisted_webhook_with_malformed_filter_is_skipped_instead_of_widened() {
    let _env = TestDataDirGuard::new();
    {
        let mut registry = lock_registry();
        registry.next_id = 0;
        registry.items.clear();
    }
    let mut malformed = registered_webhook_to_storage_json(&registered_registry_entry(
        7,
        "http://filtered.example/hook".to_owned(),
    ));
    let norito::json::Value::Object(ref mut fields) = malformed else {
        panic!("stored webhook entry must be an object");
    };
    fields.insert(
        "filter".into(),
        norito::json::Value::from("not-a-filter-expression"),
    );
    let valid = registered_webhook_to_storage_json(&RegisteredWebhook {
        entry: WebhookEntry {
            id: 2,
            url: "http://valid-filter.example/hook".to_owned(),
            active: true,
            secret: None,
            filter: Some(crate::filter::FilterExpr::Eq(
                crate::filter::FieldPath("tx_status".to_owned()),
                norito::json::Value::from("Approved"),
            )),
        },
        generation: test_webhook_generation(2),
    });
    fs::create_dir_all(data_dir()).expect("create webhook data directory");
    let body =
        norito::json::to_json_pretty(&persisted_registry_document(7, vec![malformed, valid]))
            .expect("encode persisted webhook registry");
    write_private_test_file(&registry_path(), body.as_bytes());
    load_registry().expect("load bounded webhook registry");
    let mut registry = lock_registry();
    assert!(
        !registry.items.contains_key(&7),
        "a malformed stored filter must not become an unfiltered webhook"
    );
    assert!(
        registry.items.contains_key(&2),
        "a valid neighboring webhook must still load"
    );
    assert!(
        registry
            .items
            .get(&2)
            .is_some_and(|registered| registered.entry.filter.is_some()),
        "the valid neighboring webhook must retain its filter"
    );
    assert_eq!(
        registry.next_id, 7,
        "a quarantined webhook ID must not be recycled",
    );
    registry.next_id = 0;
    registry.items.clear();
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn persisted_boolean_filter_round_trips_without_semantic_widening() {
    use crate::filter::{FieldPath, FilterExpr};

    let _env = TestDataDirGuard::new();
    let expression = FilterExpr::Or(vec![
        FilterExpr::Not(Box::new(FilterExpr::Eq(
            FieldPath("proof_backend".to_owned()),
            norito::json::Value::from("halo2/ipa"),
        ))),
        FilterExpr::Eq(
            FieldPath("proof_call_hash".to_owned()),
            norito::json::Value::from(hex::encode([0xCC; 32])),
        ),
    ]);
    let stored = registered_webhook_to_storage_json(&RegisteredWebhook {
        entry: WebhookEntry {
            id: 3,
            url: "http://boolean-filter.example/hook".to_owned(),
            active: true,
            secret: None,
            filter: Some(expression.clone()),
        },
        generation: test_webhook_generation(3),
    });
    fs::create_dir_all(data_dir()).expect("create webhook data directory");
    let body = norito::json::to_json_pretty(&persisted_registry_document(3, vec![stored]))
        .expect("encode persisted webhook registry");
    write_private_test_file(&registry_path(), body.as_bytes());

    load_registry().expect("load Boolean webhook filter");
    let loaded = lock_registry()
        .items
        .get(&3)
        .and_then(|registered| registered.entry.filter.clone())
        .expect("valid Boolean filter must reload");
    assert_eq!(loaded, expression);
    assert!(event_matches_filter(
        &proof_verified_event("halo2/ipa", Some([0xCC; 32])),
        &loaded,
    ));
    assert!(!event_matches_filter(
        &proof_verified_event("halo2/ipa", None),
        &loaded,
    ));
    assert!(event_matches_filter(
        &proof_verified_event("plonk", None),
        &loaded,
    ));

    let mut registry = lock_registry();
    registry.next_id = 0;
    registry.items.clear();
}
#[test]
fn webhook_http_response_bound_rejects_limit_plus_one() {
    let maximum = usize::try_from(WEBHOOK_HTTP_RESPONSE_HEADER_MAX_BYTES).expect("limit fits");
    assert!(ensure_webhook_http_response_is_bounded(maximum).is_ok());
    let error =
        ensure_webhook_http_response_is_bounded(maximum + 1).expect_err("limit plus one must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn plain_http_delivery_completes_after_headers_without_waiting_for_eof() {
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            sync::oneshot,
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind webhook peer");
        let address = listener.local_addr().expect("webhook peer address");
        let (release, held_open) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept webhook request");
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request).await.expect("read webhook request");
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .expect("write webhook response headers");
            let _ = held_open.await;
        });
        let url = Url::parse(&format!("http://{address}/hook")).expect("valid webhook url");
        let status = tokio::time::timeout(
            Duration::from_secs(1),
            http_post_plain(&url, address, &address.to_string(), &[], b"event"),
        )
        .await
        .expect("complete headers must complete delivery")
        .expect("valid webhook response");
        assert_eq!(status, 204);
        let _ = release.send(());
        server.await.expect("webhook peer task");
    });
}
#[test]
fn webhook_delivery_body_bound_accepts_limit_and_rejects_limit_plus_one() {
    let mut pending = PendingDelivery {
        id: "body-boundary".to_string(),
        webhook_id: 1,
        webhook_generation: test_webhook_generation(1),
        url: "http://example.test/webhook".to_string(),
        content_type: "application/octet-stream".to_string(),
        signature: None,
        body: vec![0xA5; WEBHOOK_DELIVERY_MAX_BYTES],
        attempts: 0,
        next_attempt_ms: 0,
    };
    let encoded = encode_pending_delivery(&pending).expect("boundary body must encode");
    let decoded = decode_pending_delivery(encoded.as_bytes()).expect("boundary body must decode");
    assert_eq!(decoded.body.len(), WEBHOOK_DELIVERY_MAX_BYTES);
    assert_eq!(
        decoded.webhook_generation,
        test_webhook_generation(1),
        "the durable registration generation must round-trip"
    );
    pending.body.push(0);
    let error = encode_pending_delivery(&pending).expect_err("limit plus one must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    pending.body.clear();
    pending.content_type = "x".repeat(WEBHOOK_DELIVERY_METADATA_MAX_BYTES + 1);
    let error = encode_pending_delivery(&pending).expect_err("metadata overflow must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
#[test]
fn webhook_delivery_rejects_header_injection_in_content_type() {
    let pending = PendingDelivery {
        id: "hostile-content-type".to_string(),
        webhook_id: 1,
        webhook_generation: test_webhook_generation(1),
        url: "http://example.test/webhook".to_string(),
        content_type: "text/plain\r\nX-Evil: yes".to_string(),
        signature: None,
        body: b"event".to_vec(),
        attempts: 0,
        next_attempt_ms: 0,
    };
    let error = encode_pending_delivery(&pending)
        .expect_err("header injection must not enter the durable spool");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let runtime = Runtime::new().expect("tokio runtime");
    let error = runtime
        .block_on(http_post(
            &pending.url,
            &[("Content-Type", pending.content_type)],
            b"event",
        ))
        .expect_err("transport must reject header injection defensively");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut record = norito::json::Map::new();
    record.insert(
        "id".into(),
        norito::json::Value::from("hostile-content-type"),
    );
    record.insert("webhook_id".into(), norito::json::Value::from(1_u64));
    record.insert(
        "url".into(),
        norito::json::Value::from("http://example.test/webhook"),
    );
    record.insert(
        "content_type".into(),
        norito::json::Value::from("text/plain\r\nX-Evil: yes"),
    );
    record.insert("signature".into(), norito::json::Value::Null);
    record.insert(
        "body".into(),
        norito::json::Value::from(STANDARD.encode(b"event")),
    );
    record.insert("attempts".into(), norito::json::Value::from(0_u64));
    record.insert("next_attempt_ms".into(), norito::json::Value::from(0_u64));
    let record = norito::json::to_vec(&record).expect("encode hostile spool record");
    assert!(
        decode_pending_delivery(&record).is_none(),
        "corrupted spool metadata must not reach the transport"
    );
}
#[test]
fn generated_webhook_delivery_ids_are_unique() {
    let mut ids = HashSet::new();
    for _ in 0..1_024 {
        let id = new_delivery_id(7, 42).expect("OS randomness must be available");
        assert!(ids.insert(id), "delivery identifiers must not collide");
    }
}
#[test]
fn webhook_spool_decode_rejects_encoded_body_overflow() {
    let mut payload = norito::json::Map::new();
    payload.insert("id".into(), norito::json::Value::from("encoded-overflow"));
    payload.insert("webhook_id".into(), norito::json::Value::from(1_u64));
    payload.insert(
        "url".into(),
        norito::json::Value::from("http://example.test/webhook"),
    );
    payload.insert(
        "content_type".into(),
        norito::json::Value::from("application/octet-stream"),
    );
    payload.insert("signature".into(), norito::json::Value::Null);
    payload.insert(
        "body".into(),
        norito::json::Value::from("A".repeat(WEBHOOK_DELIVERY_MAX_BASE64_BYTES + 4)),
    );
    payload.insert("attempts".into(), norito::json::Value::from(0_u64));
    payload.insert("next_attempt_ms".into(), norito::json::Value::from(0_u64));
    let record = norito::json::to_vec(&payload).expect("encode overflow record");
    assert!(record.len() <= WEBHOOK_QUEUE_FILE_MAX_BYTES);
    assert!(
        decode_pending_delivery(&record).is_none(),
        "encoded body overflow must be rejected before base64 decode"
    );
}
#[test]
fn webhook_queue_capacity_has_a_hard_ceiling() {
    let policy = WebhookPolicy {
        queue_capacity: NonZeroUsize::new(WEBHOOK_QUEUE_HARD_CAPACITY + 1)
            .expect("hard capacity plus one is non-zero"),
        ..WebhookPolicy::default()
    };
    assert_eq!(
        effective_queue_capacity(policy),
        WEBHOOK_QUEUE_HARD_CAPACITY
    );
}
#[test]
fn queue_admission_scan_fails_closed_at_work_limit() {
    let _env = TestDataDirGuard::new();
    let root = queue_dir();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create queue directory");
    for name in ["noise-1", "noise-2", "noise-3"] {
        fs::write(root.join(name), b"").expect("write queue noise");
    }
    let error = queue_depth_bounded_at(&root, 1, 2)
        .expect_err("work exhaustion must fail queue admission closed");
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
}
#[test]
fn queue_discovery_sorts_each_bounded_batch() {
    let _env = TestDataDirGuard::new();
    let root = queue_dir();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create queue directory");
    for name in ["0003.json", "0001.json", "0002.json"] {
        fs::write(root.join(name), b"{}").expect("write queue entry");
    }
    let mut cursor = QueueScanCursor::default();
    let batch = discover_queue_batch_at(&mut cursor, &root, 3, 4, 4).expect("discover queue batch");
    let names: Vec<_> = batch
        .paths
        .iter()
        .map(|path| {
            path.file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        names,
        ["0001.json", "0002.json", "0003.json"].map(str::to_string)
    );
    assert!(batch.overflow_paths.is_empty());
    assert!(batch.sweep_complete);
}
#[test]
fn queue_discovery_bounds_batches_and_marks_capacity_overflow() {
    let _env = TestDataDirGuard::new();
    let root = queue_dir();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create queue directory");
    for name in ["0001.json", "0002.json", "0003.json"] {
        fs::write(root.join(name), b"{}").expect("write queue entry");
    }
    let mut cursor = QueueScanCursor::default();
    let first =
        discover_queue_batch_at(&mut cursor, &root, 2, 2, 3).expect("discover first queue batch");
    assert_eq!(
        first.paths.len() + first.overflow_paths.len(),
        2,
        "a scan batch must not retain more paths than its bound"
    );
    assert!(!first.sweep_complete);
    let second =
        discover_queue_batch_at(&mut cursor, &root, 2, 2, 3).expect("discover second queue batch");
    assert_eq!(second.paths.len() + second.overflow_paths.len(), 1);
    assert_eq!(
        first.overflow_paths.len() + second.overflow_paths.len(),
        1,
        "records beyond capacity must be marked before replay"
    );
    assert!(second.sweep_complete);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn queue_overflow_pruning_rechecks_current_capacity() {
    let _env = TestDataDirGuard::new();
    let root = queue_dir();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create queue directory");
    let first = root.join("0001.json");
    let second = root.join("0002.json");
    fs::write(&first, b"{}").expect("write first queue entry");
    fs::write(&second, b"{}").expect("write second queue entry");
    let policy = WebhookPolicy {
        queue_capacity: NonZeroUsize::new(2).expect("non-zero capacity"),
        ..WebhookPolicy::default()
    };
    assert_eq!(
        prune_verified_queue_overflow(vec![second.clone()], policy)
            .expect("verify queue at capacity"),
        0
    );
    assert!(second.exists(), "a current in-capacity record must remain");
    let overflow = root.join("0003.json");
    fs::write(&overflow, b"{}").expect("write overflow queue entry");
    assert_eq!(
        prune_verified_queue_overflow(vec![overflow.clone()], policy)
            .expect("prune verified overflow"),
        1
    );
    assert!(!overflow.exists(), "verified overflow must be removed");
    assert_eq!(queue_depth_bounded_at(&root, 3, 3).unwrap(), 2);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn delivery_worker_removes_oversized_spool_file_before_decode() {
    let _env = TestDataDirGuard::new();
    let root = queue_dir();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create queue directory");
    let oversized = root.join("oversized.json");
    write_private_test_file(&oversized, b"");
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&oversized)
        .expect("open oversized queue file");
    file.set_len(
        u64::try_from(WEBHOOK_QUEUE_FILE_MAX_BYTES)
            .expect("file bound fits u64")
            .saturating_add(1),
    )
    .expect("extend oversized queue file");
    let _ = Runtime::new()
        .expect("tokio runtime")
        .block_on(process_queue_once());
    assert!(!oversized.exists(), "oversized spool file must be removed");
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn delivery_worker_stops_cleanly_and_can_restart() {
    let _env = TestDataDirGuard::new();
    super::init_persistence().expect("initialize webhook persistence");
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        for _ in 0..2 {
            let shutdown = ShutdownSignal::new();
            let worker = super::start_delivery_worker(shutdown.clone());
            shutdown.send();
            let exit = tokio::time::timeout(Duration::from_secs(1), worker)
                .await
                .expect("delivery worker must observe shutdown")
                .expect("delivery worker must not panic");
            assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
        }
    });
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn webhook_storage_is_private_and_atomic() {
    use std::os::unix::fs::PermissionsExt as _;

    let _env = TestDataDirGuard::new();
    ensure_dirs().expect("prepare webhook storage");
    let directory = open_webhook_queue_directory(false)
        .expect("open queue directory")
        .expect("queue directory exists");
    assert_eq!(
        directory
            .file
            .metadata()
            .expect("inspect queue directory")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    let path = directory.path.join("atomic.json");
    write_private_webhook_file_atomic(
        &directory,
        &path,
        b"first",
        32,
        WebhookPublication::CreateNew,
    )
    .expect("publish queue record");
    assert_eq!(
        fs::symlink_metadata(&path)
            .expect("inspect queue record")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    write_private_webhook_file_atomic(
        &directory,
        &path,
        b"second",
        32,
        WebhookPublication::Replace,
    )
    .expect("replace queue record");
    assert_eq!(
        fs::read(&path).expect("read replaced queue record"),
        b"second"
    );
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn webhook_startup_removes_only_owned_temporary_files() {
    let _env = TestDataDirGuard::new();
    ensure_dirs().expect("prepare webhook storage");
    let data_temp = data_dir().join(".webhook-00000000000000000000000000000000.tmp");
    let queue_temp = queue_dir().join(".webhook-11111111111111111111111111111111.tmp");
    let unrelated = queue_dir().join("keep.tmp");
    write_private_test_file(&data_temp, b"partial registry");
    write_private_test_file(&queue_temp, b"partial delivery");
    write_private_test_file(&unrelated, b"unrelated");
    recover_webhook_temporary_files().expect("recover webhook temporary files");
    assert!(!data_temp.exists());
    assert!(!queue_temp.exists());
    assert!(unrelated.exists());
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn webhook_persistence_refuses_symlink_targets() {
    use std::os::unix::fs::symlink;

    let _env = TestDataDirGuard::new();
    ensure_dirs().expect("prepare webhook storage");
    let target = data_dir().join("outside.json");
    write_private_test_file(&target, b"outside");
    let directory = open_webhook_queue_directory(false)
        .expect("open queue directory")
        .expect("queue directory exists");
    let queue_path = directory.path.join("linked.json");
    symlink(&target, &queue_path).expect("create queue symlink");
    assert!(
        write_private_webhook_file_atomic(
            &directory,
            &queue_path,
            b"replacement",
            32,
            WebhookPublication::Replace,
        )
        .is_err(),
        "a retry must not publish through a symlink"
    );
    assert_eq!(
        fs::read(&target).expect("read symlink target"),
        b"outside",
        "the symlink target must remain untouched"
    );
    let registry_target = data_dir().join("registry-target.json");
    write_private_test_file(&registry_target, b"[]");
    symlink(&registry_target, registry_path()).expect("create registry symlink");
    let mut registry = lock_registry();
    registry.items.clear();
    registry.next_id = 0;
    drop(registry);
    assert!(
        load_registry().is_err(),
        "registry loading must reject a symlink target"
    );
    assert!(lock_registry().items.is_empty());
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn queue_delete_rejects_a_replaced_inode() {
    let _env = TestDataDirGuard::new();
    ensure_dirs().expect("prepare webhook storage");
    let directory = open_webhook_queue_directory(false)
        .expect("open queue directory")
        .expect("queue directory exists");
    let path = directory.path.join("identity.json");
    write_private_webhook_file_atomic(&directory, &path, b"old", 32, WebhookPublication::CreateNew)
        .expect("publish original queue record");
    let original = read_private_webhook_file_bounded(&directory, &path, 32)
        .expect("read original queue record")
        .expect("original queue record exists");
    write_private_webhook_file_atomic(&directory, &path, b"new", 32, WebhookPublication::Replace)
        .expect("replace queue record");
    assert!(
        unlink_private_webhook_entry(&directory, &path, Some(original.identity), true).is_err(),
        "completion of an old attempt must not remove a replacement record"
    );
    assert_eq!(fs::read(&path).expect("read replacement record"), b"new");
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
struct TimeoutOverride(super::HttpTimeoutConfig);
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
impl TimeoutOverride {
    fn new(config: super::HttpTimeoutConfig) -> Self {
        let previous = super::http_timeout_config();
        super::set_http_timeout_config(config);
        Self(previous)
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
impl Drop for TimeoutOverride {
    fn drop(&mut self) {
        super::set_http_timeout_config(self.0);
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
struct WebhookPolicyGuard {
    previous: super::WebhookPolicy,
    _writer_guard: MutexGuard<'static, ()>,
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
impl WebhookPolicyGuard {
    fn new(policy: super::WebhookPolicy) -> Self {
        let writer_guard = super::webhook_policy_writer_lock()
            .lock()
            .expect("webhook policy writer lock");
        let previous = super::webhook_policy();
        super::apply_webhook_policy(policy);
        Self {
            previous,
            _writer_guard: writer_guard,
        }
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
impl Drop for WebhookPolicyGuard {
    fn drop(&mut self) {
        super::apply_webhook_policy(self.previous);
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn expect_json_object(value: norito::json::Value, context: &str) -> norito::json::Map {
    match value {
        norito::json::Value::Object(map) => map,
        _ => panic!("expected object for {context}", context = context),
    }
}
#[test]
#[expect(
    clippy::mutex_integer,
    reason = "the test verifies recovery of a value after mutex poisoning, which an atomic cannot exercise"
)]
fn registry_lock_recovers_after_a_guard_unwinds() {
    let mutex = Mutex::new(0_u8);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = mutex.lock().expect("fresh test mutex");
        *guard = 7;
        panic!("poison the local test mutex");
    }));
    assert!(unwind.is_err());
    let mut recovered = super::lock_unpoisoned(&mutex);
    assert_eq!(*recovered, 7);
    *recovered = 8;
}
#[test]
fn queue_filesystem_panic_is_recovered() {
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reached_in_worker = Arc::clone(&reached);
        let error = super::run_queue_filesystem_operation(move || -> io::Result<()> {
            assert!(
                iroha_panic_hook::is_suppressed(),
                "the recoverable boundary must be installed on the physical blocking worker"
            );
            reached_in_worker.store(true, std::sync::atomic::Ordering::SeqCst);
            panic!("injected webhook queue filesystem panic");
        })
        .await
        .expect_err("a queue filesystem panic must become a controlled I/O error");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(reached.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            !iroha_panic_hook::is_suppressed(),
            "suppression must stay scoped to the physical blocking worker"
        );
    });
}
#[test]
fn proof_id_parsing_accepts_canonical_strings_and_rejects_retired_objects() {
    use hex::encode;
    use iroha_data_model::proof::ProofId;
    let proof = ProofId {
        backend: "halo2/ipa".into(),
        proof_hash: [0xAB; 32],
    };
    let string_value = norito::json::Value::from(proof.to_string());
    assert_eq!(
        super::proof_id_from_json(&string_value),
        Some(proof.clone())
    );
    let mut map = norito::json::Map::new();
    map.insert("backend".into(), norito::json::Value::from("halo2/ipa"));
    map.insert(
        "proof_hash".into(),
        norito::json::Value::from(format!("0x{}", encode(proof.proof_hash))),
    );
    let object_value = norito::json::Value::Object(map);
    assert_eq!(super::proof_id_from_json(&object_value), None);
    let mut map_array = norito::json::Map::new();
    map_array.insert("backend".into(), norito::json::Value::from("halo2/ipa"));
    let array = proof
        .proof_hash
        .iter()
        .map(|b| norito::json::Value::from(u64::from(*b)))
        .collect();
    map_array.insert("proof_hash".into(), norito::json::Value::Array(array));
    let array_value = norito::json::Value::Object(map_array);
    assert_eq!(super::proof_id_from_json(&array_value), None);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn delivery_worker_processes_queue() {
    let _env = TestDataDirGuard::new();
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    }
    super::init_persistence().expect("initialize webhook persistence");
    let rt = Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let deliveries_clone = Arc::clone(&deliveries);
        let _http_guard = super::install_http_post_override(move |url, _headers, body| {
            deliveries_clone
                .lock()
                .expect("deliveries lock")
                .push((url.to_string(), body.to_vec()));
            Ok(200)
        });
        let target_url = "http://local.test/webhook";
        let webhook_id = {
            let mut g = registry().lock().unwrap();
            g.next_id = 1;
            g.items
                .insert(1, registered_registry_entry(1, target_url.to_string()));
            1
        };
        let queue_file = super::queue_dir().join("pending-delivery.json");
        let mut payload = norito::json::Map::new();
        payload.insert("id".into(), norito::json::Value::from("test-id"));
        payload.insert(
            "webhook_id".into(),
            norito::json::Value::from(
                u64::try_from(webhook_id).expect("webhook id should be non-negative"),
            ),
        );
        payload.insert(
            "webhook_generation".into(),
            norito::json::Value::from(hex::encode(test_webhook_generation(1))),
        );
        payload.insert("url".into(), norito::json::Value::from(target_url));
        payload.insert(
            "content_type".into(),
            norito::json::Value::from("application/json"),
        );
        payload.insert("signature".into(), norito::json::Value::Null);
        payload.insert(
            "body".into(),
            norito::json::Value::from(STANDARD.encode(b"{\"ok\":true}")),
        );
        payload.insert("attempts".into(), norito::json::Value::from(0u64));
        payload.insert("next_attempt_ms".into(), norito::json::Value::from(0u64));
        let payload = norito::json::to_json_pretty(&payload).expect("serialize payload");
        write_private_test_file(&queue_file, payload.as_bytes());
        let mut delivered = false;
        for _ in 0..50 {
            let _ = super::process_queue_once().await;
            if !queue_file.exists() {
                delivered = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(delivered, "queued delivery should be processed and removed");
        let recorded = deliveries.lock().expect("deliveries lock");
        assert_eq!(recorded.len(), 1, "expected exactly one delivery attempt");
        let (url, body) = &recorded[0];
        assert_eq!(url, target_url);
        assert!(
            body.windows(b"\"ok\":true".len())
                .any(|w| w == b"\"ok\":true")
        );
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    });
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn queue_capacity_check_and_persistence_are_atomic() {
    const WRITERS: usize = 8;
    let _env = TestDataDirGuard::new();
    let _ = fs::remove_dir_all(super::queue_dir());
    super::ensure_dirs().expect("prepare queue directory");
    let policy = super::WebhookPolicy {
        queue_capacity: NonZeroUsize::new(1).unwrap(),
        max_attempts: NonZeroU32::new(3).unwrap(),
        backoff_initial: Duration::from_secs(1),
        backoff_max: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        write_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_secs(1),
    };
    let barrier = Arc::new(Barrier::new(WRITERS));
    let handles: Vec<_> = (0..WRITERS)
        .map(|writer| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut admission = QueueAdmission::begin(policy)?;
                admission.persist(&PendingDelivery {
                    id: format!("writer-{writer}"),
                    webhook_id: u64::try_from(writer).expect("writer id fits u64"),
                    webhook_generation: test_webhook_generation(
                        u64::try_from(writer).expect("writer id fits u64"),
                    ),
                    url: "http://example.test/webhook".to_string(),
                    content_type: "text/plain".to_string(),
                    signature: None,
                    body: format!("payload-{writer}").into_bytes(),
                    attempts: 0,
                    next_attempt_ms: 0,
                })
            })
        })
        .collect();
    let mut persisted = 0_usize;
    for handle in handles {
        if handle.join().expect("queue writer thread").is_ok() {
            persisted = persisted.saturating_add(1);
        }
    }
    assert_eq!(persisted, 1, "exactly one writer should reserve capacity");
    assert_eq!(
        super::queue_depth(),
        1,
        "concurrent writers must not overshoot queue capacity"
    );
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn payload_dropped_after_max_attempts() {
    let _env = TestDataDirGuard::new();
    let _ = fs::remove_dir_all(super::queue_dir());
    super::ensure_dirs().expect("prepare queue directory");
    let _policy_guard = WebhookPolicyGuard::new(super::WebhookPolicy {
        queue_capacity: NonZeroUsize::new(10).unwrap(),
        max_attempts: NonZeroU32::new(2).unwrap(),
        backoff_initial: Duration::from_millis(10),
        backoff_max: Duration::from_millis(20),
        connect_timeout: Duration::from_secs(1),
        write_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_secs(1),
    });
    {
        let mut g = registry().lock().unwrap();
        g.items.clear();
        g.items.insert(
            1,
            registered_registry_entry(1, "http://local.test/webhook".to_string()),
        );
    }
    let pending_path = super::queue_dir().join("pending-drop.json");
    let mut payload = norito::json::Map::new();
    payload.insert("id".into(), norito::json::Value::from("pending-drop"));
    payload.insert("webhook_id".into(), norito::json::Value::from(1u64));
    payload.insert(
        "webhook_generation".into(),
        norito::json::Value::from(hex::encode(test_webhook_generation(1))),
    );
    payload.insert(
        "url".into(),
        norito::json::Value::from("http://local.test/webhook"),
    );
    payload.insert(
        "content_type".into(),
        norito::json::Value::from("application/json"),
    );
    payload.insert("signature".into(), norito::json::Value::Null);
    payload.insert(
        "body".into(),
        norito::json::Value::from(STANDARD.encode(b"payload")),
    );
    payload.insert("attempts".into(), norito::json::Value::from(1u64));
    payload.insert("next_attempt_ms".into(), norito::json::Value::from(0u64));
    let json = norito::json::to_json_pretty(&payload).expect("serialize pending payload");
    write_private_test_file(&pending_path, json.as_bytes());
    let _http_guard = super::install_http_post_override(|_, _, _| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "intentional failure",
        ))
    });
    let rt = Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        super::process_queue_once().await;
    });
    assert_eq!(super::queue_depth(), 0);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn overflowing_persisted_attempts_are_removed_without_delivery() {
    let _env = TestDataDirGuard::new();
    let _ = fs::remove_dir_all(super::queue_dir());
    super::ensure_dirs().expect("prepare queue directory");
    let pending_path = super::queue_dir().join("overflowing-attempts.json");
    let mut payload = norito::json::Map::new();
    payload.insert(
        "id".into(),
        norito::json::Value::from("overflowing-attempts"),
    );
    payload.insert("webhook_id".into(), norito::json::Value::from(1u64));
    payload.insert(
        "webhook_generation".into(),
        norito::json::Value::from(hex::encode(test_webhook_generation(1))),
    );
    payload.insert(
        "url".into(),
        norito::json::Value::from("http://local.test/webhook"),
    );
    payload.insert(
        "content_type".into(),
        norito::json::Value::from("application/json"),
    );
    payload.insert("signature".into(), norito::json::Value::Null);
    payload.insert(
        "body".into(),
        norito::json::Value::from(STANDARD.encode(b"payload")),
    );
    payload.insert(
        "attempts".into(),
        norito::json::Value::from(u64::from(u32::MAX) + 1),
    );
    payload.insert("next_attempt_ms".into(), norito::json::Value::from(0u64));
    let json = norito::json::to_json_pretty(&payload).expect("serialize pending payload");
    write_private_test_file(&pending_path, json.as_bytes());
    let delivery_attempts = Arc::new(AtomicU32::new(0));
    let recorded_attempts = Arc::clone(&delivery_attempts);
    let _http_guard = super::install_http_post_override(move |_, _, _| {
        recorded_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(200)
    });
    let rt = Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        super::process_queue_once().await;
    });
    assert!(
        !pending_path.exists(),
        "invalid spool record must be removed"
    );
    assert_eq!(
        delivery_attempts.load(Ordering::SeqCst),
        0,
        "overflow must not reset the retry budget and trigger delivery"
    );
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn delivery_worker_times_out_and_continues() {
    let _env = TestDataDirGuard::new();
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    }
    super::init_persistence().expect("initialize webhook persistence");
    let rt = Runtime::new().expect("tokio runtime");
    let _timeout_guard = TimeoutOverride::new(super::HttpTimeoutConfig {
        connect: Duration::from_millis(200),
        write: Duration::from_millis(200),
        read: Duration::from_millis(200),
    });
    rt.block_on(async {
        let hung_url = "http://local.test/hung/".to_string();
        let success_url = "http://local.test/success/".to_string();
        let hung_attempts = Arc::new(AtomicU32::new(0));
        let success_hits = Arc::new(AtomicU32::new(0));
        let hung_attempts_clone = Arc::clone(&hung_attempts);
        let success_hits_clone = Arc::clone(&success_hits);
        let closure_hung_url = hung_url.clone();
        let closure_success_url = success_url.clone();
        let _http_guard = super::install_http_post_override(move |url, _headers, _body| {
            if url == closure_hung_url {
                hung_attempts_clone.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "simulated timeout",
                ))
            } else if url == closure_success_url {
                success_hits_clone.fetch_add(1, Ordering::SeqCst);
                Ok(200)
            } else {
                Ok(200)
            }
        });
        {
            let mut g = registry().lock().unwrap();
            g.next_id = 2;
            g.items
                .insert(1, registered_registry_entry(1, hung_url.clone()));
            g.items
                .insert(2, registered_registry_entry(2, success_url.clone()));
        }
        let queue_dir = super::queue_dir();
        let hung_file = queue_dir.join("0001-timeout.json");
        let success_file = queue_dir.join("0002-success.json");
        let mut hung_payload = norito::json::Map::new();
        hung_payload.insert("id".into(), norito::json::Value::from("timeout-job"));
        hung_payload.insert("webhook_id".into(), norito::json::Value::from(1u64));
        hung_payload.insert(
            "webhook_generation".into(),
            norito::json::Value::from(hex::encode(test_webhook_generation(1))),
        );
        hung_payload.insert("url".into(), norito::json::Value::from(hung_url.clone()));
        hung_payload.insert(
            "content_type".into(),
            norito::json::Value::from("application/json"),
        );
        hung_payload.insert("signature".into(), norito::json::Value::Null);
        hung_payload.insert(
            "body".into(),
            norito::json::Value::from(STANDARD.encode(b"{\"timeout\":true}")),
        );
        hung_payload.insert("attempts".into(), norito::json::Value::from(0u64));
        hung_payload.insert("next_attempt_ms".into(), norito::json::Value::from(0u64));
        let hung_payload =
            norito::json::to_json_pretty(&hung_payload).expect("serialize timeout payload");
        write_private_test_file(&hung_file, hung_payload.as_bytes());
        let mut success_payload = norito::json::Map::new();
        success_payload.insert("id".into(), norito::json::Value::from("success-job"));
        success_payload.insert("webhook_id".into(), norito::json::Value::from(2u64));
        success_payload.insert(
            "webhook_generation".into(),
            norito::json::Value::from(hex::encode(test_webhook_generation(2))),
        );
        success_payload.insert("url".into(), norito::json::Value::from(success_url.clone()));
        success_payload.insert(
            "content_type".into(),
            norito::json::Value::from("application/json"),
        );
        success_payload.insert("signature".into(), norito::json::Value::Null);
        success_payload.insert(
            "body".into(),
            norito::json::Value::from(STANDARD.encode(b"{\"ok\":true}")),
        );
        success_payload.insert("attempts".into(), norito::json::Value::from(0u64));
        success_payload.insert("next_attempt_ms".into(), norito::json::Value::from(0u64));
        let success_payload =
            norito::json::to_json_pretty(&success_payload).expect("serialize success payload");
        write_private_test_file(&success_file, success_payload.as_bytes());
        let mut success_delivered = false;
        for _ in 0..50 {
            let _ = super::process_queue_once().await;
            if !success_file.exists() {
                success_delivered = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(success_delivered, "successful delivery should be removed");
        let mut timeout_recorded = false;
        for _ in 0..50 {
            let _ = super::process_queue_once().await;
            if let Ok(contents) = std::fs::read_to_string(&hung_file) {
                if contents.contains("\"attempts\": 1") {
                    timeout_recorded = true;
                    break;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(
            timeout_recorded,
            "timeout job should record a failed attempt"
        );
        let hung_contents =
            std::fs::read_to_string(&hung_file).expect("read timeout payload after retry");
        let hung_value: norito::json::Value =
            norito::json::from_str(&hung_contents).expect("valid timeout payload json");
        let hung_map = expect_json_object(hung_value, "timeout payload");
        assert_eq!(
            hung_map
                .get("attempts")
                .and_then(norito::json::Value::as_u64),
            Some(1)
        );
        let next_attempt = hung_map
            .get("next_attempt_ms")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(0);
        assert!(next_attempt > 0);
        assert!(
            hung_attempts.load(Ordering::SeqCst) >= 1,
            "expected at least one timeout attempt",
        );
        assert!(
            success_hits.load(Ordering::SeqCst) >= 1,
            "expected success webhook to be attempted",
        );
        std::fs::remove_file(&hung_file).expect("cleanup timeout payload");
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    });
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn expect_json_array(value: norito::json::Value, context: &str) -> Vec<norito::json::Value> {
    match value {
        norito::json::Value::Array(arr) => arr,
        _ => panic!("expected array for {context}", context = context),
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn registry_next_id_survives_last_deletion_and_restart() {
    let _env = TestDataDirGuard::new();
    super::init_persistence().expect("initialize webhook persistence");
    {
        let mut registry = lock_registry();
        registry.next_id = 1;
        registry.items.clear();
        registry.items.insert(
            1,
            registered_registry_entry(1, "http://first.example/hook".to_string()),
        );
        persist_registry(&registry).expect("persist original webhook registration");
    }
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        let response = handle_delete_webhook(AxumPath(1)).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    });
    {
        let mut registry = lock_registry();
        registry.next_id = 0;
        registry.items.clear();
    }

    load_registry().expect("reload registry after simulated restart");
    {
        let registry = lock_registry();
        assert_eq!(registry.next_id, 1);
        assert!(registry.items.is_empty());
    }
    runtime.block_on(async {
        let response = handle_create_webhook(crate::utils::extractors::JsonOnly(WebhookCreate {
            url: "http://second.example/hook".to_string(),
            secret: None,
            active: true,
            filter: None,
        }))
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    });
    let mut registry = lock_registry();
    assert_eq!(registry.next_id, 2);
    assert!(registry.items.contains_key(&2));
    assert!(!registry.items.contains_key(&1));
    registry.next_id = 0;
    registry.items.clear();
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn loading_an_empty_store_clears_stale_registry_state() {
    let _env = TestDataDirGuard::new();
    {
        let mut registry = lock_registry();
        registry.next_id = 7;
        registry.items.clear();
        registry.items.insert(
            7,
            registered_registry_entry(7, "http://stale.example/hook".to_string()),
        );
    }

    load_registry().expect("load empty webhook store");
    let registry = lock_registry();
    assert_eq!(registry.next_id, 0);
    assert!(registry.items.is_empty());
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn create_list_delete_roundtrip() {
    let _env = TestDataDirGuard::new();
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    }
    super::init_persistence().expect("initialize webhook persistence");
    let data_dir = super::data_dir();
    let rt = Runtime::new().expect("tokio runtime");
    let (entry_id, entry_url) = rt.block_on(async {
        let created_resp =
            super::handle_create_webhook(crate::utils::extractors::JsonOnly(WebhookCreate {
                url: "http://example.com/hook".into(),
                secret: Some("s".into()),
                active: true,
                filter: None,
            }))
            .await;
        let created_resp = created_resp.into_response();
        assert_eq!(created_resp.status(), StatusCode::CREATED);
        let bytes = created_resp.into_body().collect().await.unwrap().to_bytes();
        let created_value: norito::json::Value =
            norito::json::from_slice(&bytes).expect("valid json body");
        let created_map = expect_json_object(created_value, "created webhook");
        assert!(!created_map.contains_key("secret"));
        assert_eq!(
            created_map
                .get("has_secret")
                .and_then(norito::json::Value::as_bool),
            Some(true)
        );
        let id = created_map
            .get("id")
            .and_then(norito::json::Value::as_u64)
            .expect("webhook id in response");
        let url = created_map
            .get("url")
            .and_then(norito::json::Value::as_str)
            .expect("webhook url in response")
            .to_string();
        let list_resp = super::handle_list_webhooks().await.into_response();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_bytes = list_resp.into_body().collect().await.unwrap().to_bytes();
        let list_value: norito::json::Value =
            norito::json::from_slice(&list_bytes).expect("valid list json");
        let list_array = expect_json_array(list_value, "webhook list");
        assert_eq!(list_array.len(), 1);
        let list_entry_map = expect_json_object(
            list_array.into_iter().next().expect("one entry"),
            "list entry",
        );
        assert!(!list_entry_map.contains_key("secret"));
        assert_eq!(
            list_entry_map
                .get("has_secret")
                .and_then(norito::json::Value::as_bool),
            Some(true)
        );
        (id, url)
    });
    let persisted = std::fs::read_to_string(data_dir.join("webhooks.json")).unwrap();
    assert!(persisted.contains(&entry_url));
    rt.block_on(async {
        let del_status = super::handle_delete_webhook(AxumPath(entry_id)).await;
        assert_eq!(del_status.into_response().status(), StatusCode::NO_CONTENT);
    });
    rt.block_on(async {
        let del_status = super::handle_delete_webhook(AxumPath(entry_id)).await;
        assert_eq!(del_status.into_response().status(), StatusCode::NOT_FOUND);
    });
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn responses_report_secret_presence_without_exposing_value() {
    let _env = TestDataDirGuard::new();
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    }
    super::init_persistence().expect("initialize webhook persistence");
    let rt = Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let no_secret_resp =
            super::handle_create_webhook(crate::utils::extractors::JsonOnly(WebhookCreate {
                url: "http://no-secret.example".into(),
                secret: None,
                active: true,
                filter: None,
            }))
            .await
            .into_response();
        let no_secret_bytes = no_secret_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let no_secret_map = expect_json_object(
            norito::json::from_slice(&no_secret_bytes).expect("valid no-secret json"),
            "create webhook without secret",
        );
        assert!(!no_secret_map.contains_key("secret"));
        assert_eq!(
            no_secret_map
                .get("has_secret")
                .and_then(norito::json::Value::as_bool),
            Some(false)
        );
        let with_secret_resp =
            super::handle_create_webhook(crate::utils::extractors::JsonOnly(WebhookCreate {
                url: "http://with-secret.example".into(),
                secret: Some("super-secret".into()),
                active: true,
                filter: None,
            }))
            .await
            .into_response();
        let with_secret_bytes = with_secret_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let with_secret_map = expect_json_object(
            norito::json::from_slice(&with_secret_bytes).expect("valid with-secret json"),
            "create webhook with secret",
        );
        assert!(!with_secret_map.contains_key("secret"));
        assert_eq!(
            with_secret_map
                .get("has_secret")
                .and_then(norito::json::Value::as_bool),
            Some(true)
        );
        let list_resp = super::handle_list_webhooks().await.into_response();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_bytes = list_resp.into_body().collect().await.unwrap().to_bytes();
        let list_entries = expect_json_array(
            norito::json::from_slice(&list_bytes).expect("valid list json"),
            "list after secret variations",
        );
        assert_eq!(list_entries.len(), 2);
        let mut seen = Vec::new();
        for entry in list_entries {
            let map = expect_json_object(entry, "list entry secret check");
            assert!(!map.contains_key("secret"));
            let url = map
                .get("url")
                .and_then(norito::json::Value::as_str)
                .expect("url present")
                .to_string();
            let has_secret = map
                .get("has_secret")
                .and_then(norito::json::Value::as_bool)
                .expect("has_secret present");
            seen.push((url, has_secret));
        }
        assert!(
            seen.iter()
                .any(|(url, has)| url == "http://no-secret.example/" && !has)
        );
        assert!(
            seen.iter()
                .any(|(url, has)| url == "http://with-secret.example/" && *has)
        );
    });
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
    }
}
#[test]
fn hmac_known_vector() {
    // RFC 4231 Test Case 1
    let key = [0x0b_u8; 20];
    let data = b"Hi There";
    let mac = super::hmac_sha256_hex(&key, data);
    assert_eq!(
        mac,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn queued_delivery_is_invalidated_by_durable_registration_deletion() {
    let _env = TestDataDirGuard::new();
    super::init_persistence().expect("initialize webhook persistence");
    {
        let mut registry = lock_registry();
        registry.next_id = 1;
        registry.items.clear();
        registry.items.insert(
            1,
            RegisteredWebhook {
                entry: WebhookEntry {
                    id: 1,
                    url: "http://local.test/hook".to_string(),
                    active: true,
                    secret: Some("delivery-secret".to_string()),
                    filter: None,
                },
                generation: test_webhook_generation(1),
            },
        );
        persist_registry(&registry).expect("persist original webhook registration");
    }
    enqueue_event_for_matching_webhooks(
        &proof_verified_event("halo2/ipa", Some([0xA5; 32])),
        "application/json",
    );
    let queue_path = fs::read_dir(queue_dir())
        .expect("read webhook queue")
        .next()
        .expect("one queued delivery")
        .expect("queued delivery entry")
        .path();
    let mut pending = decode_pending_delivery(&fs::read(&queue_path).expect("read delivery"))
        .expect("decode queued delivery");
    pending.next_attempt_ms = u64::MAX;
    let encoded = encode_pending_delivery(&pending).expect("encode future-due delivery");
    write_private_test_file(&queue_path, encoded.as_bytes());
    let delivery_attempts = Arc::new(AtomicU32::new(0));
    let recorded_attempts = Arc::clone(&delivery_attempts);
    let _http_guard = super::install_http_post_override(move |_, _, _| {
        recorded_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(204)
    });
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        let response = handle_delete_webhook(AxumPath(1)).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        *lock_registry() = RegistryInner::default();
        load_registry().expect("reload durable deletion before delivery");
        process_queue_once().await;
    });
    assert_eq!(
        delivery_attempts.load(Ordering::SeqCst),
        0,
        "a deleted registration must never receive a queued delivery"
    );
    assert!(
        !queue_path.exists(),
        "the invalidated spool record must be removed"
    );
    let mut registry = lock_registry();
    registry.next_id = 0;
    registry.items.clear();
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn queued_delivery_is_invalidated_by_durable_registration_replacement() {
    let _env = TestDataDirGuard::new();
    super::init_persistence().expect("initialize webhook persistence");
    {
        let mut registry = lock_registry();
        registry.next_id = 1;
        registry.items.clear();
        registry.items.insert(
            1,
            RegisteredWebhook {
                entry: registry_entry(1, "http://local.test/hook".to_string()),
                generation: test_webhook_generation(1),
            },
        );
        persist_registry(&registry).expect("persist original webhook registration");
    }
    enqueue_event_for_matching_webhooks(
        &proof_verified_event("halo2/ipa", Some([0xA5; 32])),
        "application/json",
    );
    let queue_path = fs::read_dir(queue_dir())
        .expect("read webhook queue")
        .next()
        .expect("one queued delivery")
        .expect("queued delivery entry")
        .path();
    {
        let mut registry = lock_registry();
        let replacement = RegisteredWebhook {
            entry: registry_entry(1, "http://local.test/hook".to_string()),
            generation: test_webhook_generation(2),
        };
        let mut candidate = registry.clone();
        candidate.items.insert(1, replacement);
        persist_registry(&candidate).expect("persist replacement webhook registration");
        *registry = candidate;
    }
    *lock_registry() = RegistryInner::default();
    load_registry().expect("reload durable replacement before delivery");
    let delivery_attempts = Arc::new(AtomicU32::new(0));
    let recorded_attempts = Arc::clone(&delivery_attempts);
    let _http_guard = super::install_http_post_override(move |_, _, _| {
        recorded_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(204)
    });
    Runtime::new()
        .expect("tokio runtime")
        .block_on(process_queue_once());
    assert_eq!(
        delivery_attempts.load(Ordering::SeqCst),
        0,
        "a replacement registration must not inherit queued deliveries"
    );
    assert!(
        !queue_path.exists(),
        "the invalidated spool record must be removed"
    );
    let mut registry = lock_registry();
    registry.next_id = 0;
    registry.items.clear();
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn enqueue_respects_filter() {
    let _env = TestDataDirGuard::new();
    super::init_persistence().expect("initialize webhook persistence");
    // Insert 2 webhooks: one for Queued, one for Approved
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
        g.next_id += 1;
        let id1 = g.next_id;
        g.items.insert(
            id1,
            RegisteredWebhook {
                entry: WebhookEntry {
                    id: id1,
                    url: "http://127.0.0.1:9/blackhole".into(),
                    active: true,
                    secret: None,
                    filter: Some(crate::filter::FilterExpr::Eq(
                        crate::filter::FieldPath("tx_status".into()),
                        norito::json::Value::String("Queued".into()),
                    )),
                },
                generation: test_webhook_generation(id1),
            },
        );
        g.next_id += 1;
        let id2 = g.next_id;
        g.items.insert(
            id2,
            RegisteredWebhook {
                entry: WebhookEntry {
                    id: id2,
                    url: "http://127.0.0.1:9/blackhole".into(),
                    active: true,
                    secret: None,
                    filter: Some(crate::filter::FilterExpr::Eq(
                        crate::filter::FieldPath("tx_status".into()),
                        norito::json::Value::String("Approved".into()),
                    )),
                },
                generation: test_webhook_generation(id2),
            },
        );
    }
    // Event with tx_status = Queued
    let ev = EventBox::from(TransactionEvent {
        hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed([7u8; Hash::LENGTH])),
        block_height: None,
        lane_id: LaneId::SINGLE,
        dataspace_id: DataSpaceId::UNIVERSAL,
        status: TransactionStatus::Queued,
    });
    enqueue_event_for_matching_webhooks(&ev, "application/json");
    let files = std::fs::read_dir(queue_dir()).unwrap();
    let count = files
        .filter(|e| {
            if let Ok(f) = e {
                if let Some(ext) = f.path().extension() {
                    return ext == "json";
                }
            }
            false
        })
        .count();
    assert_eq!(count, 1);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn enqueue_respects_proof_envelope_hash_filter() {
    use crate::filter::{FieldPath, FilterExpr};
    use iroha_data_model::events::data::{
        prelude::DataEvent,
        proof::{ProofEvent, ProofVerified},
    };
    let _env = TestDataDirGuard::new();
    super::init_persistence().expect("initialize webhook persistence");
    // Two webhooks: one matches specific envelope hash, one with different hash
    let match_id: u64;
    {
        let mut g = registry().lock().unwrap();
        g.next_id = 0;
        g.items.clear();
        // matching: proof_envelope_hash == 0xCC..CC
        g.next_id += 1;
        let id1 = g.next_id;
        match_id = id1;
        g.items.insert(
            id1,
            RegisteredWebhook {
                entry: WebhookEntry {
                    id: id1,
                    url: "http://127.0.0.1:9/blackhole".into(),
                    active: true,
                    secret: None,
                    filter: Some(FilterExpr::Eq(
                        FieldPath("proof_envelope_hash".into()),
                        norito::json::Value::String(hex::encode([0xCCu8; 32])),
                    )),
                },
                generation: test_webhook_generation(id1),
            },
        );
        // non-matching: proof_envelope_hash == 0xDD..DD
        g.next_id += 1;
        let id2 = g.next_id;
        g.items.insert(
            id2,
            RegisteredWebhook {
                entry: WebhookEntry {
                    id: id2,
                    url: "http://127.0.0.1:9/blackhole".into(),
                    active: true,
                    secret: None,
                    filter: Some(FilterExpr::Eq(
                        FieldPath("proof_envelope_hash".into()),
                        norito::json::Value::String(hex::encode([0xDDu8; 32])),
                    )),
                },
                generation: test_webhook_generation(id2),
            },
        );
    }
    // Event with envelope_hash = 0xCC..CC
    let ev =
        iroha_data_model::events::EventBox::Data(iroha_data_model::events::SharedDataEvent::from(
            DataEvent::Proof(ProofEvent::Verified(ProofVerified {
                id: iroha_data_model::proof::ProofId {
                    backend: "halo2/ipa".into(),
                    proof_hash: [0xA1; 32],
                },
                vk_ref: None,
                vk_commitment: None,
                call_hash: None,
                envelope_hash: Some([0xCC; 32]),
            })),
        ));
    enqueue_event_for_matching_webhooks(&ev, "application/json");
    // Exactly one delivery (matching id1) should be enqueued; also assert webhook_id matches
    let files: Vec<_> = std::fs::read_dir(queue_dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    assert_eq!(files.len(), 1);
    let content = std::fs::read_to_string(files[0].path()).unwrap();
    let v: norito::json::Value = norito::json::from_str(&content).unwrap();
    let got_id = v
        .as_object()
        .and_then(|m| m.get("webhook_id"))
        .and_then(norito::json::Value::as_u64)
        .unwrap_or(0);
    assert_eq!(got_id, match_id);
}
#[test]
fn proof_id_eq_matches_only_the_exact_proof() {
    use crate::filter::{FieldPath, FilterExpr};
    let id = iroha_data_model::proof::ProofId {
        backend: "halo2/ipa".into(),
        proof_hash: [0xAA; 32],
    };
    let id_str = format!("{}", id);
    use iroha_data_model::events::data::{
        prelude::DataEvent,
        proof::{ProofEvent, ProofVerified},
    };
    let ev: iroha_data_model::events::EventBox =
        iroha_data_model::events::EventBox::Data(iroha_data_model::events::SharedDataEvent::from(
            DataEvent::Proof(ProofEvent::Verified(ProofVerified {
                id: id.clone(),
                vk_ref: None,
                vk_commitment: None,
                call_hash: None,
                envelope_hash: None,
            })),
        ));
    let expr = FilterExpr::Eq(
        FieldPath("proof_id".into()),
        norito::json::Value::String(id_str),
    );
    assert!(event_matches_filter(&ev, &expr));
    assert!(!event_matches_filter(
        &proof_verified_event("halo2/ipa", None),
        &expr,
    ));
}
#[test]
fn proof_filters_preserve_not_and_or_semantics() {
    use crate::filter::{FieldPath, FilterExpr};

    let event = proof_verified_event("halo2/ipa", Some([0xCC; 32]));
    let backend_is_halo2 = FilterExpr::Eq(
        FieldPath("proof_backend".to_owned()),
        norito::json::Value::from("halo2/ipa"),
    );
    assert!(!event_matches_filter(
        &event,
        &FilterExpr::Not(Box::new(backend_is_halo2.clone())),
    ));
    assert!(event_matches_filter(
        &event,
        &FilterExpr::Or(vec![
            FilterExpr::Eq(
                FieldPath("proof_backend".to_owned()),
                norito::json::Value::from("plonk"),
            ),
            FilterExpr::Eq(
                FieldPath("proof_call_hash".to_owned()),
                norito::json::Value::from(hex::encode([0xCC; 32])),
            ),
        ]),
    ));
    assert!(!event_matches_filter(
        &event,
        &FilterExpr::Or(vec![
            FilterExpr::Not(Box::new(backend_is_halo2)),
            FilterExpr::Eq(
                FieldPath("proof_call_hash".to_owned()),
                norito::json::Value::from(hex::encode([0xDD; 32])),
            ),
        ]),
    ));
}
#[test]
fn webhook_url_validation_rejects_localhost_when_enabled() {
    let policy = WebhookSecurityPolicy {
        enabled: true,
        allow_nets: Vec::new(),
    };
    let err = super::validate_webhook_url_for_create("http://localhost/callback", &policy)
        .expect_err("localhost must be rejected");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
}
#[test]
fn webhook_url_validation_allows_localhost_when_disabled() {
    let policy = WebhookSecurityPolicy {
        enabled: false,
        allow_nets: Vec::new(),
    };
    super::validate_webhook_url_for_create("http://localhost/callback", &policy)
        .expect("localhost allowed when guard rails disabled");
}
#[test]
fn webhook_url_validation_rejects_private_ip_literal_when_enabled() {
    let policy = WebhookSecurityPolicy {
        enabled: true,
        allow_nets: Vec::new(),
    };
    let err = super::validate_webhook_url_for_create("http://127.0.0.1:8080/callback", &policy)
        .expect_err("loopback must be rejected");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
}
#[test]
fn webhook_url_validation_allows_allowlisted_ip_literal_when_enabled() {
    let allow = crate::limits::parse_cidr("127.0.0.1/32").expect("valid cidr");
    let policy = WebhookSecurityPolicy {
        enabled: true,
        allow_nets: vec![allow],
    };
    super::validate_webhook_url_for_create("http://127.0.0.1:8080/callback", &policy)
        .expect("allow-listed loopback allowed");
}
#[test]
fn webhook_url_validation_rejects_userinfo_fragments_and_zero_ports() {
    let policy = WebhookSecurityPolicy {
        enabled: false,
        allow_nets: Vec::new(),
    };
    for invalid in [
        "http://user:secret@example.test/hook",
        "http://example.test/hook#fragment",
        "http://example.test:0/hook",
    ] {
        let error = super::validate_webhook_url_for_create(invalid, &policy)
            .expect_err("ambiguous or unsafe webhook URL must be rejected");
        assert_eq!(error.0, StatusCode::BAD_REQUEST, "URL: {invalid}");
    }
}
#[test]
fn webhook_url_validation_returns_a_canonical_destination() {
    let policy = WebhookSecurityPolicy {
        enabled: false,
        allow_nets: Vec::new(),
    };
    let url =
        super::validate_webhook_url_for_create("HTTP://EXAMPLE.TEST:80/hook?kind=event", &policy)
            .expect("valid webhook URL");
    assert_eq!(url.as_str(), "http://example.test/hook?kind=event");
}
#[cfg(not(feature = "app_api_https"))]
#[test]
fn webhook_url_validation_rejects_https_when_transport_is_absent() {
    let policy = WebhookSecurityPolicy {
        enabled: false,
        allow_nets: Vec::new(),
    };
    super::validate_webhook_url_for_create("https://example.test/hook", &policy)
        .expect_err("an unavailable HTTPS transport must be rejected at registration");
}
#[cfg(not(feature = "app_api_wss"))]
#[test]
fn webhook_url_validation_rejects_websockets_when_transport_is_absent() {
    let policy = WebhookSecurityPolicy {
        enabled: false,
        allow_nets: Vec::new(),
    };
    for unavailable in ["ws://example.test/hook", "wss://example.test/hook"] {
        super::validate_webhook_url_for_create(unavailable, &policy)
            .expect_err("an unavailable WebSocket transport must be rejected at registration");
    }
}
#[test]
fn webhook_delivery_guard_rejects_private_ip_literal_when_enabled() {
    let policy = WebhookSecurityPolicy {
        enabled: true,
        allow_nets: Vec::new(),
    };
    let url = Url::parse("http://127.0.0.1:1/callback").expect("valid url");
    let rt = Runtime::new().expect("tokio runtime");
    let err = rt
        .block_on(super::resolve_destination_addrs(&url, &policy))
        .expect_err("private destination rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}
#[cfg(feature = "app_api_https")]
#[test]
fn https_delivery_dns_override_pins_vetted_domain_addresses() {
    let url = Url::parse("https://example.test/hook").expect("valid url");
    let addrs = vec![
        "203.0.113.10:443".parse().expect("addr"),
        "203.0.113.11:443".parse().expect("addr"),
    ];
    let override_addrs = super::https_delivery_dns_override(&url, &addrs).expect("domain override");
    assert_eq!(override_addrs.0, "example.test");
    assert_eq!(override_addrs.1, addrs);
}
#[cfg(feature = "app_api_https")]
#[test]
fn https_delivery_dns_override_skips_ip_literals() {
    let url = Url::parse("https://203.0.113.10/hook").expect("valid url");
    let addrs = vec!["203.0.113.10:443".parse().expect("addr")];
    assert!(
        super::https_delivery_dns_override(&url, &addrs).is_none(),
        "ip-literal URLs should not install a DNS override"
    );
}
#[cfg(feature = "app_api_https")]
#[test]
fn https_delivery_client_does_not_follow_redirects() {
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let redirect_target = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect target");
        let target_address = redirect_target
            .local_addr()
            .expect("redirect target address");
        let redirect_source = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect source");
        let source_address = redirect_source
            .local_addr()
            .expect("redirect source address");
        let source_task = tokio::spawn(async move {
            let (mut socket, _) = redirect_source.accept().await.expect("accept request");
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request).await.expect("read request");
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write redirect");
        });

        let client = super::webhook_https_client_builder()
            .build()
            .expect("build webhook client");
        let response = client
            .post(format!("http://{source_address}/hook"))
            .body("event")
            .send()
            .await
            .expect("receive redirect response");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        source_task.await.expect("redirect source task");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), redirect_target.accept())
                .await
                .is_err(),
            "the unvetted redirect target must not be contacted"
        );
    });
}
#[cfg(feature = "app_api_wss")]
#[test]
fn websocket_pinned_connect_addr_pins_secure_delivery_when_guarded() {
    let policy = WebhookSecurityPolicy {
        enabled: true,
        allow_nets: Vec::new(),
    };
    let url = Url::parse("wss://example.test/socket").expect("valid url");
    let addrs = vec!["203.0.113.20:443".parse().expect("addr")];
    assert_eq!(
        super::websocket_pinned_connect_addr(&url, &policy, &addrs),
        addrs.first().copied()
    );
}
