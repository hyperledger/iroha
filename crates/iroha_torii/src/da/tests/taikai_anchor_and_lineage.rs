//! Taikai anchoring, durable receipts, and lineage admission tests.

use super::*;

fn is_non_regular_taikai_rejection(message: &str) -> bool {
    if message.contains("is not a regular file") {
        return true;
    }
    #[cfg(unix)]
    {
        message.contains(&std::io::Error::from_raw_os_error(libc::ELOOP).to_string())
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[derive(Default)]
struct MockAnchorSender {
    calls: AsyncMutex<Vec<(Url, String, Option<String>)>>,
}
#[async_trait]
impl AnchorSender for MockAnchorSender {
    async fn send(
        &self,
        endpoint: &Url,
        base_id: &str,
        body: &str,
        api_token: Option<&str>,
    ) -> Result<Vec<u8>, AnchorSendError> {
        self.calls.lock().await.push((
            endpoint.clone(),
            body.to_owned(),
            api_token.map(str::to_owned),
        ));
        Ok(signed_anchor_receipt(base_id, body))
    }
}
struct BlockingSentinelAnchorSender {
    calls: AsyncMutex<Vec<(Url, String, Option<String>)>>,
    sentinel_path: PathBuf,
}
#[async_trait]
impl AnchorSender for BlockingSentinelAnchorSender {
    async fn send(
        &self,
        endpoint: &Url,
        base_id: &str,
        body: &str,
        api_token: Option<&str>,
    ) -> Result<Vec<u8>, AnchorSendError> {
        {
            self.calls.lock().await.push((
                endpoint.clone(),
                body.to_owned(),
                api_token.map(str::to_owned),
            ));
        }
        async_fs::create_dir(&self.sentinel_path)
            .await
            .expect("block sentinel path");
        Ok(signed_anchor_receipt(base_id, body))
    }
}
#[derive(Default)]
struct FailingAnchorSender {
    calls: AsyncMutex<Vec<(Url, String, Option<String>)>>,
}
#[async_trait]
impl AnchorSender for FailingAnchorSender {
    async fn send(
        &self,
        endpoint: &Url,
        _base_id: &str,
        body: &str,
        api_token: Option<&str>,
    ) -> Result<Vec<u8>, AnchorSendError> {
        self.calls.lock().await.push((
            endpoint.clone(),
            body.to_owned(),
            api_token.map(str::to_owned),
        ));
        Err(Box::new(std::io::Error::new(
            ErrorKind::ConnectionRefused,
            "anchor service unavailable",
        )))
    }
}
#[derive(Default)]
struct FirstFailingAnchorSender {
    calls: AsyncMutex<Vec<(Url, String, Option<String>)>>,
}
#[async_trait]
impl AnchorSender for FirstFailingAnchorSender {
    async fn send(
        &self,
        endpoint: &Url,
        base_id: &str,
        body: &str,
        api_token: Option<&str>,
    ) -> Result<Vec<u8>, AnchorSendError> {
        let call_count = {
            let mut calls = self.calls.lock().await;
            calls.push((
                endpoint.clone(),
                body.to_owned(),
                api_token.map(str::to_owned),
            ));
            calls.len()
        };
        if call_count == 1 {
            return Err(Box::new(std::io::Error::new(
                ErrorKind::ConnectionRefused,
                "anchor service unavailable for first upload",
            )));
        }
        Ok(signed_anchor_receipt(base_id, body))
    }
}
struct FirstBlockingSentinelAnchorSender {
    calls: AsyncMutex<Vec<(Url, String, Option<String>)>>,
    sentinel_paths_by_body: BTreeMap<String, PathBuf>,
}
#[async_trait]
impl AnchorSender for FirstBlockingSentinelAnchorSender {
    async fn send(
        &self,
        endpoint: &Url,
        base_id: &str,
        body: &str,
        api_token: Option<&str>,
    ) -> Result<Vec<u8>, AnchorSendError> {
        let call_count = {
            let mut calls = self.calls.lock().await;
            calls.push((
                endpoint.clone(),
                body.to_owned(),
                api_token.map(str::to_owned),
            ));
            calls.len()
        };
        if call_count == 1 {
            let sentinel_path = self
                .sentinel_paths_by_body
                .get(body)
                .expect("first upload body should have a sentinel path");
            async_fs::create_dir(sentinel_path)
                .await
                .expect("block first sentinel path");
        }
        Ok(signed_anchor_receipt(base_id, body))
    }
}

struct StaticAnchorResponseSender {
    response: Vec<u8>,
}

#[async_trait]
impl AnchorSender for StaticAnchorResponseSender {
    async fn send(
        &self,
        _endpoint: &Url,
        _base_id: &str,
        _body: &str,
        _api_token: Option<&str>,
    ) -> Result<Vec<u8>, AnchorSendError> {
        Ok(self.response.clone())
    }
}

async fn write_minimal_taikai_anchor_artifacts(spool_dir: &Path, base_id: &str) {
    async_fs::create_dir_all(spool_dir)
        .await
        .expect("create spool");
    async_fs::write(
        spool_dir.join(format!("taikai-envelope-{base_id}.norito")),
        b"envelope-bytes",
    )
    .await
    .expect("write envelope");
    async_fs::write(
        spool_dir.join(format!("taikai-indexes-{base_id}.json")),
        b"{}",
    )
    .await
    .expect("write indexes");
    async_fs::write(
        spool_dir.join(format!("taikai-ssm-{base_id}.norito")),
        b"ssm-bytes",
    )
    .await
    .expect("write ssm");
    async_fs::write(
        spool_dir.join(format!(
            "{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"
        )),
        b"ready-v1\n",
    )
    .await
    .expect("write readiness marker");
}
const ANCHOR_BASE_ID: &str = "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
struct AnchorFixture {
    _dir: tempfile::TempDir,
    spool_dir: PathBuf,
    base_id: &'static str,
}
async fn minimal_anchor_fixture(base_id: &'static str) -> AnchorFixture {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    write_minimal_taikai_anchor_artifacts(&spool_dir, base_id).await;
    AnchorFixture {
        _dir: dir,
        spool_dir,
        base_id,
    }
}
fn taikai_anchor_config(api_token: Option<&str>) -> DaTaikaiAnchor {
    DaTaikaiAnchor {
        endpoint: Url::parse("http://localhost/anchor").unwrap(),
        api_token: api_token.map(str::to_owned),
        receipt_public_key: anchor_signer().public_key().clone(),
        poll_interval: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
    }
}
fn anchor_signer() -> KeyPair {
    checked_fixture_ed25519_keypair(0xA7)
}
fn signed_anchor_receipt(base_id: &str, request_body: &str) -> Vec<u8> {
    signed_anchor_receipt_with_signer(base_id, request_body, &anchor_signer())
}

fn signed_anchor_receipt_with_signer(
    base_id: &str,
    request_body: &str,
    signer: &KeyPair,
) -> Vec<u8> {
    let body = TaikaiAnchorReceiptBodyV1 {
        schema: TAIKAI_ANCHOR_RECEIPT_SCHEMA_V1.to_owned(),
        version: TAIKAI_ANCHOR_RECEIPT_VERSION_V1,
        base_id: base_id.to_owned(),
        request_digest: *blake3_hash(request_body.as_bytes()).as_bytes(),
        acknowledged_unix_secs: 1_750_000_000,
    };
    let receipt =
        TaikaiAnchorReceiptV1::try_sign(body, signer).expect("sign Taikai anchor receipt");
    json::to_vec(&receipt).expect("encode Taikai anchor receipt")
}
#[cfg(unix)]
async fn replace_path_with_symlink(path: &Path, target_contents: &[u8]) -> PathBuf {
    use std::os::unix::fs::symlink;
    if let Err(err) = async_fs::remove_file(path).await {
        assert_eq!(
            err.kind(),
            ErrorKind::NotFound,
            "failed to remove existing path before symlink replacement: {err}"
        );
    }
    let target = path.with_extension("symlink-target");
    async_fs::write(&target, target_contents)
        .await
        .expect("write symlink target");
    symlink(&target, path).expect("create symlink");
    target
}
#[cfg(unix)]
fn assert_path_remains_symlink(path: &Path, target: &Path) {
    assert!(
        fs::symlink_metadata(path)
            .expect("inspect symlink")
            .file_type()
            .is_symlink(),
        "failed validation should leave symlink visible for operator repair"
    );
    assert!(target.exists(), "symlink target should not be removed");
}
#[tokio::test]
async fn taikai_collect_pending_uploads_sorts_by_base_id() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    let base_a = "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let base_b = "00000001-0000000000000002-0000000000000004-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    write_minimal_taikai_anchor_artifacts(&spool_dir, base_b).await;
    write_minimal_taikai_anchor_artifacts(&spool_dir, base_a).await;
    let pending = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect pending uploads");
    let observed: Vec<_> = pending
        .iter()
        .map(crate::da::taikai::taikai_ingest::PendingUpload::base_id)
        .collect();
    assert_eq!(observed, vec![base_a, base_b]);
}
#[tokio::test]
async fn taikai_anchor_collection_waits_for_durable_readiness_marker() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    write_minimal_taikai_anchor_artifacts(&spool_dir, ANCHOR_BASE_ID).await;
    let ready_path = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_READY_PREFIX}{ANCHOR_BASE_ID}{TAIKAI_ANCHOR_READY_SUFFIX}"
    ));
    async_fs::remove_file(&ready_path)
        .await
        .expect("remove readiness marker");
    assert!(
        collect_pending_uploads(&spool_dir)
            .await
            .expect("incomplete upload collection")
            .is_empty(),
        "an envelope must remain invisible until its durable receipt publishes readiness"
    );
    async_fs::write(&ready_path, b"ready-v1\n")
        .await
        .expect("restore readiness marker");
    assert_eq!(
        collect_pending_uploads(&spool_dir)
            .await
            .expect("ready upload collection")
            .len(),
        1
    );
}
#[tokio::test]
async fn taikai_anchor_processing_continues_after_candidate_load_failure() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    let corrupt_base = "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let valid_base = "00000001-0000000000000002-0000000000000004-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    write_minimal_taikai_anchor_artifacts(&spool_dir, corrupt_base).await;
    write_minimal_taikai_anchor_artifacts(&spool_dir, valid_base).await;
    async_fs::write(
        spool_dir.join(format!("taikai-indexes-{corrupt_base}.json")),
        b"{not-json",
    )
    .await
    .expect("corrupt first indexes");
    let sender = MockAnchorSender::default();
    let err = process_batch(&spool_dir, &taikai_anchor_config(None), &sender)
        .await
        .expect_err("corrupt candidate must be reported");
    assert!(err.contains(corrupt_base), "unexpected error: {err}");
    assert_eq!(
        sender.calls.lock().await.len(),
        1,
        "the valid later candidate must still be delivered"
    );
    assert!(
        spool_dir
            .join(format!(
                "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{valid_base}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
            ))
            .exists(),
        "later successful candidate must be acknowledged"
    );
    assert!(
        spool_dir
            .join(format!(
                "{TAIKAI_ANCHOR_READY_PREFIX}{corrupt_base}{TAIKAI_ANCHOR_READY_SUFFIX}"
            ))
            .is_file(),
        "a failed candidate must remain durable for retry or operator repair"
    );
}
#[tokio::test]
async fn taikai_anchor_processing_generates_payload_and_sentinel() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    async_fs::create_dir_all(&spool_dir)
        .await
        .expect("create spool");
    let base_id = "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let envelope_path = spool_dir.join(format!("taikai-envelope-{base_id}.norito"));
    async_fs::write(&envelope_path, b"envelope-bytes")
        .await
        .expect("write envelope");
    let indexes = TaikaiEnvelopeIndexes {
        time_key: TaikaiTimeIndexKey {
            event_id: TaikaiEventId::new(Name::from_str("global-keynote").unwrap()),
            stream_id: TaikaiStreamId::new(Name::from_str("stage-a").unwrap()),
            rendition_id: TaikaiRenditionId::new(Name::from_str("1080p").unwrap()),
            segment_start_pts: SegmentTimestamp::new(3_600_000),
        },
        cid_key: TaikaiCidIndexKey {
            event_id: TaikaiEventId::new(Name::from_str("global-keynote").unwrap()),
            stream_id: TaikaiStreamId::new(Name::from_str("stage-a").unwrap()),
            rendition_id: TaikaiRenditionId::new(Name::from_str("1080p").unwrap()),
            cid_multibase: "zbafyqra".to_string(),
        },
    };
    let indexes_json = norito::json::to_json_pretty(&indexes).expect("indexes json");
    let indexes_path = spool_dir.join(format!("taikai-indexes-{base_id}.json"));
    async_fs::write(&indexes_path, indexes_json.as_bytes())
        .await
        .expect("write indexes");
    let ssm_path = spool_dir.join(format!("taikai-ssm-{base_id}.norito"));
    async_fs::write(&ssm_path, b"ssm-bytes")
        .await
        .expect("write ssm");
    async_fs::write(
        spool_dir.join(format!(
            "{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"
        )),
        b"ready-v1\n",
    )
    .await
    .expect("write readiness marker");
    let trm_bytes = sample_trm_bytes();
    let trm_path = spool_dir.join(format!("taikai-trm-{base_id}.norito"));
    async_fs::write(&trm_path, &trm_bytes)
        .await
        .expect("write trm");
    let mut lineage_hint = Map::new();
    lineage_hint.insert("version".into(), Value::from(1));
    lineage_hint.insert("alias_namespace".into(), Value::from("sora"));
    lineage_hint.insert("alias_name".into(), Value::from("docs"));
    lineage_hint.insert(
        "previous_manifest_digest_hex".into(),
        Value::from("cafebabe"),
    );
    lineage_hint.insert("previous_window_start_sequence".into(), Value::from(1));
    lineage_hint.insert("previous_window_end_sequence".into(), Value::from(120));
    lineage_hint.insert("previous_updated_unix".into(), Value::from(1_234_567));
    let lineage_value = Value::Object(lineage_hint.clone());
    let lineage_path = spool_dir.join(format!("taikai-lineage-{base_id}.json"));
    async_fs::write(
        &lineage_path,
        json::to_string(&lineage_value)
            .expect("lineage json")
            .as_bytes(),
    )
    .await
    .expect("write lineage hint");
    let anchor_cfg = taikai_anchor_config(Some("secret-token"));
    let pending = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].base_id(), base_id);
    let payload: Value = norito::json::from_str(pending[0].body()).expect("payload json");
    assert_eq!(
        payload.get("envelope_base64").and_then(Value::as_str),
        Some(BASE64.encode(b"envelope-bytes")).as_deref()
    );
    assert_eq!(
        payload.get("ssm_base64").and_then(Value::as_str),
        Some(BASE64.encode(b"ssm-bytes")).as_deref()
    );
    assert_eq!(
        payload.get("trm_base64").and_then(Value::as_str),
        Some(BASE64.encode(&trm_bytes)).as_deref()
    );
    assert_eq!(payload.get("lineage_hint"), Some(&lineage_value));
    let request_capture = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
    ));
    let capture_contents = async_fs::read_to_string(&request_capture)
        .await
        .expect("request capture after collection");
    assert_eq!(capture_contents, pending[0].body());
    assert!(
        temp_artifact_names(&spool_dir).is_empty(),
        "request capture persistence should not leave temporary artifacts"
    );
    let pending_again = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect pending idempotently");
    assert_eq!(pending_again.len(), 1);
    assert_eq!(pending_again[0].body(), pending[0].body());
    assert!(
        temp_artifact_names(&spool_dir).is_empty(),
        "idempotent request capture persistence should not leave temporary artifacts"
    );
    let sender = MockAnchorSender::default();
    process_batch(&spool_dir, &anchor_cfg, &sender)
        .await
        .expect("process batch");
    let calls = sender.calls.lock().await.clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, anchor_cfg.endpoint);
    assert_eq!(calls[0].2.as_deref(), anchor_cfg.api_token.as_deref());
    assert_eq!(calls[0].1, pending[0].body());
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    assert!(async_fs::metadata(&sentinel).await.is_ok());
    let capture_contents = async_fs::read_to_string(&request_capture)
        .await
        .expect("request capture");
    assert_eq!(capture_contents, pending[0].body());
    let pending_after = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect after upload");
    assert!(pending_after.is_empty());
}

#[tokio::test]
async fn taikai_anchor_processing_rejects_status_only_success() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let sender = StaticAnchorResponseSender {
        response: Vec::new(),
    };

    let err = process_batch(&spool_dir, &taikai_anchor_config(None), &sender)
        .await
        .expect_err("an empty 2xx response must not acknowledge an upload");

    assert!(
        err.contains("invalid Taikai receipt"),
        "unexpected process error: {err}"
    );
    assert!(
        spool_dir
            .join(format!("taikai-envelope-{base_id}.norito"))
            .is_file(),
        "status-only success must leave source artefacts retryable"
    );
    assert!(
        !spool_dir
            .join(format!(
                "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
            ))
            .exists(),
        "status-only success must not create an acknowledgement"
    );
    assert_eq!(
        collect_pending_uploads(&spool_dir)
            .await
            .expect("collect after status-only success")
            .len(),
        1
    );
}

#[tokio::test]
async fn taikai_anchor_processing_rejects_receipt_for_different_request() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let sender = StaticAnchorResponseSender {
        response: signed_anchor_receipt(base_id, "different exact request bytes"),
    };

    let err = process_batch(&spool_dir, &taikai_anchor_config(None), &sender)
        .await
        .expect_err("a receipt for different bytes must not acknowledge an upload");

    assert!(
        err.contains("request digest does not match"),
        "unexpected process error: {err}"
    );
    assert!(
        spool_dir
            .join(format!("taikai-envelope-{base_id}.norito"))
            .is_file(),
        "request-binding failure must leave source artefacts retryable"
    );
}

#[tokio::test]
async fn taikai_anchor_processing_rejects_receipt_for_different_base_id() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let pending = collect_pending_uploads(&spool_dir)
        .await
        .expect("prepare request capture");
    let different_base_id = "00000001-0000000000000002-0000000000000004-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let sender = StaticAnchorResponseSender {
        response: signed_anchor_receipt(different_base_id, pending[0].body()),
    };

    let err = process_batch(&spool_dir, &taikai_anchor_config(None), &sender)
        .await
        .expect_err("a receipt for another artefact must not acknowledge an upload");

    assert!(
        err.contains("receipt base_id") && err.contains("does not match"),
        "unexpected process error: {err}"
    );
    assert!(
        spool_dir
            .join(format!("taikai-envelope-{base_id}.norito"))
            .is_file(),
        "artefact-binding failure must leave source artefacts retryable"
    );
}

#[tokio::test]
async fn taikai_anchor_processing_rejects_receipt_from_unpinned_signer() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let pending = collect_pending_uploads(&spool_dir)
        .await
        .expect("prepare request capture");
    let wrong_signer = checked_fixture_ed25519_keypair(0xB8);
    let sender = StaticAnchorResponseSender {
        response: signed_anchor_receipt_with_signer(base_id, pending[0].body(), &wrong_signer),
    };

    let err = process_batch(&spool_dir, &taikai_anchor_config(None), &sender)
        .await
        .expect_err("an untrusted signer must not acknowledge an upload");

    assert!(
        err.contains("signature validation failed"),
        "unexpected process error: {err}"
    );
    assert!(
        spool_dir
            .join(format!("taikai-envelope-{base_id}.norito"))
            .is_file(),
        "signer validation failure must leave source artefacts retryable"
    );
}

#[tokio::test]
async fn taikai_anchor_restart_quarantines_legacy_timestamp_sentinel() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    collect_pending_uploads(&spool_dir)
        .await
        .expect("prepare request capture");
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    async_fs::write(&sentinel, b"1750000000\n")
        .await
        .expect("write legacy timestamp sentinel");

    let pending = collect_pending_uploads(&spool_dir)
        .await
        .expect("a legacy marker should be quarantined without blocking retry");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].base_id(), base_id);
    assert!(
        spool_dir
            .join(format!("taikai-envelope-{base_id}.norito"))
            .is_file(),
        "unverified restart state must not retire source artefacts"
    );
    assert!(
        !sentinel.exists(),
        "legacy marker must leave the live namespace"
    );
    let quarantine_suffix = format!("{TAIKAI_ANCHOR_INVALID_SUFFIX}-");
    let quarantined = fs::read_dir(&spool_dir)
        .expect("scan quarantine evidence")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with(TAIKAI_ANCHOR_SENTINEL_PREFIX) && name.contains(&quarantine_suffix)
        })
        .count();
    assert_eq!(quarantined, 1, "legacy marker must be retained as evidence");
}

#[tokio::test]
async fn taikai_anchor_prune_quarantines_orphan_legacy_sentinel() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    async_fs::create_dir(&spool_dir)
        .await
        .expect("create Taikai spool");
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{ANCHOR_BASE_ID}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    async_fs::write(&sentinel, b"1750000000\n")
        .await
        .expect("write orphan legacy sentinel");
    let sender = MockAnchorSender::default();

    process_batch(&spool_dir, &taikai_anchor_config(None), &sender)
        .await
        .expect("orphan legacy marker should be quarantined during pruning");

    assert!(
        sender.calls.lock().await.is_empty(),
        "an orphan acknowledgement must not trigger an upload"
    );
    assert!(
        !sentinel.exists(),
        "orphan legacy marker must leave the live acknowledgement namespace"
    );
    let quarantine_suffix = format!("{TAIKAI_ANCHOR_INVALID_SUFFIX}-");
    let quarantined = fs::read_dir(&spool_dir)
        .expect("scan orphan quarantine evidence")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with(TAIKAI_ANCHOR_SENTINEL_PREFIX) && name.contains(&quarantine_suffix)
        })
        .count();
    assert_eq!(
        quarantined, 1,
        "orphan legacy marker must be retained as evidence"
    );
}

#[tokio::test]
async fn taikai_anchor_restart_accepts_exact_signed_receipt() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let pending = collect_pending_uploads(&spool_dir)
        .await
        .expect("prepare request capture");
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    async_fs::write(&sentinel, signed_anchor_receipt(base_id, pending[0].body()))
        .await
        .expect("persist signed receipt before simulated restart");

    assert!(
        collect_pending_uploads(&spool_dir)
            .await
            .expect("recover exact signed receipt")
            .is_empty()
    );
    for source in [
        format!("taikai-envelope-{base_id}.norito"),
        format!("taikai-indexes-{base_id}.json"),
        format!("taikai-ssm-{base_id}.norito"),
        format!("{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"),
    ] {
        assert!(
            !spool_dir.join(source).exists(),
            "verified restart recovery must retire source artefacts"
        );
    }
    assert!(
        sentinel.is_file(),
        "verified receipt remains as audit evidence"
    );
    assert!(
        spool_dir
            .join(format!(
                "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
            ))
            .is_file(),
        "exact request capture remains available for future verification"
    );
}

#[tokio::test]
async fn taikai_anchor_processing_reports_anchor_delivery_failure() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    let anchor_cfg = taikai_anchor_config(None);
    let sender = FailingAnchorSender::default();
    let err = process_batch(&spool_dir, &anchor_cfg, &sender)
        .await
        .expect_err("anchor delivery failure should fail batch processing");
    assert!(
        err.contains("failed to deliver Taikai envelope"),
        "unexpected process error: {err}"
    );
    assert!(
        err.contains(base_id),
        "delivery error should identify affected artifact: {err}"
    );
    assert!(
        err.contains("anchor service unavailable"),
        "delivery error should retain sender error context: {err}"
    );
    assert_eq!(sender.calls.lock().await.len(), 1);
    assert!(
        async_fs::metadata(&sentinel).await.is_err(),
        "failed delivery must not mark the upload as anchored"
    );
    let pending_after = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect after failed delivery");
    assert_eq!(pending_after.len(), 1);
    assert_eq!(pending_after[0].base_id(), base_id);
}
#[tokio::test]
async fn taikai_anchor_processing_continues_after_anchor_delivery_failure() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    let base_ids = [
        "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "00000001-0000000000000002-0000000000000004-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ];
    for (base_id, label) in base_ids.iter().zip(["first", "second"]) {
        write_minimal_taikai_anchor_artifacts(&spool_dir, base_id).await;
        async_fs::write(
            spool_dir.join(format!("taikai-indexes-{base_id}.json")),
            format!(r#"{{"case":"{label}"}}"#),
        )
        .await
        .expect("write distinct indexes");
    }
    let pending_before = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect pending before upload");
    assert_eq!(pending_before.len(), 2);
    assert_ne!(
        pending_before[0].body(),
        pending_before[1].body(),
        "test fixture bodies must identify which upload failed"
    );
    let anchor_cfg = taikai_anchor_config(None);
    let sender = FirstFailingAnchorSender::default();
    let err = process_batch(&spool_dir, &anchor_cfg, &sender)
        .await
        .expect_err("first delivery failure should still be reported");
    assert!(
        err.contains("failed to deliver Taikai envelope"),
        "unexpected process error: {err}"
    );
    assert!(
        err.contains("anchor service unavailable for first upload"),
        "delivery error should retain sender error context: {err}"
    );
    let calls = sender.calls.lock().await.clone();
    assert_eq!(
        calls.len(),
        2,
        "batch processing must attempt later uploads after a delivery failure"
    );
    let failed_base_id = pending_before
        .iter()
        .find(|pending| pending.body() == calls[0].1.as_str())
        .map(|pending| pending.base_id().to_string())
        .expect("failed upload body should come from pending set");
    let succeeded_base_id = pending_before
        .iter()
        .find(|pending| pending.body() == calls[1].1.as_str())
        .map(|pending| pending.base_id().to_string())
        .expect("successful upload body should come from pending set");
    assert_ne!(failed_base_id, succeeded_base_id);
    assert!(
        err.contains(&failed_base_id),
        "delivery error should identify failed artifact: {err}"
    );
    let sentinel_path = |base_id: &str| {
        spool_dir.join(format!(
            "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
        ))
    };
    assert!(
        async_fs::metadata(sentinel_path(&failed_base_id))
            .await
            .is_err(),
        "failed delivery must not mark the upload as anchored"
    );
    assert!(
        async_fs::metadata(sentinel_path(&succeeded_base_id))
            .await
            .is_ok(),
        "later successful delivery should be marked as anchored"
    );
    let pending_after = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect after partial delivery failure");
    assert_eq!(pending_after.len(), 1);
    assert_eq!(pending_after[0].base_id(), failed_base_id);
}
#[tokio::test]
async fn taikai_anchor_processing_reports_all_anchor_delivery_failures() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    let base_ids = [
        "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "00000001-0000000000000002-0000000000000004-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ];
    for base_id in base_ids {
        write_minimal_taikai_anchor_artifacts(&spool_dir, base_id).await;
    }
    let anchor_cfg = taikai_anchor_config(None);
    let sender = FailingAnchorSender::default();
    let err = process_batch(&spool_dir, &anchor_cfg, &sender)
        .await
        .expect_err("delivery failures should fail batch processing");
    assert!(
        err.contains("failed to process 2 Taikai anchor uploads"),
        "unexpected process error: {err}"
    );
    for base_id in base_ids {
        assert!(
            err.contains(base_id),
            "aggregate error should identify every failed artifact: {err}"
        );
    }
    assert_eq!(
        sender.calls.lock().await.len(),
        2,
        "batch processing must attempt every pending upload"
    );
    let sentinel_path = |base_id: &str| {
        spool_dir.join(format!(
            "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
        ))
    };
    for base_id in base_ids {
        assert!(
            async_fs::metadata(sentinel_path(base_id)).await.is_err(),
            "failed delivery must not mark upload as anchored"
        );
    }
    let pending_after = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect after failed deliveries");
    let pending_base_ids: BTreeSet<_> = pending_after
        .iter()
        .map(|pending| pending.base_id().to_string())
        .collect();
    assert_eq!(
        pending_base_ids,
        base_ids.into_iter().map(str::to_string).collect()
    );
}
#[tokio::test]
async fn taikai_anchor_processing_continues_after_sentinel_persistence_failure() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    let base_ids = [
        "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "00000001-0000000000000002-0000000000000004-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ];
    for (base_id, label) in base_ids.iter().zip(["first", "second"]) {
        write_minimal_taikai_anchor_artifacts(&spool_dir, base_id).await;
        async_fs::write(
            spool_dir.join(format!("taikai-indexes-{base_id}.json")),
            format!(r#"{{"case":"{label}"}}"#),
        )
        .await
        .expect("write distinct indexes");
    }
    let pending_before = collect_pending_uploads(&spool_dir)
        .await
        .expect("collect pending before upload");
    assert_eq!(pending_before.len(), 2);
    let sentinel_paths_by_body = pending_before
        .iter()
        .map(|pending| {
            (
                pending.body().to_string(),
                spool_dir.join(format!(
                    "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}",
                    pending.base_id()
                )),
            )
        })
        .collect();
    let anchor_cfg = taikai_anchor_config(None);
    let sender = FirstBlockingSentinelAnchorSender {
        calls: AsyncMutex::new(Vec::new()),
        sentinel_paths_by_body,
    };
    let err = process_batch(&spool_dir, &anchor_cfg, &sender)
        .await
        .expect_err("blocked first sentinel should still be reported");
    assert!(
        err.contains("failed to persist Taikai anchor sentinel"),
        "unexpected process error: {err}"
    );
    let calls = sender.calls.lock().await.clone();
    assert_eq!(
        calls.len(),
        2,
        "batch processing must attempt later uploads after a sentinel failure"
    );
    let failed_base_id = pending_before
        .iter()
        .find(|pending| pending.body() == calls[0].1.as_str())
        .map(|pending| pending.base_id().to_string())
        .expect("failed upload body should come from pending set");
    let succeeded_base_id = pending_before
        .iter()
        .find(|pending| pending.body() == calls[1].1.as_str())
        .map(|pending| pending.base_id().to_string())
        .expect("successful upload body should come from pending set");
    assert_ne!(failed_base_id, succeeded_base_id);
    assert!(
        err.contains(&failed_base_id),
        "sentinel error should identify failed artifact path: {err}"
    );
    let sentinel_path = |base_id: &str| {
        spool_dir.join(format!(
            "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
        ))
    };
    assert!(
        async_fs::metadata(sentinel_path(&failed_base_id))
            .await
            .expect("failed sentinel path metadata")
            .is_dir(),
        "failed sentinel path should remain blocked for operator inspection"
    );
    assert!(
        async_fs::metadata(sentinel_path(&succeeded_base_id))
            .await
            .is_ok(),
        "later successful delivery should still be marked as anchored"
    );
    assert!(
        temp_artifact_names(&spool_dir).is_empty(),
        "failed sentinel persistence should clean up temporary artifacts"
    );
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("blocked sentinel must reject later anchor collection"),
        Err(err) => err,
    };
    assert!(
        is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&sentinel_path(&failed_base_id).display().to_string()),
        "error should identify non-file sentinel path: {err}"
    );
}
#[tokio::test]
async fn taikai_anchor_processing_rejects_unpersistable_sentinel_after_upload() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    let anchor_cfg = taikai_anchor_config(None);
    let sender = BlockingSentinelAnchorSender {
        calls: AsyncMutex::new(Vec::new()),
        sentinel_path: sentinel.clone(),
    };
    let err = process_batch(&spool_dir, &anchor_cfg, &sender)
        .await
        .expect_err("blocked sentinel should fail batch processing");
    assert!(
        err.contains("failed to persist Taikai anchor sentinel"),
        "unexpected process error: {err}"
    );
    assert!(
        err.contains(&sentinel.display().to_string()),
        "error should identify blocked sentinel path: {err}"
    );
    assert_eq!(sender.calls.lock().await.len(), 1);
    assert!(
        async_fs::metadata(&sentinel)
            .await
            .expect("sentinel path metadata")
            .is_dir(),
        "test sender should leave a directory at the sentinel path"
    );
    assert!(
        temp_artifact_names(&spool_dir).is_empty(),
        "failed sentinel persistence should clean up temporary artifacts"
    );
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("non-file sentinel must reject later anchor collection"),
        Err(err) => err,
    };
    assert!(
        is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&sentinel.display().to_string()),
        "error should identify non-file sentinel path: {err}"
    );
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_malformed_base_id() {
    let base_id = "not-a-production-base-id";
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(base_id).await;
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("malformed base id must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("malformed spool artifact id"),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(base_id),
        "error should identify malformed base id: {err}"
    );
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_non_file_sentinel() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    async_fs::create_dir(&sentinel)
        .await
        .expect("create sentinel directory");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("non-file sentinel must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&sentinel.display().to_string()),
        "error should identify non-file sentinel path: {err}"
    );
}
#[cfg(unix)]
#[tokio::test]
async fn taikai_anchor_collection_rejects_symlinked_sentinel() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let sentinel = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
    ));
    let target = replace_path_with_symlink(&sentinel, b"uploaded").await;
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("symlinked sentinel must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("Taikai anchor sentinel") && is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&sentinel.display().to_string()),
        "error should identify symlinked sentinel path: {err}"
    );
    assert_path_remains_symlink(&sentinel, &target);
}
#[cfg(unix)]
#[tokio::test]
async fn taikai_anchor_collection_rejects_symlinked_spool_root() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("taikai-spool-target");
    async_fs::create_dir(&target)
        .await
        .expect("create target directory");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    symlink(&target, &spool_dir).expect("create Taikai spool symlink");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("symlinked Taikai spool root must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("Taikai spool directory") && err.contains("not a direct directory"),
        "unexpected anchor collection error: {err}"
    );
    assert_path_remains_symlink(&spool_dir, &target);
}
#[cfg(unix)]
#[tokio::test]
async fn taikai_anchor_collection_rejects_symlinked_envelope() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let envelope = spool_dir.join(format!("taikai-envelope-{base_id}.norito"));
    let target = replace_path_with_symlink(&envelope, b"envelope-bytes").await;
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("symlinked envelope must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("Taikai envelope") && is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&envelope.display().to_string()),
        "error should identify symlinked envelope path: {err}"
    );
    assert_path_remains_symlink(&envelope, &target);
}
#[cfg(unix)]
#[tokio::test]
async fn taikai_anchor_collection_rejects_symlinked_required_companion() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let indexes = spool_dir.join(format!("taikai-indexes-{base_id}.json"));
    let target = replace_path_with_symlink(&indexes, b"{}").await;
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("symlinked indexes companion must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("Taikai indexes JSON") && is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&indexes.display().to_string()),
        "error should identify symlinked indexes path: {err}"
    );
    assert_path_remains_symlink(&indexes, &target);
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_missing_required_artifacts() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    async_fs::create_dir_all(&spool_dir)
        .await
        .expect("create spool");
    let base_id = "00000001-0000000000000002-0000000000000003-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    async_fs::write(
        spool_dir.join(format!("taikai-envelope-{base_id}.norito")),
        b"envelope-bytes",
    )
    .await
    .expect("write envelope");
    async_fs::write(
        spool_dir.join(format!(
            "{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"
        )),
        b"ready-v1\n",
    )
    .await
    .expect("write readiness marker");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("missing required companion artifact must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("failed to read Taikai indexes JSON"),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(base_id),
        "error should identify affected base id: {err}"
    );
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_corrupt_indexes_json() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    async_fs::write(
        spool_dir.join(format!("taikai-indexes-{base_id}.json")),
        b"{not-json",
    )
    .await
    .expect("write corrupt indexes");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("corrupt indexes JSON must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("failed to parse Taikai indexes JSON"),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(base_id),
        "error should identify affected base id: {err}"
    );
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_corrupt_lineage_hint() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    async_fs::write(
        spool_dir.join(format!("taikai-lineage-{base_id}.json")),
        b"{not-json",
    )
    .await
    .expect("write corrupt lineage");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("corrupt lineage hint must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("failed to parse Taikai lineage hint JSON"),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(base_id),
        "error should identify affected base id: {err}"
    );
}
#[cfg(unix)]
#[tokio::test]
async fn taikai_anchor_collection_rejects_symlinked_optional_trm() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let trm = spool_dir.join(format!("taikai-trm-{base_id}.norito"));
    let target = replace_path_with_symlink(&trm, b"trm-bytes").await;
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("symlinked optional TRM must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("Taikai routing manifest") && is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&trm.display().to_string()),
        "error should identify symlinked TRM path: {err}"
    );
    assert_path_remains_symlink(&trm, &target);
}
#[cfg(unix)]
#[tokio::test]
async fn taikai_anchor_collection_rejects_symlinked_optional_lineage_hint() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let lineage = spool_dir.join(format!("taikai-lineage-{base_id}.json"));
    let target = replace_path_with_symlink(&lineage, b"{}").await;
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("symlinked optional lineage hint must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("Taikai lineage hint JSON") && is_non_regular_taikai_rejection(&err),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&lineage.display().to_string()),
        "error should identify symlinked lineage hint path: {err}"
    );
    assert_path_remains_symlink(&lineage, &target);
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_blocked_request_capture() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let request_capture = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
    ));
    async_fs::create_dir(&request_capture)
        .await
        .expect("block request capture path");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("blocked request capture must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("failed to persist Taikai anchor request payload"),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&request_capture.display().to_string()),
        "error should identify blocked request capture path: {err}"
    );
}
#[tokio::test]
async fn taikai_anchor_collection_rejects_mismatched_request_capture() {
    let AnchorFixture {
        _dir,
        spool_dir,
        base_id,
    } = minimal_anchor_fixture(ANCHOR_BASE_ID).await;
    let request_capture = spool_dir.join(format!(
        "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
    ));
    async_fs::write(&request_capture, b"stale-different-body")
        .await
        .expect("write stale request capture");
    let err = match collect_pending_uploads(&spool_dir).await {
        Ok(_) => panic!("mismatched request capture must reject anchor collection"),
        Err(err) => err,
    };
    assert!(
        err.contains("different contents"),
        "unexpected anchor collection error: {err}"
    );
    assert!(
        err.contains(&request_capture.display().to_string()),
        "error should identify mismatched request capture path: {err}"
    );
}
#[test]
fn taikai_trm_lineage_guard_requires_zero_origin() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    let alias = manifest.alias_binding.clone();
    let digest = trm_digest_hex(0xA9);
    let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("guard")
        .expect("enabled");
    for start_sequence in [1, u64::MAX - 1] {
        manifest.segment_window = TaikaiSegmentWindow::new(start_sequence, start_sequence);
        manifest.renditions[0].ssm_range = manifest.segment_window;
        manifest
            .validate()
            .expect("nonzero window remains structurally valid before lineage admission");
        let err = guard
            .validate(&manifest, &digest)
            .expect_err("fresh alias lineage must reject a nonzero window origin");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(
            err.1.contains("must start at sequence 0"),
            "unexpected origin error: {err:?}"
        );
        let err = guard
            .commit(manifest.segment_window, &digest)
            .expect_err("the authoritative commit must independently reject a nonzero origin");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.1.contains("must start at sequence 0"),
            "unexpected commit-origin error: {err:?}"
        );
    }

    manifest.segment_window = TaikaiSegmentWindow::new(0, 15);
    manifest.renditions[0].ssm_range = manifest.segment_window;
    guard
        .validate(&manifest, &digest)
        .expect("zero-origin alias lineage must remain valid");
    guard
        .commit(manifest.segment_window, &digest)
        .expect("zero-origin authoritative lineage must remain valid");
}
#[test]
fn taikai_trm_lineage_guard_rejects_overlapping_windows() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 15);
    let alias = manifest.alias_binding.clone();
    let first_digest = trm_digest_hex(0xAA);
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard.validate(&manifest, &first_digest).expect("valid");
        guard
            .commit(manifest.segment_window, &first_digest)
            .expect("commit");
    }
    let mut overlap = manifest.clone();
    overlap.segment_window = TaikaiSegmentWindow::new(10, 20);
    let overlap_digest = trm_digest_hex(0xBB);
    let guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("guard")
        .expect("enabled");
    guard
        .validate(&overlap, &overlap_digest)
        .expect_err("must reject overlapping manifest windows");
}
#[test]
fn taikai_trm_lineage_guard_requires_exact_contiguous_successor() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 8);
    manifest.renditions[0].ssm_range = manifest.segment_window;
    manifest.validate().expect("valid root manifest");
    let alias = manifest.alias_binding.clone();
    let first_digest = trm_digest_hex(0xAC);
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard
            .validate(&manifest, &first_digest)
            .expect("valid root");
        guard
            .commit(manifest.segment_window, &first_digest)
            .expect("commit root");
    }

    let mut successor = manifest.clone();
    successor.segment_window = TaikaiSegmentWindow::new(10, 16);
    successor.renditions[0].ssm_range = successor.segment_window;
    successor
        .validate()
        .expect("structurally valid gap manifest");
    let successor_digest = trm_digest_hex(0xAD);
    let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("successor guard")
        .expect("enabled");
    let err = guard
        .validate(&successor, &successor_digest)
        .expect_err("a skipped routing window must be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("expected start 9"),
        "unexpected gap error: {err:?}"
    );
    let err = guard
        .commit(successor.segment_window, &successor_digest)
        .expect_err("the authoritative commit must independently reject a skipped window");
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1.contains("expected contiguous successor 9"),
        "unexpected commit-gap error: {err:?}"
    );

    successor.segment_window = TaikaiSegmentWindow::new(9, 16);
    successor.renditions[0].ssm_range = successor.segment_window;
    successor
        .validate()
        .expect("structurally valid contiguous manifest");
    guard
        .validate(&successor, &successor_digest)
        .expect("the exact contiguous routing window must remain valid");
    guard
        .commit(successor.segment_window, &successor_digest)
        .expect("the exact contiguous authoritative window must remain valid");
}
struct StagedTaikaiLineageFixture {
    _dir: tempfile::TempDir,
    spool_dir: PathBuf,
    receipt_log: DaReceiptLog,
    manifest: TaikaiRoutingManifestV1,
    trm_bytes: Vec<u8>,
    trm_path: PathBuf,
    digest: String,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    receipt: DaIngestReceipt,
    fingerprint: ReplayFingerprint,
}
impl StagedTaikaiLineageFixture {
    fn append_receipt(&self) {
        assert!(matches!(
            self.receipt_log
                .append(
                    LaneEpoch::new(self.lane_id, self.epoch),
                    self.sequence,
                    self.receipt.clone(),
                    self.fingerprint,
                )
                .expect("append exact durable receipt"),
            ReceiptInsertOutcome::Stored { .. }
        ));
    }
}
fn staged_taikai_lineage_fixture(seed: u8) -> StagedTaikaiLineageFixture {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().join("spool");
    let cursor_store =
        Arc::new(ReplayCursorStore::empty(dir.path().join("cursors")).expect("cursor store"));
    let signer = checked_fixture_ed25519_keypair(seed);
    let receipt_log = open_receipt_log(&dir.path().join("receipts"), &cursor_store, &signer)
        .expect("receipt log");
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 15);
    let alias = manifest.alias_binding.clone();
    let trm_bytes = to_bytes(&manifest).expect("encode routing manifest");
    let digest = hex::encode(blake3_hash(&trm_bytes).as_bytes());
    let lane_id = LaneId::new(7);
    let epoch = 42;
    let sequence = 0;
    let receipt = test_receipt(&signer, lane_id, epoch, sequence, seed);
    let fingerprint = receipt_fingerprint(&receipt);
    let trm_path = {
        let mut guard = taikai_ingest::TrmLineageGuard::new(&spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard.validate(&manifest, &digest).expect("fresh lineage");
        guard
            .stage_ingest(
                manifest.segment_window.clone(),
                &digest,
                lane_id,
                epoch,
                sequence,
                &receipt.storage_ticket,
                &fingerprint,
            )
            .expect("stage pending lineage");
        let envelope = taikai_envelope_fixture();
        taikai_ingest::persist_envelope(
            &spool_dir,
            lane_id,
            epoch,
            sequence,
            &receipt.storage_ticket,
            &fingerprint,
            &envelope.envelope_bytes,
        )
        .expect("persist pending lineage envelope")
        .expect("enabled pending lineage envelope path");
        taikai_ingest::persist_trm(
            &spool_dir,
            lane_id,
            epoch,
            sequence,
            &receipt.storage_ticket,
            &fingerprint,
            &trm_bytes,
        )
        .expect("persist routing manifest")
        .expect("enabled routing manifest path")
    };
    StagedTaikaiLineageFixture {
        _dir: dir,
        spool_dir,
        receipt_log,
        manifest,
        trm_bytes,
        trm_path,
        digest,
        lane_id,
        epoch,
        sequence,
        receipt,
        fingerprint,
    }
}
#[test]
fn taikai_pending_lineage_without_durable_receipt_is_discarded() {
    let fixture = staged_taikai_lineage_fixture(0x66);
    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_PENDING_PREFIX,
            TAIKAI_TRM_PENDING_SUFFIX,
        )
        .is_some(),
        "staging should create a pending lineage record"
    );

    taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
        .expect("receipt-less pending lineage should be discarded");

    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_PENDING_PREFIX,
            TAIKAI_TRM_PENDING_SUFFIX,
        )
        .is_none(),
        "receipt-less recovery must remove the pending lineage record"
    );
    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_LINEAGE_PREFIX,
            TAIKAI_TRM_LINEAGE_SUFFIX,
        )
        .is_none(),
        "receipt-less recovery must not advance authoritative lineage"
    );
    let guard =
        taikai_ingest::TrmLineageGuard::new(&fixture.spool_dir, &fixture.manifest.alias_binding)
            .expect("recovered guard")
            .expect("enabled");
    assert_eq!(
        guard
            .validate_ingest_retry(
                &fixture.manifest,
                &fixture.digest,
                fixture.lane_id,
                fixture.epoch,
                fixture.sequence,
                &fixture.receipt.storage_ticket,
                &fixture.fingerprint,
                &fixture.trm_bytes,
            )
            .expect("discarded pending lineage must remain fresh"),
        taikai_ingest::TrmLineageValidation::Fresh
    );
}
#[test]
fn taikai_trm_lineage_guard_allows_exact_staged_ingest_retry() {
    let fixture = staged_taikai_lineage_fixture(0x67);
    fixture.append_receipt();

    taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
        .expect("promote receipt-backed pending lineage");

    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_PENDING_PREFIX,
            TAIKAI_TRM_PENDING_SUFFIX,
        )
        .is_none(),
        "successful recovery must remove the pending lineage record"
    );
    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_LINEAGE_PREFIX,
            TAIKAI_TRM_LINEAGE_SUFFIX,
        )
        .is_some(),
        "exact receipt and TRM must promote authoritative lineage"
    );
    let guard =
        taikai_ingest::TrmLineageGuard::new(&fixture.spool_dir, &fixture.manifest.alias_binding)
            .expect("retry guard")
            .expect("enabled");
    let validation = guard
        .validate_ingest_retry(
            &fixture.manifest,
            &fixture.digest,
            fixture.lane_id,
            fixture.epoch,
            fixture.sequence,
            &fixture.receipt.storage_ticket,
            &fixture.fingerprint,
            &fixture.trm_bytes,
        )
        .expect("exact staged retry must be admitted");
    assert_eq!(
        validation,
        taikai_ingest::TrmLineageValidation::ExactArtifactRetry
    );
    assert!(
        taikai_ingest::TrmLineageValidation::Fresh.records_alias_rotation(),
        "fresh lineage must emit one alias-rotation event"
    );
    assert!(
        !validation.records_alias_rotation(),
        "an exact retry must not emit a duplicate alias-rotation event"
    );
    let err = guard
        .validate_ingest_retry(
            &fixture.manifest,
            &fixture.digest,
            fixture.lane_id,
            fixture.epoch,
            fixture.sequence + 1,
            &fixture.receipt.storage_ticket,
            &fixture.fingerprint,
            &fixture.trm_bytes,
        )
        .expect_err("a receipt-backed lineage must admit only the exact retry coordinates");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("already accepted"),
        "unexpected inexact retry error: {:?}",
        err
    );
}
#[test]
fn taikai_pending_lineage_with_tampered_trm_is_not_promoted() {
    let fixture = staged_taikai_lineage_fixture(0x69);
    fixture.append_receipt();
    fs::write(&fixture.trm_path, b"tampered routing manifest")
        .expect("tamper staged routing manifest");

    let err = taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
        .expect_err("tampered staged TRM must not promote receipt-backed lineage");
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1.contains("digest mismatch"),
        "unexpected tampered-TRM recovery error: {:?}",
        err
    );
    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_LINEAGE_PREFIX,
            TAIKAI_TRM_LINEAGE_SUFFIX,
        )
        .is_none(),
        "tampered staged TRM must not create authoritative lineage"
    );
    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_PENDING_PREFIX,
            TAIKAI_TRM_PENDING_SUFFIX,
        )
        .is_some(),
        "failed recovery should retain pending state for operator inspection"
    );
}
#[test]
fn taikai_pending_lineage_recovery_rejects_nonzero_origin() {
    let fixture = staged_taikai_lineage_fixture(0x6A);
    let pending_path = taikai_lineage_artifact_path(
        &fixture.spool_dir,
        TAIKAI_TRM_PENDING_PREFIX,
        TAIKAI_TRM_PENDING_SUFFIX,
    )
    .expect("pending lineage path");
    let mut pending: Value =
        json::from_slice(&fs::read(&pending_path).expect("read pending lineage record"))
            .expect("decode pending lineage record");
    pending
        .as_object_mut()
        .expect("pending lineage object")
        .insert("window_start_sequence".into(), Value::from(1_u64));
    fs::write(
        &pending_path,
        json::to_string(&pending)
            .expect("encode malformed pending lineage")
            .as_bytes(),
    )
    .expect("write malformed pending lineage");

    let err = taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
        .expect_err("a nonzero pending root must not become authoritative");
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1.contains("must start at sequence 0"),
        "unexpected pending-root error: {err:?}"
    );
    assert!(
        taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_LINEAGE_PREFIX,
            TAIKAI_TRM_LINEAGE_SUFFIX,
        )
        .is_none(),
        "invalid pending root must not create authoritative lineage"
    );
}
#[test]
fn taikai_pending_lineage_recovery_rejects_window_gap() {
    let fixture = staged_taikai_lineage_fixture(0x6B);
    fixture.append_receipt();
    taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
        .expect("promote the root lineage");

    let next_digest = trm_digest_hex(0xBC);
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(
            &fixture.spool_dir,
            &fixture.manifest.alias_binding,
        )
        .expect("successor guard")
        .expect("enabled");
        guard
            .stage_ingest(
                TaikaiSegmentWindow::new(16, 23),
                &next_digest,
                fixture.lane_id,
                fixture.epoch,
                1,
                &fixture.receipt.storage_ticket,
                &fixture.fingerprint,
            )
            .expect("stage exact successor before tampering it into a gap");
    }
    let pending_path = taikai_lineage_artifact_path(
        &fixture.spool_dir,
        TAIKAI_TRM_PENDING_PREFIX,
        TAIKAI_TRM_PENDING_SUFFIX,
    )
    .expect("pending lineage path");
    let mut pending: Value =
        json::from_slice(&fs::read(&pending_path).expect("read pending lineage record"))
            .expect("decode pending lineage record");
    pending
        .as_object_mut()
        .expect("pending lineage object")
        .insert("window_start_sequence".into(), Value::from(17_u64));
    fs::write(
        &pending_path,
        json::to_string(&pending)
            .expect("encode gapped pending lineage")
            .as_bytes(),
    )
    .expect("write gapped pending lineage");

    let err = taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
        .expect_err("a gapped pending successor must not become authoritative");
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1.contains("expected contiguous successor 16"),
        "unexpected pending-gap error: {err:?}"
    );
    let lineage_path = taikai_lineage_artifact_path(
        &fixture.spool_dir,
        TAIKAI_TRM_LINEAGE_PREFIX,
        TAIKAI_TRM_LINEAGE_SUFFIX,
    )
    .expect("root lineage must remain authoritative");
    let lineage: Value =
        json::from_slice(&fs::read(lineage_path).expect("read authoritative lineage"))
            .expect("decode authoritative lineage");
    assert_eq!(
        lineage.get("window_end_sequence").and_then(Value::as_u64),
        Some(15),
        "failed gap recovery must not advance the authoritative head"
    );
}
#[test]
fn taikai_pending_lineage_recovery_rejects_terminal_and_oversized_windows() {
    for (label, end_sequence) in [
        ("terminal", u64::MAX),
        (
            "oversized",
            iroha_data_model::taikai::TAIKAI_SEGMENT_WINDOW_MAX_SEQUENCES_V1,
        ),
    ] {
        let fixture = staged_taikai_lineage_fixture(0x68);
        fixture.append_receipt();
        let pending_path = taikai_lineage_artifact_path(
            &fixture.spool_dir,
            TAIKAI_TRM_PENDING_PREFIX,
            TAIKAI_TRM_PENDING_SUFFIX,
        )
        .expect("pending lineage path");
        let mut pending: Value =
            json::from_slice(&fs::read(&pending_path).expect("read pending lineage record"))
                .expect("decode pending lineage record");
        pending
            .as_object_mut()
            .expect("pending lineage object")
            .insert("window_end_sequence".into(), Value::from(end_sequence));
        fs::write(
            &pending_path,
            json::to_string(&pending)
                .expect("encode malformed pending lineage")
                .as_bytes(),
        )
        .expect("write malformed pending lineage");

        let err = taikai_ingest::recover_pending_lineages(&fixture.spool_dir, &fixture.receipt_log)
            .expect_err("invalid pending window must not be promoted");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR, "case: {label}");
        assert!(
            err.1.contains("invalid segment window"),
            "unexpected {label} pending-lineage error: {:?}",
            err
        );
        assert!(
            taikai_lineage_artifact_path(
                &fixture.spool_dir,
                TAIKAI_TRM_LINEAGE_PREFIX,
                TAIKAI_TRM_LINEAGE_SUFFIX,
            )
            .is_none(),
            "{label} pending state must not advance authoritative lineage"
        );
    }
}
#[test]
fn taikai_trm_lineage_guard_rejects_retry_from_legacy_lineage_without_provenance() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 15);
    let alias = manifest.alias_binding.clone();
    let trm_bytes = to_bytes(&manifest).expect("encode routing manifest");
    let digest = hex::encode(blake3_hash(&trm_bytes).as_bytes());
    let lane_id = LaneId::new(7);
    let epoch = 42;
    let sequence = 9;
    let storage_ticket = StorageTicketId::new([0xA5; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"legacy-lineage-retry"));
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        taikai_ingest::persist_envelope(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            &storage_ticket,
            &fingerprint,
            b"envelope",
        )
        .expect("persist envelope")
        .expect("enabled envelope path");
        taikai_ingest::persist_trm(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            &storage_ticket,
            &fingerprint,
            &trm_bytes,
        )
        .expect("persist routing manifest")
        .expect("enabled routing manifest path");
        guard
            .commit(manifest.segment_window.clone(), &digest)
            .expect("seed legacy lineage without artifact provenance");
    }
    let guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("retry guard")
        .expect("enabled");
    let err = guard
        .validate_ingest_retry(
            &manifest,
            &digest,
            lane_id,
            epoch,
            sequence,
            &storage_ticket,
            &fingerprint,
            &trm_bytes,
        )
        .expect_err("legacy lineage without provenance must not authenticate a retry");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("already accepted"),
        "unexpected legacy-lineage retry error: {:?}",
        err
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_staged_retry_at_different_coordinates() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 15);
    let alias = manifest.alias_binding.clone();
    let trm_bytes = to_bytes(&manifest).expect("encode routing manifest");
    let digest = hex::encode(blake3_hash(&trm_bytes).as_bytes());
    let lane_id = LaneId::new(7);
    let epoch = 42;
    let sequence = 9;
    let storage_ticket = StorageTicketId::new([0xA5; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"bound-lineage-retry"));
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        taikai_ingest::persist_envelope(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            &storage_ticket,
            &fingerprint,
            b"envelope",
        )
        .expect("persist envelope")
        .expect("enabled envelope path");
        taikai_ingest::persist_trm(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            &storage_ticket,
            &fingerprint,
            &trm_bytes,
        )
        .expect("persist routing manifest")
        .expect("enabled routing manifest path");
        taikai_ingest::persist_envelope(
            spool_dir,
            lane_id,
            epoch,
            sequence + 1,
            &storage_ticket,
            &fingerprint,
            b"other-envelope",
        )
        .expect("persist other partial envelope")
        .expect("enabled other envelope path");
        taikai_ingest::persist_trm(
            spool_dir,
            lane_id,
            epoch,
            sequence + 1,
            &storage_ticket,
            &fingerprint,
            &trm_bytes,
        )
        .expect("persist other partial routing manifest")
        .expect("enabled other routing manifest path");
        guard
            .commit_ingest(
                manifest.segment_window.clone(),
                &digest,
                lane_id,
                epoch,
                sequence,
                &storage_ticket,
                &fingerprint,
            )
            .expect("commit lineage");
    }
    let other_ticket = StorageTicketId::new([0x5A; 32]);
    let other_fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"other-lineage-retry"));
    let candidates = [
        (
            "lane",
            LaneId::new(8),
            epoch,
            sequence,
            storage_ticket.clone(),
            fingerprint,
        ),
        (
            "epoch",
            lane_id,
            epoch + 1,
            sequence,
            storage_ticket.clone(),
            fingerprint,
        ),
        (
            "sequence",
            lane_id,
            epoch,
            sequence + 1,
            storage_ticket.clone(),
            fingerprint,
        ),
        (
            "storage ticket",
            lane_id,
            epoch,
            sequence,
            other_ticket,
            fingerprint,
        ),
        (
            "fingerprint",
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            other_fingerprint,
        ),
    ];
    for (
        label,
        candidate_lane,
        candidate_epoch,
        candidate_sequence,
        candidate_ticket,
        candidate_fingerprint,
    ) in candidates
    {
        let guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("retry guard")
            .expect("enabled");
        let err = guard
            .validate_ingest_retry(
                &manifest,
                &digest,
                candidate_lane,
                candidate_epoch,
                candidate_sequence,
                &candidate_ticket,
                &candidate_fingerprint,
                &trm_bytes,
            )
            .expect_err("different replay coordinates must reject");
        assert_eq!(err.0, StatusCode::BAD_REQUEST, "coordinate: {label}");
        assert!(
            err.1.contains("already accepted"),
            "unexpected {label} retry error: {:?}",
            err
        );
    }
}
fn trm_digest_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}
fn taikai_lineage_artifact_path(spool_dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    fs::read_dir(spool_dir.join(TAIKAI_SPOOL_SUBDIR))
        .expect("read taikai spool")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && name.ends_with(suffix))
        })
}
fn taikai_lineage_state_path(spool_dir: &Path) -> PathBuf {
    taikai_lineage_artifact_path(
        spool_dir,
        TAIKAI_TRM_LINEAGE_PREFIX,
        TAIKAI_TRM_LINEAGE_SUFFIX,
    )
    .expect("lineage state path")
}
fn taikai_lock_path(spool_dir: &Path) -> PathBuf {
    fs::read_dir(spool_dir.join(TAIKAI_SPOOL_SUBDIR))
        .expect("read taikai spool")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(TAIKAI_TRM_LOCK_PREFIX)
                        && name.ends_with(TAIKAI_TRM_LOCK_SUFFIX)
                })
        })
        .expect("Taikai TRM lock path")
}
fn mutate_taikai_lineage_state(spool_dir: &Path, mutate: impl FnOnce(&mut Value)) {
    let path = taikai_lineage_state_path(spool_dir);
    let contents = fs::read_to_string(&path).expect("read lineage state");
    let mut value: Value = json::from_str(&contents).expect("decode lineage state");
    mutate(&mut value);
    fs::write(
        &path,
        json::to_string(&value).expect("encode mutated lineage state"),
    )
    .expect("write mutated lineage state");
}
fn assert_mutated_lineage_state_rejected(mutate: impl FnOnce(&mut Value), expected_message: &str) {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 8);
    let alias = manifest.alias_binding.clone();
    let digest = trm_digest_hex(0xAB);
    let storage_ticket = StorageTicketId::new([0xA5; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"mutated-lineage-state"));
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard.validate(&manifest, &digest).expect("valid");
        guard
            .commit_ingest(
                manifest.segment_window,
                &digest,
                LaneId::new(7),
                42,
                9,
                &storage_ticket,
                &fingerprint,
            )
            .expect("commit");
    }
    mutate_taikai_lineage_state(spool_dir, mutate);
    let err = match taikai_ingest::TrmLineageGuard::new(spool_dir, &alias) {
        Ok(_) => panic!("mutated lineage state should be rejected"),
        Err(err) => err,
    };
    assert!(
        err.1.contains(expected_message),
        "unexpected error: {:?}",
        err
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_unsupported_state_version() {
    assert_mutated_lineage_state_rejected(
        |value| {
            value
                .as_object_mut()
                .expect("lineage object")
                .insert("version".into(), Value::from(2));
        },
        "unsupported Taikai routing manifest lineage record version",
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_alias_mismatch() {
    assert_mutated_lineage_state_rejected(
        |value| {
            value
                .as_object_mut()
                .expect("lineage object")
                .insert("alias_name".into(), Value::from("other-alias"));
        },
        "belongs to alias",
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_invalid_manifest_digest() {
    assert_mutated_lineage_state_rejected(
        |value| {
            value
                .as_object_mut()
                .expect("lineage object")
                .insert("manifest_digest_hex".into(), Value::from("deadbeef"));
        },
        "manifest_digest_hex must be 32-byte lowercase hex",
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_noncanonical_uppercase_manifest_digest() {
    assert_mutated_lineage_state_rejected(
        |value| {
            value
                .as_object_mut()
                .expect("lineage object")
                .insert("manifest_digest_hex".into(), Value::from("AB".repeat(32)));
        },
        "manifest_digest_hex must be 32-byte lowercase hex",
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_malformed_artifact_base_id() {
    assert_mutated_lineage_state_rejected(
        |value| {
            value
                .as_object_mut()
                .expect("lineage object")
                .insert("artifact_base_id".into(), Value::from("not-canonical"));
        },
        "artifact_base_id must be canonical lowercase hex",
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_inverted_window() {
    assert_mutated_lineage_state_rejected(
        |value| {
            let map = value.as_object_mut().expect("lineage object");
            map.insert("window_start_sequence".into(), Value::from(20));
            map.insert("window_end_sequence".into(), Value::from(10));
        },
        "window_start_sequence exceeds window_end_sequence",
    );
}
#[cfg(unix)]
#[test]
fn taikai_trm_lineage_guard_rejects_state_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 8);
    let alias = manifest.alias_binding.clone();
    let digest = trm_digest_hex(0xAB);
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard.validate(&manifest, &digest).expect("valid");
        guard
            .commit(manifest.segment_window, &digest)
            .expect("commit");
    }
    let state_path = taikai_lineage_state_path(spool_dir);
    let state_target = spool_dir
        .join(TAIKAI_SPOOL_SUBDIR)
        .join("lineage-state-target.json");
    fs::write(
        &state_target,
        fs::read(&state_path).expect("read lineage state"),
    )
    .expect("write lineage symlink target");
    fs::remove_file(&state_path).expect("remove lineage state");
    symlink(&state_target, &state_path).expect("create lineage state symlink");
    let err = match taikai_ingest::TrmLineageGuard::new(spool_dir, &alias) {
        Ok(_) => panic!("symlinked lineage state must reject guard acquisition"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1
            .contains("Taikai routing manifest lineage record is not a regular file"),
        "unexpected lineage symlink error: {:?}",
        err
    );
    assert!(
        fs::symlink_metadata(&state_path)
            .expect("inspect lineage symlink")
            .file_type()
            .is_symlink(),
        "failed validation should leave lineage symlink visible"
    );
    assert!(
        state_target.exists(),
        "lineage symlink target should not be removed"
    );
}
#[cfg(unix)]
#[test]
fn taikai_trm_lineage_guard_rejects_spool_dir_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let target = spool_dir.join("taikai-lineage-target");
    fs::create_dir(&target).expect("create Taikai lineage target");
    let base_dir = spool_dir.join(TAIKAI_SPOOL_SUBDIR);
    symlink(&target, &base_dir).expect("create Taikai lineage spool symlink");
    let alias = sample_trm_manifest().alias_binding;
    let err = match taikai_ingest::TrmLineageGuard::new(spool_dir, &alias) {
        Ok(_) => panic!("symlinked Taikai lineage root must reject guard acquisition"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1.contains("Taikai spool directory"),
        "unexpected lineage root symlink error: {:?}",
        err
    );
    assert!(
        fs::symlink_metadata(&base_dir)
            .expect("inspect Taikai lineage symlink")
            .file_type()
            .is_symlink(),
        "failed validation should leave lineage root symlink visible"
    );
    assert_eq!(
        fs::read_dir(&target)
            .expect("read lineage target directory")
            .count(),
        0,
        "symlink target must not receive lineage locks or records"
    );
}
#[test]
fn taikai_trm_lineage_guard_rejects_busy_live_lock() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let alias = sample_trm_manifest().alias_binding;
    let guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("guard")
        .expect("enabled");
    let err = match taikai_ingest::TrmLineageGuard::new(spool_dir, &alias) {
        Ok(_) => panic!("busy live lock must reject lineage guard acquisition"),
        Err(err) => err,
    };
    drop(guard);
    assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        err.1.contains("routing manifest lock busy for alias slug"),
        "unexpected busy lock error: {:?}",
        err
    );
}
#[cfg(unix)]
#[test]
fn taikai_trm_lineage_guard_rejects_lock_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let alias = sample_trm_manifest().alias_binding;
    let guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("guard")
        .expect("enabled");
    let lock_path = taikai_lock_path(spool_dir);
    drop(guard);
    fs::remove_file(&lock_path).expect("remove persistent lock before symlink test");
    let lock_target = spool_dir
        .join(TAIKAI_SPOOL_SUBDIR)
        .join("lineage-lock-target.lock");
    fs::write(&lock_target, b"0\n").expect("write lock symlink target");
    symlink(&lock_target, &lock_path).expect("create lock symlink");
    let err = match taikai_ingest::TrmLineageGuard::new(spool_dir, &alias) {
        Ok(_) => panic!("symlinked lock must reject lineage guard acquisition"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1.contains("Taikai routing manifest lock") && is_non_regular_taikai_rejection(&err.1),
        "unexpected lock symlink error: {:?}",
        err
    );
    assert!(
        fs::symlink_metadata(&lock_path)
            .expect("inspect lock symlink")
            .file_type()
            .is_symlink(),
        "failed validation should leave lock symlink visible"
    );
    assert!(
        lock_target.exists(),
        "lock symlink target should not be removed"
    );
}
#[cfg(unix)]
#[test]
fn taikai_trm_lineage_guard_never_steals_an_aged_live_lock() {
    use std::time::SystemTime;
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let alias = sample_trm_manifest().alias_binding;
    let guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("guard")
        .expect("enabled");
    let lock_path = taikai_lock_path(spool_dir);
    let stale_at = SystemTime::now() - Duration::from_secs(24 * 60 * 60);
    let stale_times = std::fs::FileTimes::new()
        .set_accessed(stale_at)
        .set_modified(stale_at);
    fs::File::options()
        .read(true)
        .open(&lock_path)
        .expect("open stale lock")
        .set_times(stale_times)
        .expect("age live lock");
    let err = match taikai_ingest::TrmLineageGuard::new(spool_dir, &alias) {
        Ok(_) => panic!("an aged live lock must not be stolen"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        err.1.contains("routing manifest lock busy for alias slug"),
        "unexpected busy lock error: {:?}",
        err
    );
    drop(guard);
    let recovered = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
        .expect("released persistent lock must be reusable")
        .expect("enabled");
    drop(recovered);
}
#[test]
fn taikai_trm_lineage_hint_contains_previous_digest() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path();
    let mut manifest = sample_trm_manifest();
    manifest.segment_window = TaikaiSegmentWindow::new(0, 8);
    let alias = manifest.alias_binding.clone();
    let lane_id = LaneId::new(7);
    let epoch = 42;
    let storage_ticket = StorageTicketId::new([0xAA; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"lineage-hint"));
    let first_digest = trm_digest_hex(0xA1);
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard.validate(&manifest, &first_digest).expect("valid");
        guard
            .persist_lineage_hint(lane_id, epoch, 1, &storage_ticket, &fingerprint)
            .expect("persist hint");
        let base_id = format_base_id(lane_id, epoch, 1, &storage_ticket, &fingerprint);
        let hint_path = spool_dir
            .join(TAIKAI_SPOOL_SUBDIR)
            .join(format!("taikai-lineage-{base_id}.json"));
        let contents = fs::read_to_string(&hint_path).expect("lineage hint contents");
        let value: Value = json::from_str(&contents).expect("lineage value");
        assert!(
            value
                .get("previous_manifest_digest_hex")
                .is_some_and(Value::is_null)
        );
        guard
            .commit(manifest.segment_window, &first_digest)
            .expect("commit");
    }
    let mut next_manifest = manifest.clone();
    next_manifest.segment_window = TaikaiSegmentWindow::new(9, 16);
    let next_digest = trm_digest_hex(0xB2);
    {
        let mut guard = taikai_ingest::TrmLineageGuard::new(spool_dir, &alias)
            .expect("guard")
            .expect("enabled");
        guard.validate(&next_manifest, &next_digest).expect("valid");
        guard
            .persist_lineage_hint(lane_id, epoch, 2, &storage_ticket, &fingerprint)
            .expect("persist hint");
        let base_id = format_base_id(lane_id, epoch, 2, &storage_ticket, &fingerprint);
        let hint_path = spool_dir
            .join(TAIKAI_SPOOL_SUBDIR)
            .join(format!("taikai-lineage-{base_id}.json"));
        let contents = fs::read_to_string(&hint_path).expect("lineage hint contents");
        let value: Value = json::from_str(&contents).expect("lineage value");
        assert_eq!(
            value
                .get("previous_manifest_digest_hex")
                .and_then(Value::as_str),
            Some(first_digest.as_str())
        );
        guard
            .commit(next_manifest.segment_window, &next_digest)
            .expect("commit");
    }
}
