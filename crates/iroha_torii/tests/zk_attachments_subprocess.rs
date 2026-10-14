//! Integration test for the subprocess attachment sanitizer path.
#![cfg(all(feature = "app_api", feature = "ws_integration_tests"))]
#![allow(unexpected_cfgs)]
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt as _;
use iroha_config::parameters::actual::AttachmentSanitizerMode;
use iroha_torii::MaybeTelemetry;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
#[cfg(unix)]
use std::{fs, path::Path};
fn configure_subprocess_sanitizer_with_limits(
    sanitizer_path: PathBuf,
    sanitize_timeout_ms: u64,
    max_expanded_bytes: u64,
    max_archive_depth: u32,
) {
    iroha_torii::zk_attachments::configure(
        iroha_config::parameters::defaults::torii::ATTACHMENTS_TTL_SECS,
        iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_BYTES,
        iroha_config::parameters::defaults::torii::ATTACHMENTS_PER_TENANT_MAX_COUNT,
        8 * 1024 * 1024,
        iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_COUNT,
        iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_BYTES,
        iroha_config::parameters::defaults::torii::attachments_allowed_mime_types(),
        max_expanded_bytes,
        max_archive_depth,
        AttachmentSanitizerMode::Subprocess,
        sanitize_timeout_ms,
        Some(sanitizer_path),
        MaybeTelemetry::disabled(),
    );
    iroha_torii::zk_attachments::init_persistence().expect("attachment persistence preflight");
}
fn configure_subprocess_sanitizer(sanitizer_path: PathBuf, sanitize_timeout_ms: u64) {
    configure_subprocess_sanitizer_with_limits(
        sanitizer_path,
        sanitize_timeout_ms,
        iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_EXPANDED_BYTES,
        iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_ARCHIVE_DEPTH,
    );
}
fn attachment_headers(content_type: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(content_type) = content_type {
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_str(content_type).expect("valid content type"),
        );
    }
    headers
}
async fn post_attachment(body: Bytes, content_type: Option<&str>) -> (StatusCode, Bytes) {
    let tenant = iroha_torii::zk_attachments::AttachmentTenant::anonymous();
    let response = iroha_torii::zk_attachments::handle_post_attachment(
        tenant,
        attachment_headers(content_type),
        body,
    )
    .await
    .into_response();
    let status = response.status();
    let response_body = response
        .into_body()
        .collect()
        .await
        .expect("attachment response body")
        .to_bytes();
    (status, response_body)
}
fn gzip_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).expect("write gzip input");
    encoder.finish().expect("finish gzip")
}
fn run_attachment_sanitizer_binary(
    stdin_bytes: &[u8],
    enable_env_gate: bool,
    enable_sandbox_marker: bool,
    max_input_bytes: Option<&str>,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    if enable_env_gate {
        cmd.env("IROHA_ATTACHMENT_SANITIZER", "1");
    }
    if enable_sandbox_marker {
        cmd.env("IROHA_ATTACHMENT_SANITIZER_OS_SANDBOXED", "1");
    }
    if let Some(max_input_bytes) = max_input_bytes {
        cmd.env(
            "IROHA_ATTACHMENT_SANITIZER_MAX_INPUT_BYTES",
            max_input_bytes,
        );
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn attachment sanitizer");
    {
        let mut stdin = child.stdin.take().expect("attachment sanitizer stdin");
        stdin
            .write_all(stdin_bytes)
            .expect("write attachment sanitizer stdin");
    }
    child
        .wait_with_output()
        .expect("attachment sanitizer output")
}
#[cfg(unix)]
fn write_executable_script(dir: &Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, script).expect("write script");
    let mut permissions = fs::metadata(&path).expect("script metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("script permissions");
    path
}
#[tokio::test]
async fn attachments_sanitize_via_subprocess() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    let sanitize_timeout_ms =
        iroha_config::parameters::defaults::torii::ATTACHMENTS_SANITIZE_TIMEOUT_MS.max(5_000);
    configure_subprocess_sanitizer(sanitizer_path, sanitize_timeout_ms);
    let (status, meta_bytes) = post_attachment(
        Bytes::from_static(br#"{"hello":"world"}"#),
        Some("application/json"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&meta_bytes)
    );
    let meta: iroha_torii::zk_attachments::AttachmentMeta =
        norito::json::from_slice(&meta_bytes).expect("attachment meta");
    let provenance = meta.provenance.expect("provenance");
    assert!(provenance.sanitizer.sandboxed);
}
#[tokio::test]
async fn attachments_sanitize_compressed_payload_via_subprocess() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    let sanitize_timeout_ms =
        iroha_config::parameters::defaults::torii::ATTACHMENTS_SANITIZE_TIMEOUT_MS.max(5_000);
    configure_subprocess_sanitizer(sanitizer_path, sanitize_timeout_ms);
    let raw = br#"{"hello":"world"}"#;
    let compressed = gzip_compress(raw);
    let (status, meta_bytes) =
        post_attachment(Bytes::from(compressed), Some("application/octet-stream")).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&meta_bytes)
    );
    let meta: iroha_torii::zk_attachments::AttachmentMeta =
        norito::json::from_slice(&meta_bytes).expect("attachment meta");
    assert_eq!(meta.content_type, "application/json");
    assert_eq!(meta.size, raw.len() as u64);
    let provenance = meta.provenance.expect("provenance");
    assert_eq!(
        provenance.declared_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(provenance.sniffed_type, "application/json");
    assert_eq!(provenance.sanitizer.archive_depth, 1);
    assert_eq!(provenance.sanitizer.expanded_bytes, raw.len() as u64);
    assert!(provenance.sanitizer.sandboxed);
}
#[cfg(unix)]
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_invalid_child_output() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let temp = tempfile::tempdir().expect("temp dir");
    let sanitizer_path = write_executable_script(
        temp.path(),
        "invalid-sanitizer.sh",
        "#!/bin/sh\nprintf 'not-a-valid-norito-response'\n",
    );
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let (status, response_body) = post_attachment(
        Bytes::from_static(br#"{"hello":"world"}"#),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&response_body)
            .contains("attachment sanitizer response decode failed"),
        "{}",
        String::from_utf8_lossy(&response_body)
    );
}
#[cfg(unix)]
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_nonzero_exit() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let temp = tempfile::tempdir().expect("temp dir");
    let sanitizer_path =
        write_executable_script(temp.path(), "failing-sanitizer.sh", "#!/bin/sh\nexit 7\n");
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let (status, response_body) = post_attachment(
        Bytes::from_static(br#"{"hello":"world"}"#),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&response_body).contains("attachment sanitizer exited with"),
        "{}",
        String::from_utf8_lossy(&response_body)
    );
}
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_spawn_failure() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let temp = tempfile::tempdir().expect("temp dir");
    let sanitizer_path = temp.path().join("missing-sanitizer");
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let (status, response_body) = post_attachment(
        Bytes::from_static(br#"{"hello":"world"}"#),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&response_body).contains("attachment sanitizer spawn failed"),
        "{}",
        String::from_utf8_lossy(&response_body)
    );
}
#[cfg(unix)]
#[tokio::test]
async fn attachments_sanitize_via_subprocess_times_out_slow_child() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let temp = tempfile::tempdir().expect("temp dir");
    let sanitizer_path =
        write_executable_script(temp.path(), "slow-sanitizer.sh", "#!/bin/sh\nsleep 1\n");
    configure_subprocess_sanitizer(sanitizer_path, 25);
    let (status, response_body) = post_attachment(
        Bytes::from_static(br#"{"hello":"world"}"#),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&response_body).contains("attachment sanitize timeout exceeded"),
        "{}",
        String::from_utf8_lossy(&response_body)
    );
}
#[cfg(unix)]
#[tokio::test]
async fn attachments_sanitize_via_subprocess_times_out_after_child_exit_when_stdout_stays_open() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let temp = tempfile::tempdir().expect("temp dir");
    let sanitizer_path = write_executable_script(
        temp.path(),
        "output-timeout-sanitizer.sh",
        "#!/bin/sh\n(sleep 1) &\nexit 0\n",
    );
    configure_subprocess_sanitizer(sanitizer_path, 25);
    let (status, response_body) = post_attachment(
        Bytes::from_static(br#"{"hello":"world"}"#),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let response_body = String::from_utf8_lossy(&response_body);
    assert!(
        response_body.contains("attachment sanitizer output timeout exceeded")
            || response_body.contains("attachment sanitize timeout exceeded"),
        "{response_body}"
    );
}
#[cfg(unix)]
#[tokio::test]
async fn attachments_sanitize_via_subprocess_propagates_real_child_type_reject() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let (status, response_body) = post_attachment(
        Bytes::from_static(b"plain text that is not allowlisted"),
        Some("text/plain"),
    )
    .await;
    let response_body = String::from_utf8_lossy(&response_body);
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "{response_body}"
    );
    assert!(
        response_body.contains("does not match sniffed")
            || response_body.contains("is not allowlisted"),
        "{response_body}"
    );
}
#[cfg(unix)]
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_unallowlisted_octet_stream() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let (status, response_body) = post_attachment(
        Bytes::from_static(b"plain text that stays application/octet-stream"),
        Some("application/octet-stream"),
    )
    .await;
    let response_body = String::from_utf8_lossy(&response_body);
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "{response_body}"
    );
    assert!(
        response_body.contains("is not allowlisted"),
        "{response_body}"
    );
}
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_expansion_limit() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    configure_subprocess_sanitizer_with_limits(sanitizer_path, 5_000, 8, 4);
    let compressed = gzip_compress(br#"{"hello":"world"}"#);
    let (status, response_body) =
        post_attachment(Bytes::from(compressed), Some("application/octet-stream")).await;
    let response_body = String::from_utf8_lossy(&response_body);
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response_body}");
    assert!(
        response_body.contains("expanded beyond max bytes"),
        "{response_body}"
    );
}
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_archive_depth_limit() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    configure_subprocess_sanitizer_with_limits(sanitizer_path, 5_000, 1024, 1);
    let nested = gzip_compress(&gzip_compress(br#"{"hello":"world"}"#));
    let (status, response_body) =
        post_attachment(Bytes::from(nested), Some("application/octet-stream")).await;
    let response_body = String::from_utf8_lossy(&response_body);
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response_body}");
    assert!(
        response_body.contains("archive depth exceeds limit"),
        "{response_body}"
    );
}
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_malformed_gzip_payload() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let mut malformed = gzip_compress(br#"{"hello":"world"}"#);
    malformed.truncate(6);
    let (status, response_body) =
        post_attachment(Bytes::from(malformed), Some("application/octet-stream")).await;
    let response_body = String::from_utf8_lossy(&response_body);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response_body}");
    assert!(
        response_body.contains("attachment decompress failed"),
        "{response_body}"
    );
}
#[tokio::test]
async fn attachments_sanitize_via_subprocess_rejects_malformed_zstd_payload() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let sanitizer_path = PathBuf::from(env!("CARGO_BIN_EXE_attachment_sanitizer"));
    configure_subprocess_sanitizer(sanitizer_path, 5_000);
    let malformed = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x01];
    let (status, response_body) =
        post_attachment(Bytes::from(malformed), Some("application/octet-stream")).await;
    let response_body = String::from_utf8_lossy(&response_body);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response_body}");
    assert!(
        response_body.contains("attachment decompress failed"),
        "{response_body}"
    );
}
#[test]
fn attachment_sanitizer_binary_requires_env_gate() {
    let output = run_attachment_sanitizer_binary(&[], false, false, None);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("attachment sanitizer must be invoked with IROHA_ATTACHMENT_SANITIZER=1"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn attachment_sanitizer_binary_requires_os_sandbox_marker() {
    let output = run_attachment_sanitizer_binary(&[], true, false, Some("1024"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("attachment sanitizer refuses to run outside its OS sandbox"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn attachment_sanitizer_binary_rejects_oversized_stdin_request() {
    let output = run_attachment_sanitizer_binary(b"0123456789", true, true, Some("4"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("attachment sanitizer request exceeds max bytes"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn attachment_sanitizer_binary_writes_error_response_for_invalid_request() {
    let output = run_attachment_sanitizer_binary(b"not-a-norito-request", true, true, Some("1024"));
    assert!(output.status.success(), "{:?}", output.status);
    assert!(
        !output.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
