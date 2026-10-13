//! Attachment content validation and isolated sanitizer execution.

use super::*;

pub(super) fn normalize_mime(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mime = trimmed.split(';').next().unwrap_or("").trim();
    if mime.is_empty() {
        return None;
    }
    let mut normalized = mime.to_ascii_lowercase();
    if normalized.starts_with("application/") && normalized.ends_with("+json") {
        normalized = JSON_MIME_TYPE.to_string();
    }
    Some(normalized)
}
pub(super) fn sniff_format(bytes: &[u8]) -> SniffedFormat {
    if bytes.starts_with(&norito::core::MAGIC) {
        return SniffedFormat::Norito;
    }
    if bytes.len() >= 4 && &bytes[..4] == b"ZK1\0" {
        return SniffedFormat::Zk1;
    }
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return SniffedFormat::Gzip;
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return SniffedFormat::Zstd;
    }
    if bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| matches!(b, b'{' | b'['))
    {
        return SniffedFormat::Json;
    }
    SniffedFormat::Unknown
}
/// Return the canonical media type for an already-expanded attachment body.
pub(super) fn sniffed_attachment_media_type(bytes: &[u8]) -> Option<&'static str> {
    match sniff_format(bytes) {
        SniffedFormat::Norito => Some(NORITO_MIME_TYPE),
        SniffedFormat::Json => Some(JSON_MIME_TYPE),
        SniffedFormat::Zk1 => Some(ZK1_MIME_TYPE),
        SniffedFormat::Unknown => Some(OCTET_STREAM_MIME_TYPE),
        SniffedFormat::Gzip | SniffedFormat::Zstd => None,
    }
}
pub(super) fn is_canonical_attachment_digest(value: &str) -> bool {
    value.len() == ATTACHMENT_ID_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
/// Validate invariants that can be checked from persisted metadata alone.
///
/// # Errors
///
/// Returns a descriptive error when identity, tenant, provenance, sanitizer,
/// digest-shape, size, or media-type invariants are violated.
pub fn validate_attachment_metadata_contract(
    meta: &AttachmentMeta,
    expected_tenant: &str,
    expected_id: &str,
) -> Result<(), String> {
    if meta.id != expected_id {
        return Err(format!(
            "proof attachment metadata id {} does not match storage id {expected_id}",
            meta.id
        ));
    }
    if meta.tenant.as_deref() != Some(expected_tenant) {
        return Err("proof attachment metadata tenant does not match its storage namespace".into());
    }
    let provenance = meta.provenance.as_ref().ok_or_else(|| {
        "proof attachment provenance is required by the first-release storage contract".to_owned()
    })?;
    if provenance.sanitizer.verdict != "accepted" {
        return Err("proof attachment provenance sanitizer verdict is not accepted".into());
    }
    if provenance.sanitizer.expanded_bytes != meta.size {
        return Err(format!(
            "proof attachment provenance expanded size {} does not match metadata size {}",
            provenance.sanitizer.expanded_bytes, meta.size
        ));
    }
    if provenance.hashes.blake2b_256 != meta.id
        || !is_canonical_attachment_digest(&provenance.hashes.blake2b_256)
    {
        return Err(
            "proof attachment provenance Blake2b-256 digest does not match metadata id".into(),
        );
    }
    if !is_canonical_attachment_digest(&provenance.hashes.sha256) {
        return Err("proof attachment provenance SHA-256 digest is not canonical".into());
    }
    if provenance.sniffed_type != meta.content_type {
        return Err(
            "proof attachment provenance media type does not match attachment metadata".into(),
        );
    }
    Ok(())
}
/// Validate persisted attachment bytes against their required provenance.
///
/// # Errors
///
/// Returns a descriptive error when size, digest, sanitizer, or media-type
/// provenance does not match `body`.
pub fn validate_attachment_body_contract(meta: &AttachmentMeta, body: &[u8]) -> Result<(), String> {
    let actual_size = body.len() as u64;
    if meta.size != actual_size {
        return Err(format!(
            "proof attachment metadata size {} does not match the actual {actual_size}-byte body",
            meta.size
        ));
    }
    let provenance = meta.provenance.as_ref().ok_or_else(|| {
        "proof attachment provenance is required by the first-release storage contract".to_owned()
    })?;
    if provenance.sanitizer.verdict != "accepted" {
        return Err("proof attachment provenance sanitizer verdict is not accepted".into());
    }
    if provenance.sanitizer.expanded_bytes != actual_size {
        return Err(format!(
            "proof attachment provenance expanded size {} does not match the actual {actual_size}-byte body",
            provenance.sanitizer.expanded_bytes
        ));
    }
    let actual_id = hex::encode::<[u8; 32]>(iroha_crypto::Hash::new(body).into());
    if actual_id != meta.id {
        return Err(format!(
            "proof attachment body digest {actual_id} does not match storage id {}",
            meta.id
        ));
    }
    if provenance.hashes.blake2b_256 != actual_id {
        return Err("proof attachment provenance Blake2b-256 digest does not match body".into());
    }
    let actual_sha256 = hex::encode(Sha256::digest(body));
    if provenance.hashes.sha256 != actual_sha256 {
        return Err("proof attachment provenance SHA-256 digest does not match body".into());
    }
    let actual_media_type = sniffed_attachment_media_type(body).ok_or_else(|| {
        "proof attachment body does not have a supported canonical media type".to_owned()
    })?;
    if provenance.sniffed_type != actual_media_type || meta.content_type != actual_media_type {
        return Err(
            "proof attachment provenance and metadata media type do not match the body".into(),
        );
    }
    Ok(())
}
pub(super) fn read_limited<R: std::io::Read>(
    mut reader: R,
    max_bytes: u64,
    deadline: Instant,
) -> Result<Vec<u8>, SanitizeError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8 * 1024];
    loop {
        if Instant::now() > deadline {
            return Err(SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                "attachment sanitize timeout exceeded",
            ));
        }
        let read = reader.read(&mut buf).map_err(|err| {
            SanitizeError::new(
                SanitizeRejectReason::Checksum,
                format!("attachment decompress failed: {err}"),
            )
        })?;
        if read == 0 {
            break;
        }
        let next_len = out.len().saturating_add(read);
        if next_len as u64 > max_bytes {
            return Err(SanitizeError::new(
                SanitizeRejectReason::Expansion,
                format!(
                    "attachment expanded beyond max bytes (>{} bytes)",
                    max_bytes
                ),
            ));
        }
        out.extend_from_slice(&buf[..read]);
    }
    Ok(out)
}
pub(super) fn inspect_bytes(
    bytes: &[u8],
    depth: u32,
    cfg: &SanitizerConfig,
    deadline: Instant,
) -> Result<SanitizerOutcome, SanitizeError> {
    match sniff_format(bytes) {
        SniffedFormat::Norito => Ok(SanitizerOutcome {
            summary: SanitizerSummary {
                sniffed_type: NORITO_MIME_TYPE.to_string(),
                expanded_bytes: bytes.len() as u64,
                archive_depth: depth,
                sandboxed: false,
            },
            sanitized_body: bytes.to_vec(),
        }),
        SniffedFormat::Json => Ok(SanitizerOutcome {
            summary: SanitizerSummary {
                sniffed_type: JSON_MIME_TYPE.to_string(),
                expanded_bytes: bytes.len() as u64,
                archive_depth: depth,
                sandboxed: false,
            },
            sanitized_body: bytes.to_vec(),
        }),
        SniffedFormat::Zk1 => Ok(SanitizerOutcome {
            summary: SanitizerSummary {
                sniffed_type: ZK1_MIME_TYPE.to_string(),
                expanded_bytes: bytes.len() as u64,
                archive_depth: depth,
                sandboxed: false,
            },
            sanitized_body: bytes.to_vec(),
        }),
        SniffedFormat::Gzip => {
            if depth >= cfg.max_archive_depth {
                return Err(SanitizeError::new(
                    SanitizeRejectReason::Expansion,
                    format!(
                        "attachment archive depth exceeds limit ({})",
                        cfg.max_archive_depth
                    ),
                ));
            }
            let mut decoder = GzDecoder::new(bytes);
            let expanded = read_limited(&mut decoder, cfg.max_expanded_bytes, deadline)?;
            let mut inner = inspect_bytes(&expanded, depth + 1, cfg, deadline)?;
            inner.summary.archive_depth = inner.summary.archive_depth.max(depth + 1);
            inner.summary.expanded_bytes = inner.sanitized_body.len() as u64;
            Ok(inner)
        }
        SniffedFormat::Zstd => {
            if depth >= cfg.max_archive_depth {
                return Err(SanitizeError::new(
                    SanitizeRejectReason::Expansion,
                    format!(
                        "attachment archive depth exceeds limit ({})",
                        cfg.max_archive_depth
                    ),
                ));
            }
            let mut decoder = ZstdDecoder::new(bytes).map_err(|err| {
                SanitizeError::new(
                    SanitizeRejectReason::Checksum,
                    format!("attachment decompress failed: {err}"),
                )
            })?;
            let expanded = read_limited(&mut decoder, cfg.max_expanded_bytes, deadline)?;
            let mut inner = inspect_bytes(&expanded, depth + 1, cfg, deadline)?;
            inner.summary.archive_depth = inner.summary.archive_depth.max(depth + 1);
            inner.summary.expanded_bytes = inner.sanitized_body.len() as u64;
            Ok(inner)
        }
        SniffedFormat::Unknown => Err(SanitizeError::new(
            SanitizeRejectReason::Type,
            "unsupported attachment format",
        )),
    }
}
pub(super) fn sanitizer_config() -> SanitizerConfig {
    SanitizerConfig {
        allowed_mime_types: allowed_mime_types_cfg(),
        max_expanded_bytes: max_expanded_bytes_cfg(),
        max_archive_depth: max_archive_depth_cfg(),
        timeout: sanitize_timeout_cfg(),
        mode: sanitizer_mode_cfg(),
    }
}
pub(super) fn sanitize_attachment_sync(
    declared_type: Option<&str>,
    body: &[u8],
    cfg: &SanitizerConfig,
) -> Result<SanitizerOutcome, SanitizeError> {
    let deadline = Instant::now() + cfg.timeout;
    let mut outcome = match inspect_bytes(body, 0, cfg, deadline) {
        Ok(outcome) => outcome,
        Err(err) if err.reason == SanitizeRejectReason::Type => SanitizerOutcome {
            summary: SanitizerSummary {
                sniffed_type: OCTET_STREAM_MIME_TYPE.to_string(),
                expanded_bytes: body.len() as u64,
                archive_depth: 0,
                sandboxed: false,
            },
            sanitized_body: body.to_vec(),
        },
        Err(err) => return Err(err),
    };
    outcome.summary.expanded_bytes = outcome.sanitized_body.len() as u64;
    if outcome.summary.expanded_bytes > cfg.max_expanded_bytes {
        return Err(SanitizeError::new(
            SanitizeRejectReason::Expansion,
            format!(
                "attachment expanded beyond max bytes (>{} bytes)",
                cfg.max_expanded_bytes
            ),
        ));
    }
    let declared_norm = declared_type.and_then(normalize_mime);
    if let Some(ref declared) = declared_norm {
        if declared != OCTET_STREAM_MIME_TYPE && declared != &outcome.summary.sniffed_type {
            return Err(SanitizeError::new(
                SanitizeRejectReason::Type,
                format!(
                    "declared content-type `{declared}` does not match sniffed `{}`",
                    outcome.summary.sniffed_type
                ),
            ));
        }
    }
    if !cfg.allowed_mime_types.is_empty()
        && !cfg
            .allowed_mime_types
            .iter()
            .any(|allowed| allowed == &outcome.summary.sniffed_type)
    {
        return Err(SanitizeError::new(
            SanitizeRejectReason::Type,
            format!(
                "attachment type `{}` is not allowlisted",
                outcome.summary.sniffed_type
            ),
        ));
    }
    Ok(outcome)
}
pub(super) async fn sanitize_attachment(
    declared_type: Option<String>,
    body: axum::body::Bytes,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> Result<SanitizerOutcome, SanitizeError> {
    let cfg = sanitizer_config();
    match cfg.mode {
        AttachmentSanitizerMode::InProcess => {
            sanitize_attachment_in_process(declared_type, body, cfg, admission).await
        }
        AttachmentSanitizerMode::Subprocess => {
            sanitize_attachment_subprocess(declared_type, body, cfg, admission).await
        }
    }
}
pub(super) async fn sanitize_attachment_in_process(
    declared_type: Option<String>,
    body: axum::body::Bytes,
    cfg: SanitizerConfig,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> Result<SanitizerOutcome, SanitizeError> {
    let declared = declared_type.clone();
    let mut outcome = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            #[cfg(test)]
            wait_for_sanitizer_worker_test_gate();
            let outcome = sanitize_attachment_sync(declared.as_deref(), body.as_ref(), &cfg);
            drop(admission);
            outcome
        }),
    )
    .await
    .map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitize task failed: {err}"),
        )
    })??;
    outcome.summary.sandboxed = false;
    Ok(outcome)
}
pub(super) async fn sanitize_attachment_subprocess(
    declared_type: Option<String>,
    body: axum::body::Bytes,
    cfg: SanitizerConfig,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> Result<SanitizerOutcome, SanitizeError> {
    let request = SanitizerRequest {
        declared_type,
        body: body.to_vec(),
        allowed_mime_types: cfg.allowed_mime_types.clone(),
        max_expanded_bytes: cfg.max_expanded_bytes,
        max_archive_depth: cfg.max_archive_depth,
        timeout_ms: cfg.timeout.as_millis().max(1) as u64,
    };
    let outcome = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            #[cfg(test)]
            wait_for_sanitizer_worker_test_gate();
            let outcome = run_sanitizer_subprocess(request, cfg.timeout, admission.clone());
            drop(admission);
            outcome
        }),
    )
    .await
    .map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitize task failed: {err}"),
        )
    })??;
    Ok(outcome)
}
pub(super) fn run_sanitizer_subprocess(
    request: SanitizerRequest,
    timeout: Duration,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> Result<SanitizerOutcome, SanitizeError> {
    let exe = sanitizer_executable()?;
    let exe = validate_sanitizer_executable(&exe)?;
    let request_bytes = norito::encode_canonical(&request).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer request encode failed: {err}"),
        )
    })?;
    let max_input_bytes = request_bytes
        .len()
        .saturating_add(1024)
        .max(1024)
        .to_string();
    let max_output_bytes = usize::try_from(request.max_expanded_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(SANITIZER_RESPONSE_OVERHEAD_BYTES);
    let mut cmd = sandboxed_sanitizer_command(&exe, &max_input_bytes)?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer spawn failed: {err}"),
        )
    })?;
    let result = (|| -> Result<SanitizerOutcome, SanitizeError> {
        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                SanitizeError::new(
                    SanitizeRejectReason::Sandbox,
                    "attachment sanitizer stdin unavailable",
                )
            })?;
            stdin.write_all(&request_bytes).map_err(|err| {
                SanitizeError::new(
                    SanitizeRejectReason::Sandbox,
                    format!("attachment sanitizer write failed: {err}"),
                )
            })?;
        }
        let stdout = child.stdout.take().ok_or_else(|| {
            SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                "attachment sanitizer stdout unavailable",
            )
        })?;
        let rx = spawn_sanitizer_stdout_reader(stdout, max_output_bytes, admission);
        let deadline = Instant::now() + timeout;
        loop {
            let Some(status) = child.try_wait().map_err(|err| {
                SanitizeError::new(
                    SanitizeRejectReason::Sandbox,
                    format!("attachment sanitizer wait failed: {err}"),
                )
            })?
            else {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return Err(SanitizeError::new(
                        SanitizeRejectReason::Sandbox,
                        "attachment sanitize timeout exceeded",
                    ));
                }
                thread::sleep(Duration::from_millis(SANITIZER_POLL_INTERVAL_MS));
                continue;
            };
            if !status.success() {
                return Err(SanitizeError::new(
                    SanitizeRejectReason::Sandbox,
                    format!("attachment sanitizer exited with {status}"),
                ));
            }
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let stdout_bytes = rx
            .recv_timeout(remaining)
            .map_err(|_| {
                SanitizeError::new(
                    SanitizeRejectReason::Sandbox,
                    "attachment sanitizer output timeout exceeded",
                )
            })?
            .map_err(|err| SanitizeError::new(SanitizeRejectReason::Sandbox, err))?;
        decode_sanitizer_response_bytes(&stdout_bytes)
    })();
    if result.is_err() {
        // Best-effort cleanup. If the sanitizer is still running (e.g. timeout),
        // ensure we kill and reap it to avoid leaking a zombie process.
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
pub(super) fn spawn_sanitizer_stdout_reader(
    mut stdout: impl std::io::Read + Send + 'static,
    max_output_bytes: usize,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        // A sandbox descendant can inherit stdout after the direct child exits.
        // Keep physical admission for as long as this reader can remain blocked
        // so detached pipe readers cannot accumulate outside the semaphore.
        let admission = admission;
        let result = iroha_panic_hook::catch_unwind_suppressed(|| {
            read_sanitizer_stdout_limited(&mut stdout, max_output_bytes)
        })
        .unwrap_or_else(|_| Err("attachment sanitizer stdout reader panicked".to_owned()));
        drop(admission);
        let _ = tx.send(result);
    });
    rx
}
pub(super) fn read_sanitizer_stdout_limited(
    stdout: &mut impl std::io::Read,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = stdout
            .read(&mut chunk)
            .map_err(|err| format!("attachment sanitizer stdout read failed: {err}"))?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > max_bytes {
            return Err(format!(
                "attachment sanitizer output exceeds {max_bytes} bytes"
            ));
        }
        output.extend_from_slice(&chunk[..read]);
    }
}
pub(super) fn validate_sanitizer_executable(exe: &Path) -> Result<PathBuf, SanitizeError> {
    let canonical = fs::canonicalize(exe).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer spawn failed: {err}"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer spawn failed: {err}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!(
                "attachment sanitizer spawn failed: {} is not a file",
                canonical.display()
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                format!(
                    "attachment sanitizer spawn failed: {} is not executable",
                    canonical.display()
                ),
            ));
        }
    }
    let current_exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|err| {
            SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                format!("current node executable unavailable: {err}"),
            )
        })?;
    if canonical == current_exe {
        return Err(SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            "attachment sanitizer must be a dedicated executable, not the node binary",
        ));
    }
    let expected_name = format!(
        "{ATTACHMENT_SANITIZER_BINARY_STEM}{}",
        env::consts::EXE_SUFFIX
    );
    if canonical.file_name() != Some(OsStr::new(&expected_name)) {
        return Err(SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer executable must be named {expected_name}"),
        ));
    }
    Ok(canonical)
}
pub(super) fn decode_sanitizer_response_bytes(
    stdout_bytes: &[u8],
) -> Result<SanitizerOutcome, SanitizeError> {
    let response = norito::decode_canonical::<SanitizerResponse>(stdout_bytes).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer response decode failed: {err}"),
        )
    })?;
    match response {
        SanitizerResponse::Accepted {
            summary,
            sanitized_body,
        } => Ok(SanitizerOutcome {
            summary,
            sanitized_body,
        }),
        SanitizerResponse::Rejected { error } => Err(SanitizeError::from_wire(error)),
    }
}
pub(super) fn sanitizer_executable() -> Result<PathBuf, SanitizeError> {
    let override_path = attach_cfg().read().sanitizer_exe_override.clone();
    sanitizer_executable_with_override(override_path)
}
pub(super) fn sanitizer_executable_with_override(
    override_path: Option<PathBuf>,
) -> Result<PathBuf, SanitizeError> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    let current_exe = env::current_exe().map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer executable unavailable: {err}"),
        )
    })?;
    let directory = current_exe.parent().ok_or_else(|| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!(
                "attachment sanitizer executable unavailable: {} has no parent directory",
                current_exe.display()
            ),
        )
    })?;
    Ok(directory.join(format!(
        "{ATTACHMENT_SANITIZER_BINARY_STEM}{}",
        env::consts::EXE_SUFFIX
    )))
}
pub(super) fn sandboxed_sanitizer_command(
    exe: &Path,
    max_input_bytes: &str,
) -> Result<Command, SanitizeError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let search_path = Some(OsStr::new("/usr/bin:/bin"));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let search_path = None;
    sandboxed_sanitizer_command_for_search_path(exe, max_input_bytes, search_path)
}
pub(super) fn sandboxed_sanitizer_command_for_search_path(
    exe: &Path,
    max_input_bytes: &str,
    search_path: Option<&OsStr>,
) -> Result<Command, SanitizeError> {
    #[cfg(target_os = "linux")]
    {
        if let Some(bubblewrap) = find_executable_in_search_path(search_path, "bwrap") {
            let mut cmd = Command::new(bubblewrap);
            set_clean_sanitizer_environment(&mut cmd, max_input_bytes);
            cmd.args([
                "--die-with-parent",
                "--new-session",
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-uts",
                "--unshare-ipc",
                "--clearenv",
                "--tmpfs",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                "--chdir",
                "/tmp",
                "--setenv",
                ATTACHMENT_SANITIZER_ENV,
                "1",
                "--setenv",
                ATTACHMENT_SANITIZER_MAX_INPUT_ENV,
                max_input_bytes,
                "--setenv",
                ATTACHMENT_SANITIZER_SANDBOXED_ENV,
                "1",
            ]);
            add_bwrap_runtime_path(&mut cmd, Path::new("/usr"))?;
            add_bwrap_runtime_path(&mut cmd, Path::new("/lib"))?;
            add_bwrap_runtime_path(&mut cmd, Path::new("/lib64"))?;
            cmd.arg("--ro-bind")
                .arg(exe)
                .arg("/attachment_sanitizer")
                .arg("/attachment_sanitizer");
            return Ok(cmd);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(sandbox_exec) = find_executable_in_search_path(search_path, "sandbox-exec") {
            let executable_literal = macos_sandbox_literal(exe)?;
            let profile = format!(
                r#"(version 1)
(deny default)
(allow process-exec (literal "{executable_literal}"))
(allow file-read-metadata)
(allow file-read-data
    (literal "{executable_literal}")
    (subpath "/System/Library")
    (subpath "/usr/lib")
    (subpath "/private/var/db/dyld"))
(allow sysctl-read)
(deny network*)"#
            );
            let mut cmd = Command::new(sandbox_exec);
            set_clean_sanitizer_environment(&mut cmd, max_input_bytes);
            cmd.arg("-p").arg(profile).arg(exe);
            return Ok(cmd);
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = search_path;
    Err(SanitizeError::new(
        SanitizeRejectReason::Sandbox,
        "attachment sanitizer OS sandbox unavailable",
    ))
}
#[cfg(target_os = "linux")]
pub(super) fn add_bwrap_runtime_path(cmd: &mut Command, path: &Path) -> Result<(), SanitizeError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|err| {
            SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                format!(
                    "attachment sanitizer sandbox cannot resolve {}: {err}",
                    path.display()
                ),
            )
        })?;
        cmd.arg("--symlink").arg(target).arg(path);
    } else if metadata.is_dir() {
        cmd.arg("--ro-bind").arg(path).arg(path);
    }
    Ok(())
}
pub(super) fn set_clean_sanitizer_environment(cmd: &mut Command, max_input_bytes: &str) {
    cmd.env_clear()
        .env(ATTACHMENT_SANITIZER_ENV, "1")
        .env(ATTACHMENT_SANITIZER_MAX_INPUT_ENV, max_input_bytes)
        .env(ATTACHMENT_SANITIZER_SANDBOXED_ENV, "1");
}
#[cfg(target_os = "macos")]
pub(super) fn macos_sandbox_literal(path: &Path) -> Result<String, SanitizeError> {
    let raw = path.to_str().ok_or_else(|| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            "attachment sanitizer path is not valid UTF-8",
        )
    })?;
    Ok(raw.replace('\\', "\\\\").replace('"', "\\\""))
}
pub(super) fn find_executable_in_search_path(
    search_path: Option<&OsStr>,
    name: &str,
) -> Option<PathBuf> {
    let path = search_path?;
    for dir in env::split_paths(path) {
        let candidate = dir.join(name);
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}
pub(super) fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}
