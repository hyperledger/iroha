include!("platform_source_deadline.rs");

fn broker_error_status(error: BrokerError) -> Option<(u8, bool)> {
    match error {
        BrokerError::Rejected => Some((STATUS_REJECTED_V1, false)),
        BrokerError::Conflict => Some((STATUS_CONFLICT_V1, false)),
        BrokerError::StaleOrRevoked => Some((STATUS_STALE_OR_REVOKED_V1, true)),
        BrokerError::Ambiguous => Some((STATUS_AMBIGUOUS_V1, true)),
        BrokerError::Unavailable => Some((STATUS_UNAVAILABLE_V1, true)),
        BrokerError::Protocol | BrokerError::BindingMismatch => None,
    }
}
fn source_deadline_remaining(deadline: std::time::Instant) -> Result<Duration, BrokerError> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(BrokerError::Unavailable)
}
fn apply_source_socket_deadline(
    stream: &UnixStream,
    deadline: std::time::Instant,
) -> Result<(), BrokerError> {
    let remaining = source_deadline_remaining(deadline)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| BrokerError::Unavailable)
}
fn source_fetch_error(error: sorafs_node::ProviderIngestSourceFetchErrorV1) -> BrokerError {
    match error {
        sorafs_node::ProviderIngestSourceFetchErrorV1::Unavailable => BrokerError::Unavailable,
        sorafs_node::ProviderIngestSourceFetchErrorV1::ContentRejected => BrokerError::Rejected,
        sorafs_node::ProviderIngestSourceFetchErrorV1::Rejected => BrokerError::StaleOrRevoked,
    }
}
fn fetch_provider_ingest_source(
    source: &dyn crate::sorafs_provider_ingest_runtime::ProviderIngestAuthenticatedSourceRuntimeV1,
    request: sorafs_node::ProviderIngestSourceRequestV1,
    timeout: Duration,
) -> Result<crate::sorafs_provider_ingest_runtime::VerifiedProviderIngestPayloadV1, BrokerError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| BrokerError::Unavailable)?;
    runtime
        .block_on(tokio::time::timeout(
            timeout,
            sorafs_node::ProviderIngestAuthenticatedSourceFetchV1::fetch(source, request),
        ))
        .map_err(|_| BrokerError::Unavailable)?
        .map_err(source_fetch_error)
}
/// A trailer write retains its original socket, absolute deadline and process owner.
struct ProviderSourceTrailerOutput<'stream> {
    decode_pool: &'stream Arc<DecodeResourcePoolV1>,
    stream: &'stream mut UnixStream,
    deadline: std::time::Instant,
}
fn write_source_trailer(
    output: &mut ProviderSourceTrailerOutput<'_>,
    trailer: ProviderIngestSourceTrailerWireV1,
) -> Result<(), BrokerError> {
    apply_source_socket_deadline(output.stream, output.deadline)?;
    let admission = DecodeResourceAdmissionV1::acquire_from(
        Arc::clone(output.decode_pool),
        None,
        SOURCE_STREAM_FRAME_DECODE_POLICY_V1,
    )?;
    let _scope = admission.enter();
    let frame = encode_frame(
        FRAME_KIND_PROVIDER_INGEST_SOURCE_TRAILER_V1,
        &trailer,
        MAX_PROVIDER_INGEST_SOURCE_TRAILER_FRAME_BYTES_V1,
    )?;
    write_length_prefixed(
        output.stream,
        &frame,
        MAX_PROVIDER_INGEST_SOURCE_TRAILER_FRAME_BYTES_V1,
    )
}
fn write_source_failure_trailer(
    output: &mut ProviderSourceTrailerOutput<'_>,
    status: u8,
    content_length: u64,
    frame_count: u64,
    transcript: &blake3::Hasher,
    provider_metadata_digest: [u8; 32],
) {
    let _ = write_source_trailer(
        output,
        ProviderIngestSourceTrailerWireV1 {
            status,
            content_length,
            frame_count,
            payload_digest: [0; 32],
            transcript_digest: *transcript.clone().finalize().as_bytes(),
            provider_metadata_digest,
        },
    );
}
fn serve_provider_ingest_source_fetch(
    mut stream: UnixStream,
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<(), BrokerError> {
    let limits = required_binding_value!(&request.binding, provider_ingest_source_limits);
    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_millis(limits.operation_timeout_ms))
        .ok_or(BrokerError::Rejected)?;
    apply_source_socket_deadline(&stream, deadline)?;
    let configured =
        qualify_server_binding(state, &request.binding, request.provider_metadata_digest)?;
    let fetch = decode_canonical_with_policy_from::<ProviderIngestSourceFetchRequestWireV1>(
        &request.payload,
        MAX_PROVIDER_INGEST_SOURCE_REQUEST_BYTES_V1,
        CONTROL_DECODE_POLICY_V1,
        Arc::clone(&state.decode_pool),
    )?;
    validate_source_fetch_request(
        &fetch,
        &request.binding,
        Some(&configured.provider_ingest_source_provider_ids),
        &state.network_id,
    )?;
    let authorization = fetch.authorization.clone();
    let source_request = source_request_from_wire(fetch)?;
    let source = broker_backend!(state, provider_ingest_authenticated_source);
    let mut fetched = fetch_provider_ingest_source(
        source.as_ref(),
        source_request,
        source_deadline_remaining(deadline)?,
    )?;
    validate_source_payload_metadata(&authorization, &fetched.manifest, &fetched.plan)?;
    let _retained_memory = acquire_source_retained_memory(&state.decode_pool, &fetched.plan)?;
    let content_length = authorization.content_length();
    let frame_count = source_stream_frame_count(content_length)?;
    let mut transcript = {
        let initial_admission = DecodeResourceAdmissionV1::acquire_operation_from(
            Arc::clone(&state.decode_pool),
            OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1,
        )?;
        let _initial_scope = initial_admission.enter();
        let manifest = fetched
            .manifest
            .encode()
            .map_err(|_| BrokerError::Rejected)?;
        let plan = encode_source_plan(&fetched.plan)?;
        validate_source_metadata_lengths(manifest.len(), plan.len())?;
        if sorafs_manifest::decode_manifest_v1_canonical(&manifest)
            .map_err(|_| BrokerError::Rejected)?
            != fetched.manifest
        {
            return Err(BrokerError::Rejected);
        }
        let header = ProviderIngestSourceHeaderWireV1 {
            manifest,
            plan,
            content_length,
            frame_count,
        };
        let result = encode_canonical(&header, MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1)?;
        let response = make_operation_response(request, STATUS_OK_V1, result, &state.network_id)?;
        let response_frame = encode_frame(
            FRAME_KIND_OPERATION_RESPONSE_V1,
            &response,
            MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
        )?;
        apply_source_socket_deadline(&stream, deadline)?;
        write_length_prefixed(
            &mut stream,
            &response_frame,
            MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
        )?;
        source_stream_transcript(request, &response)
    };
    let mut payload_hasher = blake3::Hasher::new();
    let mut offset = 0_u64;
    for sequence in 0..frame_count {
        let remaining = content_length
            .checked_sub(offset)
            .ok_or(BrokerError::Protocol)?;
        let chunk_len = usize::try_from(
            remaining.min(
                u64::try_from(MAX_PROVIDER_INGEST_SOURCE_CHUNK_PAYLOAD_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?,
            ),
        )
        .map_err(|_| BrokerError::Protocol)?;
        let chunk_admission = DecodeResourceAdmissionV1::acquire_from(
            Arc::clone(&state.decode_pool),
            None,
            SOURCE_STREAM_FRAME_DECODE_POLICY_V1,
        )?;
        chunk_admission
            .reserve_retained_bytes(chunk_len, MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1)?;
        let _chunk_scope = chunk_admission.enter();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(chunk_len)
            .map_err(|_| BrokerError::Unavailable)?;
        bytes.resize(chunk_len, 0);
        if source_deadline_remaining(deadline).is_err()
            || std::io::Read::read_exact(&mut fetched.reader, &mut bytes).is_err()
            || source_deadline_remaining(deadline).is_err()
        {
            write_source_failure_trailer(
                &mut ProviderSourceTrailerOutput {
                    decode_pool: &state.decode_pool,
                    stream: &mut stream,
                    deadline,
                },
                STATUS_REJECTED_V1,
                content_length,
                sequence,
                &transcript,
                request.provider_metadata_digest,
            );
            return Ok(());
        }
        let chunk = ProviderIngestSourceChunkWireV1 {
            sequence,
            offset,
            bytes,
        };
        payload_hasher.update(&chunk.bytes);
        update_source_stream_transcript(&mut transcript, &chunk);
        let frame = encode_frame(
            FRAME_KIND_PROVIDER_INGEST_SOURCE_CHUNK_V1,
            &chunk,
            MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1,
        )?;
        apply_source_socket_deadline(&stream, deadline)?;
        write_length_prefixed(
            &mut stream,
            &frame,
            MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1,
        )?;
        offset = offset
            .checked_add(u64::try_from(chunk_len).map_err(|_| BrokerError::Protocol)?)
            .ok_or(BrokerError::Protocol)?;
    }
    let mut trailing = [0_u8; 1];
    let trailing_result = std::io::Read::read(&mut fetched.reader, &mut trailing);
    let payload_digest = *payload_hasher.finalize().as_bytes();
    if source_deadline_remaining(deadline).is_err()
        || !matches!(trailing_result, Ok(0))
        || payload_digest != *fetched.plan.payload_digest.as_bytes()
    {
        write_source_failure_trailer(
            &mut ProviderSourceTrailerOutput {
                decode_pool: &state.decode_pool,
                stream: &mut stream,
                deadline,
            },
            STATUS_REJECTED_V1,
            content_length,
            frame_count,
            &transcript,
            request.provider_metadata_digest,
        );
        return Ok(());
    }
    if qualify_server_binding(state, &request.binding, request.provider_metadata_digest).is_err() {
        write_source_failure_trailer(
            &mut ProviderSourceTrailerOutput {
                decode_pool: &state.decode_pool,
                stream: &mut stream,
                deadline,
            },
            STATUS_STALE_OR_REVOKED_V1,
            content_length,
            frame_count,
            &transcript,
            request.provider_metadata_digest,
        );
        return Ok(());
    }
    write_source_trailer(
        &mut ProviderSourceTrailerOutput {
            decode_pool: &state.decode_pool,
            stream: &mut stream,
            deadline,
        },
        ProviderIngestSourceTrailerWireV1 {
            status: STATUS_OK_V1,
            content_length,
            frame_count,
            payload_digest,
            transcript_digest: *transcript.finalize().as_bytes(),
            provider_metadata_digest: request.provider_metadata_digest,
        },
    )
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "each blocking session owns its shared permits and ordered transcript"
)]
fn serve_client(
    mut stream: UnixStream,
    state: &BrokerServerStateV1,
    mut session_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    source_stream_permits: Arc<tokio::sync::Semaphore>,
    inbound_operation_budget: Arc<tokio::sync::Semaphore>,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    observer_operation_timeout: Duration,
) -> Result<(), BrokerError> {
    if lifecycle.shutdown_requested() {
        return Err(BrokerError::Unavailable);
    }
    stream
        .set_read_timeout(Some(BROKER_IO_TIMEOUT_V1))
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .set_write_timeout(Some(BROKER_IO_TIMEOUT_V1))
        .map_err(|_| BrokerError::Unavailable)?;
    let request_frame = read_length_prefixed(&mut stream, MAX_HANDSHAKE_FRAME_BYTES_V1)?;
    let handshake = decode_frame_with_policy_from::<HandshakeRequestV1>(
        &request_frame,
        FRAME_KIND_HANDSHAKE_REQUEST_V1,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
        CONTROL_DECODE_POLICY_V1,
        Arc::clone(&state.decode_pool),
    )?;
    validate_handshake_request(&handshake)?;
    if lifecycle.shutdown_requested() {
        return Ok(());
    }
    if handshake.chain_id != state.chain_id || handshake.network_id != state.network_id {
        return Err(BrokerError::BindingMismatch);
    }
    let live_observations = handshake
        .requested_catalog
        .iter()
        .map(|binding| {
            let Some(_qualification_permit) = lifecycle.try_begin_qualification() else {
                return Err(BrokerError::Unavailable);
            };
            let configured = configured_observation(state, binding)?;
            qualify_server_binding(state, binding, configured.metadata_digest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if lifecycle.shutdown_requested() {
        return Ok(());
    }
    let mut session_id = [0_u8; 32];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut session_id)
        .map_err(|_| BrokerError::Unavailable)?;
    if session_id == [0; 32] {
        return Err(BrokerError::Unavailable);
    }
    let response = make_handshake_response(&handshake, session_id, live_observations)?;
    let response_frame = encode_frame(
        FRAME_KIND_HANDSHAKE_RESPONSE_V1,
        &response,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )?;
    write_length_prefixed(&mut stream, &response_frame, MAX_HANDSHAKE_FRAME_BYTES_V1)?;
    let mut expected_request_id = 1_u64;
    let mut pop_session = PopBrokerServerSessionV1::default();
    loop {
        if lifecycle.shutdown_requested() {
            return Ok(());
        }
        let (announced_slot, announced_operation, request_frame, decode_admission) =
            read_operation_request_frame_with_budget(
                &mut stream,
                Arc::clone(&inbound_operation_budget),
                Arc::clone(&state.decode_pool),
            )?;
        let decode_scope = decode_admission.enter();
        let request = decode_operation_frame::<OperationRequestV1>(
            &request_frame,
            FRAME_KIND_OPERATION_REQUEST_V1,
            announced_operation,
        )?;
        validate_operation_request_for_session(&request, &state.chain_id, &state.network_id)?;
        if request.binding.slot != announced_slot
            || request.operation != announced_operation
            || request.session_id != session_id
            || request.request_id != expected_request_id
        {
            return Err(BrokerError::Protocol);
        }
        if !handshake
            .requested_catalog
            .iter()
            .any(|binding| binding == &request.binding)
        {
            return Err(BrokerError::BindingMismatch);
        }
        let configured = configured_observation(state, &request.binding)?;
        if request.provider_metadata_digest != configured.metadata_digest {
            return Err(BrokerError::BindingMismatch);
        }
        // Retire the request identifier before dispatch. A failed or
        // partially completed mutation can never be replayed in this
        // authenticated session.
        expected_request_id = expected_request_id
            .checked_add(1)
            .ok_or(BrokerError::Protocol)?;
        // This permit is the operation's admission boundary. The
        // lifecycle's second state check closes the race with the
        // shutdown transition; a request that loses that race never
        // reaches a deployment-owned provider method.
        let Some(operation_permit) = lifecycle.try_begin_operation() else {
            return Ok(());
        };
        if request.operation == OPERATION_STREAM_TOKEN_OBSERVE_V1 {
            // One original admitted-operation bound, created before any provider
            // qualification/dispatch. Handshake and wire ingress remain separate.
            let deadline = BrokerDeadlineV1::new(observer_operation_timeout)?;
            let terminate = server_observation::serve(&mut server_observation::Output {
                state,
                request: &request,
                stream: &mut stream,
                request_frame: &request_frame,
                admission: &decode_admission,
                operation_permit: &operation_permit,
                deadline,
            })?;
            if terminate {
                return Ok(());
            }
            continue;
        }
        if request.binding.slot
            == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id()
            && request.operation == OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1
        {
            let Ok(source_stream_permit) = Arc::clone(&source_stream_permits).try_acquire_owned()
            else {
                let response = make_operation_response(
                    &request,
                    STATUS_REJECTED_V1,
                    encode_canonical(&(), MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1)?,
                    &state.network_id,
                )?;
                let response_frame = encode_frame(
                    FRAME_KIND_OPERATION_RESPONSE_V1,
                    &response,
                    MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
                )?;
                write_length_prefixed(
                    &mut stream,
                    &response_frame,
                    MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
                )?;
                return Ok(());
            };
            // A stalled source stream consumes only its independently
            // configured stream and retained-plan permits after the
            // authenticated request has been classified. Release both
            // the unary session and the full initial-frame admission
            // before entering the payload stream.
            drop(session_permit.take());
            drop(decode_scope);
            drop(decode_admission);
            drop(request_frame);
            let _source_stream_permit = source_stream_permit;
            return serve_provider_ingest_source_fetch(stream, state, &request);
        }
        let (status, result, terminate) =
            match dispatch_server_operation_with_session(state, &mut pop_session, &request) {
                Ok(result) => (STATUS_OK_V1, result, false),
                Err(error) => {
                    let Some((status, terminate)) = broker_error_status(error) else {
                        return Err(error);
                    };
                    (
                        status,
                        ScrubbedBytes::new(encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)?),
                        terminate,
                    )
                }
            };
        let response =
            make_operation_response_scrubbed(&request, status, result, &state.network_id)?;
        let response_frame_limit = operation_frame_limit(request.operation);
        let response_frame = encode_frame(
            FRAME_KIND_OPERATION_RESPONSE_V1,
            &response,
            response_frame_limit,
        )?;
        write_length_prefixed(&mut stream, &response_frame, response_frame_limit)?;
        if terminate {
            return Ok(());
        }
    }
}
struct BoundSocketGuard {
    parent_directory: fs::File,
    instance_lock: endpoint_recovery::InstanceLockGuard,
    socket_name: std::ffi::OsString,
    identity: SocketIdentity,
    expected_service_uid: u32,
    socket_mode: u32,
    armed: bool,
}
impl BoundSocketGuard {
    fn verify_entry(&self) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
        self.instance_lock.verify(&self.parent_directory)?;
        let metadata = rustix::fs::statat(
            &self.parent_directory,
            self.socket_name.as_os_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
        if !endpoint_recovery::socket_metadata_is_exact(
            &metadata,
            self.expected_service_uid,
            self.socket_mode,
        ) || socket_identity_from_stat(&metadata) != self.identity
        {
            return Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
        }
        Ok(())
    }
    fn promote(
        &mut self,
        canonical_name: std::ffi::OsString,
    ) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
        rustix::fs::renameat_with(
            &self.parent_directory,
            self.socket_name.as_os_str(),
            &self.parent_directory,
            canonical_name.as_os_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
        self.socket_name = canonical_name;
        self.verify_entry()
    }
    fn cleanup(mut self) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
        self.armed = false;
        self.instance_lock.verify(&self.parent_directory)?;
        endpoint_recovery::cleanup_socket_entry(
            &self.parent_directory,
            self.socket_name.as_os_str(),
            self.identity,
            self.expected_service_uid,
            self.socket_mode,
            &self.instance_lock,
        )
    }
}
impl Drop for BoundSocketGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if self.instance_lock.verify(&self.parent_directory).is_err() {
            return;
        }
        let _ = endpoint_recovery::cleanup_socket_entry(
            &self.parent_directory,
            self.socket_name.as_os_str(),
            self.identity,
            self.expected_service_uid,
            self.socket_mode,
            &self.instance_lock,
        );
    }
}
#[cfg(target_os = "linux")]
const fn socket_device_identity_from_raw(device: rustix::fs::Dev) -> u64 {
    device
}
#[cfg(target_os = "macos")]
#[expect(
    clippy::cast_sign_loss,
    reason = "the filesystem identity preserves MetadataExt's signed dev_t bit pattern"
)]
const fn socket_device_identity_from_raw(device: rustix::fs::Dev) -> u64 {
    // `MetadataExt::dev()` exposes `dev_t` through Rust's unsigned
    // `u64` identity. On macOS `dev_t` is signed, so `as` preserves
    // the exact conversion used by `MetadataExt` even when its high
    // bit is set; a fallible numeric conversion would reject a valid
    // filesystem identity.
    device as u64
}
fn socket_identity_from_stat(metadata: &rustix::fs::Stat) -> SocketIdentity {
    SocketIdentity {
        device: socket_device_identity_from_raw(metadata.st_dev),
        inode: metadata.st_ino,
    }
}
fn finish_startup_failure<T>(
    listener: UnixListener,
    guard: BoundSocketGuard,
    error: RuntimeProviderBrokerServerErrorV1,
) -> Result<T, RuntimeProviderBrokerServerErrorV1> {
    drop(listener);
    match guard.cleanup() {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(cleanup_error),
    }
}
fn bind_server_listener(
    policy: &EndpointPolicy,
) -> Result<(tokio::net::UnixListener, BoundSocketGuard), RuntimeProviderBrokerServerErrorV1> {
    let parent = policy
        .path
        .parent()
        .ok_or(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
    verify_directory(parent, policy.expected_service_uid, false).map_err(server_error)?;
    if policy.verify_all_ancestors {
        for ancestor in parent.ancestors().skip(1) {
            verify_directory(ancestor, policy.expected_service_uid, true).map_err(server_error)?;
        }
    }
    let parent_directory = rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(|_| RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
    let parent_metadata = parent_directory
        .metadata()
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != policy.expected_service_uid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
    }
    let socket_name = policy
        .path
        .file_name()
        .ok_or(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?
        .to_owned();
    let instance_lock = endpoint_recovery::prepare_endpoint(
        &parent_directory,
        socket_name.as_os_str(),
        policy.expected_service_uid,
        policy.socket_mode,
    )?;
    let staging_name = endpoint_recovery::staging_socket_name()?;
    let staging_path = parent.join(&staging_name);
    let listener = UnixListener::bind(&staging_path)
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
    let Ok(bound_metadata) = rustix::fs::statat(
        &parent_directory,
        staging_name.as_os_str(),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) else {
        drop(listener);
        // V1 cleanup is identity-conservative: without an observed
        // device/inode identity, this pathname is never unlinked.
        // Closing the listener, failing startup, and retaining the
        // unpredictable staging entry for operator inspection is
        // safer than removing a same-UID substituted entry.
        return Err(RuntimeProviderBrokerServerErrorV1::EndpointCleanupFailed);
    };
    let bound_identity = socket_identity_from_stat(&bound_metadata);
    let mut guard = BoundSocketGuard {
        parent_directory,
        instance_lock,
        socket_name: staging_name,
        identity: bound_identity,
        expected_service_uid: policy.expected_service_uid,
        socket_mode: policy.socket_mode,
        armed: true,
    };
    if rustix::fs::FileType::from_raw_mode(bound_metadata.st_mode) != rustix::fs::FileType::Socket
        || bound_metadata.st_uid != policy.expected_service_uid
        || bound_metadata.st_nlink != 1
    {
        return finish_startup_failure(
            listener,
            guard,
            RuntimeProviderBrokerServerErrorV1::EndpointUnavailable,
        );
    }
    let socket_mode = match rustix::fs::RawMode::try_from(policy.socket_mode) {
        Ok(mode) => mode,
        Err(_) => {
            return finish_startup_failure(
                listener,
                guard,
                RuntimeProviderBrokerServerErrorV1::EndpointUnavailable,
            );
        }
    };
    #[cfg(target_os = "linux")]
    let chmod_flags = rustix::fs::AtFlags::empty();
    #[cfg(target_os = "macos")]
    let chmod_flags = rustix::fs::AtFlags::SYMLINK_NOFOLLOW;
    if rustix::fs::chmodat(
        &guard.parent_directory,
        guard.socket_name.as_os_str(),
        rustix::fs::Mode::from_raw_mode(socket_mode),
        chmod_flags,
    )
    .is_err()
    {
        return finish_startup_failure(
            listener,
            guard,
            RuntimeProviderBrokerServerErrorV1::EndpointUnavailable,
        );
    }
    if let Err(error) = guard.verify_entry() {
        return finish_startup_failure(listener, guard, error);
    }
    if let Err(error) = guard.promote(socket_name) {
        return finish_startup_failure(listener, guard, error);
    }
    let identity = match endpoint_identity(policy) {
        Ok(identity) if identity == guard.identity => identity,
        Ok(_) | Err(_) => {
            return finish_startup_failure(
                listener,
                guard,
                RuntimeProviderBrokerServerErrorV1::EndpointUnavailable,
            );
        }
    };
    debug_assert_eq!(identity, guard.identity);
    if listener.set_nonblocking(true).is_err() {
        return finish_startup_failure(
            listener,
            guard,
            RuntimeProviderBrokerServerErrorV1::EndpointUnavailable,
        );
    }
    let listener = match tokio::net::UnixListener::from_std(listener) {
        Ok(listener) => listener,
        Err(_) => {
            return match guard.cleanup() {
                Ok(()) => Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
    };
    Ok((listener, guard))
}
fn verify_endpoint_is_pinned(
    policy: &EndpointPolicy,
    guard: &BoundSocketGuard,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    guard.verify_entry()?;
    if endpoint_identity(policy).map_err(server_error)? != guard.identity {
        return Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
    }
    Ok(())
}
struct BrokerServingLifecycleGuard {
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
}
impl Drop for BrokerServingLifecycleGuard {
    fn drop(&mut self) {
        self.lifecycle.request_shutdown();
    }
}
#[derive(Default)]
struct AcceptedSessionControlsV1 {
    controls: std::collections::BTreeMap<u64, UnixStream>,
}
impl AcceptedSessionControlsV1 {
    fn insert(&mut self, session_token: u64, control: UnixStream) {
        let replaced = self.controls.insert(session_token, control);
        debug_assert!(
            replaced.is_none(),
            "session tokens are monotonically allocated and never reused"
        );
    }
    fn remove(&mut self, session_token: u64) {
        let _ = self.controls.remove(&session_token);
    }
    fn shutdown_all(&self) {
        for control in self.controls.values() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
    }
}
impl Drop for AcceptedSessionControlsV1 {
    fn drop(&mut self) {
        // A serving-thread panic or other unexpected unwind must wake
        // every accepted session before its `JoinSet` is dropped.
        // The control sockets are clones of the descriptors owned by
        // the blocking workers, so shutdown applies to both handles.
        self.shutdown_all();
    }
}
fn serve_with_policy_and_fallible_readiness<R>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    policy: &EndpointPolicy,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce() -> Result<(), RuntimeProviderBrokerReadinessErrorV1>,
{
    serve_with_policy_and_fallible_readiness_and_peer_authorizer(
        bindings,
        backends,
        policy,
        lifecycle,
        on_ready,
        verify_peer_uid,
        shared_decode_resource_pool(),
    )
}

fn serve_with_policy_and_fallible_readiness_and_peer_authorizer<R, A>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    policy: &EndpointPolicy,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
    authorize_peer_uid: A,
    decode_pool: Arc<DecodeResourcePoolV1>,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce() -> Result<(), RuntimeProviderBrokerReadinessErrorV1>,
    A: Fn(u32, u32) -> Result<(), BrokerError>,
{
    if lifecycle.shutdown_requested() {
        return Ok(());
    }
    let _serving_lifecycle = BrokerServingLifecycleGuard {
        lifecycle: Arc::clone(&lifecycle),
    };
    let state =
        match prepare_server_state_for_lifecycle(bindings, backends, &lifecycle, decode_pool) {
            Ok(state) => Arc::new(state),
            Err(StartupQualificationErrorV1::Cancelled) => return Ok(()),
            Err(StartupQualificationErrorV1::Failed(error)) => return Err(error),
        };
    if lifecycle.shutdown_requested() {
        return Ok(());
    }
    let source_stream_limit = state
        .catalog
        .iter()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id()
        })
        .and_then(|binding| binding.provider_ingest_source_limits)
        .map(|limits| {
            usize::try_from(limits.max_concurrent_streams)
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        })
        .transpose()?
        .unwrap_or(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::EndpointUnavailable)?;
    runtime.block_on(async move {
        let (listener, guard) = bind_server_listener(policy)?;
        if lifecycle.shutdown_requested() {
            drop(listener);
            return match guard.cleanup() {
                Ok(()) => Ok(()),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        if let Err(outcome) = requalify_server_state(&state, &lifecycle) {
            let result = match outcome {
                StartupQualificationErrorV1::Cancelled => Ok(()),
                StartupQualificationErrorV1::Failed(error) => Err(error),
            };
            drop(listener);
            return match guard.cleanup() {
                Ok(()) => result,
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        if let Err(error) = verify_endpoint_is_pinned(policy, &guard) {
            drop(listener);
            return match guard.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        match lifecycle.publish_ready_fallible(on_ready) {
            Ok(true) => {}
            Ok(false) => {
                let result = if lifecycle.shutdown_requested() {
                    Ok(())
                } else {
                    Err(RuntimeProviderBrokerServerErrorV1::Protocol)
                };
                drop(listener);
                return match guard.cleanup() {
                    Ok(()) => result,
                    Err(cleanup_error) => Err(cleanup_error),
                };
            }
            Err(RuntimeProviderBrokerReadinessErrorV1) => {
                lifecycle.request_shutdown();
                drop(listener);
                return match guard.cleanup() {
                    Ok(()) => Err(RuntimeProviderBrokerServerErrorV1::ReadinessUnavailable),
                    Err(cleanup_error) => Err(cleanup_error),
                };
            }
        }
        let session_permits = Arc::new(tokio::sync::Semaphore::new(MAX_BROKER_SESSIONS_V1));
        // Hold a permit for every declared inbound operation byte until
        // the decoded request leaves its server-loop iteration. A
        // compromised same-UID peer can therefore occupy at most one
        // maximum-sized operation across all accepted sessions, and a
        // length prefix alone never triggers a maximum-sized allocation.
        let inbound_operation_budget = Arc::new(tokio::sync::Semaphore::new(
            MAX_BROKER_PROCESS_OPERATION_BYTES_V1
                .checked_sub(MAX_BROKER_SHARED_DECODE_BYTES_V1)
                .expect("combined broker memory ceiling includes raw frames"),
        ));
        let source_stream_permits = Arc::new(tokio::sync::Semaphore::new(source_stream_limit));
        let mut sessions = tokio::task::JoinSet::new();
        let mut session_controls = AcceptedSessionControlsV1::default();
        let mut next_session_token = 0_u64;
        let mut serve_result = 'serve: loop {
            while let Some(joined) = sessions.try_join_next() {
                match joined {
                    Ok((session_token, _session_result)) => {
                        session_controls.remove(session_token);
                    }
                    Err(_) => {
                        break 'serve Err(RuntimeProviderBrokerServerErrorV1::Protocol);
                    }
                }
            }
            if lifecycle.shutdown_requested() {
                break Ok(());
            }
            if let Err(error) = verify_endpoint_is_pinned(policy, &guard) {
                break Err(error);
            }
            let accepted = tokio::select! {
                accepted = listener.accept() => Some(accepted),
                () = tokio::time::sleep(Duration::from_millis(100)) => None,
            };
            let Some(accepted) = accepted else {
                if let Err(error) = verify_endpoint_is_pinned(policy, &guard) {
                    break Err(error);
                }
                continue;
            };
            let (stream, _) = match accepted {
                Ok(accepted) => accepted,
                Err(_) => {
                    break Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
                }
            };
            if lifecycle.shutdown_requested() {
                drop(stream);
                break Ok(());
            }
            if let Err(error) = verify_endpoint_is_pinned(policy, &guard) {
                drop(stream);
                break Err(error);
            }
            let credentials = match stream.peer_cred() {
                Ok(credentials) => credentials,
                Err(_) => {
                    break Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
                }
            };
            if authorize_peer_uid(credentials.uid(), policy.expected_service_uid).is_err() {
                // Authentication rejection belongs to this connection. A
                // wrong-UID local peer must not turn one failed admission
                // into a broker-wide denial of service for the authorized
                // daemon.
                drop(stream);
                continue;
            }
            let Ok(session_permit) = Arc::clone(&session_permits).try_acquire_owned() else {
                // Excess peers are closed immediately. They never
                // enter an unbounded task, thread, or request queue.
                drop(stream);
                continue;
            };
            let stream = match stream.into_std() {
                Ok(stream) => stream,
                Err(_) => {
                    break Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
                }
            };
            if stream.set_nonblocking(false).is_err() {
                break Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
            }
            let control = match stream.try_clone() {
                Ok(control) => control,
                Err(_) => {
                    break Err(RuntimeProviderBrokerServerErrorV1::EndpointUnavailable);
                }
            };
            let Some(session_token) = next_session_token.checked_add(1) else {
                break Err(RuntimeProviderBrokerServerErrorV1::Protocol);
            };
            next_session_token = session_token;
            session_controls.insert(session_token, control);
            let session_state = Arc::clone(&state);
            let session_source_stream_permits = Arc::clone(&source_stream_permits);
            let session_inbound_operation_budget = Arc::clone(&inbound_operation_budget);
            let session_lifecycle = Arc::clone(&lifecycle);
            let observer_operation_timeout = policy.observer_operation_timeout;
            let _session_registration = sessions.spawn_blocking(move || {
                // A peer protocol error, timeout, disconnect, or
                // backend rejection terminates only this authenticated
                // session.
                let result = serve_client(
                    stream,
                    &session_state,
                    Some(session_permit),
                    session_source_stream_permits,
                    session_inbound_operation_budget,
                    session_lifecycle,
                    observer_operation_timeout,
                );
                (session_token, result)
            });
            if let Err(error) = verify_endpoint_is_pinned(policy, &guard) {
                break Err(error);
            }
        };
        lifecycle.request_shutdown();
        drop(listener);
        session_controls.shutdown_all();
        // V1 shutdown is completion-safe, not time-bounded: transport
        // shutdown wakes idle sessions and prevents new operations,
        // then the broker joins every call admitted before the
        // lifecycle transition. Synchronous provider traits expose no
        // uniform cancellation primitive, so deployment adapters must
        // enforce their configured external-call deadlines. Detaching
        // a blocking worker here could let a mutating provider call
        // outlive endpoint cleanup and a subsequent broker restart.
        while let Some(joined) = sessions.join_next().await {
            match joined {
                Ok((session_token, _session_result)) => {
                    session_controls.remove(session_token);
                }
                Err(_) if serve_result.is_ok() => {
                    serve_result = Err(RuntimeProviderBrokerServerErrorV1::Protocol);
                }
                Err(_) => {}
            }
        }
        drop(session_controls);
        match guard.cleanup() {
            Ok(()) => serve_result,
            Err(cleanup_error) => Err(cleanup_error),
        }
    })
}
fn serve_with_policy_and_lifecycle<R>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    policy: &EndpointPolicy,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce(),
{
    serve_with_policy_and_fallible_readiness(bindings, backends, policy, lifecycle, || {
        on_ready();
        Ok(())
    })
}
fn serve_with_policy(
    bindings: &IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    policy: &EndpointPolicy,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    serve_with_policy_and_lifecycle(bindings, backends, policy, lifecycle, || {})
}
// An ambiguous exchange belongs to one immutable catalog entry, metadata
// generation and operation. Another provider must never recover it implicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BrokerPendingOperation {
    catalog_index: usize,
    metadata_digest: [u8; 32],
    operation: u16,
}
impl BrokerPendingOperation {
    fn permits_readback(self, request: Self, mutating: bool) -> bool {
        !mutating
            && self.operation == OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1
            && self.catalog_index == request.catalog_index
            && self.metadata_digest == request.metadata_digest
            && matches!(
                request.operation,
                OPERATION_QUALIFY_V1 | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
            )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerConnectionFailure {
    Unavailable,
    Ambiguous(BrokerPendingOperation),
    AwaitingReadback(BrokerPendingOperation),
    Permanent(BrokerError),
}
impl BrokerConnectionFailure {
    fn reason(self) -> BrokerError {
        match self {
            Self::Unavailable => BrokerError::Unavailable,
            Self::Ambiguous(_) | Self::AwaitingReadback(_) => BrokerError::Ambiguous,
            Self::Permanent(error) => error,
        }
    }
    fn check_call(
        self,
        request: Option<BrokerPendingOperation>,
        mutating: bool,
    ) -> Result<(), BrokerError> {
        if let Self::AwaitingReadback(pending) = self
            && request.is_some_and(|request| pending.permits_readback(request, mutating))
        {
            return Ok(());
        }
        Err(self.reason())
    }
}
struct BrokerConnection {
    stream: UnixStream,
    session_id: [u8; 32],
    next_request_id: u64,
    poison_reason: Option<BrokerConnectionFailure>,
}
struct BrokerSession {
    decode_pool: Arc<DecodeResourcePoolV1>,
    connection: Mutex<BrokerConnection>,
    chain_id: String,
    network_id: NetworkId,
    endpoint: EndpointPolicy,
    requested_catalog: Vec<ProviderBindingWireV1>,
}
fn connect_broker_connection(
    policy: &EndpointPolicy,
    chain_id: &str,
    network_id: NetworkId,
    requested_catalog: Vec<ProviderBindingWireV1>,
    io_timeout: Option<Duration>,
    decode_pool: &Arc<DecodeResourcePoolV1>,
) -> Result<(BrokerConnection, Vec<ProviderObservationWireV1>), BrokerError> {
    connect_broker_connection_before(
        policy,
        chain_id,
        network_id,
        requested_catalog,
        BrokerDeadlineV1::new(io_timeout.unwrap_or(BROKER_IO_TIMEOUT_V1))?,
        decode_pool,
    )
}
fn connect_broker_connection_before(
    policy: &EndpointPolicy,
    chain_id: &str,
    network_id: NetworkId,
    requested_catalog: Vec<ProviderBindingWireV1>,
    deadline: BrokerDeadlineV1,
    decode_pool: &Arc<DecodeResourcePoolV1>,
) -> Result<(BrokerConnection, Vec<ProviderObservationWireV1>), BrokerError> {
    let mut stream = connect_verified_before(policy, deadline)?;
    let mut client_nonce = [0_u8; 32];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut client_nonce)
        .map_err(|_| BrokerError::Unavailable)?;
    if client_nonce == [0; 32] {
        return Err(BrokerError::Unavailable);
    }
    let request = make_handshake_request(chain_id, network_id, requested_catalog, client_nonce)?;
    let request_frame = encode_frame(
        FRAME_KIND_HANDSHAKE_REQUEST_V1,
        &request,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )?;
    write_length_prefixed(
        &mut DeadlineUnixStreamV1::new(&mut stream, deadline),
        &request_frame,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )?;
    let response_frame = read_length_prefixed(
        &mut DeadlineUnixStreamV1::new(&mut stream, deadline),
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )?;
    let response = decode_frame_with_policy_from::<HandshakeResponseV1>(
        &response_frame,
        FRAME_KIND_HANDSHAKE_RESPONSE_V1,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
        CONTROL_DECODE_POLICY_V1,
        Arc::clone(decode_pool),
    )?;
    validate_handshake_response(&request, &response)?;
    deadline.remaining()?;
    Ok((
        BrokerConnection {
            stream,
            session_id: response.session_id,
            next_request_id: 1,
            poison_reason: None,
        },
        response.observations,
    ))
}
impl_broker_debug_fields!(BrokerSession as value {} => finish_non_exhaustive);
impl BrokerSession {
    fn connect(
        policy: &EndpointPolicy,
        chain_id: &str,
        network_id: NetworkId,
        requested_catalog: Vec<ProviderBindingWireV1>,
        decode_pool: Arc<DecodeResourcePoolV1>,
    ) -> Result<(Arc<Self>, Vec<ProviderObservationWireV1>), BrokerError> {
        Self::connect_before(
            policy,
            chain_id,
            network_id,
            requested_catalog,
            BrokerDeadlineV1::new(BROKER_IO_TIMEOUT_V1)?,
            decode_pool,
        )
    }
    fn connect_before(
        policy: &EndpointPolicy,
        chain_id: &str,
        network_id: NetworkId,
        requested_catalog: Vec<ProviderBindingWireV1>,
        deadline: BrokerDeadlineV1,
        decode_pool: Arc<DecodeResourcePoolV1>,
    ) -> Result<(Arc<Self>, Vec<ProviderObservationWireV1>), BrokerError> {
        let (connection, observations) = connect_broker_connection_before(
            policy,
            chain_id,
            network_id,
            requested_catalog.clone(),
            deadline,
            &decode_pool,
        )?;
        Ok((
            Arc::new(Self {
                connection: Mutex::new(connection),
                decode_pool,
                chain_id: chain_id.to_owned(),
                network_id,
                endpoint: policy.clone(),
                requested_catalog,
            }),
            observations,
        ))
    }
    fn operation_scope(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
    ) -> Option<BrokerPendingOperation> {
        self.requested_catalog
            .iter()
            .position(|expected| expected == binding)
            .map(|catalog_index| BrokerPendingOperation {
                catalog_index,
                metadata_digest,
                operation,
            })
    }
    fn reconnect(&self) -> Result<(), BrokerError> {
        self.reconnect_with_scope(None)
    }
    fn reconnect_for_readback(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
    ) -> Result<(), BrokerError> {
        let scope = self
            .operation_scope(
                binding,
                metadata_digest,
                OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1,
            )
            .ok_or(BrokerError::BindingMismatch)?;
        self.reconnect_with_scope(Some(scope))
    }
    fn reconnect_with_scope(
        &self,
        scope: Option<BrokerPendingOperation>,
    ) -> Result<(), BrokerError> {
        self.reconnect_using(scope, |deadline| {
            connect_broker_connection_before(
                &self.endpoint,
                &self.chain_id,
                self.network_id,
                self.requested_catalog.clone(),
                deadline,
                &self.decode_pool,
            )
            .map(|(connection, _)| connection)
        })
    }
    fn reconnect_using(
        &self,
        scope: Option<BrokerPendingOperation>,
        connect: impl FnOnce(BrokerDeadlineV1) -> Result<BrokerConnection, BrokerError>,
    ) -> Result<(), BrokerError> {
        // Keep the exchange mutex through authentication. A delayed reconnect
        // cannot replace a newer connection or discard its request/poison state.
        let deadline = BrokerDeadlineV1::new(BROKER_IO_TIMEOUT_V1)?;
        let mut current = deadline.lock(&self.connection)?;
        let pending = match current.poison_reason {
            None => return Ok(()),
            Some(BrokerConnectionFailure::Unavailable) => None,
            Some(BrokerConnectionFailure::Ambiguous(pending))
                if scope == Some(pending)
                    && pending.operation
                        == OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1 =>
            {
                Some(pending)
            }
            Some(BrokerConnectionFailure::AwaitingReadback(pending)) if scope == Some(pending) => {
                return Ok(());
            }
            Some(failure) => return Err(failure.reason()),
        };
        match connect(deadline) {
            Ok(mut connection) => {
                deadline.remaining()?;
                // Authentication restores transport, not knowledge of a write's
                // outcome. Only a verified readback may release this gate.
                connection.poison_reason = pending.map(BrokerConnectionFailure::AwaitingReadback);
                *current = connection;
                Ok(())
            }
            Err(error) => {
                if error != BrokerError::Unavailable {
                    current.poison_reason = Some(BrokerConnectionFailure::Permanent(error));
                }
                Err(error)
            }
        }
    }
    fn complete_readback(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        response_session_id: [u8; 32],
    ) -> Result<(), BrokerError> {
        let scope = self
            .operation_scope(
                binding,
                metadata_digest,
                OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1,
            )
            .ok_or(BrokerError::BindingMismatch)?;
        let deadline = BrokerDeadlineV1::new(BROKER_IO_TIMEOUT_V1)?;
        let mut current = deadline.lock(&self.connection)?;
        match current.poison_reason {
            None if current.session_id == response_session_id => Ok(()),
            None => Err(BrokerError::Unavailable),
            Some(BrokerConnectionFailure::AwaitingReadback(pending))
                if pending == scope && current.session_id == response_session_id =>
            {
                current.poison_reason = None;
                Ok(())
            }
            Some(failure) => Err(failure.reason()),
        }
    }
    fn poison(&self) {
        self.poison_with_reason(BrokerError::Protocol);
    }
    fn poison_with_reason(&self, reason: BrokerError) {
        if let Ok(mut connection) = self.connection.lock() {
            match (connection.poison_reason, reason) {
                (Some(BrokerConnectionFailure::Permanent(_)), _)
                | (
                    Some(
                        BrokerConnectionFailure::Ambiguous(_)
                        | BrokerConnectionFailure::AwaitingReadback(_),
                    ),
                    BrokerError::Unavailable,
                ) => {}
                (_, BrokerError::Unavailable) => {
                    connection.poison_reason = Some(BrokerConnectionFailure::Unavailable);
                }
                _ => {
                    connection.poison_reason = Some(BrokerConnectionFailure::Permanent(reason));
                }
            }
        }
    }
    fn decode_result<T>(&self, bytes: &ScrubbedBytes) -> Result<T, BrokerError>
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        let _scope = bytes.enter_decode_admission();
        decode_canonical::<T>(bytes, MAX_OPERATION_FRAME_BYTES_V1).inspect_err(|error| {
            self.poison_with_reason(*error);
        })
    }
    fn decode_operation_result<T>(
        &self,
        bytes: &ScrubbedBytes,
        operation: u16,
    ) -> Result<T, BrokerError>
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        if bytes
            .decode_admission
            .as_ref()
            .and_then(|admission| admission.operation)
            .is_some_and(|active| active != operation)
        {
            self.poison_with_reason(BrokerError::Protocol);
            return Err(BrokerError::Protocol);
        }
        let _scope = bytes.enter_decode_admission();
        decode_canonical_with_policy::<T>(
            bytes,
            operation_frame_limit(operation),
            operation_decode_policy(operation),
        )
        .inspect_err(|error| {
            self.poison_with_reason(*error);
        })
    }
    fn decode_nested_result<T>(&self, bytes: &ScrubbedBytes, limit: usize) -> Result<T, BrokerError>
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        let _scope = bytes.enter_decode_admission();
        decode_nested_canonical::<T>(bytes, limit).inspect_err(|error| {
            self.poison_with_reason(*error);
        })
    }
    fn call(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
        payload: Vec<u8>,
        mutating: bool,
    ) -> Result<ScrubbedBytes, BrokerError> {
        self.call_with_scrubbed_payload(
            binding,
            metadata_digest,
            operation,
            ScrubbedBytes::new(payload),
            mutating,
        )
    }
    fn call_with_scrubbed_payload(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
        payload: ScrubbedBytes,
        mutating: bool,
    ) -> Result<ScrubbedBytes, BrokerError> {
        self.exchange(binding, metadata_digest, operation, payload, mutating)
            .map(|(result, _)| result)
    }
    fn call_before(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
        payload: ScrubbedBytes,
        mutating: bool,
        deadline: BrokerDeadlineV1,
    ) -> Result<ScrubbedBytes, BrokerError> {
        self.exchange_before(
            binding,
            metadata_digest,
            operation,
            payload,
            mutating,
            deadline,
        )
        .map(|(result, _)| result)
    }
    fn exchange(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
        payload: ScrubbedBytes,
        mutating: bool,
    ) -> Result<(ScrubbedBytes, [u8; 32]), BrokerError> {
        self.exchange_before(
            binding,
            metadata_digest,
            operation,
            payload,
            mutating,
            BrokerDeadlineV1::new(BROKER_IO_TIMEOUT_V1)?,
        )
    }
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the closure is required to accept every borrowed exchange lifetime; the method item fixes one lifetime"
    )]
    fn exchange_before(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
        payload: ScrubbedBytes,
        mutating: bool,
        deadline: BrokerDeadlineV1,
    ) -> Result<(ScrubbedBytes, [u8; 32]), BrokerError> {
        self.exchange_before_with_result(
            OutboundExchangeV1 {
                binding,
                metadata_digest,
                operation,
                payload,
                mutating,
                deadline,
            },
            |received| received.regular(),
        )
    }
    fn exchange_before_with_result<T>(
        &self,
        outbound: OutboundExchangeV1<'_>,
        receive: impl FnOnce(ReceivedExchangeV1<'_>) -> Result<T, BrokerError>,
    ) -> Result<(T, [u8; 32]), BrokerError> {
        let OutboundExchangeV1 {
            binding,
            metadata_digest,
            operation,
            payload,
            mutating,
            deadline,
        } = outbound;
        deadline.remaining()?;
        let frame_limit = operation_frame_limit(operation);
        let mut connection = deadline.lock(&self.connection)?;
        let request_scope = self.operation_scope(binding, metadata_digest, operation);
        if let Some(failure) = connection.poison_reason {
            failure.check_call(request_scope, mutating)?;
        }
        // A terminal/gated call has no exchange to admit. Preserve its exact
        // outcome even when unrelated sessions exhaust the shared resource pool.
        // Reserve the full audited operation ceiling before retaining
        // the caller's payload or constructing any canonical request
        // copies. The same reservation follows the response into the
        // caller's typed result decode.
        let decode_admission = DecodeResourceAdmissionV1::acquire_operation_from(
            Arc::clone(&self.decode_pool),
            operation,
        )?;
        decode_admission.reserve_retained_bytes(payload.len(), frame_limit)?;
        let decode_scope = decode_admission.enter();
        let transport_failure = if mutating {
            request_scope.map_or(
                BrokerConnectionFailure::Permanent(BrokerError::Ambiguous),
                BrokerConnectionFailure::Ambiguous,
            )
        } else if let Some(BrokerConnectionFailure::AwaitingReadback(pending)) =
            connection.poison_reason
        {
            // Failed readback must retain the preceding mutation's uncertainty.
            BrokerConnectionFailure::Ambiguous(pending)
        } else {
            BrokerConnectionFailure::Unavailable
        };
        let request_id = connection.next_request_id;
        let next_request_id = connection
            .next_request_id
            .checked_add(1)
            .ok_or(BrokerError::Unavailable)?;
        let request = make_operation_request_with_scrubbed_payload(
            connection.session_id,
            request_id,
            binding.clone(),
            metadata_digest,
            operation,
            payload,
        )?;
        let request_frame = encode_frame(FRAME_KIND_OPERATION_REQUEST_V1, &request, frame_limit)?;
        deadline.remaining()?;
        // Retire the identifier before the first write so a partially
        // dispatched request can never be replayed with the same id.
        connection.next_request_id = next_request_id;
        if let Err(cause) = write_operation_request_frame(
            &mut DeadlineUnixStreamV1::new(&mut connection.stream, deadline),
            &request,
            &request_frame,
        ) {
            let error = if mutating {
                BrokerError::Ambiguous
            } else {
                cause
            };
            connection.poison_reason = Some(if cause == BrokerError::Unavailable {
                transport_failure
            } else {
                BrokerConnectionFailure::Permanent(error)
            });
            return Err(error);
        }
        drop(request_frame);
        let response_frame = match read_length_prefixed_with_decode_admission(
            &mut DeadlineUnixStreamV1::new(&mut connection.stream, deadline),
            frame_limit,
            &decode_admission,
        ) {
            Ok(frame) => frame,
            Err(cause) => {
                let error = if mutating {
                    BrokerError::Ambiguous
                } else {
                    cause
                };
                // Only I/O loss is recoverable. An invalid declared length or
                // resource-protocol failure must not become a retryable session.
                connection.poison_reason = Some(if cause == BrokerError::Unavailable {
                    transport_failure
                } else {
                    BrokerConnectionFailure::Permanent(error)
                });
                return Err(error);
            }
        };
        let result = receive(ReceivedExchangeV1 {
            request: &request,
            response_frame,
            decode_admission,
            connection: &mut connection,
            deadline,
            network_id: &self.network_id,
            mutating,
            transport_failure,
        })?;
        drop(decode_scope);
        Ok((result, connection.session_id))
    }

    fn call_sensitive(
        &self,
        binding: &ProviderBindingWireV1,
        metadata_digest: [u8; 32],
        operation: u16,
        payload: ScrubbedBytes,
        mutating: bool,
    ) -> Result<ScrubbedBytes, BrokerError> {
        self.call_with_scrubbed_payload(binding, metadata_digest, operation, payload, mutating)
    }
}
#[cfg(test)]
mod scoped_readback_recovery_tests {
    //! Operation-scoped recovery, permanent faults and serialized reconnects.
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    fn binding() -> ProviderBindingWireV1 {
        ProviderBindingWireV1 {
            slot: IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id(),
            handle: "transparency://sorafs/evidence-viewer/publisher-primary".to_owned(),
            revision: Some(7),
            policy_digest: Some([7; 32]),
            bootle_lantern_issuance_bindings: None,
            stream_token_signer_binding: None,
            appeal_finance_signer_binding: None,
            appeal_finance_checkpoint_binding: None,
            appeal_finance_checkpoint_max_bytes: None,
            pop_credential_runtime_binding: None,
            por_replay_archive_binding: None,
            por_replay_archive_proof_limits: None,
            potr_runtime_binding: None,
            native_signer_binding: None,
            governance_dag_publisher_peer_id: None,
            governance_dag_publisher_public_key: None,
            governance_request_ingress_binding: None,
            provider_ingest_signer_binding: None,
            provider_ingest_source_limits: None,
            provider_ingest_checkpoint_max_bytes: None,
            provider_ingest_max_signed_transaction_bytes: None,
            evidence_viewer_webauthn_binding: None,
            evidence_viewer_grant_ttl_ms: None,
            evidence_viewer_receipt_signer_public_key: None,
            evidence_viewer_transparency_publisher_public_key: Some([
                0x15, 0x09, 0xA6, 0x11, 0xAD, 0x6D, 0x97, 0xB0, 0x1D, 0x87, 0x1E, 0x58, 0xED, 0x00,
                0xC8, 0xFD, 0x7C, 0x39, 0x17, 0xB6, 0xCA, 0x61, 0xA8, 0xC2, 0x83, 0x3A, 0x19, 0xE0,
                0x00, 0xAA, 0xC2, 0xE4,
            ]),
            evidence_viewer_checkpoint_max_bytes: None,
            moderation_checkpoint_max_bytes: None,
            moderation_checkpoint_attestation_public_key: None,
            evidence_viewer_archive_id: None,
            evidence_viewer_archive_public_key: None,
            evidence_viewer_archive_max_bytes: None,
            moderation_panel_notification_archive_binding: None,
        }
    }

    fn connection(id: u8, failure: Option<BrokerConnectionFailure>) -> BrokerConnection {
        let (stream, _peer) = UnixStream::pair().expect("local stream pair");
        BrokerConnection {
            stream,
            session_id: [id; 32],
            next_request_id: 1,
            poison_reason: failure,
        }
    }

    fn session() -> BrokerSession {
        BrokerSession {
            decode_pool: Arc::new(DecodeResourcePoolV1::new(MAX_BROKER_SHARED_DECODE_BYTES_V1)),
            connection: Mutex::new(connection(1, None)),
            chain_id: "scoped-recovery-test".to_owned(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0x15; 32])
            )),
            endpoint: EndpointPolicy::for_test(PathBuf::from("unused-scoped-recovery.sock")),
            requested_catalog: vec![binding()],
        }
    }

    fn pending(session: &BrokerSession) -> BrokerPendingOperation {
        session
            .operation_scope(
                &binding(),
                [7; 32],
                OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1,
            )
            .expect("exact immutable binding")
    }

    fn failure(session: &BrokerSession) -> Option<BrokerConnectionFailure> {
        session
            .connection
            .lock()
            .expect("session lock")
            .poison_reason
    }

    #[test]
    fn ambiguity_is_scoped_to_exact_binding_metadata_and_operation() {
        let session = session();
        let pending = pending(&session);
        let mut foreign = binding();
        foreign.handle.push_str("-other");
        assert_eq!(
            session.operation_scope(&foreign, [7; 32], pending.operation),
            None
        );
        let altered_metadata = session
            .operation_scope(&binding(), [8; 32], pending.operation)
            .expect("same binding, distinct metadata");
        assert_ne!(pending, altered_metadata);
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Ambiguous(pending));
        for attempted in [
            None,
            Some(altered_metadata),
            Some(BrokerPendingOperation {
                catalog_index: 1,
                ..pending
            }),
            Some(BrokerPendingOperation {
                operation: OPERATION_SIGN_V1,
                ..pending
            }),
        ] {
            assert_eq!(
                session.reconnect_using(attempted, |_| panic!("must not handshake")),
                Err(BrokerError::Ambiguous)
            );
        }
        assert_eq!(
            session.reconnect_for_readback(&foreign, [7; 32]),
            Err(BrokerError::BindingMismatch)
        );
        let other_operation = BrokerPendingOperation {
            operation: OPERATION_SIGN_V1,
            ..pending
        };
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Ambiguous(other_operation));
        assert_eq!(
            session.reconnect_using(Some(other_operation), |_| panic!("not recoverable")),
            Err(BrokerError::Ambiguous)
        );
    }

    #[test]
    fn authenticated_reconnect_allows_only_readback_until_completion() {
        let session = session();
        let pending = pending(&session);
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Ambiguous(pending));
        assert_eq!(
            session.reconnect_using(Some(pending), |_| Ok(connection(2, None))),
            Ok(())
        );
        let gate = BrokerConnectionFailure::AwaitingReadback(pending);
        assert_eq!(failure(&session), Some(gate));
        assert_eq!(session.reconnect(), Err(BrokerError::Ambiguous));
        assert_eq!(
            session.reconnect_using(Some(pending), |_| panic!("already authenticated")),
            Ok(())
        );
        for operation in [
            OPERATION_QUALIFY_V1,
            OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1,
        ] {
            let read = BrokerPendingOperation {
                operation,
                ..pending
            };
            assert_eq!(gate.check_call(Some(read), false), Ok(()));
            assert_eq!(
                gate.check_call(Some(read), true),
                Err(BrokerError::Ambiguous)
            );
            assert_eq!(
                gate.check_call(
                    Some(BrokerPendingOperation {
                        catalog_index: 1,
                        ..read
                    }),
                    false
                ),
                Err(BrokerError::Ambiguous)
            );
            assert_eq!(
                gate.check_call(
                    Some(BrokerPendingOperation {
                        metadata_digest: [8; 32],
                        ..read
                    }),
                    false
                ),
                Err(BrokerError::Ambiguous)
            );
        }
        assert_eq!(
            gate.check_call(Some(pending), true),
            Err(BrokerError::Ambiguous)
        );
        assert_eq!(
            gate.check_call(Some(pending), false),
            Err(BrokerError::Ambiguous)
        );
        assert_eq!(gate.check_call(None, false), Err(BrokerError::Ambiguous));
        assert_eq!(
            session.complete_readback(&binding(), [8; 32], [2; 32]),
            Err(BrokerError::Ambiguous)
        );
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [1; 32]),
            Err(BrokerError::Ambiguous)
        );
        assert_eq!(failure(&session), Some(gate));
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [2; 32]),
            Ok(())
        );
        assert_eq!(failure(&session), None);
    }

    #[test]
    fn readback_deadline_preserves_the_pending_mutation_and_releases_decode_admission() {
        let session = session();
        let pending = pending(&session);
        let (stream, _peer) = UnixStream::pair().expect("local deadline exchange");
        {
            let mut current = session.connection.lock().unwrap();
            current.stream = stream;
            current.poison_reason = Some(BrokerConnectionFailure::AwaitingReadback(pending));
        }
        let payload = encode_sensitive_canonical(&(), MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)
            .expect("qualification payload");
        let result = session.exchange_before(
            &binding(),
            pending.metadata_digest,
            OPERATION_QUALIFY_V1,
            payload,
            false,
            BrokerDeadlineV1::new(Duration::from_millis(100)).unwrap(),
        );
        assert!(matches!(result, Err(BrokerError::Unavailable)));
        assert_eq!(
            failure(&session),
            Some(BrokerConnectionFailure::Ambiguous(pending))
        );
        assert_eq!(session.connection.lock().unwrap().next_request_id, 2);
        assert_eq!(session.decode_pool.allocation.reserved_bytes(), 0);
        assert_eq!(session.reconnect(), Err(BrokerError::Ambiguous));
    }

    #[test]
    fn repeated_mutation_calls_remain_sticky_scrubbed_and_never_write() {
        let session = session();
        let pending = pending(&session);
        let (stream, mut peer) = UnixStream::pair().expect("local stream pair");
        peer.set_nonblocking(true).expect("nonblocking observation");
        session.connection.lock().unwrap().stream = stream;
        for state in [
            BrokerConnectionFailure::Ambiguous(pending),
            BrokerConnectionFailure::AwaitingReadback(pending),
            BrokerConnectionFailure::Permanent(BrokerError::Ambiguous),
            BrokerConnectionFailure::Permanent(BrokerError::Protocol),
            BrokerConnectionFailure::Permanent(BrokerError::StaleOrRevoked),
        ] {
            session.connection.lock().unwrap().poison_reason = Some(state);
            for _ in 0..2 {
                let scrubbed = Arc::new(AtomicUsize::new(0));
                let result = session.call_sensitive(
                    &binding(),
                    pending.metadata_digest,
                    pending.operation,
                    ScrubbedBytes::with_drop_audit(vec![0xD1; 17], Arc::clone(&scrubbed)),
                    true,
                );
                assert_eq!(result.err(), Some(state.reason()));
                assert_eq!(scrubbed.load(Ordering::SeqCst), 17);
                assert_eq!(session.connection.lock().unwrap().next_request_id, 1);
                assert_eq!(failure(&session), Some(state));
            }
        }
        let mut byte = [0];
        assert_eq!(
            std::io::Read::read(&mut peer, &mut byte)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn delayed_readback_cannot_clear_newer_ambiguity_or_connection() {
        let session = session();
        let pending = pending(&session);
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Ambiguous(pending));
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [1; 32]),
            Err(BrokerError::Ambiguous)
        );
        assert_eq!(
            session.reconnect_using(Some(pending), |_| Ok(connection(3, None))),
            Ok(())
        );
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [2; 32]),
            Err(BrokerError::Ambiguous)
        );
        assert_eq!(
            failure(&session),
            Some(BrokerConnectionFailure::AwaitingReadback(pending))
        );
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [3; 32]),
            Ok(())
        );
        assert_eq!(failure(&session), None);
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [2; 32]),
            Err(BrokerError::Unavailable)
        );
        assert_eq!(
            failure(&session),
            None,
            "stale completion does not poison the healthy session"
        );
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [3; 32]),
            Ok(())
        );
    }

    #[test]
    fn transient_reconnect_failure_preserves_ambiguity_and_permanent_faults_latch() {
        for error in [
            BrokerError::Protocol,
            BrokerError::BindingMismatch,
            BrokerError::StaleOrRevoked,
        ] {
            let session = session();
            let pending = pending(&session);
            session.connection.lock().unwrap().poison_reason =
                Some(BrokerConnectionFailure::Ambiguous(pending));
            assert_eq!(
                session.reconnect_using(Some(pending), |_| Err(BrokerError::Unavailable)),
                Err(BrokerError::Unavailable)
            );
            assert_eq!(
                failure(&session),
                Some(BrokerConnectionFailure::Ambiguous(pending))
            );
            assert_eq!(
                session.reconnect_using(Some(pending), |_| Err(error)),
                Err(error)
            );
            assert_eq!(
                failure(&session),
                Some(BrokerConnectionFailure::Permanent(error))
            );
            session.poison_with_reason(BrokerError::Unavailable);
            assert_eq!(
                session.reconnect_using(Some(pending), |_| panic!("permanent fault")),
                Err(error)
            );
            assert_eq!(session.reconnect(), Err(error));
        }
    }

    #[test]
    fn decoded_fault_upgrades_ambiguity_without_transient_downgrade() {
        let session = session();
        let pending = pending(&session);
        for state in [
            BrokerConnectionFailure::Ambiguous(pending),
            BrokerConnectionFailure::AwaitingReadback(pending),
        ] {
            session.connection.lock().unwrap().poison_reason = Some(state);
            session.poison_with_reason(BrokerError::Unavailable);
            assert_eq!(failure(&session), Some(state));
            session.poison();
            assert_eq!(
                failure(&session),
                Some(BrokerConnectionFailure::Permanent(BrokerError::Protocol))
            );
            assert_eq!(
                session.complete_readback(&binding(), [7; 32], [1; 32]),
                Err(BrokerError::Protocol)
            );
        }
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Permanent(BrokerError::Ambiguous));
        assert_eq!(
            session.reconnect_using(Some(pending), |_| panic!(
                "bad mutation response is permanent"
            )),
            Err(BrokerError::Ambiguous)
        );
    }

    #[test]
    fn concurrent_reconnects_authenticate_once_and_preserve_request_progress() {
        let session = Arc::new(session());
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Unavailable);
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first = {
            let session = Arc::clone(&session);
            let calls = Arc::clone(&calls);
            std::thread::spawn(move || {
                session.reconnect_using(None, |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    let mut connection = connection(2, None);
                    connection.next_request_id = 19;
                    Ok(connection)
                })
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = {
            let session = Arc::clone(&session);
            let calls = Arc::clone(&calls);
            std::thread::spawn(move || {
                session.reconnect_using(None, |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(connection(3, None))
                })
            })
        };
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(()));
        assert_eq!(second.join().unwrap(), Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            session.reconnect_using(None, |_| panic!("healthy reconnect")),
            Ok(())
        );
        let current = session.connection.lock().unwrap();
        assert_eq!(current.session_id, [2; 32]);
        assert_eq!(current.next_request_id, 19);
    }

    #[test]
    fn permanent_fault_waiting_on_handshake_survives_reconnect() {
        let session = Arc::new(session());
        session.connection.lock().unwrap().poison_reason =
            Some(BrokerConnectionFailure::Unavailable);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let reconnect = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || {
                session.reconnect_using(None, |_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(connection(2, None))
                })
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let poison = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || session.poison_with_reason(BrokerError::StaleOrRevoked))
        };
        release_tx.send(()).unwrap();
        assert_eq!(reconnect.join().unwrap(), Ok(()));
        poison.join().unwrap();
        assert_eq!(
            failure(&session),
            Some(BrokerConnectionFailure::Permanent(
                BrokerError::StaleOrRevoked
            ))
        );
        assert_eq!(
            session.reconnect_using(None, |_| panic!("revocation must survive")),
            Err(BrokerError::StaleOrRevoked)
        );
    }
    fn publication_body()
    -> sorafs_node::evidence_viewer::transparency_producer::EvidenceViewerTransparencyHeadBodyV1
    {
        use sorafs_node::evidence_viewer::{self as viewer, transparency_producer as transparency};
        let binding = binding();
        let key = binding
            .evidence_viewer_transparency_publisher_public_key
            .expect("publisher key");
        transparency::EvidenceViewerTransparencyHeadBodyV1 {
            version: transparency::EVIDENCE_VIEWER_TRANSPARENCY_HEAD_VERSION_V1,
            generation: 1,
            predecessor_head_digest: None,
            operation_id: [0x81; 32],
            source_checkpoint_anchor: viewer::EvidenceViewerSignedCheckpointAnchorV1 {
                version: viewer::EVIDENCE_VIEWER_CHECKPOINT_VERSION_V1,
                checkpoint_generation: 1,
                predecessor_checkpoint_revision: None,
                predecessor_checkpoint_digest: None,
                checkpoint_digest: [0x82; 32],
                receipt_count: 0,
                chain_head: None,
                compaction_archive_head_digest: None,
                checkpoint_store_handle: "sealed://sorafs/evidence-viewer/checkpoint-primary"
                    .to_owned(),
                checkpoint_store_revision: 9,
                checkpoint_store_policy_digest: [0x83; 32],
                signer_handle: "software://sorafs/evidence-viewer/primary".to_owned(),
                signer_public_key: key,
                signature: [0x84; 64],
            },
            source_compaction_archive_head: None,
            source_predecessor: None,
            source_page_limit: 256,
            source_has_more: false,
            receipt_cursor: None,
            source_projection_digest: [0x85; 32],
            publisher_handle: binding.handle.clone(),
            publisher_revision: binding.revision.expect("revision"),
            publisher_policy_digest: binding.policy_digest.expect("policy"),
            publisher_public_key: key,
        }
    }

    fn exchange_with_response_length(
        mutating: bool,
        response_length: Option<u32>,
    ) -> (BrokerSession, BrokerError, Option<UnixStream>, usize) {
        use std::io::{Read as _, Write as _};
        let session = session();
        let binding = binding();
        validate_wire_binding(&binding).expect("valid publisher binding");
        let operation = if mutating {
            OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1
        } else {
            OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
        };
        let limit = operation_frame_limit(operation);
        let (stream, mut peer) = UnixStream::pair().expect("local exchange pair");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        session.connection.lock().unwrap().stream = stream;
        let seen = Arc::new(AtomicUsize::new(0));
        let server = {
            let seen = Arc::clone(&seen);
            let binding = binding.clone();
            let network_id = session.network_id;
            std::thread::spawn(move || {
                let mut discriminator = [0; 4];
                peer.read_exact(&mut discriminator)
                    .expect("request discriminator");
                assert_eq!(
                    u16::from_be_bytes(discriminator[..2].try_into().unwrap()),
                    binding.slot
                );
                assert_eq!(
                    u16::from_be_bytes(discriminator[2..].try_into().unwrap()),
                    operation
                );
                let bytes = read_length_prefixed(&mut peer, limit).expect("bounded request frame");
                // This peer models the separate broker process, with its own
                // unchanged operation admission ceiling, not the client's pool.
                let policy = operation_decode_policy(operation);
                let admission = DecodeResourceAdmissionV1::acquire_operation_from(
                    Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes)),
                    operation,
                )
                .expect("peer process admission");
                admission
                    .reserve_raw_frame(bytes.len(), limit)
                    .expect("peer raw frame");
                let _scope = admission.enter();
                let request = decode_frame::<OperationRequestV1>(
                    &bytes,
                    FRAME_KIND_OPERATION_REQUEST_V1,
                    limit,
                )
                .expect("canonical request");
                assert_eq!(request.binding, binding);
                assert_eq!(request.session_id, [1; 32]);
                assert_eq!(request.request_id, 1);
                validate_operation_request_for_session(
                    &request,
                    "scoped-recovery-test",
                    &network_id,
                )
                .expect("actual request passes canonical operation validation");
                seen.fetch_add(1, Ordering::SeqCst);
                // None drops the peer here: actual EOF after one received request.
                response_length.map(|length| {
                    peer.write_all(&length.to_be_bytes())
                        .expect("declared response length");
                    peer.flush().unwrap();
                    peer
                })
            })
        };
        let payload = if mutating {
            encode_sensitive_canonical(&publication_body(), MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1)
        } else {
            encode_sensitive_canonical(&(), MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)
        }
        .expect("valid request payload");
        let error = session
            .exchange(&binding, [7; 32], operation, payload, mutating)
            .expect_err("peer response fails");
        let peer = server.join().expect("response peer");
        let seen = seen.load(Ordering::SeqCst);
        (session, error, peer, seen)
    }

    #[test]
    fn malformed_response_lengths_permanently_block_exchange_and_replay() {
        for mutating in [false, true] {
            let operation = if mutating {
                OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1
            } else {
                OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
            };
            let oversized = u32::try_from(operation_frame_limit(operation) + 1).unwrap();
            for declared in [0, oversized] {
                let (session, error, peer, seen) =
                    exchange_with_response_length(mutating, Some(declared));
                let expected = if mutating {
                    BrokerError::Ambiguous
                } else {
                    BrokerError::Protocol
                };
                assert_eq!(error, expected);
                assert_eq!(seen, 1, "one actual canonical request reached the peer");
                assert_eq!(
                    failure(&session),
                    Some(BrokerConnectionFailure::Permanent(expected))
                );
                assert_eq!(session.reconnect(), Err(expected));
                assert_eq!(
                    session.reconnect_for_readback(&binding(), [7; 32]),
                    Err(expected)
                );
                for _ in 0..2 {
                    assert_eq!(
                        session
                            .exchange(
                                &binding(),
                                [7; 32],
                                operation,
                                ScrubbedBytes::new(vec![1]),
                                mutating
                            )
                            .err(),
                        Some(expected)
                    );
                }
                assert_eq!(session.connection.lock().unwrap().next_request_id, 2);
                let mut peer = peer.expect("peer remains open for no-replay observation");
                peer.set_nonblocking(true).unwrap();
                assert_eq!(
                    std::io::Read::read(&mut peer, &mut [0]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }
    }

    #[test]
    fn actual_transport_eof_retains_the_scoped_readback_path() {
        let (session, error, peer, seen) = exchange_with_response_length(true, None);
        let pending = pending(&session);
        assert_eq!(error, BrokerError::Ambiguous);
        assert!(peer.is_none());
        assert_eq!(seen, 1);
        assert_eq!(
            failure(&session),
            Some(BrokerConnectionFailure::Ambiguous(pending))
        );
        assert_eq!(session.reconnect(), Err(BrokerError::Ambiguous));
        assert_eq!(
            session.reconnect_using(Some(pending), |_| Ok(connection(2, None))),
            Ok(())
        );
        assert_eq!(
            failure(&session),
            Some(BrokerConnectionFailure::AwaitingReadback(pending))
        );
        assert_eq!(
            session.complete_readback(&binding(), [7; 32], [1; 32]),
            Err(BrokerError::Ambiguous)
        );
    }
}
