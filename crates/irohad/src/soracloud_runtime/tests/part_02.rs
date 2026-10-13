fn canonical_inrou_test_archive(files: &[(&str, u32, &[u8])]) -> Result<Vec<u8>> {
    let files = files
        .iter()
        .map(|(path, mode, payload)| BundleArchiveFile::new(path, *mode, payload))
        .collect::<Vec<_>>();
    Ok(write_gzip_ustar(Vec::new(), &files)?)
}
fn canonical_inrou_test_archive_limits() -> BundleArchiveLimits {
    BundleArchiveLimits {
        max_compressed_bytes: 1 << 20,
        max_decoded_bytes: 1 << 20,
        max_entries: 64,
        max_file_bytes: 1 << 20,
        max_total_file_bytes: 1 << 20,
    }
}
fn assert_no_inrou_transaction_paths(parent: &Path, root_name: &str) -> Result<()> {
    let prefix = format!(".{root_name}.inrou-");
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        assert!(
            !entry.file_name().to_string_lossy().starts_with(&prefix),
            "Inrou transaction path remained after completion: {}",
            entry.path().display()
        );
    }
    Ok(())
}
fn create_inrou_application_bundle_archive_for_linux_test() -> Result<Vec<u8>> {
    let files = [
        BundleArchiveFile::new("bin/sh", 0o755, b"#!/bin/sh\nexec /bin/sh \"$@\"\n"),
        BundleArchiveFile::new(
            "app/inrou-health.py",
            0o755,
            INROU_HEALTH_SERVER_PY.as_bytes(),
        ),
    ];
    Ok(write_gzip_ustar(Vec::new(), &files)?)
}
#[derive(Clone, Debug)]
struct PortableInrouGuestImageSourceFile {
    logical_path: Vec<String>,
    source_path: PathBuf,
    size: u64,
}
struct PortableInrouGuestImageReader {
    readers: Vec<io::Take<BufReader<fs::File>>>,
    current: usize,
}
impl PortableInrouGuestImageReader {
    fn open(sources: &[PortableInrouGuestImageSourceFile]) -> Result<Self> {
        let mut readers = Vec::with_capacity(sources.len());
        for source in sources {
            let file = fs::File::open(&source.source_path).wrap_err_with(|| {
                format!(
                    "open portable Inrou guest image {}",
                    source.source_path.display()
                )
            })?;
            let metadata = file.metadata().wrap_err_with(|| {
                format!(
                    "inspect portable Inrou guest image {}",
                    source.source_path.display()
                )
            })?;
            if !metadata.is_file() || metadata.len() != source.size {
                eyre::bail!(
                    "portable Inrou guest image {} changed before authenticated streaming",
                    source.source_path.display()
                );
            }
            readers.push(BufReader::new(file).take(source.size));
        }
        Ok(Self {
            readers,
            current: 0,
        })
    }
    fn ensure_exhausted(&mut self) -> Result<()> {
        let mut extra = [0_u8; 1];
        if self.read(&mut extra)? != 0 {
            eyre::bail!("portable Inrou guest-image stream exceeded its authenticated plan");
        }
        Ok(())
    }
}
impl Read for PortableInrouGuestImageReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while let Some(reader) = self.readers.get_mut(self.current) {
            let read = reader.read(buffer)?;
            if read != 0 {
                return Ok(read);
            }
            if reader.limit() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "portable Inrou guest image was truncated while streaming",
                ));
            }
            self.current += 1;
        }
        Ok(0)
    }
}
fn portable_inrou_guest_image_sources(
    guest_isa: SoraInrouGuestIsaV1,
    kernel_image: &Path,
    rootfs_image: &Path,
    initrd_image: Option<&Path>,
) -> Result<Vec<PortableInrouGuestImageSourceFile>> {
    let isa = guest_isa.as_str().to_owned();
    let mut paths = vec![("vmlinux", kernel_image), ("rootfs.ext4", rootfs_image)];
    if let Some(initrd_image) = initrd_image {
        paths.push(("initrd.img", initrd_image));
    }
    let mut sources = paths
        .into_iter()
        .map(|(member, source_path)| {
            let metadata = fs::metadata(source_path).wrap_err_with(|| {
                format!(
                    "inspect portable Inrou guest image {}",
                    source_path.display()
                )
            })?;
            if !metadata.is_file() || metadata.len() == 0 {
                eyre::bail!(
                    "portable Inrou guest image {} must be a nonempty regular file",
                    source_path.display()
                );
            }
            Ok(PortableInrouGuestImageSourceFile {
                logical_path: vec![isa.clone(), member.to_owned()],
                source_path: source_path.to_path_buf(),
                size: metadata.len(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    sources.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok(sources)
}
fn append_portable_inrou_plan_chunk(
    chunks: &mut Vec<CarChunk>,
    global_offset: u64,
    boundary_offset: usize,
    bytes: &[u8],
) -> Result<()> {
    if chunks.len() >= CAR_PLAN_MAX_CHUNKS {
        eyre::bail!("portable Inrou guest image exceeds the SoraFS chunk limit");
    }
    chunks.push(CarChunk {
        offset: global_offset
            .checked_add(u64::try_from(boundary_offset)?)
            .ok_or_else(|| eyre::eyre!("portable Inrou chunk offset overflow"))?,
        length: u32::try_from(bytes.len())?,
        digest: blake3::hash(bytes).into(),
    });
    Ok(())
}
fn build_portable_inrou_guest_image_plan(
    sources: &[PortableInrouGuestImageSourceFile],
) -> Result<CarBuildPlan> {
    const STREAM_BUFFER_BYTES: usize = 1 << 20;
    let profile = ChunkProfile::DEFAULT;
    let mut chunks = Vec::new();
    let mut files = Vec::with_capacity(sources.len());
    let mut payload_hasher = blake3::Hasher::new();
    let mut global_offset = 0_u64;
    let mut read_buffer = vec![0_u8; STREAM_BUFFER_BYTES];
    for source in sources {
        let first_chunk = chunks.len();
        let mut reader = BufReader::new(fs::File::open(&source.source_path)?);
        let mut local_offset = 0_u64;
        let mut emitted_offset = 0_usize;
        let mut pending = Vec::with_capacity(STREAM_BUFFER_BYTES + profile.max_size);
        let mut chunker = Chunker::try_with_profile(profile)?;
        while local_offset < source.size {
            let count = usize::try_from(
                (source.size - local_offset)
                    .min(u64::try_from(read_buffer.len()).expect("buffer length fits u64")),
            )?;
            reader.read_exact(&mut read_buffer[..count])?;
            payload_hasher.update(&read_buffer[..count]);
            pending.extend_from_slice(&read_buffer[..count]);
            let mut boundaries = Vec::new();
            chunker.feed(&read_buffer[..count], |boundary| boundaries.push(boundary));
            let mut consumed = 0_usize;
            for boundary in boundaries {
                if boundary.offset != emitted_offset {
                    eyre::bail!("portable Inrou streaming chunk geometry is not contiguous");
                }
                let end = consumed
                    .checked_add(boundary.length)
                    .ok_or_else(|| eyre::eyre!("portable Inrou chunk length overflow"))?;
                let bytes = pending.get(consumed..end).ok_or_else(|| {
                    eyre::eyre!("portable Inrou chunk exceeded its bounded streaming buffer")
                })?;
                append_portable_inrou_plan_chunk(
                    &mut chunks,
                    global_offset,
                    boundary.offset,
                    bytes,
                )?;
                emitted_offset = emitted_offset
                    .checked_add(boundary.length)
                    .ok_or_else(|| eyre::eyre!("portable Inrou emitted offset overflow"))?;
                consumed = end;
            }
            if consumed != 0 {
                pending.drain(..consumed);
            }
            local_offset = local_offset
                .checked_add(u64::try_from(count)?)
                .ok_or_else(|| eyre::eyre!("portable Inrou local offset overflow"))?;
        }
        let mut boundaries = Vec::new();
        chunker.finish(|boundary| boundaries.push(boundary));
        for boundary in boundaries {
            if boundary.offset != emitted_offset || pending.len() != boundary.length {
                eyre::bail!("portable Inrou final chunk geometry is not canonical");
            }
            append_portable_inrou_plan_chunk(
                &mut chunks,
                global_offset,
                boundary.offset,
                &pending,
            )?;
            emitted_offset = emitted_offset
                .checked_add(boundary.length)
                .ok_or_else(|| eyre::eyre!("portable Inrou emitted offset overflow"))?;
            pending.clear();
        }
        if u64::try_from(emitted_offset)? != source.size || !pending.is_empty() {
            eyre::bail!("portable Inrou streaming plan did not cover one image exactly");
        }
        let mut extra = [0_u8; 1];
        if reader.read(&mut extra)? != 0 {
            eyre::bail!(
                "portable Inrou guest image {} grew while its plan was built",
                source.source_path.display()
            );
        }
        files.push(FilePlan {
            path: source.logical_path.clone(),
            first_chunk,
            chunk_count: chunks.len() - first_chunk,
            size: source.size,
        });
        global_offset = global_offset
            .checked_add(source.size)
            .ok_or_else(|| eyre::eyre!("portable Inrou payload length overflow"))?;
    }
    let plan = CarBuildPlan {
        chunk_profile: profile,
        payload_digest: payload_hasher.finalize(),
        content_length: global_offset,
        chunks,
        files,
    };
    plan.validate()?;
    Ok(plan)
}
fn build_portable_inrou_guest_image_manifest(
    plan: &CarBuildPlan,
    sources: &[PortableInrouGuestImageSourceFile],
) -> Result<sorafs_manifest::ManifestV1> {
    let mut car_source = PortableInrouGuestImageReader::open(sources)?;
    let car_stats = CarStreamingWriter::new(plan).write_from_reader(&mut car_source, io::sink())?;
    car_source.ensure_exhausted()?;
    if car_stats.root_cids.len() != 1 {
        eyre::bail!(
            "portable Inrou directory CAR must produce exactly one root CID, got {}",
            car_stats.root_cids.len()
        );
    }
    let root_cid = car_stats.root_cids[0].clone();
    let mut por_source = PortableInrouGuestImageReader::open(sources)?;
    let mut chunk_store = ChunkStore::with_profile(plan.chunk_profile);
    chunk_store.ingest_plan_stream(plan, &mut por_source)?;
    por_source.ensure_exhausted()?;
    Ok(ManifestBuilder::new()
        .root_cid(root_cid)
        .dag_codec(DagCodecId(car_stats.dag_codec))
        .chunking_from_profile(plan.chunk_profile, BLAKE3_256_MULTIHASH_CODE)
        .chunk_digest_sha3_256(compute_chunk_plan_digest_sha3(&plan.chunks))
        .por_root(*chunk_store.por_tree().root())
        .content_length(plan.content_length)
        .car_digest(*car_stats.car_archive_digest.as_bytes())
        .car_size(car_stats.car_size)
        .pin_policy(ManifestPinPolicy {
            min_replicas: 1,
            storage_class: sorafs_manifest::StorageClass::Warm,
            retention_epoch: u64::MAX,
        })
        .build()?)
}
fn create_portable_inrou_operator_preseed_artifact(
    temp_dir: &tempfile::TempDir,
    guest_isa: SoraInrouGuestIsaV1,
    kernel_image: &Path,
    rootfs_image: &Path,
    initrd_image: Option<&Path>,
) -> Result<(Arc<StorageBackend>, SoraPublishedInrouGuestImageArtifactV1)> {
    let sources =
        portable_inrou_guest_image_sources(guest_isa, kernel_image, rootfs_image, initrd_image)?;
    let plan = build_portable_inrou_guest_image_plan(&sources)?;
    let manifest = build_portable_inrou_guest_image_manifest(&plan, &sources)?;
    let store = test_operator_preseed_store(temp_dir);
    let mut payload = PortableInrouGuestImageReader::open(&sources)?;
    let manifest_id = store.ingest_manifest(&manifest, &plan, &mut payload)?;
    payload.ensure_exhausted()?;
    let stored = store
        .manifest(&manifest_id)
        .ok_or_else(|| eyre::eyre!("portable Inrou preseed manifest disappeared"))?;
    let artifact = SoraPublishedInrouGuestImageArtifactV1 {
        manifest_digest_hex: hex::encode(stored.manifest_digest()),
        content_cid: encode_content_cid(stored.manifest_cid()),
    };
    Ok((store, artifact))
}
fn portable_smoke_required_env_path(name: &str) -> Result<PathBuf> {
    let value = std::env::var(name)
        .wrap_err_with(|| format!("missing required environment variable `{name}`"))?;
    let path = PathBuf::from(value);
    if !path.is_file() {
        eyre::bail!(
            "environment variable `{name}` must point to an existing file, got {}",
            path.display()
        );
    }
    Ok(path)
}
#[derive(Clone)]
struct RemoteManifestFixture {
    manifest_digest: ManifestDigest,
    manifest_root_cid: ManifestRootCid,
    chunk_digest_sha3_256: [u8; 32],
    por_root: [u8; 32],
    order_id: ReplicationOrderId,
    provider_id: [u8; 32],
    issued_epoch: u64,
    pin_policy: PinPolicy,
    canonical_order: Vec<u8>,
    manifest_id_hex: String,
    manifest_response_body: Vec<u8>,
    plan_response_body: Vec<u8>,
    chunk_path: String,
    payload: Vec<u8>,
}
#[derive(Clone)]
struct HttpFixtureResponse {
    status_code: u16,
    content_type: &'static str,
    body: Vec<u8>,
    content_length_override: Option<u64>,
    extra_headers: Vec<(String, String)>,
}
impl HttpFixtureResponse {
    fn json(body: Vec<u8>) -> Self {
        Self {
            status_code: 200,
            content_type: "application/json",
            body,
            content_length_override: None,
            extra_headers: Vec::new(),
        }
    }
    fn binary(body: Vec<u8>) -> Self {
        Self {
            status_code: 200,
            content_type: "application/octet-stream",
            body,
            content_length_override: None,
            extra_headers: Vec::new(),
        }
    }
    fn not_found() -> Self {
        Self {
            status_code: 404,
            content_type: "text/plain; charset=utf-8",
            body: b"not found".to_vec(),
            content_length_override: None,
            extra_headers: Vec::new(),
        }
    }
}
struct HttpRouteFixture {
    base_url: String,
    stop_tx: mpsc::Sender<()>,
    handle: Option<std::thread::JoinHandle<()>>,
}
impl Drop for HttpRouteFixture {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
fn fixed_chunker_handle() -> ChunkerProfileHandle {
    ChunkerProfileHandle {
        profile_id: 1,
        namespace: "sorafs".to_owned(),
        name: "sf1".to_owned(),
        semver: "1.0.0".to_owned(),
        multihash_code: BLAKE3_256_MULTIHASH_CODE,
    }
}
fn build_remote_manifest_fixture(
    payload: &[u8],
    provider_id: [u8; 32],
    order_seed: u8,
) -> Result<RemoteManifestFixture> {
    let (car_plan, manifest) = build_sorafs_manifest(payload)?;
    if car_plan.chunks.len() != 1 {
        eyre::bail!("remote hydration fixture payload must produce exactly one chunk");
    }
    let manifest_digest = ManifestDigest::from_manifest(&manifest)?;
    let manifest_root_cid = ManifestRootCid::try_from_slice(&manifest.root_cid)?;
    let manifest_id_hex = hex::encode(&manifest.root_cid);
    let chunk_profile_handle = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    let chunk_digest_hex = hex::encode(car_plan.chunks[0].digest);
    let stored_files = car_plan
        .files
        .iter()
        .map(|file| StorageStoredFileDto {
            path: file.path.clone(),
            offset: car_plan
                .chunks
                .get(file.first_chunk)
                .map_or(car_plan.content_length, |chunk| chunk.offset),
            size: file.size,
            first_chunk: u64::try_from(file.first_chunk).unwrap_or(u64::MAX),
            chunk_count: u64::try_from(file.chunk_count).unwrap_or(u64::MAX),
        })
        .collect::<Vec<_>>();
    let manifest_response = StorageManifestResponseDto {
        manifest_id_hex: manifest_id_hex.clone(),
        manifest_b64: sorafs_manifest::encode_manifest_v1_base64_canonical(&manifest)?,
        manifest_digest_hex: hex::encode(manifest_digest.as_bytes()),
        payload_digest_hex: hex::encode(car_plan.payload_digest.as_bytes()),
        content_length: car_plan.content_length,
        chunk_count: u64::try_from(car_plan.chunks.len()).unwrap_or(u64::MAX),
        chunk_profile_handle: chunk_profile_handle.clone(),
        stored_at_unix_secs: 1,
        files: stored_files,
    };
    let manifest_response_body = norito::json::to_vec(&manifest_response)?;
    let mut chunk_entry = norito::json::native::Map::new();
    chunk_entry.insert("chunk_index".into(), norito::json::Value::from(0_u64));
    chunk_entry.insert("offset".into(), norito::json::Value::from(0_u64));
    chunk_entry.insert(
        "length".into(),
        norito::json::Value::from(u64::from(car_plan.chunks[0].length)),
    );
    chunk_entry.insert(
        "digest_blake3".into(),
        norito::json::Value::from(chunk_digest_hex.clone()),
    );
    let mut plan = norito::json::native::Map::new();
    plan.insert(
        "chunk_count".into(),
        norito::json::Value::from(u64::try_from(car_plan.chunks.len()).unwrap_or(u64::MAX)),
    );
    plan.insert(
        "returned_chunk_count".into(),
        norito::json::Value::from(u64::try_from(car_plan.chunks.len()).unwrap_or(u64::MAX)),
    );
    plan.insert(
        "content_length".into(),
        norito::json::Value::from(car_plan.content_length),
    );
    plan.insert(
        "payload_digest_blake3".into(),
        norito::json::Value::from(hex::encode(car_plan.payload_digest.as_bytes())),
    );
    plan.insert(
        "chunk_profile_handle".into(),
        norito::json::Value::from(chunk_profile_handle),
    );
    plan.insert(
        "chunk_digest_count".into(),
        norito::json::Value::from(u64::try_from(car_plan.chunks.len()).unwrap_or(u64::MAX)),
    );
    plan.insert(
        "returned_chunk_digest_count".into(),
        norito::json::Value::from(u64::try_from(car_plan.chunks.len()).unwrap_or(u64::MAX)),
    );
    plan.insert(
        "chunk_digests_blake3".into(),
        norito::json::Value::Array(vec![norito::json::Value::from(chunk_digest_hex.clone())]),
    );
    plan.insert(
        "chunks".into(),
        norito::json::Value::Array(vec![norito::json::Value::Object(chunk_entry)]),
    );
    let files = car_plan
        .files
        .iter()
        .map(|file| {
            let mut entry = norito::json::native::Map::new();
            entry.insert(
                "path".into(),
                norito::json::Value::Array(
                    file.path
                        .iter()
                        .cloned()
                        .map(norito::json::Value::from)
                        .collect(),
                ),
            );
            entry.insert(
                "offset".into(),
                norito::json::Value::from(
                    car_plan
                        .chunks
                        .get(file.first_chunk)
                        .map_or(car_plan.content_length, |chunk| chunk.offset),
                ),
            );
            entry.insert("size".into(), norito::json::Value::from(file.size));
            entry.insert(
                "first_chunk".into(),
                norito::json::Value::from(u64::try_from(file.first_chunk).unwrap_or(u64::MAX)),
            );
            entry.insert(
                "chunk_count".into(),
                norito::json::Value::from(u64::try_from(file.chunk_count).unwrap_or(u64::MAX)),
            );
            norito::json::Value::Object(entry)
        })
        .collect::<Vec<_>>();
    plan.insert(
        "file_count".into(),
        norito::json::Value::from(u64::try_from(files.len()).unwrap_or(u64::MAX)),
    );
    plan.insert(
        "returned_file_count".into(),
        norito::json::Value::from(u64::try_from(files.len()).unwrap_or(u64::MAX)),
    );
    plan.insert("files".into(), norito::json::Value::Array(files));
    plan.insert("offset".into(), norito::json::Value::from(0_u64));
    plan.insert(
        "limit".into(),
        norito::json::Value::from(
            u64::try_from(SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT).unwrap_or(u64::MAX),
        ),
    );
    plan.insert("truncated_chunks".into(), norito::json::Value::from(false));
    plan.insert(
        "truncated_chunk_digests".into(),
        norito::json::Value::from(false),
    );
    plan.insert("truncated_files".into(), norito::json::Value::from(false));
    let mut plan_response = norito::json::native::Map::new();
    plan_response.insert(
        "manifest_id_hex".into(),
        norito::json::Value::from(manifest_id_hex.clone()),
    );
    plan_response.insert("plan".into(), norito::json::Value::Object(plan));
    let plan_response_body = norito::json::to_vec(&norito::json::Value::Object(plan_response))?;
    let order_id = ReplicationOrderId::new([order_seed; 32]);
    let canonical_order = norito::to_bytes(&ReplicationOrderV1 {
        version: sorafs_manifest::capacity::REPLICATION_ORDER_VERSION_V1,
        order_id: *order_id.as_bytes(),
        manifest_cid: manifest.root_cid.clone(),
        manifest_digest: *manifest_digest.as_bytes(),
        chunking_profile: fixed_chunker_handle().to_handle(),
        target_replicas: 1,
        assignments: vec![sorafs_manifest::capacity::ReplicationAssignmentV1 {
            provider_id,
            slice_gib: 1,
            lane: None,
        }],
        issued_at: u64::from(order_seed),
        deadline_at: u64::from(order_seed) + 600,
        sla: sorafs_manifest::capacity::ReplicationOrderSlaV1 {
            ingest_deadline_secs: 600,
            min_availability_percent_milli: 99_000,
            min_por_success_percent_milli: 98_000,
        },
        metadata: Vec::new(),
    })?;
    Ok(RemoteManifestFixture {
        manifest_digest,
        manifest_root_cid,
        chunk_digest_sha3_256: manifest.chunk_digest_sha3_256,
        por_root: manifest.por_root,
        order_id,
        provider_id,
        issued_epoch: u64::from(order_seed),
        pin_policy: PinPolicy {
            min_replicas: manifest.pin_policy.min_replicas,
            storage_class: match manifest.pin_policy.storage_class {
                sorafs_manifest::StorageClass::Hot => {
                    iroha_data_model::sorafs::pin_registry::StorageClass::Hot
                }
                sorafs_manifest::StorageClass::Warm => {
                    iroha_data_model::sorafs::pin_registry::StorageClass::Warm
                }
                sorafs_manifest::StorageClass::Cold => {
                    iroha_data_model::sorafs::pin_registry::StorageClass::Cold
                }
            },
            retention_epoch: manifest.pin_policy.retention_epoch,
        },
        canonical_order,
        manifest_id_hex: manifest_id_hex.clone(),
        manifest_response_body,
        plan_response_body,
        chunk_path: format!("/v1/sorafs/storage/chunk/{manifest_id_hex}/{chunk_digest_hex}"),
        payload: payload.to_vec(),
    })
}
fn remote_hydration_source_for_fixture(fixture: &RemoteManifestFixture) -> RemoteHydrationSource {
    RemoteHydrationSource {
        manifest_digest_hex: hex::encode(fixture.manifest_digest.as_bytes()),
        manifest_cid_hex: fixture.manifest_id_hex.clone(),
        chunker_handle: Some(fixed_chunker_handle().to_handle()),
        provider_ids: vec![fixture.provider_id],
    }
}
fn remote_manifest_response_for_fixture(
    fixture: &RemoteManifestFixture,
) -> Result<StorageManifestResponseDto> {
    Ok(norito::json::from_slice(&fixture.manifest_response_body)?)
}
fn verified_remote_hydration_fixture(
    fixture: &RemoteManifestFixture,
) -> Result<(VerifiedRemoteManifest, RemoteHydrationPlan)> {
    let source = remote_hydration_source_for_fixture(fixture);
    let manifest = validate_remote_manifest_response(
        &source,
        remote_manifest_response_for_fixture(fixture)?,
        u64::try_from(fixture.payload.len())?,
    )?;
    let page = parse_remote_hydration_plan_page(
        &fixture.manifest_id_hex,
        &fixture.plan_response_body,
        16,
    )?;
    let plan = RemoteHydrationPlan {
        manifest_id_hex: fixture.manifest_id_hex.clone(),
        chunker_handle: page.chunker_handle,
        content_length: page.content_length,
        payload_digest: page.payload_digest,
        chunks: page.chunks,
        files: page.files,
    };
    Ok((manifest, plan))
}
fn mutate_remote_plan_fixture(
    fixture: &RemoteManifestFixture,
    mutate: impl FnOnce(&mut norito::json::native::Map),
) -> Result<Vec<u8>> {
    let mut value: norito::json::Value = norito::json::from_slice(&fixture.plan_response_body)?;
    let plan = value
        .as_object_mut()
        .and_then(|root| root.get_mut("plan"))
        .and_then(norito::json::Value::as_object_mut)
        .ok_or_else(|| eyre::eyre!("fixture plan response must contain a plan object"))?;
    mutate(plan);
    Ok(norito::json::to_vec(&value)?)
}
fn hydrated_file(path: &[&str], offset: u64, size: u64) -> SorafsHydratedFileLayout {
    SorafsHydratedFileLayout {
        path: path
            .iter()
            .map(|component| (*component).to_owned())
            .collect(),
        offset,
        size,
    }
}
fn assert_report_contains(error: &eyre::Report, expected: &str) {
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(expected),
        "expected error containing `{expected}`, got `{rendered}`"
    );
}
#[test]
fn remote_hydration_hex_32_accepts_only_canonical_lowercase() {
    let canonical = "ab".repeat(32);
    assert_eq!(
        parse_canonical_remote_hex_32(&canonical, "fixture digest").expect("canonical digest"),
        [0xAB; 32]
    );
    for invalid in [
        canonical.to_ascii_uppercase(),
        "ab".repeat(31),
        "ab".repeat(33),
        "gg".repeat(32),
    ] {
        assert!(
            parse_canonical_remote_hex_32(&invalid, "fixture digest").is_err(),
            "invalid digest spelling was accepted: {invalid}"
        );
    }
}
#[test]
fn remote_hydration_manifest_response_rejects_substituted_commitments() -> Result<()> {
    let fixture = build_remote_manifest_fixture(b"manifest-response-binding", [0x31; 32], 31)?;
    let source = remote_hydration_source_for_fixture(&fixture);
    let exact_response = remote_manifest_response_for_fixture(&fixture)?;
    let exact_budget = exact_response.content_length;
    validate_remote_manifest_response(&source, exact_response, exact_budget)?;
    let bounded_response = remote_manifest_response_for_fixture(&fixture)?;
    let undersized_budget = exact_budget
        .checked_sub(1)
        .expect("fixture manifest content is nonempty");
    assert_report_contains(
        &validate_remote_manifest_response(&source, bounded_response, undersized_budget)
            .expect_err("remote manifest beyond the configured hydration budget must fail"),
        "content length is zero, inconsistent, or exceeds",
    );
    let mut noncanonical_base64 = remote_manifest_response_for_fixture(&fixture)?;
    noncanonical_base64.manifest_b64.push('\n');
    assert_report_contains(
        &validate_remote_manifest_response(&source, noncanonical_base64, 1_024)
            .expect_err("noncanonical manifest base64 must fail"),
        "decode exact canonical remote manifest payload",
    );
    let mut substituted_root = remote_manifest_response_for_fixture(&fixture)?;
    let mut manifest =
        sorafs_manifest::decode_manifest_v1_base64_canonical(&substituted_root.manifest_b64)?;
    manifest.root_cid[4] ^= 0x01;
    substituted_root.manifest_b64 =
        sorafs_manifest::encode_manifest_v1_base64_canonical(&manifest)?;
    assert_report_contains(
        &validate_remote_manifest_response(&source, substituted_root, 1_024)
            .expect_err("substituted manifest root must fail"),
        "root CID does not match committed ledger state",
    );
    let mut substituted_digest = remote_manifest_response_for_fixture(&fixture)?;
    substituted_digest.manifest_digest_hex = "11".repeat(32);
    assert_report_contains(
        &validate_remote_manifest_response(&source, substituted_digest, 1_024)
            .expect_err("substituted manifest digest must fail"),
        "manifest digest does not match committed ledger state",
    );
    let mut substituted_content_length = remote_manifest_response_for_fixture(&fixture)?;
    substituted_content_length.content_length =
        substituted_content_length.content_length.saturating_add(1);
    assert_report_contains(
        &validate_remote_manifest_response(&source, substituted_content_length, 1_024)
            .expect_err("substituted manifest content length must fail"),
        "content length is zero, inconsistent, or exceeds",
    );
    let mut substituted_profile = remote_manifest_response_for_fixture(&fixture)?;
    substituted_profile
        .chunk_profile_handle
        .push_str(".substituted");
    assert_report_contains(
        &validate_remote_manifest_response(&source, substituted_profile, 1_024)
            .expect_err("substituted manifest profile must fail"),
        "chunk profile does not match",
    );
    Ok(())
}
#[test]
fn remote_hydration_plan_page_rejects_inconsistent_counts_flags_indices_and_digests() -> Result<()>
{
    let fixture = build_remote_manifest_fixture(b"plan-page-binding", [0x32; 32], 32)?;
    parse_remote_hydration_plan_page(&fixture.manifest_id_hex, &fixture.plan_response_body, 16)?;
    let inconsistent_count = mutate_remote_plan_fixture(&fixture, |plan| {
        plan.insert(
            "returned_chunk_count".into(),
            norito::json::Value::from(0_u64),
        );
    })?;
    assert_report_contains(
        &parse_remote_hydration_plan_page(&fixture.manifest_id_hex, &inconsistent_count, 16)
            .expect_err("inconsistent returned count must fail"),
        "returned counts do not match page arrays",
    );
    let inconsistent_flags = mutate_remote_plan_fixture(&fixture, |plan| {
        plan.insert("truncated_chunks".into(), norito::json::Value::from(true));
        plan.insert(
            "truncated_chunk_digests".into(),
            norito::json::Value::from(true),
        );
    })?;
    assert_report_contains(
        &parse_remote_hydration_plan_page(&fixture.manifest_id_hex, &inconsistent_flags, 16)
            .expect_err("inconsistent pagination flags must fail"),
        "pagination flags or counts are inconsistent",
    );
    let inconsistent_index = mutate_remote_plan_fixture(&fixture, |plan| {
        plan.get_mut("chunks")
            .and_then(norito::json::Value::as_array_mut)
            .and_then(|chunks| chunks.first_mut())
            .and_then(norito::json::Value::as_object_mut)
            .expect("fixture chunk entry")
            .insert("chunk_index".into(), norito::json::Value::from(1_u64));
    })?;
    assert_report_contains(
        &parse_remote_hydration_plan_page(&fixture.manifest_id_hex, &inconsistent_index, 16)
            .expect_err("noncontiguous chunk index must fail"),
        "chunk page is not contiguous",
    );
    let inconsistent_digest = mutate_remote_plan_fixture(&fixture, |plan| {
        let listed_digest = plan
            .get_mut("chunk_digests_blake3")
            .and_then(norito::json::Value::as_array_mut)
            .and_then(|digests| digests.first_mut())
            .expect("fixture listed chunk digest");
        *listed_digest = norito::json::Value::from("77".repeat(32));
    })?;
    assert_report_contains(
        &parse_remote_hydration_plan_page(&fixture.manifest_id_hex, &inconsistent_digest, 16)
            .expect_err("inconsistent chunk digest arrays must fail"),
        "chunk digest arrays disagree",
    );
    Ok(())
}
#[test]
fn remote_hydration_payload_verifier_rejects_payload_car_and_por_substitution() -> Result<()> {
    let fixture = build_remote_manifest_fixture(b"payload-car-por-binding", [0x33; 32], 33)?;
    let (manifest, plan) = verified_remote_hydration_fixture(&fixture)?;
    verify_remote_hydration_payload(&fixture.payload, &plan, &manifest)?;
    let mut substituted_payload = fixture.payload.clone();
    substituted_payload[0] ^= 0x01;
    assert_report_contains(
        &verify_remote_hydration_payload(&substituted_payload, &plan, &manifest)
            .expect_err("substituted payload must fail"),
        "payload does not match the authenticated plan",
    );
    let mut substituted_car = manifest.clone();
    substituted_car.manifest.car_digest[0] ^= 0x01;
    assert_report_contains(
        &verify_remote_hydration_payload(&fixture.payload, &plan, &substituted_car)
            .expect_err("substituted CAR commitment must fail"),
        "payload does not match canonical CAR manifest fields",
    );
    let mut substituted_por = manifest;
    substituted_por.manifest.por_root[0] ^= 0x01;
    assert_report_contains(
        &verify_remote_hydration_payload(&fixture.payload, &plan, &substituted_por)
            .expect_err("substituted PoR commitment must fail"),
        "payload does not match canonical CAR manifest fields",
    );
    Ok(())
}
#[test]
fn remote_hydration_rejects_equal_size_file_offset_swap() -> Result<()> {
    let (car_plan, payload) = CarBuildPlan::from_files(vec![
        FileEntry {
            path: vec!["a.bin".to_owned()],
            data: b"aaaa".to_vec(),
        },
        FileEntry {
            path: vec!["b.bin".to_owned()],
            data: b"bbbb".to_vec(),
        },
    ])?;
    let manifest = build_sorafs_manifest_from_plan(&car_plan, &payload)?;
    let manifest_digest = ManifestDigest::from_manifest(&manifest)?;
    let manifest_id_hex = hex::encode(&manifest.root_cid);
    let chunker_handle = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    let verified_manifest = VerifiedRemoteManifest {
        manifest,
        manifest_id_hex: manifest_id_hex.clone(),
        manifest_digest: *manifest_digest.as_bytes(),
        payload_digest: *car_plan.payload_digest.as_bytes(),
        chunk_count: car_plan.chunks.len(),
        chunker_handle: chunker_handle.clone(),
    };
    let mut offset = 0_u64;
    let mut plan = RemoteHydrationPlan {
        manifest_id_hex,
        chunker_handle,
        content_length: car_plan.content_length,
        payload_digest: *car_plan.payload_digest.as_bytes(),
        chunks: car_plan
            .chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| RemoteHydrationChunk {
                index,
                offset: chunk.offset,
                length: chunk.length,
                digest: chunk.digest,
            })
            .collect(),
        files: car_plan
            .files
            .iter()
            .map(|file| {
                let remote = RemoteHydrationFile {
                    path: file.path.clone(),
                    offset,
                    size: file.size,
                    first_chunk: file.first_chunk,
                    chunk_count: file.chunk_count,
                };
                offset += file.size;
                remote
            })
            .collect(),
    };
    verify_remote_hydration_payload(&payload, &plan, &verified_manifest)?;
    let mut substituted_path = plan.clone();
    substituted_path.files[0].path = vec!["aa.bin".to_owned()];
    assert!(
        verify_remote_hydration_payload(&payload, &substituted_path, &verified_manifest).is_err(),
        "substituted canonical file path must fail"
    );
    let mut substituted_size = plan.clone();
    substituted_size.files[0].size -= 1;
    substituted_size.files[1].size += 1;
    assert!(
        verify_remote_hydration_payload(&payload, &substituted_size, &verified_manifest).is_err(),
        "substituted canonical file sizes must fail"
    );
    let mut substituted_first_chunk = plan.clone();
    substituted_first_chunk.files[0].first_chunk += 1;
    assert!(
        verify_remote_hydration_payload(&payload, &substituted_first_chunk, &verified_manifest)
            .is_err(),
        "substituted canonical first chunk must fail"
    );
    let mut substituted_chunk_count = plan.clone();
    substituted_chunk_count.files[0].chunk_count = 0;
    assert!(
        verify_remote_hydration_payload(&payload, &substituted_chunk_count, &verified_manifest)
            .is_err(),
        "substituted canonical chunk count must fail"
    );
    let (first, remaining) = plan.files.split_at_mut(1);
    std::mem::swap(&mut first[0].offset, &mut remaining[0].offset);
    assert_eq!(first[0].size, remaining[0].size);
    assert_report_contains(
        &verify_remote_hydration_payload(&payload, &plan, &verified_manifest)
            .expect_err("equal-size file offset swap must fail"),
        "does not match canonical CAR layout offset",
    );
    Ok(())
}
#[test]
fn remote_hydration_sources_exclude_noncompleted_orders_and_prefer_newest() -> Result<()> {
    let state = test_state();
    let fixtures = vec![
        build_remote_manifest_fixture(b"pending-order", [0x41; 32], 41)?,
        build_remote_manifest_fixture(b"expired-order", [0x42; 32], 42)?,
        build_remote_manifest_fixture(b"older-completed-order", [0x43; 32], 43)?,
        build_remote_manifest_fixture(b"newest-completed-order", [0x44; 32], 44)?,
        build_remote_manifest_fixture(b"unfinalized-completed-order", [0x45; 32], 45)?,
    ];
    approve_remote_hydration_sources_with_status_and_finalization(
        &state,
        &fixtures,
        |fixture| match fixture.issued_epoch {
            41 => ReplicationOrderStatus::Pending,
            42 => ReplicationOrderStatus::Expired(43),
            issued_epoch => ReplicationOrderStatus::Completed(issued_epoch + 1),
        },
        |fixture| fixture.issued_epoch != 45,
    )?;
    let view = state.view();
    let sources = collect_remote_hydration_sources(&view, &state)?;
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0].manifest_digest_hex,
        hex::encode(fixtures[3].manifest_digest.as_bytes())
    );
    assert_eq!(
        sources[1].manifest_digest_hex,
        hex::encode(fixtures[2].manifest_digest.as_bytes())
    );
    Ok(())
}
#[test]
fn operator_preseed_bundle_hydration_requires_exact_iroha_hash() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let store = test_operator_preseed_store(&temp_dir);
    let decoy = b"operator-preseed-decoy";
    let (decoy_plan, decoy_manifest) = build_sorafs_manifest(decoy)?;
    ingest_operator_preseed_payload(&store, &decoy_plan, &decoy_manifest, decoy)?;
    let payload = b"operator-preseed-bundle";
    let (plan, manifest) = build_sorafs_manifest(payload)?;
    let qualified = ingest_operator_preseed_payload(&store, &plan, &manifest, payload)?;
    let state = test_state();
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().join("runtime-state")),
        Arc::clone(&state),
    )
    .with_operator_preseed_store(
        Arc::clone(&store),
        BTreeSet::from([*qualified.manifest_digest()]),
    )?;
    let cache_path = temp_dir.path().join("runtime-state/artifacts/bundle");
    fs::create_dir_all(cache_path.parent().expect("cache path parent"))?;
    assert!(!manager.hydrate_local_sorafs_payload_to_cache(
        &[],
        Hash::new(b"not-present"),
        &cache_path,
        1 << 20,
    )?);
    assert!(!cache_path.exists());
    assert!(!manager.hydrate_local_sorafs_payload_to_cache(
        &[],
        Hash::new(decoy),
        &cache_path,
        1 << 20,
    )?);
    assert!(
        !cache_path.exists(),
        "an ingested payload outside the current qualification must not hydrate"
    );
    assert!(manager.hydrate_local_sorafs_payload_to_cache(
        &[],
        Hash::new(payload),
        &cache_path,
        1 << 20,
    )?);
    assert_eq!(fs::read(cache_path)?, payload);
    assert!(manager.cached_artifact_has_operator_preseed_qualification(
        &temp_dir.path().join("runtime-state/artifacts/bundle"),
        Hash::new(payload),
        1 << 20,
    )?);
    Ok(())
}
#[test]
fn operator_preseed_inrou_layout_accepts_real_guest_size_without_buffering() -> Result<()> {
    const KERNEL_BYTES: u64 = 27_236_288;
    const ROOTFS_BYTES: u64 = 3_085_959_168;
    const INITRD_BYTES: u64 = 13_923_072;
    let rootfs_offset = KERNEL_BYTES;
    let initrd_offset = rootfs_offset + ROOTFS_BYTES;
    let content_length = initrd_offset + INITRD_BYTES;
    assert!(content_length > SORACLOUD_REMOTE_HYDRATION_MAX_IN_MEMORY_PAYLOAD_BYTES);
    let files = vec![
        hydrated_file(&["aarch64", "vmlinux"], 0, KERNEL_BYTES),
        hydrated_file(&["aarch64", "rootfs.ext4"], rootfs_offset, ROOTFS_BYTES),
        hydrated_file(&["aarch64", "initrd.img"], initrd_offset, INITRD_BYTES),
    ];
    let planned = plan_operator_preseed_sorafs_files(
        &files,
        Path::new("/private/runtime/inrou"),
        content_length,
        3,
        content_length,
    )?;
    assert_eq!(planned.len(), 3);
    assert_eq!(
        planned.iter().map(|file| file.size).sum::<u64>(),
        content_length
    );
    assert_report_contains(
        &plan_operator_preseed_sorafs_files(
            &files,
            Path::new("/private/runtime/inrou"),
            content_length,
            3,
            content_length
                .checked_sub(1)
                .expect("fixture content is nonempty"),
        )
        .expect_err("one byte below the exact Inrou preseed size must fail"),
        "configured materialization byte budget",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn operator_preseed_inrou_directory_hydration_requires_exact_manifest_binding() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let store = test_operator_preseed_store(&temp_dir);
    let files = [
        ("x86_64/initrd.img", b"preseed-initrd".as_slice()),
        ("x86_64/rootfs.ext4", b"preseed-rootfs".as_slice()),
        ("x86_64/vmlinux", b"preseed-kernel".as_slice()),
    ];
    let (car_plan, payload) = CarBuildPlan::from_files(
        files
            .iter()
            .map(|(path, data)| FileEntry {
                path: path.split('/').map(ToOwned::to_owned).collect(),
                data: data.to_vec(),
            })
            .collect(),
    )?;
    let manifest = build_sorafs_manifest_from_plan(&car_plan, &payload)?;
    let stored = ingest_operator_preseed_payload(&store, &car_plan, &manifest, &payload)?;
    let manifest_digest_hex = hex::encode(stored.manifest_digest());
    let correct_content_cid = encode_content_cid(stored.manifest_cid());
    let guest_isa = SoraInrouGuestIsaV1::X8664;
    let mut bundle = sample_inrou_test_bundle()?;
    bundle
        .container
        .inrou
        .as_mut()
        .expect("Inrou fixture manifest")
        .guest_images
        .get_mut(&guest_isa)
        .expect("x86_64 guest-image fixture")
        .published_artifact = SoraPublishedInrouGuestImageArtifactV1 {
        manifest_digest_hex,
        content_cid: encode_content_cid(&sorafs_manifest::canonical_manifest_root_cid([0xA5; 32])),
    };
    let state = test_state();
    let configured_artifact = bundle
        .container
        .inrou
        .as_ref()
        .expect("manifest")
        .guest_images
        .get(&guest_isa)
        .expect("image")
        .published_artifact
        .clone();
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state"),
            configured_artifact,
        ),
        Arc::clone(&state),
    )
    .with_operator_preseed_store(
        Arc::clone(&store),
        qualified_test_operator_preseed_manifests(&store),
    )?;
    let plan = sample_inrou_runtime_plan(&bundle, guest_isa);
    let bundle_root_path = canonical_test_runtime_state_dir(&temp_dir)?.join("bundle");
    fs::create_dir_all(&bundle_root_path)?;
    let bundle_root = ensure_secure_inrou_disk_directory(&bundle_root_path)?;
    assert_report_contains(
        &manager
            .hydrate_published_inrou_guest_image_artifact(&bundle_root, &bundle, &plan)
            .expect_err("a substituted manifest CID must fail"),
        "manifest CID does not match",
    );
    bundle
        .container
        .inrou
        .as_mut()
        .expect("Inrou fixture manifest")
        .guest_images
        .get_mut(&guest_isa)
        .expect("x86_64 guest-image fixture")
        .published_artifact
        .content_cid = correct_content_cid;
    let plan = sample_inrou_runtime_plan(&bundle, guest_isa);
    let configured_artifact = bundle
        .container
        .inrou
        .as_ref()
        .expect("manifest")
        .guest_images
        .get(&guest_isa)
        .expect("image")
        .published_artifact
        .clone();
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state-correct"),
            configured_artifact,
        ),
        state,
    )
    .with_operator_preseed_store(
        Arc::clone(&store),
        qualified_test_operator_preseed_manifests(&store),
    )?;
    manager.hydrate_published_inrou_guest_image_artifact(&bundle_root, &bundle, &plan)?;
    for (path, expected) in files {
        assert_eq!(
            fs::read(bundle_root.path().join("inrou").join(path))?,
            expected
        );
    }
    Ok(())
}
#[test]
fn enabled_inrou_host_requires_exact_trusted_guest_preseed_before_startup() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let kernel = temp_dir.path().join("vmlinux");
    let rootfs = temp_dir.path().join("rootfs.ext4");
    fs::write(&kernel, b"trusted-kernel")?;
    fs::write(&rootfs, b"trusted-rootfs")?;
    let host_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    let (store, artifact) = create_portable_inrou_operator_preseed_artifact(
        &temp_dir,
        host_guest_isa,
        &kernel,
        &rootfs,
        None,
    )?;
    let manifest_digest = parse_sorafs_manifest_digest_hex(&artifact.manifest_digest_hex)?;
    let guest_image_bytes = store
        .manifest_by_digest(&manifest_digest)
        .expect("newly published guest manifest")
        .content_length();
    let state = test_state();

    let missing_store = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("missing-store"),
            artifact.clone(),
        ),
        Arc::clone(&state),
    );
    assert_report_contains(
        &missing_store
            .ensure_trusted_inrou_guest_artifact_preseeded()
            .expect_err("enabled hosting must not fetch its trust anchor at runtime"),
        "requires a disabled-provider operator-preseed SoraFS store",
    );

    let missing_artifact = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("missing-artifact"),
            sample_published_inrou_guest_image_artifact(0x7F),
        ),
        Arc::clone(&state),
    )
    .with_operator_preseed_store(
        Arc::clone(&store),
        qualified_test_operator_preseed_manifests(&store),
    )?;
    assert_report_contains(
        &missing_artifact
            .ensure_trusted_inrou_guest_artifact_preseeded()
            .expect_err("a different valid artifact must not satisfy the configured trust"),
        "is missing or does not currently qualify trusted Inrou guest manifest",
    );

    let mut undersized_guest_budget = test_runtime_manager_config_with_trusted_guest(
        temp_dir.path().join("undersized-guest-budget"),
        artifact.clone(),
    );
    undersized_guest_budget.inrou.guest_image_max_bytes = std::num::NonZeroU64::new(
        guest_image_bytes
            .checked_sub(1)
            .expect("guest image fixture is nonempty"),
    )
    .expect("one byte below guest image fixture remains nonzero");
    let undersized_guest_budget =
        SoracloudRuntimeManager::new(undersized_guest_budget, Arc::clone(&state))
            .with_operator_preseed_store(
                Arc::clone(&store),
                qualified_test_operator_preseed_manifests(&store),
            )?;
    assert_report_contains(
        &undersized_guest_budget
            .ensure_trusted_inrou_guest_artifact_preseeded()
            .expect_err("the immutable guest-image budget must bound preseed materialization"),
        "configured materialization byte budget",
    );

    let mut exact_config = test_runtime_manager_config_with_trusted_guest(
        temp_dir.path().join("exact-artifact"),
        artifact,
    );
    exact_config.inrou.guest_image_max_bytes =
        std::num::NonZeroU64::new(guest_image_bytes).expect("guest image fixture is nonempty");
    exact_config.inrou.max_storage_bytes =
        std::num::NonZeroU64::new(SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1)
            .expect("minimum writable storage capacity");
    SoracloudRuntimeManager::new(exact_config, state)
        .with_operator_preseed_store(
            Arc::clone(&store),
            qualified_test_operator_preseed_manifests(&store),
        )?
        .ensure_trusted_inrou_guest_artifact_preseeded()?;
    Ok(())
}
#[test]
fn enabled_inrou_host_rejects_embedded_provider_storage() {
    for operator_preseed_attached in [false, true] {
        let error =
            validate_operator_preseed_provider_boundary(true, operator_preseed_attached, true)
                .expect_err("Inrou V1 hosting and provider storage must be mutually exclusive");
        assert_report_contains(
            &error,
            "Inrou V1 hosting requires embedded SoraFS provider storage to be disabled",
        );
    }
}
#[test]
fn enabled_inrou_host_rejects_wrong_isa_trusted_guest_preseed() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let kernel = temp_dir.path().join("vmlinux");
    let rootfs = temp_dir.path().join("rootfs.ext4");
    fs::write(&kernel, b"wrong-isa-kernel")?;
    fs::write(&rootfs, b"wrong-isa-rootfs")?;
    let host_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    let wrong_guest_isa = match host_guest_isa {
        SoraInrouGuestIsaV1::X8664 => SoraInrouGuestIsaV1::Aarch64,
        SoraInrouGuestIsaV1::Aarch64 => SoraInrouGuestIsaV1::X8664,
    };
    let (store, artifact) = create_portable_inrou_operator_preseed_artifact(
        &temp_dir,
        wrong_guest_isa,
        &kernel,
        &rootfs,
        None,
    )?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state"),
            artifact,
        ),
        test_state(),
    )
    .with_operator_preseed_store(
        Arc::clone(&store),
        qualified_test_operator_preseed_manifests(&store),
    )?;
    assert_report_contains(
        &manager
            .ensure_trusted_inrou_guest_artifact_preseeded()
            .expect_err("a valid artifact for a different ISA must fail startup"),
        "must contain exactly the selected image",
    );
    Ok(())
}
#[test]
fn enabled_inrou_host_rejects_extra_trusted_guest_preseed_member() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let store = test_operator_preseed_store(&temp_dir);
    let host_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    let isa = host_guest_isa.as_str();
    let files = [
        (format!("{isa}/vmlinux"), b"trusted-kernel".as_slice()),
        (format!("{isa}/rootfs.ext4"), b"trusted-rootfs".as_slice()),
        (format!("{isa}/metadata.json"), b"{{}}".as_slice()),
    ];
    let (car_plan, payload) = CarBuildPlan::from_files(
        files
            .iter()
            .map(|(path, data)| FileEntry {
                path: path.split('/').map(ToOwned::to_owned).collect(),
                data: data.to_vec(),
            })
            .collect(),
    )?;
    let manifest = build_sorafs_manifest_from_plan(&car_plan, &payload)?;
    let stored = ingest_operator_preseed_payload(&store, &car_plan, &manifest, &payload)?;
    let artifact = SoraPublishedInrouGuestImageArtifactV1 {
        manifest_digest_hex: hex::encode(stored.manifest_digest()),
        content_cid: encode_content_cid(stored.manifest_cid()),
    };
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state"),
            artifact,
        ),
        test_state(),
    )
    .with_operator_preseed_store(
        Arc::clone(&store),
        qualified_test_operator_preseed_manifests(&store),
    )?;
    assert_report_contains(
        &manager
            .ensure_trusted_inrou_guest_artifact_preseeded()
            .expect_err("an extra authenticated member must fail startup"),
        "must contain exactly the selected image",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn published_inrou_guest_image_requires_exact_operator_trust_anchor() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let guest_isa = SoraInrouGuestIsaV1::X8664;
    let plan = sample_inrou_runtime_plan(&bundle, guest_isa);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let bundle_root = secure_test_inrou_disk_directory(&temp_dir)?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state"),
            sample_published_inrou_guest_image_artifact(0x7F),
        ),
        test_state(),
    );
    assert_report_contains(
        &manager
            .hydrate_published_inrou_guest_image_artifact(&bundle_root, &bundle, &plan)
            .expect_err("a different valid operator trust anchor must fail closed"),
        "does not match the operator-approved host artifact",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn published_inrou_guest_image_does_not_trust_preexisting_local_files() -> Result<()> {
    let mut bundle = sample_inrou_test_bundle()?;
    let guest_isa = SoraInrouGuestIsaV1::X8664;
    let image = bundle
        .container
        .inrou
        .as_mut()
        .expect("Inrou fixture manifest")
        .guest_images
        .get_mut(&guest_isa)
        .expect("x86_64 guest-image fixture");
    image.published_artifact = SoraPublishedInrouGuestImageArtifactV1 {
        manifest_digest_hex: "11".repeat(32),
        content_cid: encode_content_cid(&sorafs_manifest::canonical_manifest_root_cid([0x22; 32])),
    };
    let required_paths = [
        image.kernel_image_path.clone(),
        image.rootfs_image_path.clone(),
        image
            .initrd_image_path
            .clone()
            .expect("Inrou fixture initrd"),
    ];
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    for path in &required_paths {
        let target = temp_dir.path().join(
            path.strip_prefix('/')
                .expect("fixture guest-image path is absolute"),
        );
        fs::create_dir_all(target.parent().expect("guest-image path parent"))?;
        fs::write(target, b"unverified-local-image")?;
    }
    let state = test_state();
    let configured_artifact = image.published_artifact.clone();
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state"),
            configured_artifact,
        ),
        state,
    );
    let plan = sample_inrou_runtime_plan(&bundle, guest_isa);
    let bundle_root = secure_test_inrou_disk_directory(&temp_dir)?;
    assert_report_contains(
        &manager
            .hydrate_published_inrou_guest_image_artifact(&bundle_root, &bundle, &plan)
            .expect_err("preexisting local guest images must not bypass SoraFS verification"),
        "operator-preseed store is missing configured",
    );
    for path in required_paths {
        assert_eq!(
            fs::read(
                temp_dir.path().join(
                    path.strip_prefix('/')
                        .expect("fixture guest-image path is absolute"),
                )
            )?,
            b"unverified-local-image"
        );
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn published_inrou_guest_image_requires_manifest_and_selected_isa() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let bundle_root = secure_test_inrou_disk_directory(&temp_dir)?;
    let state = test_state();
    let bundle = sample_inrou_test_bundle()?;
    let trusted_guest_artifact = bundle
        .container
        .inrou
        .as_ref()
        .expect("Inrou fixture manifest")
        .guest_images
        .get(&SoraInrouGuestIsaV1::X8664)
        .expect("x86_64 guest image")
        .published_artifact
        .clone();
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config_with_trusted_guest(
            temp_dir.path().join("runtime-state"),
            trusted_guest_artifact,
        ),
        state,
    );
    let plan = sample_inrou_runtime_plan(&bundle, SoraInrouGuestIsaV1::X8664);

    let mut missing_manifest = bundle.clone();
    missing_manifest.container.inrou = None;
    assert_report_contains(
        &manager
            .hydrate_published_inrou_guest_image_artifact(&bundle_root, &missing_manifest, &plan)
            .expect_err("a signed Inrou bundle without its manifest must fail closed"),
        "missing its manifest",
    );

    let mut missing_guest_isa = bundle;
    missing_guest_isa
        .container
        .inrou
        .as_mut()
        .expect("Inrou fixture manifest")
        .guest_images
        .remove(&plan.selected_guest_isa);
    assert_report_contains(
        &manager
            .hydrate_published_inrou_guest_image_artifact(&bundle_root, &missing_guest_isa, &plan)
            .expect_err("a signed Inrou bundle without the selected ISA must fail closed"),
        "missing selected guest ISA",
    );
    Ok(())
}
#[test]
fn published_inrou_guest_image_requires_exact_authenticated_members() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let plan = sample_inrou_runtime_plan(&bundle, SoraInrouGuestIsaV1::X8664);
    let expected = vec![
        hydrated_file(&["x86_64", "vmlinux"], 0, 1),
        hydrated_file(&["x86_64", "rootfs.ext4"], 1, 1),
        hydrated_file(&["x86_64", "initrd.img"], 2, 1),
    ];
    validate_published_inrou_guest_image_files(&plan, &expected)?;
    let mut unrelated = expected.clone();
    unrelated[0].path = vec!["x86_64".to_owned(), "unrelated.bin".to_owned()];
    assert_report_contains(
        &validate_published_inrou_guest_image_files(&plan, &unrelated)
            .expect_err("an unrelated authenticated file must not satisfy the image contract"),
        "must contain exactly",
    );
    let mut extra = expected;
    extra.push(hydrated_file(&["metadata.json"], 3, 1));
    assert_report_contains(
        &validate_published_inrou_guest_image_files(&plan, &extra)
            .expect_err("extra authenticated files must fail the exact image contract"),
        "must contain exactly",
    );
    let mut noncanonical_plan = plan;
    noncanonical_plan.kernel_image_path = "/inrou//x86_64/vmlinux".to_owned();
    assert_report_contains(
        &validate_published_inrou_guest_image_files(&noncanonical_plan, &[])
            .expect_err("noncanonical selected image paths must fail closed"),
        "nonportable path component",
    );
    Ok(())
}
#[test]
fn sorafs_materialization_preserves_unrelated_existing_files() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let target_root = temp_dir.path().join("dataset");
    fs::create_dir(&target_root)?;
    fs::write(target_root.join("keep.txt"), b"unrelated")?;
    let payload = b"fresh payload";
    let files = vec![hydrated_file(
        &["nested", "artifact.bin"],
        0,
        u64::try_from(payload.len())?,
    )];
    materialize_sorafs_payload_files(payload, &files, &target_root, 8, 1_024, 1_024)?;
    assert_eq!(fs::read(target_root.join("keep.txt"))?, b"unrelated");
    assert_eq!(
        fs::read(target_root.join("nested").join("artifact.bin"))?,
        payload
    );
    Ok(())
}
#[test]
fn sorafs_materialization_rejects_unsafe_duplicate_and_noncontiguous_layouts_without_mutation()
-> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let target_root = temp_dir.path().join("live");
    fs::create_dir(&target_root)?;
    fs::write(target_root.join("marker"), b"live-state")?;
    let payload = b"abcd";
    let unsafe_path = vec![hydrated_file(&["..", "escaped"], 0, 4)];
    assert!(
        materialize_sorafs_payload_files(payload, &unsafe_path, &target_root, 8, 1_024, 1_024,)
            .is_err()
    );
    assert!(!temp_dir.path().join("escaped").exists());
    assert_eq!(fs::read(target_root.join("marker"))?, b"live-state");
    let duplicate_path = vec![
        hydrated_file(&["duplicate"], 0, 2),
        hydrated_file(&["duplicate"], 2, 2),
    ];
    assert!(
        materialize_sorafs_payload_files(payload, &duplicate_path, &target_root, 8, 1_024, 1_024,)
            .is_err()
    );
    assert_eq!(fs::read(target_root.join("marker"))?, b"live-state");
    let noncontiguous = vec![hydrated_file(&["gap"], 1, 3)];
    assert!(
        materialize_sorafs_payload_files(payload, &noncontiguous, &target_root, 8, 1_024, 1_024,)
            .is_err()
    );
    assert_eq!(fs::read(target_root.join("marker"))?, b"live-state");
    assert_eq!(fs::read_dir(&target_root)?.count(), 1);
    Ok(())
}
#[cfg(unix)]
#[test]
fn sorafs_materialization_rejects_existing_symlink_without_mutation() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let target_root = temp_dir.path().join("live");
    fs::create_dir(&target_root)?;
    fs::write(target_root.join("marker"), b"live-state")?;
    let external = temp_dir.path().join("external");
    fs::write(&external, b"external-state")?;
    std::os::unix::fs::symlink(&external, target_root.join("forbidden-link"))?;
    let payload = b"fresh";
    let files = vec![hydrated_file(&["artifact"], 0, 5)];
    let _error = materialize_sorafs_payload_files(payload, &files, &target_root, 8, 1_024, 1_024)
        .expect_err("existing symlink must abort materialization");
    assert_eq!(fs::read(target_root.join("marker"))?, b"live-state");
    assert_eq!(fs::read(&external)?, b"external-state");
    assert!(
        fs::symlink_metadata(target_root.join("forbidden-link"))?
            .file_type()
            .is_symlink()
    );
    let payload_digest_hex = hex::encode(blake3::hash(payload).as_bytes());
    let transaction_suffix = &payload_digest_hex[..16];
    assert!(
        !temp_dir
            .path()
            .join(format!(".live.sorafs-stage-{transaction_suffix}"))
            .exists()
    );
    Ok(())
}
#[test]
fn sorafs_materialization_recovers_interrupted_backup_before_commit() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let target_root = temp_dir.path().join("dataset");
    let payload = b"recovered-payload";
    let payload_digest_hex = hex::encode(blake3::hash(payload).as_bytes());
    let transaction_suffix = &payload_digest_hex[..16];
    let backup_root = temp_dir
        .path()
        .join(format!(".dataset.sorafs-backup-{transaction_suffix}"));
    fs::create_dir(&backup_root)?;
    fs::write(backup_root.join("keep.txt"), b"backup-state")?;
    let files = vec![hydrated_file(
        &["artifact.bin"],
        0,
        u64::try_from(payload.len())?,
    )];
    materialize_sorafs_payload_files(payload, &files, &target_root, 8, 1_024, 1_024)?;
    assert_eq!(fs::read(target_root.join("keep.txt"))?, b"backup-state");
    assert_eq!(fs::read(target_root.join("artifact.bin"))?, payload);
    assert!(!backup_root.exists());
    Ok(())
}
fn read_http_request(stream: &mut std::net::TcpStream) -> Result<(String, String)> {
    // Accepted sockets inherit a nonblocking listener's mode on macOS.
    // Preserve the existing bounded synchronous request-reader contract.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let request = String::from_utf8_lossy(&buffer);
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    Ok((
        parts.next().unwrap_or_default().to_owned(),
        parts.next().unwrap_or_default().to_owned(),
    ))
}
fn write_http_response(
    stream: &mut std::net::TcpStream,
    response: &HttpFixtureResponse,
) -> Result<()> {
    let reason = match response.status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Response",
    };
    let content_length = response
        .content_length_override
        .unwrap_or_else(|| u64::try_from(response.body.len()).unwrap_or(u64::MAX));
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n",
        response.status_code, reason, content_length, response.content_type,
    );
    for (key, value) in &response.extra_headers {
        headers.push_str(key);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&response.body)?;
    Ok(())
}
fn spawn_remote_hydration_fixture(fixtures: &[RemoteManifestFixture]) -> Result<HttpRouteFixture> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let base_url = format!("http://{}", listener.local_addr()?);
    let mut routes = BTreeMap::<(String, String), HttpFixtureResponse>::new();
    let mut token_response = norito::json::native::Map::new();
    token_response.insert(
        "token_base64".into(),
        norito::json::Value::from("fixture-stream-token"),
    );
    routes.insert(
        ("POST".to_owned(), "/v1/sorafs/storage/token".to_owned()),
        HttpFixtureResponse::json(norito::json::to_vec(&norito::json::Value::Object(
            token_response,
        ))?),
    );
    for fixture in fixtures {
        routes.insert(
            (
                "GET".to_owned(),
                format!(
                    "/v1/sorafs/storage/manifest/{}?limit=1",
                    fixture.manifest_id_hex
                ),
            ),
            HttpFixtureResponse::json(fixture.manifest_response_body.clone()),
        );
        routes.insert(
            (
                "GET".to_owned(),
                format!(
                    "/v1/sorafs/storage/plan/{}?limit={SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT}&offset=0",
                    fixture.manifest_id_hex
                ),
            ),
            HttpFixtureResponse::json(fixture.plan_response_body.clone()),
        );
        routes.insert(
            ("GET".to_owned(), fixture.chunk_path.clone()),
            HttpFixtureResponse::binary(fixture.payload.clone()),
        );
    }
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let response = match read_http_request(&mut stream) {
                        Ok((method, path)) => routes
                            .get(&(method, path))
                            .cloned()
                            .unwrap_or_else(HttpFixtureResponse::not_found),
                        Err(_) => HttpFixtureResponse::not_found(),
                    };
                    let _ = write_http_response(&mut stream, &response);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    Ok(HttpRouteFixture {
        base_url,
        stop_tx,
        handle: Some(handle),
    })
}
fn test_provider_cache_with_transport_hints(
    base_url: &str,
    provider_id: [u8; 32],
    transport_hints: Option<Vec<TransportHintV1>>,
    max_concurrent_streams: u16,
    max_in_flight: Option<u16>,
) -> Result<Arc<AsyncRwLock<ProviderAdvertCache>>> {
    let advert_key = PrivateKey::from_bytes(Algorithm::Ed25519, &[0xA5; 32])?;
    let advert_public = PublicKey::from(advert_key.clone());
    let advert_public_payload = ed25519_public_key_payload(&advert_public)?;
    let council_key = PrivateKey::from_bytes(Algorithm::Ed25519, &[0x42; 32])?;
    let council_public = PublicKey::from(council_key.clone());
    let council_public_payload = ed25519_public_key_payload(&council_public)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let issued_at = now.saturating_sub(60);
    let expires_at = issued_at + 600;
    let capabilities = vec![
        CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        },
        CapabilityTlv {
            cap_type: CapabilityType::ChunkRangeFetch,
            payload: ProviderCapabilityRangeV1 {
                max_chunk_span: 32,
                min_granularity: 8,
                supports_sparse_offsets: true,
                requires_alignment: false,
                supports_merkle_proof: true,
            }
            .to_bytes()?,
        },
    ];
    let stream_budget = max_in_flight.map(|max_in_flight| StreamBudgetV1 {
        max_in_flight,
        max_bytes_per_sec: 8_388_608,
        burst_bytes: Some(1_048_576),
    });
    let endpoint = AdvertEndpoint {
        kind: EndpointKind::Torii,
        host_pattern: base_url.to_owned(),
        metadata: vec![EndpointMetadata {
            key: EndpointMetadataKey::Region,
            value: b"global".to_vec(),
        }],
    };
    let body = ProviderAdvertBodyV1 {
        provider_id,
        profile_id: "sorafs.sf1@1.0.0".to_owned(),
        profile_aliases: Some(vec!["sorafs.sf1@1.0.0".to_owned(), "sorafs-sf1".to_owned()]),
        stake: StakePointer {
            pool_id: [0x21; 32],
            stake_amount: XorQuantity::try_from_micro(1_000)
                .expect("fixture stake is representable"),
        },
        qos: QosHints {
            availability: AvailabilityTier::Hot,
            max_retrieval_latency_ms: 1_000,
            max_concurrent_streams,
        },
        capabilities: capabilities.clone(),
        endpoints: vec![endpoint.clone()],
        rendezvous_topics: vec![RendezvousTopic {
            topic: "sorafs.sf1.primary".to_owned(),
            region: "global".to_owned(),
        }],
        path_policy: PathDiversityPolicy {
            min_guard_weight: 5,
            max_same_asn_per_path: 1,
            max_same_pool_per_path: 1,
        },
        notes: None,
        stream_budget,
        transport_hints: transport_hints.clone(),
    };
    let mut advert = ProviderAdvertV1 {
        version: PROVIDER_ADVERT_VERSION_V1,
        network_id: [0xA1; 32],
        issued_at,
        expires_at,
        body: body.clone(),
        signature: sorafs_manifest::AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: advert_public_payload.to_vec(),
            signature: vec![0; 64],
        },
        signature_strict: true,
        allow_unknown_capabilities: false,
    };
    let advert_signature_payload = advert
        .signature_payload_bytes()
        .wrap_err("encode Soracloud provider advert signature envelope")?;
    advert.signature.signature = Signature::try_new(&advert_key, &advert_signature_payload)
        .wrap_err("sign Soracloud provider advert fixture")?
        .payload()
        .to_vec();
    advert
        .verify_signature()
        .wrap_err("verify Soracloud provider advert fixture signature")?;
    let (vrf_public, vrf_private) =
        BlsNormal::try_keypair(KeyGenOption::UseSeed(provider_id.to_vec()))
            .wrap_err("derive Soracloud provider VRF fixture key")?;
    let vrf_pair: KeyPair = (vrf_public, vrf_private).into();
    let proposal = ProviderAdmissionProposalV1 {
        version: PROVIDER_ADMISSION_PROPOSAL_VERSION_V1,
        provider_id,
        profile_id: body.profile_id.clone(),
        profile_aliases: body.profile_aliases.clone(),
        stake: body.stake.clone(),
        capabilities: body.capabilities.clone(),
        endpoints: vec![EndpointAdmissionV1 {
            endpoint,
            attestation: EndpointAttestationV1 {
                version: sorafs_manifest::ENDPOINT_ATTESTATION_VERSION_V1,
                kind: EndpointAttestationKind::Tls,
                attested_at: issued_at.saturating_sub(10),
                expires_at: expires_at + 60,
                leaf_certificate: vec![0xAA],
                intermediate_certificates: Vec::new(),
                alpn_ids: vec!["h2".to_owned()],
                report: Vec::new(),
            },
        }],
        advert_key: advert_public_payload,
        por_vrf_key: ProviderVrfPublicKeyV1::BlsNormal(
            vrf_pair
                .public_key()
                .to_bytes()
                .1
                .try_into()
                .expect("Normal BLS public key is 48 bytes"),
        ),
        jurisdiction_code: "US".to_owned(),
        contact_uri: Some("mailto:ops@example.test".to_owned()),
        stream_budget,
        transport_hints,
    };
    let proposal_digest = compute_proposal_digest(&proposal)?;
    let mut envelope = ProviderAdmissionEnvelopeV1 {
        version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
        network_id: [0xA1; 32],
        policy_id: [0xC1; 32],
        policy_revision: 1,
        policy_digest: [0xD1; 32],
        admission_revision: 1,
        expected_current_event_digest: None,
        proposal,
        proposal_digest,
        advert_body: body.clone(),
        advert_body_digest: compute_advert_body_digest(&body)?,
        issued_at,
        retention_epoch: expires_at + 600,
        council_signatures: Vec::new(),
        notes: None,
    };
    let authorization_digest = compute_envelope_authorization_digest(&envelope)?;
    envelope.council_signatures.push(CouncilSignature {
        signer: council_public_payload,
        signature: Signature::try_new(&council_key, &authorization_digest)
            .wrap_err("sign Soracloud provider admission fixture")?
            .payload()
            .to_vec(),
    });
    let policy = ProviderAdmissionCouncilPolicy::new([council_public_payload], 1)?;
    let admission = AdmissionRegistry::from_envelopes(envelope.network_id, policy, [envelope])?;
    let mut cache = ProviderAdvertCache::new(
        vec![
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        Arc::new(admission),
    );
    let now = issued_at.saturating_add(1);
    let prepared = cache
        .validation_policy()
        .prepare(advert, now)
        .map_err(|error| eyre::eyre!(error.to_string()))?;
    cache
        .commit_prepared(prepared, now)
        .map_err(|error| eyre::eyre!(error.to_string()))?;
    Ok(Arc::new(AsyncRwLock::new(cache)))
}
fn test_provider_cache(
    base_url: &str,
    provider_id: [u8; 32],
) -> Result<Arc<AsyncRwLock<ProviderAdvertCache>>> {
    test_provider_cache_with_transport_hints(
        base_url,
        provider_id,
        Some(vec![TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 0,
        }]),
        8,
        Some(8),
    )
}
#[test]
fn remote_hydration_provider_target_requires_range_hint_and_stream_budget() -> Result<()> {
    let state = test_state();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let cases = [
        ([0x91; 32], None, Some(8), false),
        (
            [0x92; 32],
            Some(vec![TransportHintV1 {
                protocol: TransportProtocol::QuicStream,
                priority: 0,
            }]),
            Some(8),
            false,
        ),
        (
            [0x93; 32],
            Some(vec![TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            }]),
            Some(8),
            true,
        ),
        (
            [0x94; 32],
            Some(vec![TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            }]),
            None,
            false,
        ),
    ];
    for (provider_id, transport_hints, max_in_flight, expected) in cases {
        let cache = test_provider_cache_with_transport_hints(
            "https://provider.example/",
            provider_id,
            transport_hints,
            8,
            max_in_flight,
        )?;
        let manager = SoracloudRuntimeManager::new(
            test_runtime_manager_config(
                temp_dir.path().join(format!("provider-{}", provider_id[0])),
            ),
            Arc::clone(&state),
        )
        .with_sorafs_provider_cache(cache);
        assert_eq!(
            manager
                .remote_hydration_provider_target(&provider_id)
                .is_some(),
            expected
        );
    }
    Ok(())
}
#[test]
fn remote_hydration_provider_target_uses_tighter_advertised_stream_limit() -> Result<()> {
    let provider_id = [0x95; 32];
    let cache = test_provider_cache_with_transport_hints(
        "https://provider.example/",
        provider_id,
        Some(vec![TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 0,
        }]),
        7,
        Some(3),
    )?;
    let state = test_state();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        state,
    )
    .with_sorafs_provider_cache(cache);

    let target = manager
        .remote_hydration_provider_target(&provider_id)
        .expect("admitted range provider with a stream budget");
    assert_eq!(target.maximum_concurrent_streams.get(), 3);
    Ok(())
}
#[test]
fn remote_hydration_provider_session_retries_after_advert_replacement() -> Result<()> {
    let provider_id = [0x96; 32];
    let cache = test_provider_cache_with_transport_hints(
        "https://provider.example/",
        provider_id,
        Some(vec![TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 0,
        }]),
        2,
        Some(2),
    )?;
    let old_advert = cache
        .try_read()
        .expect("provider advert fixture cache is uncontended")
        .record_by_provider(&provider_id)
        .expect("provider advert fixture record")
        .advert()
        .clone();
    let state = test_state();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        state,
    )
    .with_sorafs_provider_cache(Arc::clone(&cache));
    let observed_generations = Arc::new(Mutex::new(Vec::new()));

    let session = thread::scope(|scope| -> Result<_> {
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let worker_generations = Arc::clone(&observed_generations);
        let worker_manager = &manager;
        let worker_provider_id = provider_id;
        let worker = scope.spawn(move || {
            worker_manager.acquire_remote_hydration_provider_session_inner(
                &worker_provider_id,
                |attempt, target| {
                    worker_generations
                        .lock()
                        .expect("generation observer lock")
                        .push((attempt, target.advert_issued_at));
                    if attempt == 0 {
                        let _ = paused_sender.send(());
                        let _ = resume_receiver.recv();
                    }
                },
            )
        });
        paused_receiver
            .recv_timeout(Duration::from_secs(2))
            .wrap_err("provider session did not pause after resolving the old advert")?;

        let mut replacement = old_advert.clone();
        replacement.issued_at = replacement.issued_at.saturating_add(1);
        replacement.expires_at = replacement.expires_at.saturating_add(1);
        let replacement_issued_at = replacement.issued_at;
        let advert_key = PrivateKey::from_bytes(Algorithm::Ed25519, &[0xA5; 32])?;
        let signature_payload = replacement
            .signature_payload_bytes()
            .wrap_err("encode replacement provider advert signature envelope")?;
        replacement.signature.signature = Signature::try_new(&advert_key, &signature_payload)
            .wrap_err("sign replacement provider advert")?
            .payload()
            .to_vec();
        let validation_policy = cache
            .try_read()
            .expect("provider advert fixture cache is uncontended")
            .validation_policy();
        let prepared = validation_policy
            .prepare(replacement, replacement_issued_at)
            .map_err(|error| eyre::eyre!(error.to_string()))?;
        cache
            .try_write()
            .expect("provider advert fixture cache is uncontended")
            .commit_prepared(prepared, replacement_issued_at)
            .map_err(|error| eyre::eyre!(error.to_string()))?;
        resume_sender
            .send(())
            .expect("provider session worker remains connected");
        worker
            .join()
            .map_err(|_| eyre::eyre!("provider session worker panicked"))
    })?
    .expect("the replacement advert must be admitted on the bounded retry");

    assert_eq!(
        *observed_generations
            .lock()
            .expect("generation observer lock"),
        vec![
            (0, old_advert.issued_at),
            (1, old_advert.issued_at.saturating_add(1))
        ]
    );
    assert_eq!(
        session.target.advert_issued_at,
        old_advert.issued_at.saturating_add(1)
    );
    assert_eq!(session.target.maximum_concurrent_streams.get(), 2);
    let gate = manager
        .remote_hydration_provider_gates
        .lock()
        .get(&provider_id)
        .cloned()
        .expect("provider gate is retained while its session is active");
    {
        let gate_state = gate.state.lock();
        assert_eq!(
            gate_state.advert_issued_at,
            old_advert.issued_at.saturating_add(1)
        );
        assert_eq!(gate_state.in_flight, 1);
    }
    drop(session);
    assert_eq!(gate.state.lock().in_flight, 0);
    Ok(())
}
#[test]
fn remote_hydration_provider_session_fails_closed_when_advert_expires() -> Result<()> {
    let provider_id = [0x97; 32];
    let cache = test_provider_cache_with_transport_hints(
        "https://provider.example/",
        provider_id,
        Some(vec![TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 0,
        }]),
        1,
        Some(1),
    )?;
    let old_advert = cache
        .try_read()
        .expect("provider advert fixture cache is uncontended")
        .record_by_provider(&provider_id)
        .expect("provider advert fixture record")
        .advert()
        .clone();
    let state = test_state();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        state,
    )
    .with_sorafs_provider_cache(Arc::clone(&cache));
    let observed_generations = Arc::new(Mutex::new(Vec::new()));

    let session = thread::scope(|scope| -> Result<_> {
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let worker_generations = Arc::clone(&observed_generations);
        let worker_manager = &manager;
        let worker_provider_id = provider_id;
        let worker = scope.spawn(move || {
            worker_manager.acquire_remote_hydration_provider_session_inner(
                &worker_provider_id,
                |attempt, target| {
                    worker_generations
                        .lock()
                        .expect("generation observer lock")
                        .push((attempt, target.advert_issued_at));
                    if attempt == 0 {
                        let _ = paused_sender.send(());
                        let _ = resume_receiver.recv();
                    }
                },
            )
        });
        paused_receiver
            .recv_timeout(Duration::from_secs(2))
            .wrap_err("provider session did not pause after resolving the live advert")?;
        assert_eq!(
            cache
                .try_write()
                .expect("provider advert fixture cache is uncontended")
                .prune_stale(old_advert.expires_at.saturating_add(1)),
            1
        );
        resume_sender
            .send(())
            .expect("provider session worker remains connected");
        worker
            .join()
            .map_err(|_| eyre::eyre!("provider session worker panicked"))
    })?;

    assert!(session.is_none());
    assert_eq!(
        *observed_generations
            .lock()
            .expect("generation observer lock"),
        vec![(0, old_advert.issued_at)]
    );
    assert!(
        manager
            .remote_hydration_provider_target(&provider_id)
            .is_none()
    );
    let gate = manager
        .remote_hydration_provider_gates
        .lock()
        .get(&provider_id)
        .cloned()
        .expect("the rejected attempt constructed one provider gate");
    assert_eq!(gate.state.lock().in_flight, 0);
    Ok(())
}
#[test]
fn hydration_workers_share_the_provider_stream_limit() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let provider_id = [0x98; 32];
    let cache = test_provider_cache_with_transport_hints(
        "https://provider.example/",
        provider_id,
        Some(vec![TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 0,
        }]),
        4,
        Some(1),
    )?;
    let state = test_state();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        state,
    )
    .with_sorafs_provider_cache(cache);
    let blocker = manager
        .acquire_remote_hydration_provider_session(&provider_id)
        .expect("provider fixture admits one blocking session");
    assert_eq!(blocker.target.maximum_concurrent_streams.get(), 1);
    let active = AtomicUsize::new(0);
    let maximum_active = AtomicUsize::new(0);
    let (attempted_sender, attempted_receiver) = mpsc::channel();
    let (acquired_sender, acquired_receiver) = mpsc::channel();
    let (completed_sender, completed_receiver) = mpsc::channel();
    let tasks = [0_usize, 1, 2, 3];

    let (mut attempted, mut acquired, gate_counts, result) = thread::scope(|scope| {
        let runner = scope.spawn(|| {
            run_bounded_hydration_tasks(
                &tasks,
                NonZeroUsize::new(4).expect("nonzero hydration worker count"),
                |task| {
                    attempted_sender
                        .send(*task)
                        .wrap_err("send provider admission attempt")?;
                    let session = manager
                        .acquire_remote_hydration_provider_session(&provider_id)
                        .ok_or_else(|| eyre::eyre!("provider session was not admitted"))?;
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_active.fetch_max(current, Ordering::SeqCst);
                    let (release_sender, release_receiver) = mpsc::channel();
                    acquired_sender
                        .send((*task, release_sender))
                        .wrap_err("send admitted provider session")?;
                    release_receiver
                        .recv_timeout(Duration::from_secs(2))
                        .wrap_err("wait for provider-session release")?;
                    active.fetch_sub(1, Ordering::SeqCst);
                    drop(session);
                    completed_sender
                        .send(*task)
                        .wrap_err("send completed provider session")?;
                    Ok(())
                },
            )
        });
        let mut attempted = Vec::new();
        for _ in &tasks {
            attempted.push(
                attempted_receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("all four workers must reach provider admission"),
            );
        }
        drop(blocker);
        let mut acquired = Vec::new();
        let mut gate_counts = Vec::new();
        for _ in &tasks {
            let (task, release) = acquired_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("one provider session must be admitted at a time");
            acquired.push(task);
            gate_counts.push(
                manager
                    .remote_hydration_provider_gates
                    .lock()
                    .get(&provider_id)
                    .expect("provider gate remains registered")
                    .state
                    .lock()
                    .in_flight,
            );
            release
                .send(())
                .expect("hydration worker remains connected");
            assert_eq!(
                completed_receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("released provider session must complete"),
                task
            );
        }
        let result = runner.join().expect("hydration coordinator must not panic");
        (attempted, acquired, gate_counts, result)
    });
    result?;

    attempted.sort_unstable();
    acquired.sort_unstable();
    assert_eq!(attempted, tasks.to_vec());
    assert_eq!(acquired, tasks.to_vec());
    assert_eq!(maximum_active.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(gate_counts, vec![1; tasks.len()]);
    assert_eq!(
        manager
            .remote_hydration_provider_gates
            .lock()
            .get(&provider_id)
            .expect("provider gate remains registered")
            .state
            .lock()
            .in_flight,
        0
    );
    Ok(())
}
#[test]
fn remote_provider_advert_must_be_fresh_and_signature_valid() -> Result<()> {
    let provider_id = [0x91; 32];
    let cache = test_provider_cache("https://provider.example/", provider_id)?;
    let guard = cache
        .try_read()
        .expect("provider advert fixture cache is uncontended");
    let advert = guard
        .record_by_provider(&provider_id)
        .expect("provider advert fixture record")
        .advert();
    assert!(provider_advert_is_fresh(advert, advert.issued_at));
    assert!(provider_advert_is_fresh(
        advert,
        advert.expires_at.saturating_sub(1)
    ));
    assert!(!provider_advert_is_fresh(advert, advert.expires_at));
    let mut substituted = advert.clone();
    substituted.body.provider_id[0] ^= 0x01;
    assert!(!provider_advert_is_fresh(
        &substituted,
        substituted.issued_at
    ));
    Ok(())
}
#[test]
fn committed_remote_hydration_rejects_case_variant_digest_and_chunker() -> Result<()> {
    let provider_id = [0x94; 32];
    let fixture = build_remote_manifest_fixture(
        b"case-sensitive-remote-hydration-identifiers",
        provider_id,
        1,
    )?;
    let server = spawn_remote_hydration_fixture(std::slice::from_ref(&fixture))?;
    let cache = test_provider_cache(&server.base_url, provider_id)?;
    let state = test_state();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_test_remote_stream_token_operator(*state.network_id_ref())
    .with_sorafs_provider_cache(cache);
    let source = remote_hydration_source_for_fixture(&fixture);
    let manifest_digest_hex = hex::encode(fixture.manifest_digest.as_bytes());

    assert!(
        manager
            .read_committed_remote_sorafs_directory_payload(
                std::slice::from_ref(&source),
                &manifest_digest_hex,
                fixture.manifest_root_cid.as_bytes(),
            )?
            .is_some(),
        "canonical remote identifiers must hydrate"
    );

    let mut case_variant_digest = source.clone();
    let digest_byte = case_variant_digest
        .manifest_digest_hex
        .as_bytes()
        .iter()
        .position(u8::is_ascii_lowercase)
        .expect("fixture manifest digest contains a hexadecimal letter");
    case_variant_digest.manifest_digest_hex.replace_range(
        digest_byte..=digest_byte,
        &manifest_digest_hex[digest_byte..=digest_byte].to_ascii_uppercase(),
    );
    assert!(
        manager
            .read_committed_remote_sorafs_directory_payload(
                std::slice::from_ref(&case_variant_digest),
                &manifest_digest_hex,
                fixture.manifest_root_cid.as_bytes(),
            )?
            .is_none(),
        "case-variant committed manifest digests must not match"
    );

    let mut case_variant_chunker = source;
    case_variant_chunker.chunker_handle = case_variant_chunker
        .chunker_handle
        .take()
        .map(|handle| handle.to_ascii_uppercase());
    assert!(
        manager
            .read_committed_remote_sorafs_payload(
                std::slice::from_ref(&case_variant_chunker),
                Hash::new(&fixture.payload),
            )
            .is_none(),
        "case-variant committed chunker handles must not match"
    );
    Ok(())
}
fn ed25519_public_key_payload(public_key: &PublicKey) -> Result<[u8; 32]> {
    let (algorithm, payload) = public_key
        .try_to_bytes()
        .wrap_err("extract Soracloud provider Ed25519 public-key payload")?;
    if algorithm != Algorithm::Ed25519 {
        eyre::bail!("expected Ed25519 public key, got {algorithm}");
    }
    payload.try_into().wrap_err_with(|| {
        format!(
            "expected 32-byte Soracloud provider Ed25519 public key, got {} bytes",
            payload.len()
        )
    })
}
#[test]
fn ed25519_public_key_payload_rejects_non_ed25519_key() -> Result<()> {
    let private_key = PrivateKey::from_bytes(Algorithm::Secp256k1, &[0x13; 32])?;
    let public_key = PublicKey::from(private_key);
    let error = ed25519_public_key_payload(&public_key)
        .expect_err("secp256k1 provider key must be rejected");
    assert!(
        error
            .to_string()
            .contains("expected Ed25519 public key, got secp256k1")
    );
    Ok(())
}
fn approve_remote_hydration_sources(
    state: &Arc<State>,
    fixtures: &[RemoteManifestFixture],
) -> Result<()> {
    approve_remote_hydration_sources_with_status_and_finalization(
        state,
        fixtures,
        |fixture| ReplicationOrderStatus::Completed(fixture.issued_epoch + 1),
        |_| true,
    )
}
fn approve_remote_hydration_sources_with_status_and_finalization(
    state: &Arc<State>,
    fixtures: &[RemoteManifestFixture],
    status_for: impl Fn(&RemoteManifestFixture) -> ReplicationOrderStatus,
    finalized_for: impl Fn(&RemoteManifestFixture) -> bool,
) -> Result<()> {
    let view = state.view();
    let pricing = view.world().sorafs_pricing().clone();
    let next_height = NonZeroU64::new(
        u64::try_from(view.height())
            .unwrap_or(u64::MAX.saturating_sub(1))
            .saturating_add(1),
    )
    .expect("nonzero block height");
    let header = BlockHeader::new(next_height, view.latest_block_hash(), None, 0, 0);
    drop(view);
    let mut block = state.block(header);
    {
        let mut pin_manifests = block.world.pin_manifests_mut_for_testing().transaction();
        for fixture in fixtures {
            let policy = fixture.pin_policy;
            let content_length = fixture.payload.len() as u64;
            let amount = pricing
                .public_pin_fee(
                    policy.storage_class,
                    content_length,
                    policy.min_replicas,
                    fixture.issued_epoch,
                    policy.retention_epoch,
                )
                .wrap_err("compute remote hydration fixture pin fee")?;
            let mut record = PinManifestRecord::new(
                fixture.manifest_digest,
                fixture.manifest_root_cid,
                fixed_chunker_handle(),
                fixture.chunk_digest_sha3_256,
                fixture.por_root,
                content_length,
                policy,
                (*ALICE_ID).clone(),
                fixture.issued_epoch,
                None,
                None,
                Metadata::default(),
            );
            record.record_pin_fee_payment(PinFeePayment {
                paid_by: (*ALICE_ID).clone(),
                fee_asset_id: state.gov.sorafs_pin_fee_asset_id.clone(),
                treasury_account_id: state.gov.sorafs_pin_fee_treasury_account.clone(),
                amount,
            });
            record.approve(fixture.issued_epoch, None);
            pin_manifests.insert(fixture.manifest_digest, record);
        }
        pin_manifests.apply();
    }
    {
        let mut replication_orders = block
            .world
            .replication_orders_mut_for_testing()
            .transaction();
        for fixture in fixtures {
            replication_orders.insert(
                fixture.order_id,
                ReplicationOrderRecord {
                    order_id: fixture.order_id,
                    manifest_digest: fixture.manifest_digest,
                    manifest_root_cid: fixture.manifest_root_cid,
                    musubi_archive: None,
                    issued_by: (*ALICE_ID).clone(),
                    issued_epoch: fixture.issued_epoch,
                    deadline_epoch: fixture.issued_epoch + 600,
                    canonical_order: fixture.canonical_order.clone(),
                    assignment_revision: 1,
                    provider_completions: vec![
                        iroha_data_model::sorafs::pin_registry::ReplicationOrderCompletionRecord {
                            provider_id:
                                iroha_data_model::sorafs::capacity::ProviderId::new(
                                    fixture.provider_id,
                            ),
                            completed_by: (*ALICE_ID).clone(),
                            completion_epoch: fixture.issued_epoch + 1,
                            assignment_revision: 1,
                            completion_authority: iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionAuthorityV1::new(((*ALICE_ID).clone()).clone(), (*ALICE_ID).clone(), iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
                                    policy_id: [0xA1; 32],
                                    revision: 1,
                                    predecessor_digest: None,
                                    policy_digest: [0xA2; 32],
                                }),
                            finalized_anchor: if finalized_for(fixture) {
                                iroha_data_model::sorafs::pin_registry::ProviderIngestFinalizedAnchorV1 {
                                    height: fixture.issued_epoch,
                                    block_hash: [0xA3; 32],
                                }
                            } else {
                                iroha_data_model::sorafs::pin_registry::ProviderIngestFinalizedAnchorV1 {
                                    height: 0,
                                    block_hash: [0; 32],
                                }
                            },
                        },
                    ],
                    status: status_for(fixture),
                },
            );
        }
        replication_orders.apply();
    }
    block.commit_world_overlay_for_testing()?;
    Ok(())
}
fn canonical_runtime_fixture_tempdir() -> io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir())?)
}
fn canonical_test_runtime_state_dir(temp_dir: &tempfile::TempDir) -> Result<PathBuf> {
    fs::canonicalize(temp_dir.path()).wrap_err("canonicalize test runtime state directory")
}
#[cfg(unix)]
fn secure_test_inrou_disk_directory(temp_dir: &tempfile::TempDir) -> Result<PinnedInrouDirectory> {
    ensure_secure_inrou_disk_directory(&canonical_test_runtime_state_dir(temp_dir)?)
}
fn test_runtime_manager_config(state_dir: PathBuf) -> SoracloudRuntimeManagerConfig {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime {
        state_dir,
        ..Default::default()
    };
    let mut config = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
    config.production_mode = true;
    config.inrou.enabled = true;
    config.inrou.portable_vm_uid = std::num::NonZeroU32::new(70_000);
    config.inrou.portable_vm_gid = std::num::NonZeroU32::new(70_000);
    config.inrou.trusted_guest_artifact = Some(sample_published_inrou_guest_image_artifact(0x41));
    config.egress.default_allow = false;
    config.egress.rate_per_minute = std::num::NonZeroU32::new(60);
    config.egress.max_bytes_per_minute = std::num::NonZeroU64::new(1_048_576);
    config.submission.signer = Some(
        iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding {
            handle: "test://soracloud/runtime-primary".to_owned(),
            authority: AccountId::new(ALICE_KEYPAIR.public_key().clone()),
            algorithm: iroha_crypto::Algorithm::Ed25519,
            public_key: ALICE_KEYPAIR.public_key().clone(),
            revision: 1,
            policy_digest: [0xA7; 32],
        },
    );
    config
}
fn test_runtime_manager_config_with_trusted_guest(
    state_dir: PathBuf,
    trusted_guest_artifact: SoraPublishedInrouGuestImageArtifactV1,
) -> SoracloudRuntimeManagerConfig {
    let mut config = test_runtime_manager_config(state_dir);
    config.inrou.trusted_guest_artifact = Some(trusted_guest_artifact);
    config
}
fn inrou_capability_unit_test_manager(
    config: SoracloudRuntimeManagerConfig,
    state: Arc<State>,
) -> SoracloudRuntimeManager {
    let capability = InrouStartupCapabilitySnapshot::for_capability_record_unit_test(&config)
        .expect("unit-test Inrou config has the exact PortableVM V1 shape")
        .expect("unit-test Inrou config is enabled");
    let mut manager = SoracloudRuntimeManager::new(config, state);
    manager.inrou_startup_capability = Some(capability);
    manager
}
fn test_runtime_handle(
    manager: &SoracloudRuntimeManager,
    state: Arc<State>,
) -> SoracloudRuntimeManagerHandle {
    SoracloudRuntimeManagerHandle {
        snapshot: Arc::clone(&manager.snapshot),
        config: Arc::new(manager.config.clone()),
        state_dir: Arc::new(manager.config.state_dir.clone()),
        state,
        ivm_runtime_cache: Arc::new(SoracloudPreparedRuntimeCache::from_config(&manager.config)),
    }
}
#[derive(Default)]
struct RecordingRuntimeMutationSink {
    instructions: parking_lot::Mutex<Vec<InstructionBox>>,
}
impl RecordingRuntimeMutationSink {
    #[allow(dead_code)]
    fn submitted_inrou_host_capabilities(
        &self,
    ) -> Vec<iroha_data_model::isi::soracloud::AdvertiseSoracloudInrouHost> {
        self.instructions
            .lock()
            .iter()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::soracloud::AdvertiseSoracloudInrouHost>()
                    .cloned()
            })
            .collect()
    }
    fn submitted_inrou_replica_runtime_states(
        &self,
    ) -> Vec<iroha_data_model::isi::soracloud::SetSoracloudInrouReplicaRuntimeState> {
        self.instructions
            .lock()
            .iter()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<
                        iroha_data_model::isi::soracloud::SetSoracloudInrouReplicaRuntimeState,
                    >()
                    .cloned()
            })
            .collect()
    }
    fn submitted_inrou_replica_runtime_state_clears(
        &self,
    ) -> Vec<iroha_data_model::isi::soracloud::ClearSoracloudInrouReplicaRuntimeState> {
        self.instructions
            .lock()
            .iter()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<
                        iroha_data_model::isi::soracloud::ClearSoracloudInrouReplicaRuntimeState,
                    >()
                    .cloned()
            })
            .collect()
    }
    fn submitted_service_lease_usage(
        &self,
    ) -> Vec<iroha_data_model::isi::soracloud::ReportSoracloudServiceLeaseUsage> {
        self.instructions
            .lock()
            .iter()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<
                        iroha_data_model::isi::soracloud::ReportSoracloudServiceLeaseUsage,
                    >()
                    .cloned()
            })
            .collect()
    }
    #[allow(dead_code)]
    fn submitted_inrou_placement_reconciles(&self) -> usize {
        self.instructions
            .lock()
            .iter()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<
                        iroha_data_model::isi::soracloud::ReconcileSoracloudInrouPlacements,
                    >()
                    .is_some()
            })
            .count()
    }
    fn submitted_inrou_host_withdrawals(&self) -> usize {
        self.instructions
            .lock()
            .iter()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::soracloud::WithdrawSoracloudInrouHost>()
                    .is_some()
            })
            .count()
    }
}
