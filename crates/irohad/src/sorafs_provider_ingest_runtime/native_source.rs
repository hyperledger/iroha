//! Bounded assignment-authorized native source fallback; one verified chunk is buffered at a time.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_core::query::provider_ingest_source::authorize_provider_source_v1;
use iroha_crypto::Signature;
use iroha_data_model::sorafs::publication::SorafsAssignedSourceRequestV1;
use rand::{rand_core::TryRngCore as _, rngs::OsRng};
use reqwest::Url;
use sorafs_car::publisher::{
    PROVIDER_SOURCE_RESPONSE_MAX_BYTES_V1, ProviderSourceResponseV1, PublisherSourceHeaderV1,
};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct NativeAssignedSourceV1 {
    resolver: Arc<NativeResolverV1>,
    origins: BTreeMap<[u8; 32], Url>,
    ids: Vec<[u8; 32]>,
}
fn rejected() -> ProviderIngestSourceFetchErrorV1 {
    ProviderIngestSourceFetchErrorV1::Rejected
}
pub(super) fn now() -> std::result::Result<u64, ProviderIngestSourceFetchErrorV1> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rejected())?
            .as_millis(),
    )
    .map_err(|_| rejected())
}
fn origin(text: &str) -> std::result::Result<Url, ProviderIngestSourceFetchErrorV1> {
    let url = Url::parse(text).map_err(|_| rejected())?;
    if text.len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
        || !(url.scheme() == "https"
            || url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1")))
    {
        return Err(rejected());
    }
    Ok(url)
}
impl NativeAssignedSourceV1 {
    pub(super) fn new(resolver: Arc<NativeResolverV1>) -> Result<Self> {
        let mut origins = BTreeMap::new();
        for (provider, endpoint) in &resolver.config.native_source_origins {
            let mut id = [0; 32];
            hex::decode_to_slice(provider, &mut id)
                .map_err(|_| eyre::eyre!("native source provider id rejected"))?;
            if id == [0; 32] || id == *resolver.provider.as_bytes() || hex::encode(id) != *provider
            {
                bail!("native source provider id rejected");
            }
            origins.insert(
                id,
                origin(endpoint).map_err(|_| eyre::eyre!("native source origin rejected"))?,
            );
        }
        let ids = origins.keys().copied().collect();
        Ok(Self {
            resolver,
            origins,
            ids,
        })
    }
}
impl ProviderIngestAuthenticatedSourceRuntimeV1 for NativeAssignedSourceV1 {
    fn runtime_handle(&self) -> &str {
        &self.resolver.config.authenticated_source_fetch_handle
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestSourceFetchErrorV1,
    > {
        Ok(configured_authenticated_source_qualification(
            &self.resolver.config,
        ))
    }
    fn source_provider_ids(&self) -> &[[u8; 32]] {
        &self.ids
    }
    fn check_readiness(&self) -> std::result::Result<(), ProviderIngestSourceFetchErrorV1> {
        Ok(())
    }
}
impl ProviderIngestAuthenticatedSourceFetchV1 for NativeAssignedSourceV1 {
    type Fetched = VerifiedProviderIngestPayloadV1;
    fn fetch(
        &self,
        request: ProviderIngestSourceRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>,
    > {
        let resolver = Arc::clone(&self.resolver);
        let origins = self.origins.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    let deadline = Instant::now()
                        .checked_add(Duration::from_millis(
                            resolver.config.source_operation_timeout_ms,
                        ))
                        .ok_or_else(rejected)?;
                    let authorization = request.authorization();
                    if authorization.provider_id() != *resolver.provider.as_bytes() {
                        return Err(rejected());
                    }
                    let state = resolver.state().map_err(|_| rejected())?;
                    let revision = {
                        let view = state.view();
                        let order = view
                            .world()
                            .replication_orders()
                            .get(&ReplicationOrderId::new(authorization.order_id()))
                            .ok_or_else(rejected)?;
                        order.assignment_revision
                    };
                    let floor = authorization.admission_finalized_cursor();
                    let mut wire = SorafsAssignedSourceRequestV1 {
                        target_provider: authorization.provider_id(),
                        source_provider: [0; 32],
                        order_id: authorization.order_id(),
                        assignment_revision: revision,
                        manifest_digest: authorization.manifest_digest(),
                        chunk_index: None,
                        floor_height: floor.height,
                        floor_block_hash: floor.block_hash,
                    };
                    let candidates = request
                        .source_provider_ids()
                        .iter()
                        .filter_map(|id| origins.get(id).map(|origin| (*id, origin.clone())))
                        .collect::<Vec<_>>();
                    let client = reqwest::blocking::Client::builder()
                        .no_proxy()
                        .no_gzip()
                        .no_brotli()
                        .no_deflate()
                        .no_zstd()
                        .redirect(reqwest::redirect::Policy::none())
                        .retry(reqwest::retry::never())
                        .connect_timeout(Duration::from_secs(5))
                        .build()
                        .map_err(|_| rejected())?;
                    for (provider, endpoint) in &candidates {
                        wire.source_provider = *provider;
                        let Ok(response) =
                            fetch_response(&resolver, &client, endpoint, &wire, deadline)
                        else {
                            continue;
                        };
                        let ProviderSourceResponseV1::Metadata(header) = response else {
                            continue;
                        };
                        let (manifest, plan) = header.verify().map_err(|_| rejected())?;
                        if manifest.digest().map_err(|_| rejected())?.as_bytes()
                            != &authorization.manifest_digest()
                            || manifest.root_cid != authorization.manifest_cid()
                            || manifest.content_length != authorization.content_length()
                            || manifest.chunk_digest_sha3_256
                                != authorization.chunk_digest_sha3_256()
                            || manifest.por_root != authorization.por_root()
                            || format!(
                                "{}.{}@{}",
                                manifest.chunking.namespace,
                                manifest.chunking.name,
                                manifest.chunking.semver
                            ) != authorization.chunker_handle()
                            || plan.chunk_profile
                                != sorafs_manifest::validate_registered_chunker_profile(
                                    &manifest.chunking,
                                )
                                .map_err(|_| rejected())?
                                .profile
                        {
                            continue;
                        }
                        let read_resolver = Arc::clone(&resolver);
                        let read_request = wire;
                        let reader = AssignedChunkReaderV1 {
                            resolver,
                            client,
                            candidates,
                            wire,
                            header,
                            deadline,
                            index: 0,
                            chunk: io::Cursor::new(Vec::new()),
                        };
                        // Every read rechecks native authority and its chunk digest. Ordinary storage
                        // ingest validates the whole CAR, payload, PoR and PDP before admitting the pin.
                        return Ok(VerifiedProviderIngestPayloadV1::new(
                            manifest,
                            plan,
                            Box::new(AuthorizedReaderV1 {
                                inner: reader,
                                deadline,
                                failed: false,
                                authorize: move || {
                                    let state = read_resolver.state().map_err(|_| rejected())?;
                                    authorize_provider_source_v1(
                                        &state.view(),
                                        &read_resolver.completion_signer,
                                        &read_request,
                                        now()? / 1000,
                                    )
                                    .map_err(|_| rejected())
                                },
                            }),
                        ));
                    }
                    Err(ProviderIngestSourceFetchErrorV1::Unavailable)
                }),
            )
            .await
            .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)?
        })
    }
}

fn fetch_response(
    resolver: &NativeResolverV1,
    client: &reqwest::blocking::Client,
    endpoint: &Url,
    request: &SorafsAssignedSourceRequestV1,
    deadline: Instant,
) -> std::result::Result<ProviderSourceResponseV1, ProviderIngestSourceFetchErrorV1> {
    let state = resolver.state().map_err(|_| rejected())?;
    authorize_provider_source_v1(
        &state.view(),
        &resolver.completion_signer,
        request,
        now()? / 1000,
    )
    .map_err(|_| rejected())?;
    let url = endpoint
        .join("v1/sorafs/provider/source")
        .map_err(|_| rejected())?;
    let bytes = norito::to_bytes(request).map_err(|_| rejected())?;
    let timestamp = now()?;
    let mut entropy = [0; 32];
    OsRng.try_fill_bytes(&mut entropy).map_err(|_| rejected())?;
    let nonce = hex::encode(entropy);
    let message = iroha_torii::canonical_network_request_signature_message(
        state.network_id_ref(),
        &reqwest::Method::POST,
        &url.as_str().parse().map_err(|_| rejected())?,
        &bytes,
        timestamp,
        &nonce,
    )
    .map_err(|_| rejected())?;
    let signature =
        Signature::try_new(resolver.key.private_key(), &message).map_err(|_| rejected())?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(rejected)?;
    let mut response = client
        .post(url)
        .timeout(remaining)
        .header("Content-Type", "application/x-norito")
        .header("Accept-Encoding", "identity")
        .header(
            "X-Iroha-Account",
            resolver
                .completion_signer
                .to_canonical_hex()
                .map_err(|_| rejected())?,
        )
        .header("X-Iroha-Signature", STANDARD.encode(signature.payload()))
        .header("X-Iroha-Timestamp-Ms", timestamp.to_string())
        .header("X-Iroha-Nonce", nonce)
        .body(bytes)
        .send()
        .map_err(|_| rejected())?;
    if !response.status().is_success()
        || response.headers().get_all("Content-Type").iter().count() != 1
        || response
            .headers()
            .get("Content-Type")
            .is_none_or(|value| value != "application/x-norito")
        || response
            .headers()
            .get("Content-Encoding")
            .is_some_and(|value| value != "identity")
        || response
            .content_length()
            .is_some_and(|length| length > PROVIDER_SOURCE_RESPONSE_MAX_BYTES_V1 as u64)
    {
        return Err(rejected());
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(PROVIDER_SOURCE_RESPONSE_MAX_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| rejected())?;
    if Instant::now() >= deadline {
        return Err(rejected());
    }
    let result = ProviderSourceResponseV1::decode(&bytes).map_err(|_| rejected())?;
    if !response_matches_request(&result, request) {
        return Err(rejected());
    }
    authorize_provider_source_v1(
        &state.view(),
        &resolver.completion_signer,
        request,
        now()? / 1000,
    )
    .map_err(|_| rejected())?;
    Ok(result)
}

fn response_matches_request(
    response: &ProviderSourceResponseV1,
    request: &SorafsAssignedSourceRequestV1,
) -> bool {
    match (response, request.chunk_index) {
        (ProviderSourceResponseV1::Metadata(header), None) => {
            let provider_matches = header.provider_id == request.target_provider;
            provider_matches
                && header.order_id == request.order_id
                && header.assignment_revision == request.assignment_revision
        }
        (ProviderSourceResponseV1::Chunk(upload), Some(index)) if upload.index == index => true,
        _ => false,
    }
}

// A payload may be consumed long after its HTTP response arrived. Guard buffered reads and EOF,
// and latch failures so a later authority change cannot revive an interrupted ingest stream.
struct AuthorizedReaderV1<R, F> {
    inner: R,
    deadline: Instant,
    failed: bool,
    authorize: F,
}
impl<R: Read, F: FnMut() -> std::result::Result<(), ProviderIngestSourceFetchErrorV1>> Read
    for AuthorizedReaderV1<R, F>
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed || Instant::now() >= self.deadline || (self.authorize)().is_err() {
            self.failed = true;
            return Err(io::Error::other(
                "native assigned source authority unavailable",
            ));
        }
        match self.inner.read(output) {
            Ok(count) => {
                if Instant::now() >= self.deadline || (self.authorize)().is_err() {
                    self.failed = true;
                    Err(io::Error::other(
                        "native assigned source authority unavailable",
                    ))
                } else {
                    Ok(count)
                }
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
}

struct AssignedChunkReaderV1 {
    resolver: Arc<NativeResolverV1>,
    client: reqwest::blocking::Client,
    candidates: Vec<([u8; 32], Url)>,
    wire: SorafsAssignedSourceRequestV1,
    header: PublisherSourceHeaderV1,
    deadline: Instant,
    index: usize,
    chunk: io::Cursor<Vec<u8>>,
}
impl Read for AssignedChunkReaderV1 {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let count = self.chunk.read(output)?;
            if count != 0 {
                return Ok(count);
            }
            if self.index == self.header.chunks.len() {
                return Ok(0);
            }
            self.wire.chunk_index = Some(
                u32::try_from(self.index)
                    .map_err(|_| io::Error::other("native source index rejected"))?,
            );
            let mut verified = None;
            for (provider, endpoint) in &self.candidates {
                self.wire.source_provider = *provider;
                if let Ok(response) = fetch_response(
                    &self.resolver,
                    &self.client,
                    endpoint,
                    &self.wire,
                    self.deadline,
                ) && let ProviderSourceResponseV1::Chunk(upload) = response
                    && verified_chunk(&self.header, self.index, &upload)
                {
                    verified = Some(upload.bytes);
                    break;
                }
            }
            self.chunk = io::Cursor::new(
                verified.ok_or_else(|| io::Error::other("native assigned source unavailable"))?,
            );
            self.index += 1;
        }
    }
}

fn verified_chunk(
    header: &PublisherSourceHeaderV1,
    index: usize,
    upload: &sorafs_car::publisher::PublisherSourceUploadV1,
) -> bool {
    usize::try_from(upload.index).ok() == Some(index)
        && header.chunks.get(index).is_some_and(|chunk| {
            upload.bytes.len() == chunk.length as usize
                && blake3::hash(&upload.bytes).as_bytes() == &chunk.digest
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_chunk_matches_the_retained_ordinal_length_and_commitment() {
        use sorafs_car::publisher::{PublisherSourceChunkV1, PublisherSourceUploadV1};
        let bytes = b"one authenticated chunk".to_vec();
        let header = PublisherSourceHeaderV1 {
            version: 1,
            provider_id: [1; 32],
            order_id: [2; 32],
            assignment_revision: 1,
            manifest_bytes: Vec::new(),
            payload_digest: *blake3::hash(&bytes).as_bytes(),
            chunks: vec![PublisherSourceChunkV1 {
                offset: 0,
                length: u32::try_from(bytes.len()).expect("fixture chunk fits u32"),
                digest: *blake3::hash(&bytes).as_bytes(),
            }],
            files: Vec::new(),
        };
        let mut upload = PublisherSourceUploadV1 { index: 0, bytes };
        assert!(verified_chunk(&header, 0, &upload));
        assert!(!verified_chunk(&header, 1, &upload));
        upload.index = 1;
        assert!(!verified_chunk(&header, 0, &upload));
        upload.index = 0;
        upload.bytes[0] ^= 0x80;
        assert!(!verified_chunk(&header, 0, &upload));
        upload.bytes[0] ^= 0x80;
        upload.bytes.pop();
        assert!(!verified_chunk(&header, 0, &upload));

        let mut request = SorafsAssignedSourceRequestV1 {
            target_provider: header.provider_id,
            source_provider: [3; 32],
            order_id: header.order_id,
            assignment_revision: header.assignment_revision,
            manifest_digest: [4; 32],
            chunk_index: None,
            floor_height: 1,
            floor_block_hash: [5; 32],
        };
        let metadata = ProviderSourceResponseV1::Metadata(header);
        let chunk = ProviderSourceResponseV1::Chunk(upload);
        assert!(response_matches_request(&metadata, &request));
        assert!(!response_matches_request(&chunk, &request));
        request.chunk_index = Some(0);
        assert!(!response_matches_request(&metadata, &request));
        assert!(response_matches_request(&chunk, &request));
        request.chunk_index = Some(1);
        assert!(!response_matches_request(&chunk, &request));
        request.chunk_index = None;
        request.assignment_revision += 1;
        assert!(!response_matches_request(&metadata, &request));
    }
    #[test]
    fn native_source_origins_require_explicit_tls_or_local_loopback() {
        for source in [
            "https://provider.example/",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080/",
        ] {
            assert!(origin(source).is_ok());
        }
        for source in [
            "http://localhost:8080/",
            "http://provider.example/",
            "https://user@provider.example/",
            "https://provider.example/path",
            "https://provider.example/?q=secret",
            "https://provider.example/#secret",
        ] {
            assert!(origin(source).is_err());
        }
    }
    #[test]
    fn native_buffered_reads_and_eof_recheck_authority_with_sticky_failure() {
        let permitted = std::cell::Cell::new(true);
        let mut reader = AuthorizedReaderV1 {
            inner: io::Cursor::new(b"payload"),
            deadline: Instant::now() + Duration::from_secs(30),
            failed: false,
            authorize: || {
                if permitted.get() {
                    Ok(())
                } else {
                    Err(rejected())
                }
            },
        };
        assert_eq!(reader.read(&mut [0; 2]).unwrap(), 2);
        permitted.set(false);
        assert!(reader.read(&mut [0; 2]).is_err());
        permitted.set(true);
        assert!(reader.read(&mut [0; 2]).is_err());
        let mut eof = AuthorizedReaderV1 {
            inner: io::empty(),
            deadline: Instant::now(),
            failed: false,
            authorize: || Ok(()),
        };
        assert!(eof.read(&mut [0; 1]).is_err());
    }
}
