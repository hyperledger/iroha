//! Bounded canonical account transport and independent publication verification for real peers.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use eyre::{Result, ensure};
use iroha::{
    blocking::Client,
    crypto::{KeyPair, Signature},
};
use iroha_data_model::{
    isi::sorafs::AssertSorafsPublicationV1,
    prelude::*,
    sorafs::{
        pin_registry::{ManifestDigest, ReplicationOrderStatus},
        publication::{
            PUBLICATION_PROOF_MAX_BYTES_V1, SorafsPublicationPreparationV1,
            SorafsPublicationProofRequestV1, SorafsPublicationProofV1,
            verify_sorafs_publication_v1,
        },
    },
    sumeragi_finality::{
        FinalityValidator, MAX_FINALITY_BLOCK_BYTES, SumeragiFinalityCheckpoint,
        SumeragiFinalityProof, SumeragiFinalityVerifier,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_test_network::Network;
use sorafs_car::{
    CarBuildPlan,
    publisher::{
        PublisherSourceChunkRequestV1, PublisherSourceHeaderV1, PublisherSourceRequestV1,
        PublisherSourceUploadV1,
    },
};
use sorafs_manifest::ManifestV1;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, timeout_at};

static NONCE: AtomicU64 = AtomicU64::new(0);
pub const DEADLINE: Duration = Duration::from_secs(180);

pub fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()?)
}

pub async fn bytes(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= maximum as u64),
        "publication response length exceeds bound"
    );
    ensure!(
        response
            .headers()
            .get("Content-Encoding")
            .is_none_or(|encoding| encoding == "identity"),
        "unexpected content encoding"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= maximum.saturating_sub(bytes.len()),
            "publication response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn post(
    http: &reqwest::Client,
    network: &NetworkId,
    base: &str,
    key: &KeyPair,
    path: &str,
    body: Vec<u8>,
) -> Result<reqwest::Response> {
    post_with_headers(
        http,
        network,
        base,
        key,
        path,
        body,
        ("application/x-norito", None),
    )
    .await
}

/// Send exact canonical Norito JSON with the compliance route's request-bound replay key.
pub async fn post_json(
    http: &reqwest::Client,
    network: &NetworkId,
    base: &str,
    key: &KeyPair,
    path: &str,
    body: Vec<u8>,
    idempotency_key: &str,
) -> Result<reqwest::Response> {
    post_with_headers(
        http,
        network,
        base,
        key,
        path,
        body,
        ("application/json", Some(idempotency_key)),
    )
    .await
}

async fn post_with_headers(
    http: &reqwest::Client,
    network: &NetworkId,
    base: &str,
    key: &KeyPair,
    path: &str,
    body: Vec<u8>,
    (content_type, idempotency_key): (&str, Option<&str>),
) -> Result<reqwest::Response> {
    let url = reqwest::Url::parse(base)?.join(path)?;
    let timestamp = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let nonce = format!(
        "publication-{timestamp}-{}",
        NONCE.fetch_add(1, Ordering::Relaxed)
    );
    let message = iroha_torii::canonical_network_request_signature_message(
        network,
        &reqwest::Method::POST,
        &url.as_str().parse()?,
        &body,
        timestamp,
        &nonce,
    )?;
    let signature = Signature::try_new(key.private_key(), &message)?;
    let mut request = http
        .post(url)
        .header("Content-Type", content_type)
        .header("Accept-Encoding", "identity")
        .header(
            "X-Iroha-Account",
            AccountId::new(key.public_key().clone()).to_canonical_hex()?,
        )
        .header("X-Iroha-Signature", STANDARD.encode(signature.payload()))
        .header("X-Iroha-Timestamp-Ms", timestamp.to_string())
        .header("X-Iroha-Nonce", nonce)
        .body(body);
    if let Some(value) = idempotency_key {
        request = request.header("Idempotency-Key", value);
    }
    Ok(request.send().await?)
}

pub fn decode<
    T: for<'de> norito::NoritoDeserialize<'de> + norito::NoritoSerialize + norito::NoritoSchema,
>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T> {
    ensure!(bytes.len() <= maximum, "publication carrier exceeds limit");
    Ok(norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(maximum, maximum, maximum, maximum * 4, 64),
    )?)
}

/// Start trust from the independently constructed signed genesis and its registered roster.
/// The current genesis certificate has no QC; certified successors authenticate its result binding.
pub async fn genesis_checkpoint(
    http: &reqwest::Client,
    network: &Network,
) -> Result<SumeragiFinalityCheckpoint> {
    let provisioned = network.native_genesis_provisioning_bundle()?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        norito::json::from_slice(&provisioned.manifest_json)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &provisioned.signed_wire,
        &manifest,
        &provisioned.public_key,
        provisioned.block_hash,
    )?;
    let validators = genesis
        .validator_pops()
        .iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key: public_key.clone(),
            proof_of_possession: proof_of_possession.clone(),
        })
        .collect::<Vec<_>>();
    ensure!(
        validators.len() == 4,
        "qualification requires exactly four independently registered validators"
    );
    let mut verifier =
        SumeragiFinalityVerifier::new(genesis.block(), network.chain_id().as_ref(), validators)?;
    ensure!(
        NetworkId::from_genesis_hash(genesis.expected_hash()) == network.network_id(),
        "independently constructed genesis differs from network identity"
    );
    let deadline = Instant::now() + DEADLINE;
    timeout_at(deadline, async {
        loop {
            let path = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY
                .path()
                .replace("{height}", "1");
            let response = http
                .get(format!(
                    "{}{}",
                    network.peers()[0].torii_url().trim_end_matches('/'),
                    path
                ))
                .header("Accept", "application/x-norito")
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND
                || response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            ensure!(
                response.status().is_success(),
                "genesis finality endpoint rejected: {}",
                response.status()
            );
            let maximum = MAX_FINALITY_BLOCK_BYTES + 4 * 1024 * 1024;
            let proof: SumeragiFinalityProof = decode(&bytes(response, maximum).await?, maximum)?;
            let authenticated = verifier.verify(&proof)?;
            ensure!(
                authenticated.height() == 1
                    && authenticated.block().hash() == genesis.expected_hash(),
                "queried checkpoint changed independent signed-genesis identity"
            );
            let checkpoint = verifier.export_checkpoint(&proof)?;
            ensure!(
                Instant::now() < deadline,
                "genesis checkpoint verification exceeded its deadline"
            );
            return Ok(checkpoint);
        }
    })
    .await?
}

pub async fn preparation(
    http: &reqwest::Client,
    network: &NetworkId,
    base: &str,
    publisher: &KeyPair,
    digest: ManifestDigest,
    complete: bool,
) -> Result<SorafsPublicationPreparationV1> {
    timeout_at(Instant::now() + DEADLINE, async {
        loop {
            let response = post(
                http,
                network,
                base,
                publisher,
                "v1/sorafs/publish/prepare",
                norito::to_bytes(&digest)?,
            )
            .await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND
                || response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
                || response.status() == reqwest::StatusCode::ACCEPTED
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            ensure!(
                response.status().is_success(),
                "preparation rejected: {}",
                response.status()
            );
            let row: SorafsPublicationPreparationV1 =
                decode(&bytes(response, 2 * 1024 * 1024).await?, 2 * 1024 * 1024)?;
            ensure!(
                row.pin.digest == digest
                    && row.pin.submitted_by == AccountId::new(publisher.public_key().clone()),
                "preparation identity substituted"
            );
            if complete && !matches!(row.order.status, ReplicationOrderStatus::Completed(_)) {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            return Ok(row);
        }
    })
    .await?
}

pub async fn prove(
    http: &reqwest::Client,
    client: &Client,
    base: &str,
    publisher: &KeyPair,
    row: &SorafsPublicationPreparationV1,
    floor: &SumeragiFinalityCheckpoint,
    completed: bool,
) -> Result<SumeragiFinalityCheckpoint> {
    let deadline = Instant::now() + DEADLINE;
    let network = *client.account_client().network_id();
    let challenge = *blake3::hash(&norito::to_bytes(&(
        row.pin.digest,
        completed,
        NONCE.fetch_add(1, Ordering::Relaxed),
    ))?)
    .as_bytes();
    let signed = super::sorafs_network::prepare_transaction(
        client,
        [AssertSorafsPublicationV1 {
            manifest_digest: row.pin.digest,
            order_id: row.order.order_id,
            assignment_revision: row.order.assignment_revision,
            canonical_order_digest: *blake3::hash(&row.order.canonical_order).as_bytes(),
            require_complete: completed,
            challenge,
            minimum_height: floor.height(),
            minimum_block_hash: *floor.block_hash().as_ref(),
        }],
        Metadata::default(),
    )
    .await?;
    client
        .account_client()
        .submit_transaction_and_wait(&signed)
        .await?;
    let selector = SorafsPublicationProofRequestV1 {
        entry_hash: *signed.hash_as_entrypoint().as_ref(),
        floor_height: floor.height(),
        floor_block_hash: *floor.block_hash().as_ref(),
    };
    timeout_at(deadline, async {
        loop {
            let response = post(
                http,
                &network,
                base,
                publisher,
                "v1/sorafs/publish/proof",
                norito::to_bytes(&selector)?,
            )
            .await?;
            if response.status() == reqwest::StatusCode::ACCEPTED {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            ensure!(
                response.status().is_success(),
                "publication proof rejected: {}",
                response.status()
            );
            let proof: SorafsPublicationProofV1 = decode(
                &bytes(response, PUBLICATION_PROOF_MAX_BYTES_V1).await?,
                PUBLICATION_PROOF_MAX_BYTES_V1,
            )?;
            let authenticated = verify_sorafs_publication_v1(&network, floor, &signed, &proof)?;
            ensure!(
                authenticated.completed() == completed,
                "publication phase substituted"
            );
            let mut malformed = proof.clone();
            malformed
                .lineage
                .last_mut()
                .ok_or_else(|| eyre::eyre!("publication lineage missing"))?
                .block_wire
                .clear();
            ensure!(
                verify_sorafs_publication_v1(&network, floor, &signed, &malformed).is_err(),
                "unexecuted claim accepted"
            );
            ensure!(
                Instant::now() < deadline,
                "publication verification exceeded its deadline"
            );
            return Ok(authenticated.finality().clone());
        }
    })
    .await?
}

pub async fn stage(
    http: &reqwest::Client,
    network: &NetworkId,
    base: &str,
    publisher: &KeyPair,
    provider: [u8; 32],
    row: &SorafsPublicationPreparationV1,
    (manifest, plan, payload): (&ManifestV1, &CarBuildPlan, &[u8]),
) -> Result<()> {
    let header = PublisherSourceHeaderV1::new(
        provider,
        *row.order.order_id.as_bytes(),
        row.order.assignment_revision,
        manifest,
        plan,
    )?;
    let header_digest = header.canonical_digest()?;
    let manifest_digest = *manifest.digest()?.as_bytes();
    let requests = std::iter::once(PublisherSourceRequestV1::Metadata(header)).chain(
        plan.chunks.iter().enumerate().map(|(index, chunk)| {
            PublisherSourceRequestV1::Chunk(PublisherSourceChunkRequestV1 {
                provider_id: provider,
                order_id: *row.order.order_id.as_bytes(),
                assignment_revision: row.order.assignment_revision,
                manifest_digest,
                header_digest,
                upload: PublisherSourceUploadV1 {
                    index: u32::try_from(index).expect("fixture chunk index fits u32"),
                    bytes: payload[usize::try_from(chunk.offset)
                        .expect("fixture chunk offset fits usize")
                        ..usize::try_from(chunk.offset).expect("fixture chunk offset fits usize")
                            + usize::try_from(chunk.length)
                                .expect("fixture chunk length fits usize")]
                        .to_vec(),
                },
            })
        }),
    );
    for request in requests {
        let response = post(
            http,
            network,
            base,
            publisher,
            "v1/sorafs/publish/source",
            norito::encode_canonical(&request)?,
        )
        .await?;
        ensure!(
            response.status() == reqwest::StatusCode::NO_CONTENT,
            "staging rejected: {}",
            response.status()
        );
    }
    Ok(())
}
