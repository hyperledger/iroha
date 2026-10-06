#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration smoke test: submit a proof attachment and query its record via Torii.
use eyre::{Report, Result};
use integration_tests::sandbox;
#[path = "proof_fixtures.rs"]
mod proof_fixtures;
use iroha_data_model::{
    isi::verifying_keys,
    permission::Permission,
    prelude::{Grant, Json},
    proof::{ProofAttachment, ProofBox, ProofId, ProofStatus},
};
use iroha_test_network::{NetworkBuilder, NetworkPeer};
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
use proof_fixtures::confidential_attachment;
use reqwest::Client as HttpClient;
use std::{convert::TryFrom as _, str::FromStr as _, time::Duration};
#[path = "proofs/fastpq_finalized_transcripts.rs"]
mod fastpq_finalized_transcripts;
#[path = "proofs/full_tree_wallet.rs"]
mod full_tree_wallet;
fn compute_proof_hash(backend: &str, bytes: &[u8]) -> [u8; 32] {
    iroha_core_zk::hash_proof(&ProofBox::new(backend.into(), bytes.to_vec()))
}
fn parse_hex32(input: &str) -> Option<[u8; 32]> {
    let hex = input.strip_prefix("0x").unwrap_or(input);
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_char(*bytes.get(2 * i)?)?;
        let lo = hex_char(*bytes.get(2 * i + 1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}
fn hex_char(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}
fn parse_proof_id_from_json(value: &norito::json::Value) -> Option<ProofId> {
    match value {
        norito::json::Value::String(s) => ProofId::from_str(s).ok(),
        norito::json::Value::Object(map) => {
            let backend = map.get("backend")?.as_str()?;
            let proof_hash = map
                .get("proof_hash")
                .and_then(|v| match v {
                    norito::json::Value::String(s) => parse_hex32(s),
                    norito::json::Value::Array(arr) if arr.len() == 32 => {
                        let mut out = [0u8; 32];
                        for (i, item) in arr.iter().enumerate() {
                            let n = u8::try_from(item.as_u64()?).ok()?;
                            out[i] = n;
                        }
                        Some(out)
                    }
                    _ => None,
                })
                .unwrap_or([0; 32]);
            Some(ProofId {
                backend: backend.into(),
                proof_hash,
            })
        }
        _ => None,
    }
}
fn is_retryable_snapshot_error(err: &Report) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .and_then(reqwest::Error::status)
            .is_some_and(|status| {
                status == reqwest::StatusCode::NOT_FOUND
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            })
    })
}
fn is_tx_confirmation_timeout(err: &Report) -> bool {
    const NEEDLES: [&str; 4] = [
        "haven't got tx confirmation within",
        "transaction queued for too long",
        "Connection dropped without `Committed/Applied` or `Rejected` event",
        "fallback status check failed",
    ];
    err.chain().any(|cause| {
        let text = cause.to_string();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}
fn is_transient_client_error(err: &Report) -> bool {
    const NEEDLES: [&str; 6] = [
        "Failed to send http",
        "error sending request for url",
        "operation timed out",
        "Connection refused",
        "connection closed",
        "connection reset",
    ];
    err.chain().any(|cause| {
        let text = cause.to_string();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}
fn is_duplicate_tx_error(err: &Report) -> bool {
    const NEEDLES: [&str; 6] = [
        "PRTRY:ALREADY_COMMITTED",
        "PRTRY:ALREADY_ENQUEUED",
        "already_committed",
        "already_enqueued",
        "transaction already committed",
        "transaction already present in the queue",
    ];
    err.chain().any(|cause| {
        let text = cause.to_string();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}
fn active_halo2_vk_registration(
    vk_name: &str,
) -> (ProofAttachment, verifying_keys::RegisterVerifyingKey) {
    confidential_attachment("proof-record", vk_name)
}
async fn fetch_proof_snapshot(url: reqwest::Url) -> Result<(String, [u8; 32], ProofStatus)> {
    let response = HttpClient::new()
        .get(url)
        .header("Accept", "application/x-norito, application/json")
        .send()
        .await
        .map_err(Report::new)?
        .error_for_status()
        .map_err(Report::new)?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let bytes = response.bytes().await.map_err(Report::new)?;
    if bytes.len() >= norito::core::Header::SIZE && bytes.starts_with(&norito::core::MAGIC) {
        let record: iroha_data_model::proof::ProofRecord =
            norito::decode_from_bytes(&bytes).map_err(Report::new)?;
        return Ok((
            record.id.backend.clone(),
            record.id.proof_hash,
            record.status,
        ));
    }
    if content_type.starts_with("application/json") || bytes.starts_with(b"{") {
        let value: norito::json::Value = norito::json::from_slice(&bytes).map_err(Report::new)?;
        let status_str = value
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Report::msg("missing status field in proof response"))?;
        let status = match status_str {
            "Submitted" => ProofStatus::Submitted,
            "Verified" => ProofStatus::Verified,
            "Rejected" => ProofStatus::Rejected,
            other => {
                return Err(Report::msg(format!(
                    "unexpected proof status value: {other}"
                )));
            }
        };
        let proof_id = value
            .get("id")
            .and_then(parse_proof_id_from_json)
            .ok_or_else(|| Report::msg("missing id field in proof response"))?;
        return Ok((proof_id.backend.clone(), proof_id.proof_hash, status));
    }
    Err(Report::msg("unexpected proof response payload"))
}
#[tokio::test]
async fn submit_proof_and_query_record() -> Result<()> {
    let (attachment, vk_registration) = active_halo2_vk_registration("proof_vk");
    // Start a minimal network
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new()
            .with_peers(4)
            .with_genesis_instruction(Grant::account_permission(
                Permission::new("CanManageVerifyingKeys".into(), Json::new(())),
                SAMPLE_GENESIS_ACCOUNT_ID.clone(),
            ))
            .with_genesis_instruction(vk_registration),
        stringify!(submit_proof_and_query_record),
    )
    .await?
    else {
        return Ok(());
    };
    let client = network.client();
    let mut peer_clients = network
        .peers()
        .iter()
        .map(NetworkPeer::client)
        .collect::<Vec<_>>();
    if peer_clients.is_empty() {
        peer_clients.push(client.clone());
    }
    let backend = "halo2/ipa";
    let proof_bytes = attachment.proof.bytes.clone();
    let isi = iroha_data_model::isi::zk::VerifyProof::new(attachment);
    // Submit the transaction to all peers so one healthy peer can accept it
    // even if another peer is timing out under load.
    let tx = {
        let account = client.account_client();
        let mut payload =
            account.prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [isi],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                iroha_model_base::metadata::Metadata::default(),
            ))?;
        let quote = account
            .quote_fees(iroha::client::FeeQuoteRequest::AccountSignature { payload: &payload })
            .await?;
        eyre::ensure!(
            payload
                .fee_payment
                .has_same_payer_and_gas_bound(&quote.intent),
            "fee quote changed selected payer or gas limit"
        );
        payload.fee_payment = quote.intent;
        account.sign_transaction(payload)?
    };
    let mut accepted = false;
    let mut submit_last_err: Option<Report> = None;
    for submit_client in &peer_clients {
        match submit_client.submit_transaction(&tx) {
            Ok(_) => accepted = true,
            Err(err) if is_duplicate_tx_error(&err) => accepted = true,
            Err(err) if is_transient_client_error(&err) => {
                submit_last_err = Some(err);
            }
            Err(err) if is_tx_confirmation_timeout(&err) => {
                submit_last_err = Some(err);
            }
            Err(err) => {
                let submit: Result<()> = Err(err);
                let Some(()) =
                    sandbox::handle_result(submit, "submit_proof_and_query_record::submit")?
                else {
                    return Ok(());
                };
            }
        }
    }
    if !accepted {
        let submit: Result<()> =
            Err(submit_last_err.unwrap_or_else(|| Report::msg("all peers unreachable")));
        let Some(()) = sandbox::handle_result(submit, "submit_proof_and_query_record::submit")?
        else {
            return Ok(());
        };
    }
    let Some(_) = sandbox::handle_result(
        network.ensure_blocks(2).await,
        "submit_proof_and_query_record::wait_blocks",
    )?
    else {
        return Ok(());
    };
    // Compute the expected ProofId string for GET /v1/proofs/:id
    let proof_hash = compute_proof_hash(backend, &proof_bytes);
    let pid = iroha_data_model::proof::ProofId {
        backend: backend.into(),
        proof_hash,
    };
    let pid_str = format!("{pid}");
    // Query Torii
    let proof_path = ["v1", "proofs", pid_str.as_str()];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    let mut last_err: Option<Report> = None;
    let mut next_client_idx = 0usize;
    let snapshot = loop {
        let mut url = peer_clients[next_client_idx % peer_clients.len()]
            .client()
            .endpoint()
            .clone();
        next_client_idx = next_client_idx.wrapping_add(1);
        {
            let mut segments = url
                .path_segments_mut()
                .expect("torii_url must be a base URL");
            segments.clear();
            segments.extend(proof_path);
        }
        match fetch_proof_snapshot(url).await {
            Ok((backend_got, proof_hash_got, status_got))
                if status_got == iroha_data_model::proof::ProofStatus::Verified =>
            {
                break Ok((backend_got, proof_hash_got, status_got));
            }
            Ok((_backend_got, _proof_hash_got, status_got))
                if status_got == iroha_data_model::proof::ProofStatus::Rejected =>
            {
                break Err(Report::msg("proof record reached Rejected status"));
            }
            Ok(_) => {
                if tokio::time::Instant::now() >= deadline {
                    break Err(Report::msg(
                        "timed out waiting for proof record to reach Verified status",
                    ));
                }
            }
            Err(err) => {
                if is_retryable_snapshot_error(&err) {
                    last_err = Some(err);
                    if tokio::time::Instant::now() >= deadline {
                        break Err(Report::msg(
                            "timed out waiting for proof record to become queryable",
                        ));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                if tokio::time::Instant::now() >= deadline {
                    break Err(err);
                }
                last_err = Some(err);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    .or_else(|err| match last_err {
        Some(last_err) => Err(err.wrap_err(last_err)),
        None => Err(err),
    });
    let Some((backend_got, proof_hash_got, status_got)) =
        sandbox::handle_result(snapshot, "submit_proof_and_query_record::fetch_record")?
    else {
        return Ok(());
    };
    // Validate record fields
    assert_eq!(backend_got, backend);
    assert_eq!(proof_hash_got, proof_hash);
    assert_eq!(status_got, iroha_data_model::proof::ProofStatus::Verified);
    Ok(())
}
