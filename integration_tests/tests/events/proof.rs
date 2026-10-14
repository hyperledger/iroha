//! Integration tests for ZK proof events over the Torii event stream.
use assert_matches::assert_matches;
use eyre::{Result, eyre};
use futures_util::StreamExt;
use integration_tests::sandbox;
use iroha::blocking::Client;
use iroha::data_model::prelude::*;
#[path = "../proof_fixtures.rs"]
mod proof_fixtures;
use iroha_data_model::events::data::prelude::ProofEventFilter;
use iroha_data_model::{isi::verifying_keys, proof::ProofAttachment};
use iroha_test_network::*;
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
use proof_fixtures::{confidential_attachment, rejected_confidential_attachment};
use std::time::Duration;
use tokio::{task::spawn_blocking, time::timeout};
const CLIENT_STATUS_TIMEOUT: Duration = Duration::from_secs(600);
const PROOF_EVENT_TIMEOUT: Duration = Duration::from_secs(600);
fn halo2_attachment_and_registration(
    vk_name: &str,
) -> (ProofAttachment, verifying_keys::RegisterVerifyingKey) {
    confidential_attachment("event-verified", vk_name)
}
fn rejected_halo2_attachment() -> ProofAttachment {
    rejected_confidential_attachment("event-rejected", "event_vk")
}
fn client_with_timeout(network: &Network) -> Client {
    integration_tests::sync::rebind_blocking_client(&network.client(), |client| {
        client.transaction_status_timeout = CLIENT_STATUS_TIMEOUT;
        client.transaction_ttl = Some(CLIENT_STATUS_TIMEOUT + Duration::from_secs(5));
    })
}
fn proof_event_timeout(network: &Network) -> Duration {
    network.sync_timeout().max(PROOF_EVENT_TIMEOUT)
}
fn proof_network_builder() -> NetworkBuilder {
    let (_, verified_vk) = halo2_attachment_and_registration("event_vk");
    NetworkBuilder::new()
        .with_peers(4)
        .with_genesis_instruction(Grant::account_permission(
            Permission::new("CanManageVerifyingKeys".into(), Json::new(())),
            SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        ))
        .with_genesis_instruction(verified_vk)
}
fn is_tx_confirmation_timeout(err: &eyre::Report) -> bool {
    const NEEDLES: [&str; 3] = [
        "haven't got tx confirmation within",
        "transaction queued for too long",
        "Connection dropped without `Committed/Applied` or `Rejected` event",
    ];
    err.chain().any(|cause| {
        let text = cause.to_string();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}
async fn verify_proof_emits_event(
    network: &Network,
    context: &'static str,
    attachment: iroha::data_model::proof::ProofAttachment,
    expect_verified: bool,
) -> Result<()> {
    network.ensure_blocks(1).await?;
    let client = client_with_timeout(network);
    let mut events = tokio::time::timeout(
        proof_event_timeout(network),
        client
            .account_client()
            .events()
            .subscribe([DataEventFilter::Proof(ProofEventFilter::new())]),
    )
    .await
    .map_err(|_| eyre!("{context}: timed out opening proof event stream"))??;
    let verify: InstructionBox = iroha::data_model::isi::zk::VerifyProof::new(attachment).into();
    {
        let submit_client = client.clone();
        let submit_result = spawn_blocking(move || {
            submit_client.submit_all(
                [verify],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        })
        .await?;
        if let Err(err) = submit_result {
            if is_tx_confirmation_timeout(&err) {
                eprintln!(
                    "warning: {context} confirmation timed out; continuing to wait for events"
                );
            } else {
                return Err(err);
            }
        }
    }
    network.ensure_blocks(2).await?;
    let result = async {
        let proof_event = timeout(proof_event_timeout(network), async {
            loop {
                let ev = events.next().await.expect("event stream open")?;
                if let EventBox::Data(event) = ev
                    && let DataEvent::Proof(pe) = event.as_ref()
                {
                    break Ok::<_, eyre::Report>(pe.clone());
                }
            }
        })
        .await??;
        if expect_verified {
            assert_matches!(
                proof_event,
                iroha::data_model::events::data::proof::ProofEvent::Verified(_)
            );
        } else {
            assert_matches!(
                proof_event,
                iroha::data_model::events::data::proof::ProofEvent::Rejected(_)
            );
        }
        Ok(())
    }
    .await;
    events.close().await?;
    result
}
#[tokio::test]
async fn proof_event_scenarios() -> Result<()> {
    let _override_guard = sandbox::override_network_parallelism(Some(true), None);
    let Some(network) =
        sandbox::start_network_async_or_skip(proof_network_builder(), "proof_event_scenarios")
            .await?
    else {
        return Ok(());
    };
    let result: Result<()> = async {
        verify_proof_emits_event(
            &network,
            stringify!(verify_proof_emits_verified_event),
            halo2_attachment_and_registration("event_vk").0,
            true,
        )
        .await?;
        verify_proof_emits_event(
            &network,
            stringify!(verify_proof_emits_rejected_event),
            rejected_halo2_attachment(),
            false,
        )
        .await?;
        Ok(())
    }
    .await;
    if sandbox::handle_result(result, stringify!(proof_event_scenarios))?.is_none() {
        return Ok(());
    }
    Ok(())
}
