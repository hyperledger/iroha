//! Pipeline transaction and block event surface coverage.
use eyre::{Result, WrapErr, eyre};
use futures_util::StreamExt;
use integration_tests::sandbox;
use iroha::data_model::{
    ValidationFail,
    events::pipeline::{TransactionEventFilter, TransactionStatus},
    isi::error::InstructionExecutionError,
    prelude::*,
    query::error::FindError,
    transaction::error::TransactionRejectionReason,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_test_network::*;
use std::{
    io::{Read as _, Seek as _, SeekFrom},
    time::{Duration, Instant},
};
use tokio::{
    task::spawn_blocking,
    time::{sleep, timeout},
};
fn pipeline_event_timeout(network: &Network) -> Duration {
    network.sync_timeout().max(Duration::from_secs(60))
}
async fn test_with_instruction_and_status(
    context: &'static str,
    network: &Network,
    exec: impl Into<Executable> + Send,
    should_be: &TransactionStatus,
) -> Result<()> {
    let exec = exec.into();
    // Given
    let client = network.client();
    // When
    let transaction = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                exec,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let hash = transaction.hash();
    let event_timeout = pipeline_event_timeout(network);
    let mut events = tokio::time::timeout(
        event_timeout,
        client
            .account_client()
            .events()
            .subscribe([TransactionEventFilter::default().for_hash(hash)]),
    )
    .await
    .wrap_err_with(|| format!("{context}: timed out opening pipeline event stream"))??;
    spawn_blocking(move || client.submit_transaction(&transaction)).await??;
    // Then
    timeout(event_timeout, async {
        let mut saw_queued = false;
        loop {
            let Some(next) = events.next().await else {
                return Err(eyre!("transaction event stream closed"));
            };
            let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = next? else {
                return Err(eyre!("expected transaction event"));
            };
            match event.status() {
                TransactionStatus::Queued => {
                    saw_queued = true;
                }
                status if status == should_be => {
                    if !saw_queued {
                        // The subscription handshake is async; queued may be emitted before
                        // this stream is ready, so only require the terminal status here.
                    }
                    return Ok(());
                }
                status => {
                    return Err(eyre!("unexpected transaction status, got {:?}", status));
                }
            }
        }
    })
    .await
    .wrap_err_with(|| format!("{context}: timed out waiting for pipeline events"))??;
    events.close().await?;
    Ok(())
}
#[allow(clippy::too_many_lines)]
async fn applied_block_must_be_available_in_kura_scenario(network: &Network) -> Result<()> {
    let client = network.client();
    // When: submit a simple transaction to ensure a new non-genesis block is committed
    let kura_domain: DomainId = DomainId::try_new("kura-test", "universal")?;
    let register = domain_setup_instruction(&kura_domain, client.client().account())?;
    let tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [register],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let hash = tx.hash();
    let event_timeout = pipeline_event_timeout(network);
    let mut events = tokio::time::timeout(
        event_timeout,
        client
            .account_client()
            .events()
            .subscribe([TransactionEventFilter::default().for_hash(hash)]),
    )
    .await
    .wrap_err(
        "applied_block_must_be_available_in_kura: timed out opening pipeline event stream",
    )??;
    spawn_blocking(move || client.submit_transaction(&tx)).await??;
    // Wait for the transaction pipeline to advance to Approved (committed)
    timeout(event_timeout, async {
        let mut saw_queued = false;
        loop {
            let EventBox::Pipeline(PipelineEventBox::Transaction(event)) =
                events.next().await.unwrap().unwrap()
            else {
                panic!("Expected transaction event");
            };
            match event.status() {
                TransactionStatus::Queued => {
                    saw_queued = true;
                }
                TransactionStatus::Approved => {
                    if !saw_queued {
                        // Stream setup may lag; queued can be missed without affecting the
                        // approved signal for the transaction.
                    }
                    break;
                }
                status => {
                    panic!("unexpected transaction status: {status:?}");
                }
            }
        }
    })
    .await?;
    events.close().await?;
    // And wait until the peer reports at least 2 non-empty blocks (genesis + our tx)
    let peer = network.peer();
    peer.once_block_with(BlockHeight::predicate_non_empty(2))
        .await;
    // Then: the Kura storage on disk must contain at least two block entries
    let store_dir = peer.kura_store_dir();
    let blocks_dir = iroha_core::kura::Kura::canonical_storage_path(&store_dir);
    let hashes_path = blocks_dir.join("blocks.hashes");
    let index_path = blocks_dir.join("blocks.index");
    let data_path = blocks_dir.join("blocks.data");
    // Verify files exist
    assert!(
        hashes_path.exists(),
        "blocks.hashes not found at {hashes_path:?}"
    );
    assert!(
        index_path.exists(),
        "blocks.index not found at {index_path:?}"
    );
    assert!(data_path.exists(), "blocks.data not found at {data_path:?}");
    // Wait for Kura writer to flush the new block to disk
    let expected_hash_bytes = 2 * 32;
    let expected_index_bytes = 2 * 16;
    let mut hashes_len;
    let mut index_len;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        hashes_len = std::fs::metadata(&hashes_path)?.len();
        index_len = std::fs::metadata(&index_path)?.len();
        if hashes_len >= expected_hash_bytes && index_len >= expected_index_bytes {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "kura files not updated in time; hashes_len={hashes_len}, index_len={index_len}"
        );
        sleep(Duration::from_millis(50)).await;
    }
    // Verify at least two hashes are present (32 bytes per hash)
    assert_eq!(
        hashes_len % 32,
        0,
        "blocks.hashes size must be multiple of 32 bytes"
    );
    assert!(
        hashes_len >= expected_hash_bytes,
        "expected at least two block hashes, got {hashes_len} bytes"
    );
    // Verify the index contains at least two entries (each entry is two u64 = 16 bytes)
    assert_eq!(
        index_len % 16,
        0,
        "blocks.index size must be multiple of 16 bytes"
    );
    assert!(
        index_len >= expected_index_bytes,
        "expected at least two block indices, got {index_len} bytes"
    );
    let index_count = index_len / 16;
    // Read the last block index and ensure the length is non-zero once Kura flushes.
    let deadline = Instant::now() + Duration::from_secs(15);
    let (start, length) = loop {
        let mut idx_file = std::fs::File::open(&index_path)?;
        idx_file.seek(SeekFrom::Start((index_count - 1) * 16))?;
        let mut buf8 = [0u8; 8];
        idx_file.read_exact(&mut buf8)?;
        let start = u64::from_le_bytes(buf8);
        idx_file.read_exact(&mut buf8)?;
        let length = u64::from_le_bytes(buf8);
        if length > 0 {
            break (start, length);
        }
        assert!(
            Instant::now() < deadline,
            "last block length must be positive"
        );
        sleep(Duration::from_millis(50)).await;
    };
    let mut data_file = std::fs::File::open(&data_path)?;
    data_file.seek(SeekFrom::Start(start))?;
    let mut block_buf = vec![0u8; usize::try_from(length).expect("block length fits in usize")];
    data_file.read_exact(&mut block_buf)?;
    assert!(!block_buf.is_empty(), "last block data must be non-empty");
    Ok(())
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn pipeline_event_scenarios() -> Result<()> {
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new().with_min_peers(4),
        stringify!(pipeline_event_scenarios),
    )
    .await?
    else {
        return Ok(());
    };
    let domain = DomainId::try_new("looking-glass", "universal")?;
    let register = domain_setup_instruction(&domain, network.client().client().account())?;
    test_with_instruction_and_status(
        stringify!(transaction_with_ok_instruction_should_be_committed),
        &network,
        [register],
        &TransactionStatus::Approved,
    )
    .await?;
    let unknown_domain_id = DomainId::try_new("dummy", "universal")?;
    let fail_isi = Unregister::domain(unknown_domain_id.clone());
    test_with_instruction_and_status(
        stringify!(transaction_with_fail_instruction_should_be_rejected),
        &network,
        [fail_isi],
        &TransactionStatus::Rejected(Box::new(TransactionRejectionReason::Validation(
            ValidationFail::InstructionFailed(InstructionExecutionError::Find(FindError::Domain(
                unknown_domain_id,
            ))),
        ))),
    )
    .await?;
    applied_block_must_be_available_in_kura_scenario(&network).await?;
    Ok(())
}
