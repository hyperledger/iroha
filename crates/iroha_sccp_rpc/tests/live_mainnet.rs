//! Live mainnet checks of the light-client builders (`specs/sccp.md` §4.13).
//!
//! Each test builds a bootstrap from the compiled default public endpoints, installs it into an
//! in-memory light client exactly as core applies `InitializeLightClient`, then builds the next
//! advance and applies it with the compiled verifier, as the zero-touch keeper does. Where no
//! SCCP deployment exists yet, a source proof of an ordinary mainnet transaction must pass every
//! anchor, header and inclusion check and fail only at the SCCP event. They read public mainnet
//! endpoints and nothing else, so they are ignored by default:
//!
//! ```text
//! cargo test -p iroha_sccp_rpc --test live_mainnet -- --ignored --nocapture
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroha_config::parameters::defaults::sccp::endpoints;
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::light_client::{
        SccpLcAdvanceBytesV1, SccpLcBootstrapV1, SccpLcInitExpectationV1, SccpLightClientParamsV1,
    },
};
use iroha_sccp::light_client::{
    self, SccpLcError, SccpLcStateView, bsc::BscLcError, ethereum::EthereumLcError,
    state::SccpLcMemoryStateV1,
};
use iroha_sccp_rpc::{
    BeaconClient, EndpointSet, EvmClient, FailoverPolicy, HttpConfig, HttpTransport,
    builders::{
        AdvanceBudgetV1, BuildError, LightClientReplayV1, SourceChainBuilder, SourceEventRefV1,
        TairaLightClientView, bsc::BscBuilder, ethereum::EthereumBuilder,
        ethereum::EthereumEventV1, ton::TonBuilder,
    },
    evm::{BlockId, BlockTag},
    ton::{LiteClient, LiteClientConfig, LiteServerSet},
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn transport(urls: &[&str]) -> HttpTransport {
    let endpoints = EndpointSet::parse(urls, &[]).expect("compiled endpoints parse");
    HttpTransport::new(endpoints, HttpConfig::default(), FailoverPolicy::default())
        .expect("transport")
}

/// Install `bootstrap`, wait `pause`, then build and apply one advance from the installed head,
/// stepped to the keeper's default budget, with Taira's clock reading `now()`; returns the
/// replayed light client.
fn bootstrap_then_advance(
    network: SccpNetworkV1,
    bootstrap: &SccpLcBootstrapV1,
    pause: Duration,
    now: impl Fn() -> u64,
    advance: impl FnOnce(u64, AdvanceBudgetV1) -> Result<SccpLcAdvanceBytesV1, BuildError>,
) -> LightClientReplayV1 {
    let params = SccpLightClientParamsV1::defaults_for(network).expect("defaults");
    let initial = light_client::initialize_light_client(
        &SccpLcMemoryStateV1::new(),
        network,
        SccpLcInitExpectationV1::Absent,
        &params,
        bootstrap,
        now(),
    )
    .expect("the live bootstrap verifies");
    let mut replay = LightClientReplayV1::installed(network, &initial);
    let installed = replay.light_client().expect("installed");
    println!(
        "{}: bootstrap {} bytes, set {}, head {:?}",
        network.profile_key(),
        bootstrap.bytes.len(),
        installed.head.latest_set_id,
        installed.head
    );
    std::thread::sleep(pause);
    let budget = AdvanceBudgetV1::for_params(&params, 262_144);
    match advance(installed.head.latest_set_id, budget) {
        Ok(bytes) => {
            let delta = replay
                .advance(&bytes, now())
                .expect("the live advance verifies");
            let head = replay.light_client().expect("installed").head;
            println!(
                "{}: advance {} bytes, {} new sets, head {head:?}",
                network.profile_key(),
                bytes.len(),
                delta.new_sets.len()
            );
        }
        Err(BuildError::Unavailable(reason)) => {
            println!(
                "{}: nothing to advance yet: {reason}",
                network.profile_key()
            );
        }
        Err(error) => panic!("{}: advance: {error}", network.profile_key()),
    }
    replay
}

/// The first successful receipt with a log in EVM block `number`.
fn receipt_with_log(client: &EvmClient, number: u64) -> [u8; 32] {
    client
        .block_receipts(BlockId::Tag(BlockTag::Number(number)))
        .expect("receipts")
        .expect("served")
        .into_iter()
        .find(|receipt| receipt.status == Some(1) && !receipt.logs.is_empty())
        .expect("a successful receipt with a log")
        .transaction_hash
}

#[test]
#[ignore = "reads public Ethereum mainnet endpoints"]
fn ethereum_bootstrap_and_advance_verify() {
    let execution = EvmClient::new(transport(endpoints::ETHEREUM_EXECUTION));
    let builder = EthereumBuilder::new(
        BeaconClient::new(transport(endpoints::ETHEREUM_BEACON)),
        execution,
    );
    let bootstrap = builder.bootstrap().expect("bootstrap");
    let replay = bootstrap_then_advance(
        SccpNetworkV1::EthereumMainnet,
        &bootstrap,
        Duration::ZERO,
        now_ms,
        |latest, budget| builder.advance(latest, budget),
    );
    let execution = EvmClient::new(transport(endpoints::ETHEREUM_EXECUTION));
    let finalized = execution
        .block_by_number(BlockTag::Finalized)
        .expect("finalized block")
        .expect("served")
        .header
        .number;
    let tx = receipt_with_log(&execution, finalized - 8);
    let event = SourceEventRefV1::Evm {
        tx_hash: tx,
        event: EthereumEventV1::TransferToTaira { log_index: 0 },
    };
    let evidence = builder
        .evidence(&event, &replay, now_ms())
        .expect("the proof builds");
    let error = replay
        .verify_evidence(&evidence, now_ms())
        .expect_err("an ordinary log is not an SCCP event");
    println!(
        "ethereum-mainnet: proof {} bytes, {error}",
        evidence.proof.len()
    );
    assert!(
        matches!(error, SccpLcError::Ethereum(EthereumLcError::Event(_))),
        "the proof must fail only at the event: {error:?}"
    );
}

#[test]
#[ignore = "reads public BNB Smart Chain mainnet endpoints"]
fn bsc_bootstrap_and_advance_verify() {
    let builder = BscBuilder::new(EvmClient::new(transport(endpoints::BSC)));
    let bootstrap = builder.bootstrap().expect("bootstrap");
    let replay = bootstrap_then_advance(
        SccpNetworkV1::BscMainnet,
        &bootstrap,
        Duration::from_secs(10),
        now_ms,
        |latest, budget| builder.advance(latest, budget),
    );
    let head = replay.light_client().expect("installed").head;
    assert!(
        replay
            .state()
            .consensus_set(SccpNetworkV1::BscMainnet, head.latest_set_id)
            .is_some(),
        "the newest set is stored"
    );
    let rpc = EvmClient::new(transport(endpoints::BSC));
    let tx = receipt_with_log(&rpc, head.latest_finalized.source_height - 4);
    let event = SourceEventRefV1::Evm {
        tx_hash: tx,
        event: EthereumEventV1::TransferToTaira { log_index: 0 },
    };
    let evidence = builder
        .evidence(&event, &replay, now_ms())
        .expect("the proof builds");
    let error = replay
        .verify_evidence(&evidence, now_ms())
        .expect_err("an ordinary log is not an SCCP event");
    println!("bsc-mainnet: proof {} bytes, {error}", evidence.proof.len());
    assert!(
        matches!(
            error,
            SccpLcError::Bsc(BscLcError::Receipt(EthereumLcError::Event(_)))
        ),
        "the proof must fail only at the event: {error:?}"
    );
}

#[test]
#[ignore = "reads public TON mainnet liteservers"]
fn ton_bootstrap_and_advance_verify() {
    let builder = TonBuilder::new(LiteClient::new(
        LiteServerSet::compiled_defaults(),
        LiteClientConfig::default(),
        FailoverPolicy::default(),
    ));
    let newest = builder.newest_key_block().expect("newest key block");
    let _ = bootstrap_then_advance(
        SccpNetworkV1::TonMainnet,
        &builder.bootstrap_at(newest).expect("bootstrap"),
        Duration::ZERO,
        now_ms,
        |latest, budget| builder.advance(latest, budget),
    );
    // Replay the hop into the newest key block at a Taira time just after it, while the earlier
    // epoch was still fresh, so the hop verifier runs on real signatures and config proofs.
    let params =
        SccpLightClientParamsV1::defaults_for(SccpNetworkV1::TonMainnet).expect("defaults");
    let newest_time = light_client::verify_bootstrap(
        SccpNetworkV1::TonMainnet,
        &params,
        &builder.bootstrap_at(newest).expect("bootstrap"),
        now_ms(),
    )
    .expect("fresh")
    .light_client
    .head
    .latest_finalized
    .source_time_ms;
    let previous = builder
        .previous_key_block(newest)
        .expect("previous key block");
    let reached = bootstrap_then_advance(
        SccpNetworkV1::TonMainnet,
        &builder.bootstrap_at(previous).expect("earlier bootstrap"),
        Duration::ZERO,
        || newest_time + 60_000,
        |latest, budget| builder.advance(latest, budget),
    )
    .light_client()
    .expect("installed")
    .head
    .latest_set_id;
    assert!(
        u64::from(newest) <= reached,
        "the hop reaches the newest key block"
    );
}
