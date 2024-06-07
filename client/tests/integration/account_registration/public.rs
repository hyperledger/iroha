//! In public use cases, a new account should be:
//! - recognized when targeted as (a part of) a destination (or an object) of a creative instruction
//!     - becomes able to hold assets, permissions, roles, and metadata
//!     - cannot yet execute any queries or transactions
//! - automatically activated by an administrative trigger
//!     - becomes able to execute queries and transactions

use eyre::Result;
use iroha::data_model::prelude::*;
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID};

/// A new account e.g. "carol" should be:
/// - recognized when targeted as a destination of a transfer of numeric asset e.g. "rose"
/// - automatically activated by an administrative trigger
///
/// # Scenario
///
/// 0. ... administrative trigger registered
/// 0. new carol targeted ... carol recognized
/// 0. clock forward by one block ... carol activated
/// 0. carol tries query ... ok
/// 0. carol tries transaction ... ok
#[test]
fn on_transfer_asset_numeric() -> Result<()> {
    let (_rt, _peer, client_alice) = <PeerBuilder>::new().with_port(11_310).start_with_runtime();
    wait_for_genesis_committed(&[client_alice.clone()], 0);
    let observer = client_alice.clone();

    // ... administrative trigger registered
    let wasm = iroha_wasm_builder::Builder::new(
        "tests/integration/smartcontracts/trigger_activate_account",
    )
    .show_output()
    .build()?
    .optimize()?
    .into_bytes()?;
    let register_activator = Register::trigger(Trigger::new(
        "activator$wonderland".parse().unwrap(),
        Action::new(
            WasmSmartContract::from_compiled(wasm),
            Repeats::Indefinitely,
            ALICE_ID.clone(),
            AccountEventFilter::new().for_events(AccountEventSet::Recognized),
        ),
    ));
    client_alice
        .submit_blocking(register_activator)
        .expect("alice should succeed to register activator");

    // new carol targeted ... carol recognized
    let (carol_id, carol_keypair) = gen_account_in("wonderland");
    let _ = observer
        .request(FindAccountById::new(carol_id.clone()))
        .expect_err("carol should not be recognized at this point");
    let rose: AssetDefinitionId = "rose#wonderland".parse().unwrap();
    let rose_alice = AssetId::new(rose.clone(), ALICE_ID.clone());
    let n_roses_alice = observer
        .request(FindAssetQuantityById::new(rose_alice.clone()))
        .expect("alice should have roses");
    assert!(numeric!(3) < n_roses_alice);
    let transfer = Transfer::asset_numeric(rose_alice, 3_u32, carol_id.clone());
    client_alice
        .submit_blocking(transfer)
        .expect("alice should succeed to transfer");
    let _ = observer
        .request(FindAccountById::new(carol_id.clone()))
        .expect("carol should be recognized now");
    let rose_carol = AssetId::new(rose.clone(), carol_id.clone());
    let n_roses_carol = observer
        .request(FindAssetQuantityById::new(rose_carol.clone()))
        .expect("carol should have roses");
    assert_eq!(n_roses_carol, numeric!(3));

    // clock forward by one block ... carol activated
    let instruction = Log::new(
        iroha_data_model::Level::DEBUG,
        "the one least likely to be rejected".to_string(),
    );
    client_alice
        .submit_blocking(instruction.clone())
        .expect("instruction should succeed");

    // carol tries query ... ok
    let client_carol = {
        let mut client = client_alice.clone();
        client.key_pair = carol_keypair;
        client.account_id = carol_id.clone();
        client
    };
    let query = FindAssetQuantityById::new(rose_carol.clone());
    let _ = client_carol
        .request(query)
        .expect("queries from active carol should be accepted");

    // carol tries transaction ... ok
    client_carol
        .submit_blocking(instruction)
        .expect("transactions from active carol should be accepted");

    Ok(())
}
