//! Tests that Torii fails to bind to an occupied port and exits with a non-zero status.
use integration_tests::sandbox;
use iroha_primitives::addr::socket_addr;
use iroha_test_network::{NetworkBuilder, PeerLifecycleEvent};
use std::{net::TcpListener, time::Duration};
use tokio::time::timeout;
#[tokio::test]
async fn torii_bind_failure_results_in_non_zero_exit() -> eyre::Result<()> {
    // occupy a random port so Torii cannot bind to it
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            let msg = err.to_string();
            if msg.to_ascii_lowercase().contains("permission denied")
                || msg.to_ascii_lowercase().contains("operation not permitted")
            {
                eprintln!(
                    "Skipping test: environment denies binding TCP sockets on 127.0.0.1 ({msg})"
                );
                return Ok(());
            }
            return Err(err.into());
        }
    };
    let port = listener.local_addr()?.port();
    // build a network with Torii configured to the occupied port
    let Some(network) = sandbox::build_network_or_skip(
        NetworkBuilder::new().with_config_layer(|c| {
            c.write(
                ["torii", "address"],
                socket_addr!(127.0.0.1:port).to_string(),
            );
        }),
        stringify!(torii_bind_failure_results_in_non_zero_exit),
    ) else {
        return Ok(());
    };
    let peer = network.peer();
    let mut events = peer.events();
    // start the peer; it should fail to bind Torii and exit
    if let Err(err) = peer.start(network.config_layers(), None).await {
        if let Some(reason) = sandbox::sandbox_reason(&err) {
            eprintln!("Skipping test: environment denied loopback networking ({reason})");
            return Ok(());
        }
        return Err(err);
    }
    // wait for the termination event and ensure exit status is non-zero
    let status = timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(PeerLifecycleEvent::Terminated { status }) => break status,
                Ok(_) => {}
                Err(err) => panic!("{err}"),
            }
        }
    })
    .await?;
    assert!(!status.success());
    // keep listener alive until after Torii has failed
    drop(listener);
    Ok(())
}
