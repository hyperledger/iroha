use std::{num::NonZero, time::Duration};

use eyre::Result;
use futures_util::StreamExt;
use iroha::{
    client::{self},
    data_model::prelude::*,
};
use iroha_data_model::{
    events::pipeline::{BlockEventFilter, TransactionEventFilter},
    parameter::BlockParameter,
};
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;
use rand::{prelude::IteratorRandom, thread_rng};
use tokio::{
    sync::{mpsc, watch},
    task::{spawn_blocking, JoinSet},
    time::{sleep, timeout},
};

/// Bombard random peers with random mints in multiple rounds, ensuring they all have
/// a consistent total amount in the end.
#[tokio::test]
async fn multiple_blocks_created() -> Result<()> {
    const N_ROUNDS: u64 = 50;
    const N_MAX_TXS_PER_BLOCK: u64 = 10;

    // Given
    let network = NetworkBuilder::new()
        .with_peers(4)
        .with_genesis_instruction(SetParameter(Parameter::Block(
            BlockParameter::MaxTransactions(NonZero::new(N_MAX_TXS_PER_BLOCK).expect("valid")),
        )))
        .with_pipeline_time(Duration::from_secs(1))
        .start()
        .await?;

    let create_domain = Register::domain(Domain::new("domain".parse()?));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse()?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));

    {
        let client = network.client();
        spawn_blocking(move || {
            client.clone().submit_all::<InstructionBox>([
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
        })
        .await??;
    }

    network.ensure_blocks(2).await?;

    let blocks = BlocksTracker::start(&network);

    // When
    let mut total: u128 = 0;
    for _ in 1..=N_ROUNDS {
        let txs = (1..=N_MAX_TXS_PER_BLOCK)
            .choose(&mut thread_rng())
            .expect("there is a room to choose from");
        println!("submitting {txs} transactions to random peers");
        for _ in 0..txs {
            let value = (0..999_999)
                .choose(&mut thread_rng())
                .expect("there is quite a room to choose from");
            total += value;

            let client = network.client();
            let tx = client.build_transaction(
                [Mint::asset_numeric(
                    Numeric::new(value, 0),
                    AssetId::new(asset_definition_id.clone(), account_id.clone()),
                )],
                <_>::default(),
            );
            spawn_blocking(move || client.submit_transaction(&tx)).await??;
        }

        timeout(network.sync_timeout(), blocks.sync()).await?;
    }

    // ensuring all have the same total
    sleep(Duration::from_secs(2)).await;
    println!("all peers should have total={total}");
    let expected_value = AssetValue::Numeric(Numeric::new(total, 0));
    for peer in network.peers() {
        let client = peer.client();
        let expected_value = expected_value.clone();
        let account_id = account_id.clone();
        let definition = asset_definition_id.clone();
        let assets = spawn_blocking(move || {
            client
                .query(client::asset::all())
                .filter_with(|asset| {
                    asset.id.account.eq(account_id) & asset.id.definition_id.eq(definition)
                })
                .execute_all()
        })
        .await??;
        assert_eq!(assets.len(), 1);
        let asset = assets.into_iter().next().unwrap();
        assert_eq!(*asset.value(), expected_value);
    }

    Ok(())
}

// TODO: consider making a part of `iroha_test_network`
struct BlocksTracker {
    sync_tx: watch::Sender<bool>,
    _children: JoinSet<()>,
}

impl BlocksTracker {
    fn start(network: &Network) -> Self {
        enum PeerEvent {
            Block(u64),
            Transaction,
        }

        let mut children = JoinSet::new();

        let (block_tx, mut block_rx) = mpsc::channel::<(PeerEvent, usize)>(10);
        for (i, peer) in network.peers().iter().cloned().enumerate() {
            let tx = block_tx.clone();
            children.spawn(async move {
                let mut events = peer
                    .client()
                    .listen_for_events_async([
                        EventFilterBox::from(BlockEventFilter::default()),
                        TransactionEventFilter::default().into(),
                    ])
                    .await
                    .expect("peer should be up");
                while let Some(Ok(event)) = events.next().await {
                    match event {
                        EventBox::Pipeline(PipelineEventBox::Block(x))
                            if matches!(*x.status(), BlockStatus::Applied) =>
                        {
                            let _ = tx
                                .send((PeerEvent::Block(x.header().height().get()), i))
                                .await;
                        }
                        EventBox::Pipeline(PipelineEventBox::Transaction(x))
                            if matches!(*x.status(), TransactionStatus::Queued) =>
                        {
                            let _ = tx.send((PeerEvent::Transaction, i)).await;
                        }
                        _ => {}
                    }
                }
            });
        }

        let peers_count = network.peers().len();
        let (sync_tx, _sync_rx) = watch::channel(false);
        let sync_clone = sync_tx.clone();
        children.spawn(async move {
            #[derive(Copy, Clone)]
            struct PeerState {
                height: u64,
                mutated: bool,
            }

            let mut blocks = vec![
                PeerState {
                    height: 0,
                    mutated: false
                };
                peers_count
            ];
            loop {
                tokio::select! {
                    Some((event, i)) = block_rx.recv() => {
                        let state = blocks.get_mut(i).unwrap();
                        match event {
                            PeerEvent::Block(height) => {
                                state.height = height;
                                state.mutated = false;
                            }
                            PeerEvent::Transaction => {
                                state.mutated = true;
                            }
                        }

                        let max_height = blocks.iter().map(|x| x.height).max().expect("there is at least 1");
                        let is_sync = blocks.iter().all(|x| x.height == max_height && !x.mutated);
                        sync_tx.send_modify(|flag| *flag = is_sync);
                    }
                }
            }
        });

        Self {
            sync_tx: sync_clone,
            _children: children,
        }
    }

    async fn sync(&self) {
        let mut recv = self.sync_tx.subscribe();
        loop {
            if *recv.borrow_and_update() {
                return;
            }
            recv.changed().await.unwrap()
        }
    }
}
