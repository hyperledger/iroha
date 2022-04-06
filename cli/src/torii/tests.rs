#![allow(clippy::pedantic, clippy::restriction)]

use std::{collections::BTreeSet, str::FromStr, time::Duration};

use futures::future::FutureExt;
use iroha_actor::{broker::Broker, Actor};
use iroha_core::{
    block::{
        stream::{
            BlockPublisherMessage, BlockSubscriberMessage, VersionedBlockPublisherMessage,
            VersionedBlockSubscriberMessage,
        },
        BlockHeader, EmptyChainHash,
    },
    queue::Queue,
    smartcontracts::{isi::error::FindError, permissions::DenyAll},
    sumeragi::view_change::ProofChain,
    tx::TransactionValidator,
    wsv::World,
};
use iroha_data_model::{account::GENESIS_ACCOUNT_NAME, prelude::*};
use iroha_version::prelude::*;
use tokio::time;
use warp::test::WsClient;

use super::{routing::*, *};
use crate::{
    samples::{get_config, get_trusted_peers},
    stream::{Sink, Stream},
};

async fn create_torii() -> (Torii<World>, KeyPair) {
    let mut config = crate::samples::get_config(crate::samples::get_trusted_peers(None), None);
    config.torii.p2p_addr = format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap());
    config.torii.api_url = format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap());
    config.torii.telemetry_url =
        format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap());
    let (events, _) = tokio::sync::broadcast::channel(100);
    let wsv = Arc::new(WorldStateView::new(World::with(
        ('a'..'z')
            .map(|name| DomainId::from_str(&name.to_string()).expect("Valid"))
            .map(|domain_id| Domain::new(domain_id).build()),
        vec![],
    )));
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let domain_id = DomainId::from_str("wonderland").expect("Valid");
    let mut domain = Domain::new(domain_id.clone()).build();
    assert!(domain
        .add_account(
            Account::new(
                AccountId::from_str("alice@wonderland").expect("Valid"),
                [keys.public_key().clone()],
            )
            .build()
        )
        .is_none());
    wsv.world.domains.insert(domain_id, domain);
    let queue = Arc::new(Queue::from_configuration(&config.queue, Arc::clone(&wsv)));
    let network = IrohaNetwork::new(
        Broker::new(),
        config.torii.p2p_addr.clone(),
        config.public_key.clone(),
        config.network.mailbox,
    )
    .await
    .expect("Failed to create network")
    .start()
    .await;

    (
        Torii::from_configuration(config, wsv, queue, AllowAll::new(), events, network),
        keys,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn create_and_start_torii() {
    let (torii, _) = create_torii().await;

    let result = time::timeout(Duration::from_millis(50), torii.start()).await;

    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn torii_pagination() {
    let (torii, keys) = create_torii().await;

    let get_domains = |start, limit| {
        let query: VerifiedQueryRequest = QueryRequest::new(
            QueryBox::FindAllDomains(Default::default()),
            AccountId::from_str("alice@wonderland").expect("Valid"),
        )
        .sign(keys.clone())
        .expect("Failed to sign query with keys")
        .try_into()
        .expect("Failed to verify");

        let pagination = Pagination { start, limit };
        handle_queries(
            Arc::clone(&torii.wsv),
            Arc::clone(&torii.query_validator),
            pagination,
            query,
        )
        .map(|result| {
            let Scale(query_result) = result.unwrap();
            let VersionedPaginatedQueryResult::V1(PaginatedQueryResult { result, .. }) =
                query_result;

            if let QueryResult(Value::Vec(domains)) = result {
                domains
            } else {
                unreachable!()
            }
        })
    };

    assert_eq!(get_domains(None, None).await.len(), 26);
    assert_eq!(get_domains(Some(0), None).await.len(), 26);
    assert_eq!(get_domains(Some(15), Some(5)).await.len(), 5);
    assert_eq!(get_domains(None, Some(10)).await.len(), 10);
    assert_eq!(get_domains(Some(1), Some(15)).await.len(), 15);
}

#[derive(Default)]
struct QuerySet {
    instructions: Vec<Instruction>,
    account: Option<AccountId>,
    keys: Option<KeyPair>,
    deny_all: bool,
}

impl QuerySet {
    fn new() -> Self {
        Self::default()
    }
    fn given(mut self, instruction: Instruction) -> Self {
        self.instructions.push(instruction);
        self
    }
    fn account(mut self, account: AccountId) -> Self {
        self.account = Some(account);
        self
    }
    fn keys(mut self, keys: KeyPair) -> Self {
        self.keys = Some(keys);
        self
    }
    fn deny_all(mut self) -> Self {
        self.deny_all = true;
        self
    }
    async fn query(self, query: QueryBox) -> QueryResponseTest {
        use iroha_core::smartcontracts::Execute;

        let (mut torii, keys) = create_torii().await;
        if self.deny_all {
            torii.query_validator = Arc::new(DenyAll.into());
        }

        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        for instruction in self.instructions {
            instruction
                .execute(authority.clone(), &torii.wsv)
                .expect("Given instructions disorder");
        }

        let router = torii.create_api_router();

        let request: VersionedSignedQueryRequest =
            QueryRequest::new(query, self.account.unwrap_or(authority))
                .sign(self.keys.unwrap_or(keys))
                .expect("Failed to sign query with keys")
                .into();

        let response = warp::test::request()
            .method("POST")
            .path("/query")
            .body(request.encode_versioned())
            .reply(&router)
            .await;

        QueryResponseTest {
            response_status: response.status(),
            response_body: response.into(),
            status: None,
            body_matches: None,
        }
    }
}

impl From<warp::http::Response<warp::hyper::body::Bytes>> for QueryResponseBody {
    fn from(src: warp::http::Response<warp::hyper::body::Bytes>) -> Self {
        if StatusCode::OK == src.status() {
            let body = VersionedQueryResult::decode_versioned(src.body())
                .expect("The response body failed to be decoded to VersionedQueryResult even though the status is Ok 200");
            Self::Ok(body)
        } else {
            let body = query::Error::decode(&mut src.body().as_ref())
                .expect("The response body failed to be decoded to query::Error even though the status is not Ok 200");
            Self::Err(body)
        }
    }
}

struct QueryResponseTest {
    response_status: StatusCode,
    response_body: QueryResponseBody,
    status: Option<StatusCode>,
    body_matches: Option<bool>,
}

#[allow(variant_size_differences)]
enum QueryResponseBody {
    Ok(VersionedQueryResult),
    Err(query::Error),
}

impl QueryResponseTest {
    fn status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }
    fn body_matches_ok(mut self, predicate: impl Fn(&VersionedQueryResult) -> bool) -> Self {
        self.body_matches = if let QueryResponseBody::Ok(body) = &self.response_body {
            Some(predicate(body))
        } else {
            Some(false)
        };
        self
    }
    fn body_matches_err(mut self, predicate: impl Fn(&query::Error) -> bool) -> Self {
        self.body_matches = if let QueryResponseBody::Err(body) = &self.response_body {
            Some(predicate(body))
        } else {
            Some(false)
        };
        self
    }
    fn assert(self) {
        if let Some(status) = self.status {
            assert_eq!(self.response_status, status)
        }
        if let Some(body_matches) = self.body_matches {
            assert!(body_matches)
        }
    }
}

const DOMAIN: &str = "desert";

fn register_domain() -> Instruction {
    RegisterBox::new(Domain::new(DomainId::from_str(DOMAIN).expect("Valid"))).into()
}

fn register_account(name: &str) -> Instruction {
    let (public_key, _) = KeyPair::generate().unwrap().into();
    RegisterBox::new(Account::new(
        AccountId::new(name.parse().expect("Valid"), DOMAIN.parse().expect("Valid")),
        [public_key],
    ))
    .into()
}

fn register_asset_definition(name: &str) -> Instruction {
    RegisterBox::new(
        AssetDefinition::quantity(AssetDefinitionId::new(
            name.parse().expect("Valid"),
            DOMAIN.parse().expect("Valid"),
        ))
        .build(),
    )
    .into()
}

fn mint_asset(quantity: u32, asset: &str, account: &str) -> Instruction {
    MintBox::new(Value::U32(quantity), asset_id_new(asset, DOMAIN, account)).into()
}

fn asset_id_new(asset: &str, domain: &str, account: &str) -> AssetId {
    AssetId::new(
        AssetDefinitionId::new(
            asset.parse().expect("Valid"),
            domain.parse().expect("Valid"),
        ),
        AccountId::new(
            account.parse().expect("Valid"),
            DOMAIN.parse().expect("Valid"),
        ),
    )
}

// TODO: All the following tests must be parameterised and collapsed

#[tokio::test]
async fn find_asset() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .given(register_asset_definition("rose"))
        .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(asset_id_new(
            "rose", DOMAIN, "alice",
        ))))
        .await
        .status(StatusCode::OK)
        .body_matches_ok(|body| {
            if let VersionedQueryResult::V1(QueryResult(Value::Identifiable(
                IdentifiableBox::Asset(asset),
            ))) = body
            {
                *asset.value() == AssetValue::Quantity(99)
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_asset_with_no_mint() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            asset_id_new("rose", DOMAIN, "alice"),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::Asset(_))
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_asset_with_no_asset_definition() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
    // .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            asset_id_new("rose", DOMAIN, "alice"),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::AssetDefinition(_))
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_asset_with_no_account() {
    QuerySet::new()
        .given(register_domain())
    // .given(register_account("alice"))
        .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            asset_id_new("rose", DOMAIN, "alice"),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::Account(_))
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_asset_with_no_domain() {
    QuerySet::new()
    // .given(register_domain())
    // .given(register_account("alice"))
    // .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            asset_id_new("rose", DOMAIN, "alice"),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::Domain(_))
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_asset_definition() {
    QuerySet::new()
        .given(register_domain())
        .given(register_asset_definition("rose"))
        .query(QueryBox::FindAllAssetsDefinitions(Default::default()))
        .await
        .status(StatusCode::OK)
        .body_matches_ok(|body| {
            if let VersionedQueryResult::V1(QueryResult(Value::Vec(vec))) = body {
                vec.iter().any(|value| {
                    if let Value::Identifiable(IdentifiableBox::AssetDefinition(asset_definition)) =
                        value
                    {
                        asset_definition.id().name.as_ref() == "rose"
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_account() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .query(QueryBox::FindAccountById(FindAccountById::new(
            AccountId::new(
                "alice".parse().expect("Valid"),
                DOMAIN.parse().expect("Valid"),
            ),
        )))
        .await
        .status(StatusCode::OK)
        .assert()
}

#[tokio::test]
async fn find_account_with_no_account() {
    QuerySet::new()
        .given(register_domain())
    // .given(register_account("alice"))
        .query(QueryBox::FindAccountById(FindAccountById::new(
            AccountId::new("alice".parse().expect("Valid"), DOMAIN.parse().expect("Valid")),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::Account(_))
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_account_with_no_domain() {
    QuerySet::new()
    // .given(register_domain())
    // .given(register_account("alice"))
        .query(QueryBox::FindAccountById(FindAccountById::new(
            AccountId::new("alice".parse().expect("Valid"), DOMAIN.parse().expect("Valid")),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::Domain(_))
            } else {
                false
            }
        })
        .assert()
}

#[tokio::test]
async fn find_domain() {
    QuerySet::new()
        .given(register_domain())
        .query(QueryBox::FindDomainById(FindDomainById::new(
            DomainId::from_str(DOMAIN).expect("Valid"),
        )))
        .await
        .status(StatusCode::OK)
        .assert()
}

#[tokio::test]
async fn find_domain_with_no_domain() {
    QuerySet::new()
    // .given(register_domain())
        .query(QueryBox::FindDomainById(FindDomainById::new(
            DomainId::from_str(DOMAIN).expect("Valid"),
        )))
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| {
            if let query::Error::Find(err) = body {
                matches!(**err, FindError::Domain(_))
            } else {
                false
            }
        })
        .assert()
}

fn query() -> QueryBox {
    QueryBox::FindAccountById(FindAccountById::new(AccountId::new(
        "alice".parse().expect("Valid"),
        DOMAIN.parse().expect("Valid"),
    )))
}

#[tokio::test]
async fn query_with_wrong_signatory() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .account(AccountId::new("alice".parse().expect("Valid"), DOMAIN.parse().expect("Valid")))
    // .deny_all()
        .query(query())
        .await
        .status(StatusCode::UNAUTHORIZED)
        .body_matches_err(|body| matches!(*body, query::Error::Signature(_)))
        .assert()
}

#[tokio::test]
async fn query_with_wrong_signature() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .keys(KeyPair::generate().unwrap())
    // .deny_all()
        .query(query())
        .await
        .status(StatusCode::UNAUTHORIZED)
        .body_matches_err(|body| matches!(*body, query::Error::Signature(_)))
        .assert()
}

#[tokio::test]
async fn query_with_wrong_signature_and_no_permission() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .keys(KeyPair::generate().unwrap())
        .deny_all()
        .query(query())
        .await
        .status(StatusCode::UNAUTHORIZED)
        .body_matches_err(|body| matches!(*body, query::Error::Signature(_)))
        .assert()
}

#[tokio::test]
async fn query_with_no_permission() {
    QuerySet::new()
        .given(register_domain())
        .given(register_account("alice"))
    // .keys(KeyPair::generate().unwrap())
        .deny_all()
        .query(query())
        .await
        .status(StatusCode::FORBIDDEN)
        .body_matches_err(|body| matches!(*body, query::Error::Permission(_)))
        .assert()
}

#[tokio::test]
async fn query_with_no_permission_and_no_find() {
    QuerySet::new()
        .given(register_domain())
    // .given(register_account("alice"))
    // .keys(KeyPair::generate().unwrap())
        .deny_all()
        .query(query())
        .await
        .status(StatusCode::FORBIDDEN)
        .body_matches_err(|body| matches!(*body, query::Error::Permission(_)))
        .assert()
}

#[tokio::test]
async fn query_with_no_find() {
    QuerySet::new()
        .given(register_domain())
    // .given(register_account("alice"))
    // .keys(KeyPair::generate().unwrap())
    // .deny_all()
        .query(query())
        .await
        .status(StatusCode::NOT_FOUND)
        .body_matches_err(|body| matches!(*body, query::Error::Find(_)))
        .assert()
}

// Iroha peers are not allowed to create empty blocks. This block should not exist outside of testing.
fn new_dummy() -> ValidBlock {
    ValidBlock {
        header: BlockHeader {
            timestamp: 0,
            consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
            height: 1,
            previous_block_hash: EmptyChainHash::default().into(),
            transactions_hash: EmptyChainHash::default().into(),
            rejected_transactions_hash: EmptyChainHash::default().into(),
            view_change_proofs: ProofChain::empty(),
            invalidated_blocks_hashes: Vec::new(),
            genesis_topology: None,
        },
        rejected_transactions: vec![],
        transactions: vec![],
        event_recommendations: vec![],
        signatures: BTreeSet::default(),
    }
    .sign(KeyPair::generate().unwrap())
    .unwrap()
}

#[tokio::test]
async fn blocks_stream() {
    const BLOCK_COUNT: usize = 4;

    let (torii, _) = create_torii().await;
    let router = torii.create_api_router();

    // Initialize blockchain
    let mut block = new_dummy().commit();
    for i in 1..=BLOCK_COUNT {
        block.header.height = i as u64;
        let block: VersionedCommittedBlock = block.clone().into();
        torii.wsv.apply(block).await.unwrap();
    }

    let mut client = warp::test::ws()
        .path("/block/stream")
        .handshake(router)
        .await
        .unwrap();

    <WsClient as Sink<_>>::send(
        &mut client,
        VersionedBlockSubscriberMessage::from(BlockSubscriberMessage::SubscriptionRequest(2)),
    )
    .await
    .unwrap();

    let subscription_accepted_message: VersionedBlockPublisherMessage =
        <WsClient as Stream<_>>::recv(&mut client).await.unwrap();
    assert!(matches!(
        subscription_accepted_message.into_v1(),
        BlockPublisherMessage::SubscriptionAccepted
    ));

    for i in 2..=BLOCK_COUNT {
        let block_message: VersionedBlockPublisherMessage =
            <WsClient as Stream<_>>::recv(&mut client).await.unwrap();
        let block: VersionedCommittedBlock = block_message.into_v1().try_into().unwrap();
        assert_eq!(block.header().height, i as u64);

        <WsClient as Sink<_>>::send(
            &mut client,
            VersionedBlockSubscriberMessage::from(BlockSubscriberMessage::BlockReceived),
        )
        .await
        .unwrap();
    }

    block.header.height = BLOCK_COUNT as u64 + 1;
    let block: VersionedCommittedBlock = block.clone().into();
    torii.wsv.apply(block).await.unwrap();

    let block_message: VersionedBlockPublisherMessage =
        <WsClient as Stream<_>>::recv(&mut client).await.unwrap();
    let block: VersionedCommittedBlock = block_message.into_v1().try_into().unwrap();
    assert_eq!(block.header().height, BLOCK_COUNT as u64 + 1);
}

/// Returns the a map of a form `domain_name -> domain`, for initial domains.
fn domains(
    configuration: &crate::config::Configuration,
) -> eyre::Result<impl Iterator<Item = Domain>> {
    let key = configuration.genesis.account_public_key.clone();
    Ok([Domain::from(GenesisDomain::new(key))].into_iter())
}

#[test]
fn hash_should_be_the_same() {
    let key_pair = KeyPair::generate().expect("Failed to generate key pair.");
    let mut config = get_config(
        get_trusted_peers(Some(key_pair.public_key())),
        Some(key_pair.clone()),
    );
    config.genesis.account_private_key = Some(key_pair.private_key().clone());
    config.genesis.account_public_key = key_pair.public_key().clone();

    let tx = Transaction::new(
        AccountId::new(
            GENESIS_ACCOUNT_NAME.parse().expect("Valid"),
            GENESIS_DOMAIN_NAME.parse().expect("Valid"),
        ),
        Vec::<Instruction>::new().into(),
        1000,
    );
    let tx_hash = tx.hash();

    let signed_tx = tx.sign(key_pair).expect("Failed to sign.");
    let signed_tx_hash = signed_tx.hash();
    let tx_limits = TransactionLimits {
        max_instruction_number: 4096,
        max_wasm_size_bytes: 0,
    };
    let accepted_tx =
        AcceptedTransaction::from_transaction(signed_tx, &tx_limits).expect("Failed to accept.");
    let accepted_tx_hash = accepted_tx.hash();
    let wsv = Arc::new(WorldStateView::new(World::with(
        domains(&config).unwrap(),
        BTreeSet::new(),
    )));
    let valid_tx_hash = TransactionValidator::new(tx_limits, AllowAll::new(), AllowAll::new(), wsv)
        .validate(accepted_tx, true)
        .expect("Failed to validate.")
        .hash();
    assert_eq!(tx_hash, signed_tx_hash);
    assert_eq!(tx_hash, accepted_tx_hash);
    assert_eq!(tx_hash, valid_tx_hash.transmute());
}

#[tokio::test]
async fn test_subscription_websocket_clean_closing() {
    use iroha_data_model::events::{pipeline, EventFilter};
    use warp::filters::ws;

    use crate::stream::{Sink, Stream};

    let (torii, _) = create_torii().await;
    let router = torii.create_api_router();

    let mut endpoint = warp::test::ws()
        .path("/events")
        .handshake(router)
        .await
        .unwrap();

    // Subscribing
    let event_filter = EventFilter::Pipeline(
        pipeline::EventFilter::new().entity_kind(pipeline::EntityKind::Block),
    );
    let subscribe_message = VersionedEventSubscriberMessage::from(
        EventSubscriberMessage::SubscriptionRequest(event_filter),
    );
    Sink::send(&mut endpoint, subscribe_message).await.unwrap();

    let confirmation_response: VersionedEventPublisherMessage =
        Stream::recv(&mut endpoint).await.unwrap();
    let confirmation_response = confirmation_response.into_v1();
    assert!(matches!(
        confirmation_response,
        EventPublisherMessage::SubscriptionAccepted
    ));

    // Closing connection
    let close_message = ws::Message::close();
    endpoint.send(close_message).await;
    assert!(endpoint.recv_closed().await.is_ok());
}
