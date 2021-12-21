#![allow(clippy::pedantic, clippy::restriction)]

use std::time::Duration;

use futures::future::FutureExt;
use iroha_actor::{broker::Broker, Actor};
use iroha_version::prelude::*;
use tokio::time;
use warp::test::WsClient;

use super::*;
use crate::{
    queue::Queue,
    samples::{get_config, get_trusted_peers},
    smartcontracts::permissions::DenyAll,
    stream::{Sink, Stream},
    wsv::World,
};

async fn create_torii() -> (Torii<World>, KeyPair) {
    let mut config = get_config(get_trusted_peers(None), None);
    config.torii.p2p_addr = format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap());
    config.torii.api_url = format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap());
    config.torii.telemetry_url =
        format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap());
    let (events, _) = tokio::sync::broadcast::channel(100);
    let wsv = Arc::new(WorldStateView::new(World::with(
        ('a'..'z')
            .map(|name| name.to_string())
            .map(|name| (DomainId::test(&name), Domain::test(&name))),
        vec![],
    )));
    let keys = KeyPair::generate().expect("Failed to generate keys");
    wsv.world.domains.insert(
        DomainId::test("wonderland"),
        Domain::with_accounts(
            "wonderland",
            std::iter::once(Account::with_signatory(
                AccountId::test("alice", "wonderland"),
                keys.public_key.clone(),
            )),
        ),
    );
    let queue = Arc::new(Queue::from_configuration(&config.queue));
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
        Torii::from_configuration(
            config,
            wsv,
            queue,
            Arc::new(AllowAll.into()),
            events,
            network,
        ),
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
            AccountId::test("alice", "wonderland"),
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
            if let VersionedQueryResult::V1(QueryResult(Value::Vec(domain))) = query_result {
                domain
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
struct AssertSet {
    instructions: Vec<Instruction>,
    account: Option<AccountId>,
    keys: Option<KeyPair>,
    deny_all: bool,
}

impl AssertSet {
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
    fn query(self, query: QueryBox) -> AssertReady {
        let Self {
            instructions,
            account,
            keys,
            deny_all,
        } = self;
        AssertReady {
            instructions,
            account,
            keys,
            deny_all,
            query,
            status: None,
            hints: Vec::new(),
        }
    }
}

struct AssertReady {
    instructions: Vec<Instruction>,
    account: Option<AccountId>,
    keys: Option<KeyPair>,
    deny_all: bool,
    query: QueryBox,
    status: Option<StatusCode>,
    hints: Vec<&'static str>,
}

impl AssertReady {
    fn status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }
    fn hint(mut self, hint: &'static str) -> Self {
        self.hints.push(hint);
        self
    }
    async fn assert(self) {
        use crate::smartcontracts::Execute;

        let (mut torii, keys) = create_torii().await;
        if self.deny_all {
            torii.query_validator = Arc::new(DenyAll.into());
        }

        let authority = AccountId::test("alice", "wonderland");
        for instruction in self.instructions {
            instruction
                .execute(authority.clone(), &torii.wsv)
                .expect("Given instructions disorder");
        }

        let post_router = endpoint4(
            handle_queries,
            warp::path(uri::QUERY)
                .and(add_state!(torii.wsv, torii.query_validator))
                .and(paginate())
                .and(body::query()),
        );
        let router = warp::post()
            .and(post_router)
            .with(warp::trace::request())
            .recover(Torii::<World>::recover_arg_parse);

        let request: VersionedSignedQueryRequest =
            QueryRequest::new(self.query, self.account.unwrap_or(authority))
                .sign(self.keys.unwrap_or(keys))
                .expect("Failed to sign query with keys")
                .into();

        let response = warp::test::request()
            .method("POST")
            .path("/query")
            .body(request.encode_versioned().unwrap())
            .reply(&router)
            .await;

        let response_body = match response.status() {
            StatusCode::OK => {
                let response = VersionedQueryResult::decode_versioned(response.body()).unwrap();
                let VersionedQueryResult::V1(QueryResult(value)) = response;
                format!("{:?}", value)
            }
            _ => String::from_utf8(response.body().to_vec()).unwrap_or_default(),
        };
        dbg!(&response_body);

        if let Some(status) = self.status {
            assert_eq!(response.status(), status)
        }
        for hint in self.hints {
            dbg!(hint);
            assert!(response_body.contains(hint))
        }
    }
}

const DOMAIN: &str = "desert";

fn register_domain() -> Instruction {
    Instruction::Register(RegisterBox::new(Domain::test(DOMAIN)))
}
fn register_account(name: &str) -> Instruction {
    Instruction::Register(RegisterBox::new(NewAccount::with_signatory(
        AccountId::test(name, DOMAIN),
        KeyPair::generate().unwrap().public_key,
    )))
}
fn register_asset_definition(name: &str) -> Instruction {
    Instruction::Register(RegisterBox::new(AssetDefinition::new_quantity(
        AssetDefinitionId::test(name, DOMAIN),
    )))
}
fn mint_asset(quantity: u32, asset: &str, account: &str) -> Instruction {
    Instruction::Mint(MintBox::new(
        Value::U32(quantity),
        AssetId::test(asset, DOMAIN, account, DOMAIN),
    ))
}
#[tokio::test]
async fn find_asset() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .given(register_asset_definition("rose"))
        .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(AssetId::test(
            "rose", DOMAIN, "alice", DOMAIN,
        ))))
        .status(StatusCode::OK)
        .hint("Quantity")
        .hint("99")
        .assert()
        .await
}
#[tokio::test]
async fn find_asset_with_no_mint() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            AssetId::test("rose", DOMAIN, "alice", DOMAIN),
        )))
        .status(StatusCode::NOT_FOUND)
        .assert()
        .await
}
#[tokio::test]
async fn find_asset_with_no_asset_definition() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
    // .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            AssetId::test("rose", DOMAIN, "alice", DOMAIN),
        )))
        .status(StatusCode::NOT_FOUND)
        .hint("definition")
        .assert()
        .await
}
#[tokio::test]
async fn find_asset_with_no_account() {
    AssertSet::new()
        .given(register_domain())
    // .given(register_account("alice"))
        .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            AssetId::test("rose", DOMAIN, "alice", DOMAIN),
        )))
        .status(StatusCode::NOT_FOUND)
        .hint("account")
        .assert()
        .await
}
#[tokio::test]
async fn find_asset_with_no_domain() {
    AssertSet::new()
    // .given(register_domain())
    // .given(register_account("alice"))
    // .given(register_asset_definition("rose"))
    // .given(mint_asset(99, "rose", "alice"))
        .query(QueryBox::FindAssetById(FindAssetById::new(
            AssetId::test("rose", DOMAIN, "alice", DOMAIN),
        )))
        .status(StatusCode::NOT_FOUND)
        .hint("domain")
        .assert()
        .await
}
#[tokio::test]
async fn find_asset_definition() {
    AssertSet::new()
        .given(register_domain())
        .given(register_asset_definition("rose"))
        .query(QueryBox::FindAllAssetsDefinitions(Default::default()))
        .status(StatusCode::OK)
        .hint("rose")
        .hint(DOMAIN)
        .assert()
        .await
}
#[tokio::test]
async fn find_account() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .query(QueryBox::FindAccountById(FindAccountById::new(
            AccountId::test("alice", DOMAIN),
        )))
        .status(StatusCode::OK)
        .assert()
        .await
}
#[tokio::test]
async fn find_account_with_no_account() {
    AssertSet::new()
        .given(register_domain())
    // .given(register_account("alice"))
        .query(QueryBox::FindAccountById(FindAccountById::new(
            AccountId::test("alice", DOMAIN),
        )))
        .status(StatusCode::NOT_FOUND)
        .assert()
        .await
}
#[tokio::test]
async fn find_account_with_no_domain() {
    AssertSet::new()
    // .given(register_domain())
    // .given(register_account("alice"))
        .query(QueryBox::FindAccountById(FindAccountById::new(
            AccountId::test("alice", DOMAIN),
        )))
        .status(StatusCode::NOT_FOUND)
        .hint("domain")
        .assert()
        .await
}
#[tokio::test]
async fn find_domain() {
    AssertSet::new()
        .given(register_domain())
        .query(QueryBox::FindDomainById(FindDomainById::new(
            DomainId::test(DOMAIN),
        )))
        .status(StatusCode::OK)
        .assert()
        .await
}
#[tokio::test]
async fn find_domain_with_no_domain() {
    AssertSet::new()
    // .given(register_domain())
        .query(QueryBox::FindDomainById(FindDomainById::new(
            DOMAIN.to_string(),
        )))
        .status(StatusCode::NOT_FOUND)
        .assert()
        .await
}
fn query() -> QueryBox {
    QueryBox::FindAccountById(FindAccountById::new(AccountId::test("alice", DOMAIN)))
}
#[tokio::test]
async fn query_with_wrong_signatory() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .account(AccountId::test("alice", DOMAIN))
    // .deny_all()
        .query(query())
        .status(StatusCode::UNAUTHORIZED)
        .assert()
        .await
}
#[tokio::test]
async fn query_with_wrong_signature() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .keys(KeyPair::generate().unwrap())
    // .deny_all()
        .query(query())
        .status(StatusCode::UNAUTHORIZED)
        .assert()
        .await
}
#[tokio::test]
async fn query_with_wrong_signature_and_no_permission() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
        .keys(KeyPair::generate().unwrap())
        .deny_all()
        .query(query())
        .status(StatusCode::UNAUTHORIZED)
        .assert()
        .await
}
#[tokio::test]
async fn query_with_no_permission() {
    AssertSet::new()
        .given(register_domain())
        .given(register_account("alice"))
    // .keys(KeyPair::generate().unwrap())
        .deny_all()
        .query(query())
        .status(StatusCode::NOT_FOUND)
        .assert()
        .await
}
#[tokio::test]
async fn query_with_no_permission_and_no_find() {
    AssertSet::new()
        .given(register_domain())
    // .given(register_account("alice"))
    // .keys(KeyPair::generate().unwrap())
        .deny_all()
        .query(query())
        .status(StatusCode::NOT_FOUND)
        .assert()
        .await
}
#[tokio::test]
async fn query_with_no_find() {
    AssertSet::new()
        .given(register_domain())
    // .given(register_account("alice"))
    // .keys(KeyPair::generate().unwrap())
    // .deny_all()
        .query(query())
        .status(StatusCode::NOT_FOUND)
        .assert()
        .await
}
#[tokio::test]
async fn blocks_stream() {
    const BLOCK_COUNT: usize = 4;

    let (torii, _) = create_torii().await;
    let router = torii.create_api_router();

    // Initialize blockchain
    let mut block = ValidBlock::new_dummy().commit();
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
