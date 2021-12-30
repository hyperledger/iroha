/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <boost/variant.hpp>
#include "crypto/keypair.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/mock_block_query.hpp"
#include "module/irohad/ametsuchi/mock_query_executor.hpp"
#include "module/irohad/ametsuchi/mock_storage.hpp"
#include "module/irohad/ametsuchi/mock_wsv_query.hpp"
#include "module/irohad/network/network_mocks.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "module/irohad/torii/torii_mocks.hpp"
#include "module/irohad/validation/validation_mocks.hpp"

#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "validators/protobuf/proto_query_validator.hpp"

#include "framework/common_constants.hpp"
#include "framework/test_client_factory.hpp"
#include "main/server_runner.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "network/impl/channel_factory.hpp"
#include "torii/processor/query_processor_impl.hpp"
#include "torii/query_client.hpp"
#include "torii/query_service.hpp"
#include "utils/query_error_response_visitor.hpp"

constexpr size_t TimesFind = 1;
static constexpr shared_model::interface::types::TransactionsNumberType
    kTxPageSize(10);

using ::testing::_;
using ::testing::A;
using ::testing::AtLeast;
using ::testing::ByMove;
using ::testing::Return;

using namespace iroha::ametsuchi;
using namespace iroha::torii;
using namespace shared_model::interface::permissions;

using wTransaction = std::shared_ptr<shared_model::interface::Transaction>;
using ErrorQueryType =
    shared_model::interface::QueryResponseFactory::ErrorQueryType;

// TODO kamilsa 22.06.18 IR-1472 rework this test so that query service is
// mocked
class ToriiQueriesTest : public testing::Test {
 public:
  virtual void SetUp() {
    signatories.emplace_back(pair.publicKey());
    runner = std::make_unique<iroha::network::ServerRunner>(
        ip + ":0", getTestLogger("ServerRunner"));
    wsv_query = std::make_shared<MockWsvQuery>();
    block_query = std::make_shared<MockBlockQuery>();
    query_executor = std::make_unique<MockQueryExecutor>();
    storage = std::make_shared<MockStorage>();
    pending_txs_storage =
        std::make_shared<iroha::MockPendingTransactionStorage>();
    query_response_factory =
        std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();

    //----------- Query Service ----------

    EXPECT_CALL(*storage, getWsvQuery()).WillRepeatedly(Return(wsv_query));
    EXPECT_CALL(*storage, getBlockQuery()).WillRepeatedly(Return(block_query));

    auto qpi = std::make_shared<iroha::torii::QueryProcessorImpl>(
        storage,
        storage,
        pending_txs_storage,
        query_response_factory,
        getTestLogger("QueryProcessor"));

    //----------- Server run ----------------
    initQueryFactory();
    runner
        ->append(std::make_unique<QueryService>(qpi,
                                                query_factory,
                                                blocks_query_factory,
                                                getTestLogger("QueryService"),
                                                nullptr))
        .run()
        .match([this](auto port) { this->port = port.value; },
               [](const auto &err) { FAIL() << err.error; });

    stub_ = iroha::network::createInsecureClient<
        torii_utils::QuerySyncClient::Service>(ip, port, std::nullopt);

    runner->waitForServersReady();
  }

  void initQueryFactory() {
    std::unique_ptr<shared_model::validation::AbstractValidator<
        shared_model::interface::Query>>
        query_validator = std::make_unique<
            shared_model::validation::DefaultSignedQueryValidator>(
            iroha::test::kTestsValidatorsConfig);
    std::unique_ptr<
        shared_model::validation::AbstractValidator<iroha::protocol::Query>>
        proto_query_validator =
            std::make_unique<shared_model::validation::ProtoQueryValidator>();
    query_factory = std::make_shared<shared_model::proto::ProtoTransportFactory<
        shared_model::interface::Query,
        shared_model::proto::Query>>(std::move(query_validator),
                                     std::move(proto_query_validator));

    auto blocks_query_validator = std::make_unique<
        shared_model::validation::DefaultSignedBlocksQueryValidator>(
        iroha::test::kTestsValidatorsConfig);
    auto proto_blocks_query_validator =
        std::make_unique<shared_model::validation::ProtoBlocksQueryValidator>();

    blocks_query_factory =
        std::make_shared<shared_model::proto::ProtoTransportFactory<
            shared_model::interface::BlocksQuery,
            shared_model::proto::BlocksQuery>>(
            std::move(blocks_query_validator),
            std::move(proto_blocks_query_validator));
  }

  std::unique_ptr<iroha::network::ServerRunner> runner;
  shared_model::crypto::Keypair pair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  std::vector<std::string> signatories;
  std::shared_ptr<torii_utils::QuerySyncClient::Service::StubInterface> stub_;

  std::shared_ptr<MockWsvQuery> wsv_query;
  std::shared_ptr<MockBlockQuery> block_query;
  std::unique_ptr<MockQueryExecutor> query_executor;
  std::shared_ptr<MockStorage> storage;
  std::shared_ptr<iroha::MockPendingTransactionStorage> pending_txs_storage;
  std::shared_ptr<shared_model::interface::QueryResponseFactory>
      query_response_factory;
  std::shared_ptr<QueryService::QueryFactoryType> query_factory;
  std::shared_ptr<QueryService::BlocksQueryFactoryType> blocks_query_factory;

  const std::string ip = "127.0.0.1";
  int port;
};

/**
 * Given a Query Synchronous Client
 * When copied, moved, copy and move assigned
 * Then final object works as the first one
 */
TEST_F(ToriiQueriesTest, QueryClient) {
  iroha::protocol::QueryResponse response;
  auto query = TestUnsignedQueryBuilder()
                   .creatorAccountId("accountA")
                   .getAccount("accountB")
                   .build()
                   .signAndAddSignature(pair)
                   .finish();

  auto client1 = torii_utils::QuerySyncClient(stub_);
  // Copy ctor
  torii_utils::QuerySyncClient client2(client1);
  // copy assignment
  auto client3 = client2;
  // move ctor
  torii_utils::QuerySyncClient client4(std::move(client3));
  // move assignment
  auto client5 = std::move(client4);
  auto stat = client5.Find(query.getTransport(), response);
  ASSERT_TRUE(stat.ok());
}

/**
 * Test for error response
 */

TEST_F(ToriiQueriesTest, FindWhenResponseInvalid) {
  iroha::protocol::QueryResponse response;
  auto query = TestUnsignedQueryBuilder()
                   .creatorAccountId("accountA")
                   .getAccount("accountB")
                   .build()
                   .signAndAddSignature(pair)
                   .finish();

  auto stat =
      torii_utils::QuerySyncClient(stub_).Find(query.getTransport(), response);
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  ASSERT_TRUE(stat.ok());
  // Must return Error Response
  ASSERT_TRUE(boost::apply_visitor(
      shared_model::interface::QueryErrorResponseChecker<
          shared_model::interface::StatelessFailedErrorResponse>(),
      resp.get()));

  ASSERT_EQ(query.hash(), resp.queryHash());
}

/**
 * Tests for account response
 */

TEST_F(ToriiQueriesTest, FindAccountWhenNoGrantPermissions) {
  std::string account_id = "b@domain";
  auto creator = "a@domain";

  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getAccount(account_id)
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  auto *r = query_response_factory
                ->createErrorQueryResponse(
                    ErrorQueryType::kStatefulFailed, "", 2, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);

  ASSERT_TRUE(stat.ok());
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  // Must be invalid due to failed stateful validation caused by no permission
  // to read account
  ASSERT_TRUE(boost::apply_visitor(
      shared_model::interface::QueryErrorResponseChecker<
          shared_model::interface::StatefulFailedErrorResponse>(),
      resp.get()));

  ASSERT_EQ(model_query.hash(), resp.queryHash());
}

TEST_F(ToriiQueriesTest, FindAccountWhenHasReadPermissions) {
  auto creator = "a@domain";

  std::string accountB_id = "b@domain";
  std::string domainB_id = "domain";

  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  std::vector<std::string> roles = {"user"};

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getAccount(accountB_id)
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  auto *r = query_response_factory
                ->createAccountResponse(
                    accountB_id, domainB_id, 1, {}, roles, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};

  ASSERT_TRUE(stat.ok());
  // Should not return Error Response because tx is stateless and stateful valid
  ASSERT_FALSE(response.has_error_response());

  ASSERT_NO_THROW({
    const auto &account_resp =
        boost::get<const shared_model::interface::AccountResponse &>(
            resp.get());

    ASSERT_EQ(account_resp.account().accountId(), accountB_id);
    ASSERT_EQ(account_resp.roles().size(), 1);
    ASSERT_EQ(model_query.hash(), resp.queryHash());
  });
}

TEST_F(ToriiQueriesTest, FindAccountWhenHasRolePermission) {
  std::string account_id = "accountA";
  std::string domain_id = "domain";
  auto creator = "a@domain";
  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));
  std::vector<std::string> roles = {"test"};

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getAccount(creator)
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  auto *r = query_response_factory
                ->createAccountResponse(
                    account_id, domain_id, 1, "{}", roles, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  ASSERT_TRUE(stat.ok());
  // Should not return Error Response because tx is stateless and stateful valid
  ASSERT_FALSE(response.has_error_response());

  ASSERT_NO_THROW({
    const auto &detail_resp =
        boost::get<const shared_model::interface::AccountResponse &>(
            resp.get());

    ASSERT_EQ(detail_resp.account().accountId(), account_id);
    ASSERT_EQ(detail_resp.account().domainId(), domain_id);
    ASSERT_EQ(model_query.hash(), resp.queryHash());
  });
}

/**
 * Test for account asset response
 */

TEST_F(ToriiQueriesTest, FindAccountAssetWhenNoGrantPermissions) {
  auto creator = "a@domain";
  auto accountb_id = "b@domain";

  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  iroha::protocol::QueryResponse response;

  auto model_query =
      shared_model::proto::QueryBuilder()
          .creatorAccountId(creator)
          .queryCounter(1)
          .createdTime(iroha::time::now())
          .getAccountAssets(accountb_id, kMaxPageSize, std::nullopt)
          .build()
          .signAndAddSignature(pair)
          .finish();

  auto *r = query_response_factory
                ->createErrorQueryResponse(
                    ErrorQueryType::kStatefulFailed, "", 2, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  ASSERT_TRUE(stat.ok());
  // Must be invalid due to failed stateful validation caused by no permission
  // to read account asset
  ASSERT_TRUE(boost::apply_visitor(
      shared_model::interface::QueryErrorResponseChecker<
          shared_model::interface::StatefulFailedErrorResponse>(),
      resp.get()));

  ASSERT_EQ(model_query.hash(), resp.queryHash());
}

TEST_F(ToriiQueriesTest, FindAccountAssetWhenHasRolePermissions) {
  std::string account_id = "accountA";
  std::string asset_id = "usd";
  auto amount = shared_model::interface::Amount("1.00");

  auto creator = "a@domain";
  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getAccountAssets(creator, kMaxPageSize, std::nullopt)
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  std::vector<std::tuple<shared_model::interface::types::AccountIdType,
                         shared_model::interface::types::AssetIdType,
                         shared_model::interface::Amount>>
      assets;
  assets.push_back(std::make_tuple(account_id, asset_id, amount));
  auto *r = query_response_factory
                ->createAccountAssetResponse(
                    assets, assets.size(), std::nullopt, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);

  auto hash = response.query_hash();

  ASSERT_TRUE(stat.ok());
  // Should not return Error Response because tx is stateless and stateful valid
  ASSERT_FALSE(response.has_error_response());

  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  ASSERT_NO_THROW({
    const auto &asset_resp =
        boost::get<const shared_model::interface::AccountAssetResponse &>(
            resp.get());
    // Check if the fields in account asset response are correct
    ASSERT_EQ(asset_resp.accountAssets()[0].assetId(), asset_id);
    ASSERT_EQ(asset_resp.accountAssets()[0].accountId(), account_id);
    ASSERT_EQ(asset_resp.accountAssets()[0].balance(), amount);
    ASSERT_EQ(model_query.hash(), resp.queryHash());
  });
}

/**
 * Test for signatories response
 */

TEST_F(ToriiQueriesTest, FindSignatoriesWhenNoGrantPermissions) {
  auto creator = "a@domain";
  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getSignatories("b@domain")
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  auto *r = query_response_factory
                ->createErrorQueryResponse(
                    ErrorQueryType::kStatefulFailed, "", 2, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);
  ASSERT_TRUE(stat.ok());
  // Must be invalid due to failed stateful validation caused by no permission
  // to read account
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  ASSERT_TRUE(boost::apply_visitor(
      shared_model::interface::QueryErrorResponseChecker<
          shared_model::interface::StatefulFailedErrorResponse>(),
      resp.get()));

  ASSERT_EQ(model_query.hash(), resp.queryHash());
}

TEST_F(ToriiQueriesTest, FindSignatoriesHasRolePermissions) {
  auto creator = "a@domain";

  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getSignatories(creator)
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  auto *r = query_response_factory
                ->createSignatoriesResponse(signatories, model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);
  shared_model::proto::QueryResponse shared_response{
      iroha::protocol::QueryResponse{response}};
  ASSERT_NO_THROW({
    auto resp_pubkey =
        *boost::get<const shared_model::interface::SignatoriesResponse &>(
             shared_response.get())
             .keys()
             .begin();

    ASSERT_TRUE(stat.ok());
    /// Should not return Error Response because tx is stateless and stateful
    /// valid
    ASSERT_FALSE(response.has_error_response());
    // check if fields in response are valid
    ASSERT_EQ(resp_pubkey, signatories.back());
    ASSERT_EQ(model_query.hash(), shared_response.queryHash());
  }) << shared_response.toString();
}

/**
 * Test for transactions response
 */

TEST_F(ToriiQueriesTest, FindTransactionsWhenValid) {
  std::string account_id = "accountA";
  auto creator = "a@domain";
  std::vector<wTransaction> txs;
  std::vector<shared_model::proto::Transaction> proto_txs;
  for (size_t i = 0; i < 3; ++i) {
    std::shared_ptr<shared_model::interface::Transaction> current =
        clone(TestTransactionBuilder().creatorAccountId(account_id).build());
    txs.push_back(current);
    proto_txs.push_back(
        *std::static_pointer_cast<shared_model::proto::Transaction>(current));
  }

  EXPECT_CALL(*wsv_query, getSignatories(creator))
      .WillRepeatedly(Return(signatories));

  iroha::protocol::QueryResponse response;

  auto model_query = shared_model::proto::QueryBuilder()
                         .creatorAccountId(creator)
                         .queryCounter(1)
                         .createdTime(iroha::time::now())
                         .getAccountTransactions(creator, kTxPageSize)
                         .build()
                         .signAndAddSignature(pair)
                         .finish();

  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      response_txs;
  std::transform(std::begin(proto_txs),
                 std::end(proto_txs),
                 std::back_inserter(response_txs),
                 [](const auto &proto_tx) { return clone(proto_tx); });

  auto *r = query_response_factory
                ->createTransactionsResponse(std::move(response_txs),
                                             model_query.hash())
                .release();

  EXPECT_CALL(*query_executor, validateAndExecute_(_))
      .WillRepeatedly(Return(r));
  EXPECT_CALL(*storage, createQueryExecutor(_, _))
      .WillOnce(Return(ByMove(std::move(query_executor))));

  auto stat = torii_utils::QuerySyncClient(stub_).Find(
      model_query.getTransport(), response);
  ASSERT_TRUE(stat.ok());
  // Should not return Error Response because tx is stateless and stateful valid
  ASSERT_FALSE(response.has_error_response());
  shared_model::proto::QueryResponse resp{
      iroha::protocol::QueryResponse{response}};
  ASSERT_NO_THROW({
    const auto &tx_resp =
        boost::get<const shared_model::interface::TransactionsResponse &>(
            resp.get());

    const auto &txs = tx_resp.transactions();
    for (const auto &tx : txs) {
      ASSERT_EQ(tx.creatorAccountId(), account_id);
    }
    ASSERT_EQ(model_query.hash(), resp.queryHash());
  });
}

TEST_F(ToriiQueriesTest, FindManyTimesWhereQueryServiceSync) {
  auto client = torii_utils::QuerySyncClient(stub_);

  for (size_t i = 0; i < TimesFind; ++i) {
    iroha::protocol::QueryResponse response;

    // stateless invalid query
    auto model_query = TestQueryBuilder()
                           .creatorAccountId("a@domain")
                           .queryCounter(i)
                           .createdTime(iroha::time::now())
                           .getAccountTransactions("a@2domain", kTxPageSize)
                           .build();

    auto stat = client.Find(model_query.getTransport(), response);
    ASSERT_TRUE(stat.ok());
    shared_model::proto::QueryResponse resp{
        iroha::protocol::QueryResponse{response}};
    // Must return Error Response
    ASSERT_TRUE(boost::apply_visitor(
        shared_model::interface::QueryErrorResponseChecker<
            shared_model::interface::StatelessFailedErrorResponse>(),
        resp.get()));

    ASSERT_EQ(model_query.hash(), resp.queryHash());
  }
}
