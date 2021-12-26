/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/query_service.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/torii/processor/mock_query_processor.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "utils/query_error_response_visitor.hpp"
#include "validators/protobuf/proto_query_validator.hpp"

using namespace iroha;
using namespace iroha::torii;

using namespace shared_model::detail;
using namespace shared_model::interface;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Truly;

class QueryServiceTest : public ::testing::Test {
 public:
  void SetUp() override {
    query_processor = std::make_shared<MockQueryProcessor>();
    // any query
    query = std::make_shared<shared_model::proto::Query>(
        shared_model::proto::QueryBuilder()
            .creatorAccountId("user@domain")
            .createdTime(iroha::time::now())
            .queryCounter(1)
            .getAccount("user@domain")
            .build()
            .signAndAddSignature(
                shared_model::crypto::DefaultCryptoAlgorithmType::
                    generateKeypair())
            .finish());

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

  void init() {
    query_service =
        std::make_shared<QueryService>(query_processor,
                                       query_factory,
                                       blocks_query_factory,
                                       getTestLogger("QueryService"),
                                       nullptr);
  }

  std::unique_ptr<shared_model::interface::QueryResponse> getResponse() {
    return shared_model::proto::ProtoQueryResponseFactory()
        .createAccountResponse("a", "ru", 2, "", {"user"}, query->hash());
  }

  std::shared_ptr<shared_model::proto::Query> query;
  std::shared_ptr<QueryService> query_service;
  std::shared_ptr<QueryService::QueryFactoryType> query_factory;
  std::shared_ptr<QueryService::BlocksQueryFactoryType> blocks_query_factory;
  std::shared_ptr<MockQueryProcessor> query_processor;
};

/**
 * @given query and expected valid response
 * @when query is sent to query service and query_processor processes query
 * @then expected response is returned
 */
TEST_F(QueryServiceTest, ValidWhenUniqueHash) {
  // unique query => query handled by query processor
  EXPECT_CALL(*query_processor,
              queryHandle(
                  // match by shared_ptr's content
                  Truly([this](const shared_model::interface::Query &rhs) {
                    return rhs == *query;
                  })))
      .WillOnce(Invoke([this](auto &) { return this->getResponse(); }));
  init();

  protocol::QueryResponse response;
  query_service->Find(query->getTransport(), response);
  shared_model::proto::QueryResponse resp{protocol::QueryResponse{response}};
  ASSERT_EQ(resp, *getResponse());
}

/**
 * @given query
 * @when query is sent to query service twice
 * @then query processor will be invoked once and second response will have
 * STATELESS_INVALID status
 */
TEST_F(QueryServiceTest, InvalidWhenDuplicateHash) {
  // two same queries => only first query handled by query processor
  EXPECT_CALL(*query_processor, queryHandle(_)).WillOnce(Invoke([this](auto &) {
    return this->getResponse();
  }));

  init();

  protocol::QueryResponse response;
  query_service->Find(query->getTransport(), response);

  // second call of the same query
  query_service->Find(query->getTransport(), response);
  ASSERT_TRUE(response.has_error_response());
  shared_model::proto::QueryResponse resp{protocol::QueryResponse{response}};
  ASSERT_TRUE(boost::apply_visitor(
      shared_model::interface::QueryErrorResponseChecker<
          shared_model::interface::StatelessFailedErrorResponse>(),
      resp.get()));
}
