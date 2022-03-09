/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/query_service.hpp"

#include <gtest/gtest.h>
#include <memory>
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "libfuzzer/libfuzzer_macro.h"
#include "logger/dummy_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/ametsuchi/mock_query_executor.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/network/network_mocks.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "torii/processor/query_processor_impl.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_query_validator.hpp"

using namespace std::chrono_literals;
using testing::_;
using testing::Return;

struct QueryFixture {
  std::shared_ptr<iroha::torii::QueryService> service_;
  std::shared_ptr<iroha::torii::QueryProcessorImpl> qry_processor_;
  std::shared_ptr<iroha::ametsuchi::MockStorage> storage_;
  std::shared_ptr<iroha::MockPendingTransactionStorage> pending_transactions_;
  std::shared_ptr<iroha::ametsuchi::MockBlockQuery> bq_;
  std::shared_ptr<iroha::ametsuchi::MockWsvQuery> wq_;

  QueryFixture() {
    storage_ = std::make_shared<iroha::ametsuchi::MockStorage>();
    bq_ = std::make_shared<iroha::ametsuchi::MockBlockQuery>();
    wq_ = std::make_shared<iroha::ametsuchi::MockWsvQuery>();
    EXPECT_CALL(*storage_, getBlockQuery()).WillRepeatedly(Return(bq_));
    EXPECT_CALL(*storage_, getWsvQuery()).WillRepeatedly(Return(wq_));
    EXPECT_CALL(*storage_, createQueryExecutor(_, _))
        .WillRepeatedly([&](const auto & /* pending_txs */,
                            const auto &response_factory) {
          using namespace ::testing;
          auto query_executor =
              std::make_unique<iroha::ametsuchi::MockQueryExecutor>();
          EXPECT_CALL(*query_executor, validateAndExecute_(_))
              .WillOnce(
                  Return(response_factory
                             ->createErrorQueryResponse(
                                 shared_model::interface::QueryResponseFactory::
                                     ErrorQueryType::kStatefulFailed,
                                 "I'm a teapot",
                                 418,
                                 shared_model::crypto::Hash{"BADD00DE"})
                             .release()));
          return query_executor;
        });
    pending_transactions_ =
        std::make_shared<iroha::MockPendingTransactionStorage>();
    auto query_response_factory_ =
        std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();
    qry_processor_ = std::make_shared<iroha::torii::QueryProcessorImpl>(
        storage_,
        storage_,
        pending_transactions_,
        query_response_factory_,
        logger::getDummyLoggerPtr());

    std::unique_ptr<shared_model::validation::AbstractValidator<
        shared_model::interface::Query>>
        query_validator = std::make_unique<
            shared_model::validation::DefaultSignedQueryValidator>(
            iroha::test::kTestsValidatorsConfig);
    std::unique_ptr<
        shared_model::validation::AbstractValidator<iroha::protocol::Query>>
        proto_query_validator =
            std::make_unique<shared_model::validation::ProtoQueryValidator>();
    auto query_factory =
        std::make_shared<shared_model::proto::ProtoTransportFactory<
            shared_model::interface::Query,
            shared_model::proto::Query>>(std::move(query_validator),
                                         std::move(proto_query_validator));

    auto blocks_query_validator = std::make_unique<
        shared_model::validation::DefaultSignedBlocksQueryValidator>(
        iroha::test::kTestsValidatorsConfig);
    auto proto_blocks_query_validator =
        std::make_unique<shared_model::validation::ProtoBlocksQueryValidator>();
    auto blocks_query_factory =
        std::make_shared<shared_model::proto::ProtoTransportFactory<
            shared_model::interface::BlocksQuery,
            shared_model::proto::BlocksQuery>>(
            std::move(blocks_query_validator),
            std::move(proto_blocks_query_validator));

    service_ = std::make_shared<iroha::torii::QueryService>(
        qry_processor_,
        query_factory,
        blocks_query_factory,
        logger::getDummyLoggerPtr(),
        nullptr);
  }
};

DEFINE_BINARY_PROTO_FUZZER(const iroha::protocol::Query &qry) {
  static QueryFixture handler;
  iroha::protocol::QueryResponse resp;
  handler.service_->Find(nullptr, &qry, &resp);
}
