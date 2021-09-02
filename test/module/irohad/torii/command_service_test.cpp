/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_impl.hpp"

#include <gtest/gtest.h>
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "cryptography/hash.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/mock_tx_presence_cache.hpp"
#include "module/irohad/torii/torii_mocks.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace testing;

class CommandServiceTest : public Test {
 public:
  void SetUp() override {
    transaction_processor_ =
        std::make_shared<iroha::torii::MockTransactionProcessor>();

    status_bus_ = std::make_shared<iroha::torii::MockStatusBus>();

    tx_status_factory_ =
        std::make_shared<shared_model::proto::ProtoTxStatusFactory>();
    cache_ = std::make_shared<iroha::torii::CommandServiceImpl::CacheType>();
    tx_presence_cache_ =
        std::make_shared<iroha::ametsuchi::MockTxPresenceCache>();

    log_ = getTestLogger("CommandServiceTest");
  }

  void initCommandService() {
    command_service_ = std::make_shared<iroha::torii::CommandServiceImpl>(
        transaction_processor_,
        status_bus_,
        tx_status_factory_,
        cache_,
        tx_presence_cache_,
        log_);
  }

  std::shared_ptr<iroha::torii::MockTransactionProcessor>
      transaction_processor_;
  std::shared_ptr<iroha::torii::MockStatusBus> status_bus_;
  std::shared_ptr<shared_model::interface::TxStatusFactory> tx_status_factory_;
  std::shared_ptr<iroha::ametsuchi::MockTxPresenceCache> tx_presence_cache_;
  logger::LoggerPtr log_;
  std::shared_ptr<iroha::torii::CommandServiceImpl::CacheType> cache_;
  std::shared_ptr<iroha::torii::CommandService> command_service_;
};

/**
 * @given initialized command service
 * @when  invoke processBatch on batch which isn't present in runtime and
 * persistent caches
 * @then  tx_processor batchHandle is invoked
 */
TEST_F(CommandServiceTest, ProcessBatchOn) {
  auto hash = shared_model::crypto::Hash("a");
  auto batch = createMockBatchWithTransactions(
      {createMockTransactionWithHash(hash)}, "a");

  EXPECT_CALL(
      *tx_presence_cache_,
      check(Matcher<const shared_model::interface::TransactionBatch &>(_)))
      .WillRepeatedly(Return(std::vector<iroha::ametsuchi::TxCacheStatusType>(
          {iroha::ametsuchi::tx_cache_status_responses::Missing(hash)})));

  EXPECT_CALL(*transaction_processor_, batchHandle(_)).Times(1);

  initCommandService();
  command_service_->handleTransactionBatch(batch);
}

/**
 * @given initialized command service
 * @when  status of a transaction is queried
 *        @and in-memory cache does not contain info about the transaction
 *        @and the transaction is saved to the ledger as Rejected
 * @then  query response tells that the transaction has been rejected
 */
TEST_F(CommandServiceTest, RejectedTxStatus) {
  auto hash = shared_model::crypto::Hash("a");
  auto batch = createMockBatchWithTransactions(
      {createMockTransactionWithHash(hash)}, "a");

  iroha::ametsuchi::TxCacheStatusType ret_value{
      iroha::ametsuchi::tx_cache_status_responses::Rejected{hash}};

  EXPECT_CALL(*tx_presence_cache_,
              check(Matcher<const shared_model::crypto::Hash &>(hash)))
      .WillOnce(Return(ret_value));

  initCommandService();
  auto response = command_service_->getStatus(hash);

  ASSERT_NO_THROW({
    boost::get<const shared_model::interface::RejectedTxResponse &>(
        response->get());
  }) << "Wrong response. Expected: RejectedTxResponse, Received: "
     << response->toString();
}
