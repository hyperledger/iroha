/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_impl.hpp"

#include <gtest/gtest.h>
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "cryptography/hash.hpp"
#include "cryptography/public_key.hpp"
#include "framework/test_logger.hpp"
#include "framework/test_subscriber.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/ametsuchi/mock_storage.hpp"
#include "module/irohad/ametsuchi/mock_tx_presence_cache.hpp"
#include "module/irohad/torii/torii_mocks.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace testing;

class CommandServiceTest : public Test {
 public:
  void SetUp() override {
    transaction_processor_ =
        std::make_shared<iroha::torii::MockTransactionProcessor>();
    storage_ = std::make_shared<iroha::ametsuchi::MockStorage>();

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
        storage_,
        status_bus_,
        tx_status_factory_,
        cache_,
        tx_presence_cache_,
        log_);
  }

  std::shared_ptr<iroha::torii::MockTransactionProcessor>
      transaction_processor_;
  std::shared_ptr<iroha::ametsuchi::MockStorage> storage_;
  std::shared_ptr<iroha::torii::MockStatusBus> status_bus_;
  std::shared_ptr<shared_model::interface::TxStatusFactory> tx_status_factory_;
  std::shared_ptr<iroha::ametsuchi::MockTxPresenceCache> tx_presence_cache_;
  logger::LoggerPtr log_;
  std::shared_ptr<iroha::torii::CommandServiceImpl::CacheType> cache_;
  std::shared_ptr<iroha::torii::CommandService> command_service_;
};

/**
 * @given intialized command service
 *        @and hash with passed consensus but not present in runtime cache
 * @when  invoke getStatusStream by hash
 * @then  verify that code checks run-time and persistent caches for the hash
 *        @and return CommittedTxResponse status
 */
TEST_F(CommandServiceTest, getStatusStreamWithAbsentHash) {
  using HashType = shared_model::crypto::Hash;
  auto hash = HashType("a");
  iroha::ametsuchi::TxCacheStatusType ret_value{
      iroha::ametsuchi::tx_cache_status_responses::Committed{hash}};

  // TODO: 2019-03-13 @muratovv add expect call for runtime cache invocation
  // IR-397
  EXPECT_CALL(*tx_presence_cache_,
              check(Matcher<const shared_model::crypto::Hash &>(_)))
      .Times(1)
      .WillOnce(Return(ret_value));
  EXPECT_CALL(*status_bus_, statuses())
      .WillRepeatedly(Return(
          rxcpp::observable<>::empty<iroha::torii::StatusBus::Objects>()));

  initCommandService();
  auto wrapper = framework::test_subscriber::make_test_subscriber<
      framework::test_subscriber::CallExact>(
      command_service_->getStatusStream(hash), 1);
  wrapper.subscribe([](const auto &tx_response) {
    return iroha::visit_in_place(
        tx_response->get(),
        [](const shared_model::interface::CommittedTxResponse &) {},
        [](const auto &a) { FAIL() << "Wrong response!"; });
  });
  ASSERT_TRUE(wrapper.validate());
}

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
  EXPECT_CALL(*status_bus_, statuses())
      .WillRepeatedly(Return(
          rxcpp::observable<>::empty<iroha::torii::StatusBus::Objects>()));

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

  auto block_query_mock = std::make_shared<iroha::ametsuchi::MockBlockQuery>();
  iroha::ametsuchi::TxCacheStatusType ret_value{
      iroha::ametsuchi::tx_cache_status_responses::Rejected{hash}};

  EXPECT_CALL(
      *block_query_mock,
      checkTxPresence(Matcher<const shared_model::crypto::Hash &>(hash)))
      .WillOnce(Return(ret_value));
  EXPECT_CALL(*storage_, getBlockQuery()).WillOnce(Return(block_query_mock));
  EXPECT_CALL(*status_bus_, statuses())
      .WillRepeatedly(Return(
          rxcpp::observable<>::empty<iroha::torii::StatusBus::Objects>()));

  initCommandService();
  auto response = command_service_->getStatus(hash);

  ASSERT_NO_THROW({
    boost::get<const shared_model::interface::RejectedTxResponse &>(
        response->get());
  }) << "Wrong response. Expected: RejectedTxResponse, Received: "
     << response->toString();
}
