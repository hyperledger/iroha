/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_impl.hpp"

#include <gtest/gtest.h>
#include "ametsuchi/tx_cache_response.hpp"
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "framework/batch_helper.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/ametsuchi/mock_tx_presence_cache.hpp"
#include "module/irohad/torii/torii_mocks.hpp"

using ::testing::_;
using ::testing::Matcher;
using ::testing::Ref;
using ::testing::Return;

// Return matcher for batch, which passes it by const &
// used when passing batch as an argument to check() in transaction cache
auto batchRef(const shared_model::interface::TransactionBatch &batch) {
  return Matcher<const shared_model::interface::TransactionBatch &>(Ref(batch));
}

/**
 * This a test for CommandService implementation for possible replays.
 */
class CommandServiceReplayTest : public ::testing::Test {
 public:
  void SetUp() override {
    transaction_processor =
        std::make_shared<iroha::torii::MockTransactionProcessor>();
    status_bus = std::make_shared<iroha::torii::MockStatusBus>();
    tx_status_factory =
        std::make_shared<shared_model::proto::ProtoTxStatusFactory>();
    tx_presence_cache =
        std::make_shared<iroha::ametsuchi::MockTxPresenceCache>();
    log = getTestLogger("CommandServiceReplayTest");
    cache = std::make_shared<iroha::torii::CommandServiceImpl::CacheType>();

    command_service = std::make_shared<iroha::torii::CommandServiceImpl>(
        transaction_processor,
        status_bus,
        tx_status_factory,
        cache,
        tx_presence_cache,
        log);
  }

  auto prepareBatch() {
    auto batch_type = shared_model::interface::types::BatchType::ORDERED;
    auto creator_id = "user@test";
    auto created_time = iroha::time::now();
    shared_model::interface::types::QuorumType quorum = 2;
    auto txs_collection = framework::batch::createBatchOneSignTransactions(
        {std::make_pair(batch_type, creator_id)}, created_time, quorum);
    auto batch =
        std::make_shared<shared_model::interface::TransactionBatchImpl>(
            txs_collection);
    return batch;
  }

  std::shared_ptr<iroha::torii::MockTransactionProcessor> transaction_processor;
  std::shared_ptr<iroha::torii::StatusBus> status_bus;
  std::shared_ptr<shared_model::interface::TxStatusFactory> tx_status_factory;
  std::shared_ptr<iroha::ametsuchi::MockTxPresenceCache> tx_presence_cache;
  logger::LoggerPtr log;
  std::shared_ptr<iroha::torii::CommandServiceImpl::CacheType> cache;
  std::shared_ptr<iroha::torii::CommandService> command_service;
};

/**
 * @given a CommandService with empty internal cache
 * @when an already committed transaction arrives
 * @then the transaction is not passed to transaction processor
 */
TEST_F(CommandServiceReplayTest, ReplayTest) {
  auto batch = prepareBatch();
  auto hash = batch->transactions().front()->hash();

  EXPECT_CALL(*tx_presence_cache, check(batchRef(*batch)))
      .WillOnce(Return(std::vector<iroha::ametsuchi::TxCacheStatusType>(
          {iroha::ametsuchi::tx_cache_status_responses::Committed(hash)})));

  EXPECT_CALL(*transaction_processor, batchHandle(_)).Times(0);

  command_service->handleTransactionBatch(batch);
}

/**
 * @given a CommandService with internal cache that contains MstPending status
 * for the transaction
 * @when an already rejected transaction arrives (it is a replay and may have
 * pending status in internal cache, for example, after cache overflow)
 * @then transaction is not passed to transaction processor
 */
TEST_F(CommandServiceReplayTest, ReplayWhenPendingAndRejectedTest) {
  auto batch = prepareBatch();
  auto hash = batch->transactions().front()->hash();

  cache->addItem(hash, tx_status_factory->makeMstPending(hash));

  EXPECT_CALL(*tx_presence_cache, check(batchRef(*batch)))
      .WillOnce(Return(std::vector<iroha::ametsuchi::TxCacheStatusType>(
          {iroha::ametsuchi::tx_cache_status_responses::Rejected(hash)})));

  EXPECT_CALL(*transaction_processor, batchHandle(_)).Times(0);

  command_service->handleTransactionBatch(batch);
}

/**
 * @given a CommandService with internal cache that contains MstPending status
 * for the transaction
 * @when the transaction arrives
 * @then the transaction is passed to transaction processor
 */
TEST_F(CommandServiceReplayTest, ReplayWhenPendingAndMissingTest) {
  auto batch = prepareBatch();
  auto hash = batch->transactions().front()->hash();

  cache->addItem(hash, tx_status_factory->makeMstPending(hash));

  EXPECT_CALL(*tx_presence_cache, check(batchRef(*batch)))
      .WillOnce(Return(std::vector<iroha::ametsuchi::TxCacheStatusType>(
          {iroha::ametsuchi::tx_cache_status_responses::Missing(hash)})));

  EXPECT_CALL(*transaction_processor, batchHandle(_)).Times(1);

  command_service->handleTransactionBatch(batch);
}
