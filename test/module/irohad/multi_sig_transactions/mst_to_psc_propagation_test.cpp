/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/propagation_to_pcs.hpp"

#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include "framework/test_logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_mocks.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "module/irohad/network/network_mocks.hpp"
#include "storage_shared_limit/storage_limit_none.hpp"

using namespace iroha;
using namespace testing;

class MstToPcsPropagationTest : public ::testing::Test {
 protected:
  std::shared_ptr<shared_model::interface::Transaction> makeTx() {
    return clone(txBuilder(tx_counter_++).build());
  }

  std::shared_ptr<shared_model::interface::TransactionBatch> makeBatch(
      size_t num_txs) {
    shared_model::interface::types::SharedTxsCollectionType txs;
    std::generate_n(
        std::back_inserter(txs), num_txs, [this]() { return this->makeTx(); });
    return createMockBatchWithTransactions(txs, {});
  }

  rxcpp::subjects::subject<size_t> propagation_available_subject_;
  std::shared_ptr<iroha::network::MockPeerCommunicationService> pcs_{
      std::make_shared<iroha::network::MockPeerCommunicationService>()};
  MstToPcsPropagation propagator{
      pcs_,
      std::make_shared<StorageLimitNone<BatchPtr>>(),
      propagation_available_subject_.get_observable(),
      getTestLogger("MstToPcsPropagation")};

 private:
  size_t tx_counter_{0};
};

/**
 * @given a batch and a PCS that can accept it
 * @when propagator receives the batch
 * @then propagator propagates the batch to PCS immediately
 */
TEST_F(MstToPcsPropagationTest, PropagateImmediately) {
  const auto batch = makeBatch(1);
  EXPECT_CALL(*pcs_, propagate_batch(batch)).WillOnce(Return(true));

  propagator.notifyCompletedBatch(std::make_shared<MockMovedBatch>(batch));
  EXPECT_EQ(propagator.pendingBatchesQuantity(), 0)
      << "Batch must have been propagated immediately.";
}

/**
 * @given several batches and a PCS that is full at first, but then notifies of
 * some available space
 * @when propagator receives the batches
 * @then propagator propagates the batches to PCS respecting the availability
 */
TEST_F(MstToPcsPropagationTest, PropagateWhenAvailabilityNotified) {
  std::vector<BatchPtr> batches{{makeBatch(100),
                                 makeBatch(5),
                                 makeBatch(80),
                                 makeBatch(25),
                                 makeBatch(40),
                                 makeBatch(10)}};

  // feed the batches to propagator
  for (auto batch : batches) {
    EXPECT_CALL(*pcs_, propagate_batch(batch)).WillOnce(Return(false));
    propagator.notifyCompletedBatch(std::make_shared<MockMovedBatch>(batch));
  }

  // notifies propagator of available transactions for propagation to PCS, sets
  // expectations on PCS and removes batches that must have been propagated
  auto notify_available_and_check_propagation =
      [&batches, this](const size_t available_txs) {
        size_t available_after_propagation = available_txs;
        for (auto it = batches.begin(); it != batches.end();) {
          const size_t txs_in_batch = boost::size((*it)->transactions());
          if (txs_in_batch <= available_after_propagation) {
            EXPECT_CALL(*pcs_, propagate_batch(*it)).WillOnce(Return(true));
            available_after_propagation -= txs_in_batch;
            it = batches.erase(it);
          } else {
            EXPECT_CALL(*pcs_, propagate_batch(*it)).Times(0);
            ++it;
          }
        }
        propagation_available_subject_.get_subscriber().on_next(available_txs);
        EXPECT_EQ(propagator.pendingBatchesQuantity(), batches.size());
      };

  notify_available_and_check_propagation(50);
  notify_available_and_check_propagation(90);
  notify_available_and_check_propagation(50);
  notify_available_and_check_propagation(50);
  notify_available_and_check_propagation(100);
}
