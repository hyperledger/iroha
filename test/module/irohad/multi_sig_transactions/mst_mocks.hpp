/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_MOCKS_HPP
#define IROHA_MST_MOCKS_HPP

#include <gmock/gmock.h>
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/mst_processor.hpp"
#include "multi_sig_transactions/mst_propagation_strategy.hpp"
#include "multi_sig_transactions/mst_time_provider.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "network/mst_transport.hpp"
#include "storage_shared_limit/moved_item.hpp"
#include "storage_shared_limit/storage_limit_none.hpp"

namespace iroha {

  class MockMstTransport : public network::MstTransport {
   public:
    MOCK_METHOD1(subscribe,
                 void(std::shared_ptr<network::MstTransportNotification>));
    MOCK_METHOD2(sendState,
                 void(const shared_model::interface::Peer &to,
                      const MstState &providing_state));
  };

  /**
   * Transport notification mock
   */
  class MockMstTransportNotification
      : public network::MstTransportNotification {
   public:
    void onNewState(const shared_model::crypto::PublicKey &from,
                    MstState new_state) override {
      onNewStateMock(from, new_state);
    }

    MOCK_METHOD2(onNewStateMock,
                 void(const shared_model::crypto::PublicKey &from,
                      const MstState &state));
  };

  /**
   * Propagation strategy mock
   */
  class MockPropagationStrategy : public PropagationStrategy {
   public:
    MOCK_METHOD0(emitter, rxcpp::observable<PropagationData>());
  };

  /**
   * Time provider mock
   */
  class MockTimeProvider : public MstTimeProvider {
   public:
    MOCK_CONST_METHOD0(getCurrentTime, TimeType());
  };

  struct MockMstProcessor : public MstProcessor {
    MockMstProcessor(logger::LoggerPtr log) : MstProcessor(std::move(log)) {}
    MOCK_METHOD1(propagateBatchImpl, bool(const DataType &));
    MOCK_CONST_METHOD0(onStateUpdateImpl,
                       rxcpp::observable<std::shared_ptr<const MstState>>());
    MOCK_CONST_METHOD0(onPreparedBatchesImpl,
                       rxcpp::observable<std::shared_ptr<MovedBatch>>());
    MOCK_CONST_METHOD0(onExpiredBatchesImpl, rxcpp::observable<DataType>());
    MOCK_CONST_METHOD1(batchInStorageImpl, bool(const DataType &));
  };

  struct MockMovedBatch : public MovedItem<BatchPtr> {
    explicit MockMovedBatch(BatchPtr batch)
        : MovedBatch(batch, std::make_shared<StorageLimitNone<BatchPtr>>()) {
      EXPECT_CALL(*this, get()).WillRepeatedly(::testing::Return(batch));
      EXPECT_CALL(*this, extract())
          .Times(::testing::AtMost(1))
          .WillRepeatedly(::testing::Return(batch));
    }
    MOCK_CONST_METHOD0(get, BatchPtr());
    MOCK_METHOD0(extract, BatchPtr());
  };
}  // namespace iroha
#endif  // IROHA_MST_MOCKS_HPP
