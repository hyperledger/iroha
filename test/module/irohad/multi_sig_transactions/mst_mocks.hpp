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
    MOCK_METHOD2(onNewState,
                 void(const shared_model::crypto::PublicKey &from,
                      MstState state));
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
    MOCK_METHOD1(propagateBatchImpl, void(const DataType &));
    MOCK_CONST_METHOD0(onStateUpdateImpl,
                       rxcpp::observable<std::shared_ptr<MstState>>());
    MOCK_CONST_METHOD0(onPreparedBatchesImpl, rxcpp::observable<DataType>());
    MOCK_CONST_METHOD0(onExpiredBatchesImpl, rxcpp::observable<DataType>());
    MOCK_CONST_METHOD1(batchInStorageImpl, bool(const DataType &));
  };
}  // namespace iroha
#endif  // IROHA_MST_MOCKS_HPP
