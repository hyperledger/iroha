/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TORII_MOCKS_HPP
#define IROHA_TORII_MOCKS_HPP

#include <gmock/gmock.h>

#include "cryptography/hash.hpp"
#include "endpoint.grpc.pb.h"
#include "endpoint.pb.h"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "torii/command_service.hpp"
#include "torii/processor/query_processor.hpp"
#include "torii/processor/transaction_processor.hpp"
#include "torii/status_bus.hpp"

namespace iroha {
  namespace torii {

    class MockStatusBus : public StatusBus {
     public:
      MOCK_METHOD1(publish, void(StatusBus::Objects));
      MOCK_METHOD0(statuses, rxcpp::observable<StatusBus::Objects>());
    };

    class MockCommandService : public iroha::torii::CommandService {
     public:
      MOCK_METHOD1(handleTransactionBatch,
                   void(std::shared_ptr<
                        shared_model::interface::TransactionBatch> batch));
      MOCK_METHOD1(
          getStatus,
          std::shared_ptr<shared_model::interface::TransactionResponse>(
              const shared_model::crypto::Hash &request));
      MOCK_METHOD1(
          getStatusStream,
          rxcpp::observable<
              std::shared_ptr<shared_model::interface::TransactionResponse>>(
              const shared_model::crypto::Hash &));
    };

    class MockTransactionProcessor : public TransactionProcessor {
     public:
      MOCK_CONST_METHOD1(
          batchHandle,
          void(std::shared_ptr<shared_model::interface::TransactionBatch>
                   transaction_batch));
    };

  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_TORII_MOCKS_HPP
