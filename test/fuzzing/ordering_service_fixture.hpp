/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_SERVICE_FIXTURE_HPP
#define IROHA_ORDERING_SERVICE_FIXTURE_HPP

#include <memory>

#include <gtest/gtest.h>
#include <libfuzzer/libfuzzer_macro.h>

#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "module/shared_model/interface/mock_transaction_batch_factory.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/validators/validators.hpp"
#include "ordering/impl/on_demand_ordering_service_impl.hpp"
#include "ordering/impl/on_demand_os_server_grpc.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_transaction_validator.hpp"

using namespace testing;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;

namespace fuzzing {
  struct OrderingServiceFixture {
    std::shared_ptr<OnDemandOsServerGrpc::TransportFactoryType>
        transaction_factory_;
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser_;
    std::shared_ptr<NiceMock<MockTransactionBatchFactory>>
        transaction_batch_factory_;

    OrderingServiceFixture() {
      std::unique_ptr<shared_model::validation::AbstractValidator<
          shared_model::interface::Transaction>>
          interface_transaction_validator =
              std::make_unique<NiceMock<shared_model::validation::MockValidator<
                  shared_model::interface::Transaction>>>();
      std::unique_ptr<shared_model::validation::AbstractValidator<
          iroha::protocol::Transaction>>
          proto_transaction_validator =
              std::make_unique<NiceMock<shared_model::validation::MockValidator<
                  iroha::protocol::Transaction>>>();
      transaction_factory_ =
          std::make_shared<shared_model::proto::ProtoTransportFactory<
              shared_model::interface::Transaction,
              shared_model::proto::Transaction>>(
              std::move(interface_transaction_validator),
              std::move(proto_transaction_validator));

      batch_parser_ = std::make_shared<
          shared_model::interface::TransactionBatchParserImpl>();
      transaction_batch_factory_ =
          std::make_shared<NiceMock<MockTransactionBatchFactory>>();
    }
  };
}  // namespace fuzzing

#endif  // IROHA_ORDERING_SERVICE_FIXTURE_HPP
