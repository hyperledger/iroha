/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <gtest/gtest.h>
#include <libfuzzer/libfuzzer_macro.h>

#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "fuzzing/grpc_servercontext_dtor_segv_workaround.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "logger/dummy_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_transaction_validator.hpp"

using namespace testing;
using namespace iroha::network;

namespace fuzzing {
  struct MstFixture {
    std::shared_ptr<iroha::TestCompleter> completer_;
    std::shared_ptr<MstTransportGrpc> mst_transport_grpc_;

    MstFixture() {
      auto async_call_ = std::make_shared<
          iroha::network::AsyncGrpcClient<google::protobuf::Empty>>(
          logger::getDummyLoggerPtr());
      // TODO luckychess 25.12.2018 Component initialisation reuse
      // IR-1886, IR-142
      std::unique_ptr<shared_model::validation::AbstractValidator<
          shared_model::interface::Transaction>>
          interface_validator = std::make_unique<
              shared_model::validation::DefaultUnsignedTransactionValidator>(
              iroha::test::kTestsValidatorsConfig);
      std::unique_ptr<shared_model::validation::AbstractValidator<
          iroha::protocol::Transaction>>
          tx_validator = std::make_unique<
              shared_model::validation::ProtoTransactionValidator>();

      auto tx_factory =
          std::make_shared<shared_model::proto::ProtoTransportFactory<
              shared_model::interface::Transaction,
              shared_model::proto::Transaction>>(std::move(interface_validator),
                                                 std::move(tx_validator));
      auto parser = std::make_shared<
          shared_model::interface::TransactionBatchParserImpl>();
      std::shared_ptr<shared_model::validation::AbstractValidator<
          shared_model::interface::TransactionBatch>>
          batch_validator =
              std::make_shared<shared_model::validation::DefaultBatchValidator>(
                  iroha::test::kTestsValidatorsConfig);
      auto batch_factory = std::make_shared<
          shared_model::interface::TransactionBatchFactoryImpl>(
          batch_validator);
      auto storage =
          std::make_shared<NiceMock<iroha::ametsuchi::MockStorage>>();
      auto cache =
          std::make_shared<iroha::ametsuchi::TxPresenceCacheImpl>(storage);
      completer_ = std::make_shared<iroha::TestCompleter>();
      mst_transport_grpc_ = std::make_shared<MstTransportGrpc>(
          async_call_,
          std::move(tx_factory),
          std::move(parser),
          std::move(batch_factory),
          std::move(cache),
          completer_,
          shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair()
              .publicKey(),
          logger::getDummyLoggerPtr(),
          logger::getDummyLoggerPtr());
    }
  };
}  // namespace fuzzing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
  static fuzzing::MstFixture fixture;

  if (size < 1) {
    return 0;
  }

  transport::MstState request;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(true, data, size, &request)) {
    grpc::ServerContext context;
    google::protobuf::Empty response;
    fixture.mst_transport_grpc_->SendState(&context, &request, &response);
  }

  return 0;
}
