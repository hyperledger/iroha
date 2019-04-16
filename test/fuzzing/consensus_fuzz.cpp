/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <libfuzzer/libfuzzer_macro.h>

#include "consensus/yac/transport/impl/network_impl.hpp"

#include "logger/dummy_logger.hpp"
#include "module/irohad/consensus/yac/mock_yac_network.hpp"

using namespace testing;

namespace fuzzing {
  struct ConsensusFixture {
    std::shared_ptr<
        NiceMock<iroha::consensus::yac::MockYacNetworkNotifications>>
        notifications_;
    std::shared_ptr<iroha::network::AsyncGrpcClient<google::protobuf::Empty>>
        async_call_;
    std::shared_ptr<iroha::consensus::yac::NetworkImpl> network_;

    ConsensusFixture() {
      notifications_ = std::make_shared<
          NiceMock<iroha::consensus::yac::MockYacNetworkNotifications>>();
      async_call_ = std::make_shared<
          iroha::network::AsyncGrpcClient<google::protobuf::Empty>>(
          logger::getDummyLoggerPtr());
      network_ = std::make_shared<iroha::consensus::yac::NetworkImpl>(
          async_call_, logger::getDummyLoggerPtr());
      network_->subscribe(notifications_);
    }
  };
}  // namespace fuzzing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
  static fuzzing::ConsensusFixture fixture;

  if (size < 1) {
    return 0;
  }

  iroha::consensus::yac::proto::State request;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(true, data, size, &request)) {
    grpc::ServerContext context;
    google::protobuf::Empty response;
    fixture.network_->SendState(&context, &request, &response);
  }

  return 0;
}
