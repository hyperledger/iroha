/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fuzzing/block_loader_fixture.hpp"

#include "fuzzing/grpc_servercontext_dtor_segv_workaround.hpp"
#include "module/vendor/grpc_mocks.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
  static fuzzing::BlockLoaderFixture fixture;

  if (size < 1) {
    return 0;
  }

  iroha::network::proto::BlockRequest request;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(true, data, size, &request)) {
    grpc::ServerContext context;
    NiceMock<iroha::MockServerWriter<iroha::protocol::Block>> serverWriter;
    fixture.block_loader_service_->retrieveBlocks(
        &context,
        &request,
        reinterpret_cast<grpc::ServerWriter<iroha::protocol::Block> *>(
            &serverWriter));
  }

  return 0;
}
