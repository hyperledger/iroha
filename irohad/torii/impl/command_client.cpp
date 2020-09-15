/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <thread>

#include <grpc++/grpc++.h>

#include "common/byteutils.hpp"
#include "logger/logger.hpp"
#include "torii/command_client.hpp"
#include "transaction.pb.h"

namespace torii {

  using iroha::protocol::ToriiResponse;
  using iroha::protocol::Transaction;

  CommandSyncClient::CommandSyncClient(
      std::shared_ptr<torii::CommandSyncClient::Service::StubInterface> stub,
      logger::LoggerPtr log)
      : stub_(std::move(stub)), log_(std::move(log)) {}

  grpc::Status CommandSyncClient::Torii(const Transaction &tx) const {
    google::protobuf::Empty a;
    grpc::ClientContext context;
    return stub_->Torii(&context, tx, &a);
  }

  grpc::Status CommandSyncClient::ListTorii(
      const iroha::protocol::TxList &tx_list) const {
    google::protobuf::Empty a;
    grpc::ClientContext context;
    return stub_->ListTorii(&context, tx_list, &a);
  }

  grpc::Status CommandSyncClient::Status(
      const iroha::protocol::TxStatusRequest &request,
      iroha::protocol::ToriiResponse &response) const {
    grpc::ClientContext context;
    return stub_->Status(&context, request, &response);
  }

  void CommandSyncClient::StatusStream(
      const iroha::protocol::TxStatusRequest &tx,
      std::vector<iroha::protocol::ToriiResponse> &response) const {
    grpc::ClientContext context;
    ToriiResponse resp;
    auto reader = stub_->StatusStream(&context, tx);
    while (reader->Read(&resp)) {
      log_->debug("received new status: {}, hash {}",
                  resp.tx_status(),
                  iroha::bytestringToHexstring(resp.tx_hash()));
      response.push_back(resp);
    }
    reader->Finish();
  }

}  // namespace torii
