/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/utility_client.hpp"

#include <map>

#include "util/proto_status_tools.hpp"

#include <grpc++/grpc++.h>
#include <boost/optional.hpp>
#include "common/bind.hpp"
#include "logger/logger.hpp"
#include "network/impl/channel_factory.hpp"
#include "utility_endpoint.grpc.pb.h"

using namespace iroha::utility_service;

using iroha::operator|;

struct UtilityClient::StubHolder {
  StubHolder(const std::string &address)
      : channel_(
            iroha::network::createInsecureChannel<proto::UtilityService_v1>(
                address, std::nullopt)),
        stub_(proto::UtilityService_v1::NewStub(channel_)) {}

  std::shared_ptr<grpc::Channel> channel_;
  std::unique_ptr<proto::UtilityService_v1::StubInterface> stub_;
};

UtilityClient::UtilityClient(std::string const &irohad_address,
                             logger::LoggerPtr log)
    : log_(std::move(log)),
      stub_holder_(std::make_unique<StubHolder>(irohad_address)) {}

UtilityClient::~UtilityClient() = default;

bool UtilityClient::waitForServerReady(
    std::chrono::milliseconds timeout) const {
  auto state = stub_holder_->channel_->GetState(true);
  auto state_is_ready = [&state] {
    return state == grpc_connectivity_state::GRPC_CHANNEL_READY;
  };
  auto deadline = std::chrono::system_clock::now() + timeout;
  while (not state_is_ready()
         and deadline > ::std::chrono::system_clock::now()) {
    log_->trace("Channel state is not ready.");
    stub_holder_->channel_->WaitForStateChange(state, deadline);
    state = stub_holder_->channel_->GetState(true);
  }
  log_->trace("Channel state is {}ready when finished waiting.",
              state_is_ready() ? "" : "not ");
  return state_is_ready();
}

bool UtilityClient::status(StatusCallback callback) const {
  log_->trace("Sending status request.");

  ::google::protobuf::Empty request;
  ::grpc::ClientContext context;
  proto::Status proto_status;
  auto reader = stub_holder_->stub_->Status(&context, request);

  while (reader->Read(&proto_status)) {
    log_->trace("Got status {}.", proto_status.status());
    auto iface_status = makeStatus(proto_status.status());
    if (not callback(iface_status)) {
      return true;
    }
  }
  return false;
}

bool UtilityClient::shutdown() const {
  log_->trace("Sending shutdown request.");

  ::google::protobuf::Empty request;
  ::google::protobuf::Empty response;
  ::grpc::ClientContext context;
  auto status = stub_holder_->stub_->Shutdown(&context, request, &response);
  if (status.error_code() == ::grpc::StatusCode::OK) {
    log_->trace("Shutdown request completed, status code {}.",
                status.error_code());
    return true;
  }
  log_->warn("Shutdown request error, code {}: {}",
             status.error_code(),
             status.error_message());
  return false;
}
