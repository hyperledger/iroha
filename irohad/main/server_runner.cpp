/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/server_runner.hpp"

#include <boost/format.hpp>
#include "logger/logger.hpp"

const auto kPortBindError = "Cannot bind server to address %s";

ServerRunner::ServerRunner(const std::string &address,
                           logger::LoggerPtr log,
                           bool reuse)
    : log_(std::move(log)), serverAddress_(address), reuse_(reuse) {}

ServerRunner &ServerRunner::append(std::shared_ptr<grpc::Service> service) {
  services_.push_back(service);
  return *this;
}

iroha::expected::Result<int, std::string> ServerRunner::run() {
  grpc::ServerBuilder builder;
  int selected_port = 0;

  if (not reuse_) {
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
  }

  builder.AddListeningPort(
      serverAddress_, grpc::InsecureServerCredentials(), &selected_port);

  for (auto &service : services_) {
    builder.RegisterService(service.get());
  }

  // in order to bypass built-it limitation of gRPC message size
  builder.SetMaxReceiveMessageSize(INT_MAX);
  builder.SetMaxSendMessageSize(INT_MAX);

  serverInstance_ = builder.BuildAndStart();
  serverInstanceCV_.notify_one();

  if (selected_port == 0) {
    return iroha::expected::makeError(
        (boost::format(kPortBindError) % serverAddress_).str());
  }

  return iroha::expected::makeValue(selected_port);
}

void ServerRunner::waitForServersReady() {
  std::unique_lock<std::mutex> lock(waitForServer_);
  while (not serverInstance_) {
    serverInstanceCV_.wait(lock);
  }
}

void ServerRunner::shutdown() {
  if (serverInstance_) {
    serverInstance_->Shutdown();
  } else {
    log_->warn("Tried to shutdown without a server instance");
  }
}

void ServerRunner::shutdown(
    const std::chrono::system_clock::time_point &deadline) {
  if (serverInstance_) {
    serverInstance_->Shutdown(deadline);
  } else {
    log_->warn("Tried to shutdown without a server instance");
  }
}
