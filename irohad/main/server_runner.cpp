/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/server_runner.hpp"

#include <grpc/impl/codegen/grpc_types.h>

#include <boost/format.hpp>
#include <chrono>

#include "logger/logger.hpp"
#include "network/channel_constants.hpp"
#include "network/impl/tls_credentials.hpp"

using namespace iroha::network;

namespace {

  std::shared_ptr<grpc::ServerCredentials> createCredentials(
      const boost::optional<std::shared_ptr<const TlsCredentials>>
          &my_tls_creds) {
    if (not my_tls_creds) {
      return grpc::InsecureServerCredentials();
    }
    auto options = grpc::SslServerCredentialsOptions(
        GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    grpc::SslServerCredentialsOptions::PemKeyCertPair keypair = {
        my_tls_creds.value()->private_key, my_tls_creds.value()->certificate};
    options.pem_key_cert_pairs.push_back(keypair);
    std::shared_ptr<grpc::ServerCredentials> credentials =
        grpc::SslServerCredentials(options);
    return credentials;
  }

}  // namespace

ServerRunner::ServerRunner(
    const std::string &address,
    logger::LoggerPtr log,
    bool reuse,
    const boost::optional<std::shared_ptr<const TlsCredentials>> &my_tls_creds)
    : log_(std::move(log)),
      server_address_(address),
      credentials_(createCredentials(my_tls_creds)),
      reuse_(reuse) {}

ServerRunner::~ServerRunner() {
  shutdown(std::chrono::system_clock::now());
}

ServerRunner &ServerRunner::append(std::shared_ptr<grpc::Service> service) {
  if (service)
    services_.push_back(service);
  return *this;
}

iroha::expected::Result<int, std::string> ServerRunner::run() {
  grpc::ServerBuilder builder;
  int selected_port = 0;

  builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, reuse_ ? 1 : 0);
  builder.AddListeningPort(server_address_, credentials_, &selected_port);
  builder.SetMaxReceiveMessageSize(kMaxMessageSize);
  builder.SetMaxSendMessageSize(kMaxMessageSize);

  for (auto &service : services_) {
    builder.RegisterService(service.get());
  }

  // enable retry policy
  builder.AddChannelArgument(GRPC_ARG_ENABLE_RETRIES, 1);

  server_instance_ = builder.BuildAndStart();
  server_instance_cv_.notify_one();

  if (selected_port == 0) {
    return iroha::expected::makeError(
        fmt::format("Cannot bind server to address {}", server_address_));
  }

  return iroha::expected::makeValue(selected_port);
}

void ServerRunner::waitForServersReady() {
  std::unique_lock<std::mutex> lock(wait_for_server_);
  while (not server_instance_) {
    server_instance_cv_.wait(lock);
  }
}

void ServerRunner::shutdown() {
  if (server_instance_) {
    server_instance_->Shutdown();
  } else {
    log_->warn("Tried to shutdown without a server instance");
  }
}

void ServerRunner::shutdown(
    const std::chrono::system_clock::time_point &deadline) {
  if (server_instance_) {
    server_instance_->Shutdown(deadline);
  } else {
    log_->warn("Tried to shutdown without a server instance");
  }
}
