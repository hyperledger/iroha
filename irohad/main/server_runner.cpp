/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/server_runner.hpp"

#include <fstream>
#include <boost/format.hpp>
#include "logger/logger.hpp"

const auto kPortBindError = "Cannot bind server to address %s";
const auto kPrivateKeyError = "Cannot read private key file";
const auto kCertificateError = "Cannot read certificate file";

ServerRunner::ServerRunner(const std::string &address,
                           logger::LoggerPtr log,
                           bool reuse,
                           const std::string &tls_keypair)
    : log_(std::move(log)),
      serverAddress_(address),
      reuse_(reuse),
      tlsKeypair_(tls_keypair) {}

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

  bool enable_tls = tlsKeypair_.length() > 0;
  if (enable_tls) {
    std::string private_key_data, certificate_data;
    try {
      std::ifstream private_key_file(tlsKeypair_ + ".key");
      std::stringstream ss;
      ss << private_key_file.rdbuf();
      private_key_data = ss.str();
    } catch (std::ifstream::failure e) {
      return iroha::expected::makeError(kPrivateKeyError);
    }
    try {
      std::ifstream certificate_file(tlsKeypair_ + ".crt");
      std::stringstream ss;
      ss << certificate_file.rdbuf();
      certificate_data = ss.str();
    } catch (std::ifstream::failure e) {
      return iroha::expected::makeError(kCertificateError);
    }

    grpc::SslServerCredentialsOptions::PemKeyCertPair keypair = {
      private_key_data, certificate_data
    };
    auto options = grpc::SslServerCredentialsOptions();
    options.pem_key_cert_pairs.push_back(keypair);
    auto credentials = grpc::SslServerCredentials(options);
    builder.AddListeningPort(serverAddress_, credentials, &selected_port);
  } else { // if (enable_tls)
    builder.AddListeningPort(
        serverAddress_, grpc::InsecureServerCredentials(), &selected_port);
  }

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
