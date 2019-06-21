/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/server_runner.hpp"

#include <fstream>

#include <boost/format.hpp>
#include "logger/logger.hpp"
#include "main/server_runner_auth.hpp"

const auto kPortBindError = "Cannot bind server to address %s";
const auto kPrivateKeyError = "Cannot read private key file";
const auto kCertificateError = "Cannot read certificate file";

ServerRunner::ServerRunner(
    const std::string &address,
    logger::LoggerPtr log,
    bool reuse,
    const boost::optional<std::string> &tls_keypair,
    const boost::optional<std::shared_ptr<iroha::ametsuchi::PeerQuery>>
        &peer_query)
    : log_(std::move(log)),
      server_address_(address),
      reuse_(reuse),
      tls_keypair_(tls_keypair),
      peer_query_(peer_query) {}

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

  auto port_error = addListeningPortToBuilder(builder, &selected_port);
  if (port_error) {
    return iroha::expected::makeError(*port_error);
  }

  for (auto &service : services_) {
    builder.RegisterService(service.get());
  }

  // in order to bypass built-it limitation of gRPC message size
  builder.SetMaxReceiveMessageSize(INT_MAX);
  builder.SetMaxSendMessageSize(INT_MAX);

  server_instance_ = builder.BuildAndStart();
  server_instance_cv_.notify_one();

  if (selected_port == 0) {
    return iroha::expected::makeError(
        (boost::format(kPortBindError) % server_address_).str());
  }

  return iroha::expected::makeValue(selected_port);
}

void ServerRunner::waitForServersReady() {
  std::unique_lock<std::mutex> lock(wait_for_server_);
  while (not server_instance_) {
    server_instance_cv_.wait(lock);
  }
}

iroha::expected::Result<std::shared_ptr<grpc::ServerCredentials>, std::string>
ServerRunner::createSecureCredentials() {
  std::string private_key_data, certificate_data;
  try {
    std::ifstream private_key_file(*tls_keypair_ + ".key");
    std::stringstream ss;
    ss << private_key_file.rdbuf();
    private_key_data = ss.str();
  } catch (std::ifstream::failure e) {
    return iroha::expected::makeError(kPrivateKeyError);
  }
  try {
    std::ifstream certificate_file(*tls_keypair_ + ".crt");
    std::stringstream ss;
    ss << certificate_file.rdbuf();
    certificate_data = ss.str();
  } catch (const std::ifstream::failure &e) {
    return iroha::expected::makeError(kCertificateError);
  }

  grpc::SslServerCredentialsOptions::PemKeyCertPair keypair = {
      private_key_data, certificate_data};
  auto options = grpc::SslServerCredentialsOptions();
  options.pem_key_cert_pairs.push_back(keypair);
  if (peer_query_) {  // client verification is only enabled if using peer_query
    options.pem_root_certs = certificate_data;  // dummy value
    options.client_certificate_request =
        GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY;
  }
  auto credentials = grpc::SslServerCredentials(options);
  if (peer_query_) {
    credentials->SetAuthMetadataProcessor(
        std::make_shared<PeerCertificateAuthMetadataProcessor>(*peer_query_));
  }
  return iroha::expected::makeValue(credentials);
}

boost::optional<std::string> ServerRunner::addListeningPortToBuilder(
    grpc::ServerBuilder &builder, int *selected_port) {
  if (tls_keypair_) {  // if specified, requested to enable TLS
    std::shared_ptr<grpc::ServerCredentials> credentials;
    boost::optional<std::string> credentials_error = {};
    createSecureCredentials().match(
        [&](const auto &secure_credentials) {
          credentials = secure_credentials.value;
        },
        [&](const auto &error) { credentials_error = error.error; });
    if (credentials_error) {
      return credentials_error;
    }

    builder.AddListeningPort(server_address_, credentials, selected_port);
  } else {  // tls is disabled
    builder.AddListeningPort(
        server_address_, grpc::InsecureServerCredentials(), selected_port);
  }

  return boost::none;
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
