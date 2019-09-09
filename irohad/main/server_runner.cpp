/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/server_runner.hpp"

#include <chrono>

#include <grpc/impl/codegen/grpc_types.h>
#include <boost/format.hpp>
#include "logger/logger.hpp"
#include "main/server_runner_auth.hpp"
#include "network/impl/tls_credentials.hpp"

namespace {

  const auto kPortBindError = "Cannot bind server to address %s";

  std::shared_ptr<grpc::ServerCredentials> ServerRunner::createCredentials(
      const boost::optional<std::shared_ptr<iroha::network::TlsCredentials>>
          &my_tls_creds,
      const boost::optional<
          std::unique_ptr<iroha::network::PeerTlsCertificatesProvider>>
          &peer_tls_certificates_provider) {
    std::shared_ptr<grpc::ServerCredentials> credentials;
    if (my_tls_creds) {
      grpc::SslServerCredentialsOptions::PemKeyCertPair keypair = {
          my_tls_creds->private_key, my_tls_creds->certificate};
      auto options = grpc::SslServerCredentialsOptions();
      options.pem_key_cert_pairs.push_back(keypair);
      // options.pem_root_certs = my_tls_creds->certificate;  // dummy value
      options.client_certificate_request =
          GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY;
      credentials = grpc::SslServerCredentials(options);
    } else {
      credentials = grpc::InsecureServerCredentials();
    }
    if (peer_tls_certificates_provider) {
      credentials->SetAuthMetadataProcessor(
          std::make_shared<PeerCertificateAuthMetadataProcessor>(
              peer_tls_certificates_provider.value()));
    }
    return credentials;
  }

}  // namespace

ServerRunner::ServerRunner(
    const std::string &address,
    logger::LoggerPtr log,
    bool reuse,
    const boost::optional<std::shared_ptr<iroha::network::TlsCredentials>>
        &my_tls_creds,
    const boost::optional<
        std::unique_ptr<iroha::network::PeerTlsCertificatesProvider>>
        &peer_tls_certificates_provider)
    : log_(std::move(log)),
      server_address_(address),
      reuse_(reuse),
      credentials_(my_tls_creds, peer_tls_certificates_provider) {}

ServerRunner::~ServerRunner() {
  shutdown(std::chrono::system_clock::now());
}

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

  builder.AddListeningPort(server_address_, credentials_, selected_port);

  for (auto &service : services_) {
    builder.RegisterService(service.get());
  }

  // in order to bypass built-it limitation of gRPC message size
  builder.SetMaxReceiveMessageSize(INT_MAX);
  builder.SetMaxSendMessageSize(INT_MAX);

  // enable retry policy
  builder.AddChannelArgument(GRPC_ARG_ENABLE_RETRIES, 1);

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
