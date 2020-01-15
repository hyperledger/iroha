/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "common/byteutils.hpp"
#include "common/files.hpp"
#include "cryptography/blob.hpp"
#include "endpoint.grpc.pb.h"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_client_factory.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/server_runner.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "network/impl/client_factory.hpp"
#include "network/impl/peer_tls_certificates_provider_root.hpp"
#include "network/impl/tls_credentials.hpp"
#include "test_data_providers/test_keys.hpp"
#include "test_data_providers/test_p2p_tls_creds.hpp"

namespace {
  constexpr auto kLocalhost = "127.0.0.1";
  constexpr auto kLocalhostAnyPort = "127.0.0.1:0";

  class MockQueryService : public iroha::protocol::QueryService_v1::Service {
   public:
    grpc::Status Find(grpc::ServerContext *context,
                      const iroha::protocol::Query *request,
                      iroha::protocol::QueryResponse *response) override {
      return grpc::Status::OK;
    }
  };
}  // namespace

class ClientFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    insecure_client_factory_ = iroha::network::getTestInsecureClientFactory();
    insecure_server_runner_ = std::make_unique<iroha::network::ServerRunner>(
        kLocalhostAnyPort,
        getTestLoggerManager()->getChild("InsecureServerRunner"),
        false);
    insecure_server_runner_->append(std::make_shared<MockQueryService>());
    auto insecure_port_optional =
        iroha::expected::resultToOptionalValue(insecure_server_runner_->run());
    ASSERT_TRUE(insecure_port_optional) << "Could not create insecure server";
    insecure_address_ =
        std::string(kLocalhost) + ":" + std::to_string(*insecure_port_optional);

    auto server_cert_provider =
        std::make_shared<iroha::network::PeerTlsCertificatesProviderRoot>(
            iroha::getPeer1TlsCreds().certificate);

    tls_client_factory_ = iroha::network::getTestTlsClientFactory(
        std::string(iroha::getPeer2TlsCreds().certificate),
        std::make_shared<const iroha::network::TlsCredentials>(
            iroha::getPeer1TlsCreds()));
    tls_server_runner_ = std::make_unique<iroha::network::ServerRunner>(
        kLocalhostAnyPort,
        getTestLoggerManager()->getChild("TlsServerRunner"),
        false,
        std::make_shared<const iroha::network::TlsCredentials>(
            iroha::getPeer2TlsCreds()),
        std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>(
            server_cert_provider));
    tls_server_runner_->append(std::make_shared<MockQueryService>());
    auto tls_port_optional =
        iroha::expected::resultToOptionalValue(tls_server_runner_->run());
    ASSERT_TRUE(tls_port_optional) << "Could not create TLS server";
    tls_address_ =
        std::string(kLocalhost) + ":" + std::to_string(*tls_port_optional);

    outside_client_factory_ = iroha::network::getTestTlsClientFactory(
        std::string(iroha::getPeer2TlsCreds().certificate),
        std::make_shared<const iroha::network::TlsCredentials>(
            iroha::getPeer3TlsCreds()));
  }

  auto makeRequestAndCheckStatus(
      const std::shared_ptr<iroha::protocol::QueryService_v1::StubInterface>
          &client,
      grpc::StatusCode code) {
    iroha::protocol::Query query;
    iroha::protocol::QueryResponse response;

    grpc::ClientContext client_context;

    auto status = client->Find(&client_context, query, &response);

    ASSERT_EQ(status.error_code(), code) << status.error_message();
  }

  auto makeClient(
      const std::unique_ptr<iroha::network::GenericClientFactory> &factory,
      const std::string &address) {
    return factory
        ->createClient<iroha::protocol::QueryService_v1>(
            *makePeer(address,
                      iroha::getPeer1PublicKey(),
                      iroha::getPeer2TlsCreds().certificate))
        .assumeValue();
  }

  std::string insecure_address_;
  std::unique_ptr<iroha::network::ServerRunner> insecure_server_runner_;
  std::unique_ptr<iroha::network::GenericClientFactory>
      insecure_client_factory_;

  std::string tls_address_;
  std::unique_ptr<iroha::network::ServerRunner> tls_server_runner_;
  std::unique_ptr<iroha::network::GenericClientFactory> tls_client_factory_;

  std::unique_ptr<iroha::network::GenericClientFactory> outside_client_factory_;
};

TEST_F(ClientFactoryTest, InsecureConnectionToInsecureServer) {
  makeRequestAndCheckStatus(
      makeClient(insecure_client_factory_, insecure_address_), grpc::OK);
}

TEST_F(ClientFactoryTest, SecureConnectionToInsecureServer) {
  makeRequestAndCheckStatus(makeClient(tls_client_factory_, insecure_address_),
                            grpc::UNAVAILABLE);
}

TEST_F(ClientFactoryTest, InsecureConnectionToSecureServer) {
  makeRequestAndCheckStatus(makeClient(insecure_client_factory_, tls_address_),
                            grpc::UNAVAILABLE);
}

TEST_F(ClientFactoryTest, SecureConnectionToSecureServer) {
  makeRequestAndCheckStatus(makeClient(tls_client_factory_, tls_address_),
                            grpc::OK);
}

TEST_F(ClientFactoryTest, SecureConnectionToSecureServerWrongClientPublicKey) {
  makeRequestAndCheckStatus(makeClient(outside_client_factory_, tls_address_),
                            grpc::CANCELLED);
}
