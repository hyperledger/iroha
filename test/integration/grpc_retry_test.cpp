/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include "endpoint.grpc.pb.h"
#include "framework/test_logger.hpp"
#include "main/server_runner.hpp"
#include "network/impl/grpc_channel_builder.hpp"
#include "qry_responses.pb.h"
#include "queries.pb.h"

namespace {
  constexpr auto kErrorMessage = "this is a test error message";
}

class MockQueryService : public iroha::protocol::QueryService_v1::Service {
 public:
  explicit MockQueryService(int max_attempts) : max_attempts_(max_attempts) {}

  grpc::Status Find(grpc::ServerContext *context,
                    const iroha::protocol::Query *request,
                    iroha::protocol::QueryResponse *response) override {
    if (attempts_ < max_attempts_) {
      attempts_++;
      return grpc::Status(grpc::StatusCode::ABORTED, kErrorMessage);
    }
    return grpc::Status::OK;
  }

 private:
  int attempts_ = 0;
  int max_attempts_;
};

namespace {
  constexpr int kAttemptsForSuccess =
      iroha::network::details::kClientRequestRetryAttempts - 1;
  constexpr int kAttemptsForFailure =
      iroha::network::details::kClientRequestRetryAttempts;
  constexpr auto kListenIP = "127.0.0.1";

  auto makeRunner() {
    auto listen_addr = std::string(kListenIP) + ":0";
    auto logger = getTestLogger("TestServerRunner");
    return std::make_shared<iroha::network::ServerRunner>(
        listen_addr, logger, true);
  }

  std::shared_ptr<iroha::network::ServerRunner> makeServer(int max_attempts,
                                                           int &port) {
    auto runner = makeRunner();
    runner->append(std::make_shared<MockQueryService>(max_attempts));
    runner->run().match([&](const auto &val) { port = val.value; },
                        [](const auto &err) {
                          FAIL() << "Error creating test server: " << err.error;
                        });
    return runner;
  }

  auto makeRequestAndCheckStatus(int port,
                                 grpc::StatusCode code,
                                 const std::string &message) {
    auto client =
        iroha::network::createClient<iroha::protocol::QueryService_v1>(
            std::string(kListenIP) + ":" + std::to_string(port));

    iroha::protocol::Query query;
    iroha::protocol::QueryResponse response;

    grpc::ClientContext client_context;

    auto status = client->Find(&client_context, query, &response);

    ASSERT_EQ(status.error_code(), code);
    ASSERT_EQ(status.error_message(), message);
  }

}  // namespace

/*
 * @given a gRPC server is created, which fails `kAttemptsForSuccess` times
 *        and then responds with an OK
 * @when  we call an endpoint from that server
 * @then  the final response is OK
 */
TEST(GrpcRetryTest, GrpcRetrySuccessTest) {
  // the variable is not used in any way except keeping the server alive
  int port;
  auto server = makeServer(kAttemptsForSuccess, port);
  makeRequestAndCheckStatus(port, grpc::StatusCode::OK, "");
}

/*
 * @given a gRPC server is created, which fails `kAttemptsForFailure` times
 *        and then responds with an OK
 * @when  we call an endpoint from that server
 * @then  the final response is the error
 */
TEST(GrpcRetryTest, GrpcRetryFailureTest) {
  // the variable is not used in any way except keeping the server alive
  int port;
  auto server = makeServer(kAttemptsForFailure, port);
  makeRequestAndCheckStatus(port, grpc::StatusCode::ABORTED, kErrorMessage);
}
