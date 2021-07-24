/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <fmt/core.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include "endpoint.grpc.pb.h"
#include "framework/test_logger.hpp"
#include "main/server_runner.hpp"
#include "network/impl/channel_factory.hpp"
#include "qry_responses.pb.h"
#include "queries.pb.h"

using namespace std::literals::chrono_literals;

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
  const auto kChannelParams = [] {
    static const auto retry_policy = [] {
      iroha::network::GrpcChannelParams::RetryPolicy retry_policy;
      retry_policy.max_attempts = 5u;
      retry_policy.initial_backoff = 1s;
      retry_policy.max_backoff = 1s;
      retry_policy.backoff_multiplier = 1.f;
      retry_policy.retryable_status_codes = {
          "UNKNOWN", "DEADLINE_EXCEEDED", "ABORTED", "INTERNAL", "UNAVAILABLE"};
      return retry_policy;
    }();
    auto params = std::make_unique<iroha::network::GrpcChannelParams>();
    params->max_request_message_bytes = std::numeric_limits<int>::max();
    params->max_response_message_bytes = std::numeric_limits<int>::max();
    params->retry_policy = retry_policy;
    return params;
  }();
  const unsigned int kAttemptsForFailure =
      kChannelParams->retry_policy->max_attempts;
  const unsigned int kAttemptsForSuccess = kAttemptsForFailure - 1;
  constexpr auto kListenIP = "127.0.0.1";

  auto makeRunner(int port) {
    auto listen_addr = fmt::format("{}:{}", kListenIP, port);
    auto logger = getTestLogger("TestServerRunner");
    return std::make_shared<iroha::network::ServerRunner>(
        listen_addr, logger, true);
  }

  std::shared_ptr<iroha::network::ServerRunner> makeServer(int max_attempts,
                                                           int &port) {
    auto runner = makeRunner(port);
    runner->append(std::make_shared<MockQueryService>(max_attempts));
    runner->run().match([&](const auto &val) { port = val.value; },
                        [](const auto &err) {
                          FAIL() << "Error creating test server: " << err.error;
                        });
    return runner;
  }

  auto makeClient(int port) {
    return iroha::network::createInsecureClient<
        iroha::protocol::QueryService_v1>(kListenIP, port, *kChannelParams);
  }

  template <typename T>
  auto makeRequestAndCheckStatusWithGivenClient(T client,
                                                grpc::StatusCode code,
                                                const std::string &message) {
    iroha::protocol::Query query;
    iroha::protocol::QueryResponse response;

    grpc::ClientContext client_context;

    auto status = client->Find(&client_context, query, &response);

    EXPECT_EQ(status.error_code(), code);
    EXPECT_EQ(status.error_message(), message);
  }

  auto makeRequestAndCheckStatus(int port,
                                 grpc::StatusCode code,
                                 const std::string &message) {
    makeRequestAndCheckStatusWithGivenClient(makeClient(port), code, message);
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
  int port = 0;
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
  int port = 0;
  auto server = makeServer(kAttemptsForFailure, port);
  makeRequestAndCheckStatus(port, grpc::StatusCode::ABORTED, kErrorMessage);
}

/*
 * @given a gRPC client tries to connect to a stopped server and fails,
 *        then the server is started again
 * @when  the client makes a request
 * @then  the request succeeds
 */
TEST(GrpcRetryTest, GrpcReuseConnectionAfterServerUnavailable) {
  int port = 0;
  decltype(makeClient(port)) client;
  {
    auto server = makeServer(kAttemptsForSuccess, port);
    client = makeClient(port);
  }
  makeRequestAndCheckStatus(port,
                            grpc::StatusCode::UNAVAILABLE,
                            "failed to connect to all addresses");

  // the variable is not used in any way except keeping the server alive
  auto server = makeServer(kAttemptsForSuccess, port);
  makeRequestAndCheckStatus(port, grpc::StatusCode::OK, "");
}
