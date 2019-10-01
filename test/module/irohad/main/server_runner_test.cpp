/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/format.hpp>

#include "endpoint.grpc.pb.h"  // any gRPC service is required for test
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/server_runner.hpp"

using iroha::network::ServerRunner;

boost::format address{"0.0.0.0:%d"};
auto port_visitor = iroha::make_visitor(
    [](iroha::expected::Value<int> x) { return x.value; },
    [](iroha::expected::Error<std::string> x) { return 0; });

/**
 * @given a running ServerRunner
 * @when another ServerRunner tries to run on the same port without port reuse
 * @then Result with error is returned
 */
TEST(ServerRunnerTest, SamePortNoReuse) {
  ServerRunner first_runner((address % 0).str(),
                            getTestLoggerManager()->getChild("ServerRunner1"),
                            true);
  auto first_query_service =
      std::make_shared<iroha::protocol::QueryService_v1::Service>();
  auto result = first_runner.append(first_query_service).run();
  auto port = boost::apply_visitor(port_visitor, result);
  ASSERT_NE(0, port);

  ServerRunner second_runner((address % port).str(),
                             getTestLoggerManager()->getChild("ServerRunner2"),
                             false);
  auto second_query_service =
      std::make_shared<iroha::protocol::QueryService_v1::Service>();
  result = second_runner.append(second_query_service).run();
  port = boost::apply_visitor(port_visitor, result);
  ASSERT_EQ(0, port);
}

/**
 * @given a running ServerRunner
 * @when another ServerRunner tries to run on the same port with port reuse
 * @then Result with port number is returned
 */
TEST(ServerRunnerTest, SamePortWithReuse) {
  ServerRunner first_runner((address % 0).str(),
                            getTestLoggerManager()->getChild("ServerRunner1"),
                            true);
  auto first_query_service =
      std::make_shared<iroha::protocol::QueryService_v1::Service>();
  auto result = first_runner.append(first_query_service).run();
  auto port = boost::apply_visitor(port_visitor, result);
  ASSERT_NE(0, port);

  ServerRunner second_runner((address % port).str(),
                             getTestLoggerManager()->getChild("ServerRunner2"),
                             true);
  auto second_query_service =
      std::make_shared<iroha::protocol::QueryService_v1::Service>();
  result = second_runner.append(second_query_service).run();
  port = boost::apply_visitor(port_visitor, result);
  ASSERT_NE(0, port);
}
