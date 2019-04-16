/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MAIN_SERVER_RUNNER_HPP
#define MAIN_SERVER_RUNNER_HPP

#include <grpc++/grpc++.h>
#include <grpc++/impl/codegen/service_type.h>
#include "common/result.hpp"
#include "logger/logger_fwd.hpp"

/**
 * Class runs Torii server for handling queries and commands.
 */
class ServerRunner {
 public:
  /**
   * Constructor. Initialize a new instance of ServerRunner class.
   * @param address - the address the server will be bind to in URI form
   * @param log to print progress to
   * @param reuse - allow multiple sockets to bind to the same port
   */
  explicit ServerRunner(const std::string &address,
                        logger::LoggerPtr log,
                        bool reuse = true);

  /**
   * Adds a new grpc service to be run.
   * @param service - service to append.
   * @return reference to this with service appended
   */
  ServerRunner &append(std::shared_ptr<grpc::Service> service);

  /**
   * Initialize the server and run main loop.
   * @return Result with used port number or error message
   */
  iroha::expected::Result<int, std::string> run();

  /**
   * Wait until the server is up.
   */
  void waitForServersReady();

  /**
   * Ask grpc server to terminate.
   */
  void shutdown();

  /**
   * Shutdown gRPC server with force on given deadline
   */
  void shutdown(const std::chrono::system_clock::time_point &deadline);

 private:
  logger::LoggerPtr log_;

  std::unique_ptr<grpc::Server> serverInstance_;
  std::mutex waitForServer_;
  std::condition_variable serverInstanceCV_;

  std::string serverAddress_;
  bool reuse_;
  std::vector<std::shared_ptr<grpc::Service>> services_;
};

#endif  // MAIN_SERVER_RUNNER_HPP
