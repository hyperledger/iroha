/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_COMMAND_CLIENT_HPP
#define TORII_COMMAND_CLIENT_HPP

#include <endpoint.grpc.pb.h>
#include <grpc++/grpc++.h>
#include <memory>
#include <thread>

#include "logger/logger_fwd.hpp"

namespace torii {

  /**
   * CommandSyncClient
   */
  class CommandSyncClient {
   public:
    using Service = iroha::protocol::CommandService_v1;

    CommandSyncClient(std::shared_ptr<Service::StubInterface> stub,
                      logger::LoggerPtr log);

    /**
     * requests tx to a torii server and returns response (blocking, sync)
     * @param tx
     * @return grpc::Status - returns connection is success or not.
     */
    grpc::Status Torii(const iroha::protocol::Transaction &tx) const;

    /**
     * requests list of txs to a torii server and returns response
     * @param tx_list
     * @return grpc::Status - returns connection is success or not.
     */
    grpc::Status ListTorii(const iroha::protocol::TxList &tx_list) const;

    /**
     * @param tx
     * @param response returns ToriiResponse if succeeded
     * @return grpc::Status - returns connection is success or not.
     */
    grpc::Status Status(const iroha::protocol::TxStatusRequest &tx,
                        iroha::protocol::ToriiResponse &response) const;

    /**
     * Acquires stream of transaction statuses from the request
     * moment until final.
     * @param tx - transaction to send.
     * @param response - vector of all statuses during tx pipeline.
     */
    void StatusStream(
        const iroha::protocol::TxStatusRequest &tx,
        std::vector<iroha::protocol::ToriiResponse> &response) const;

   private:
    std::shared_ptr<Service::StubInterface> stub_;
    logger::LoggerPtr log_;
  };

}  // namespace torii

#endif  // TORII_COMMAND_CLIENT_HPP
