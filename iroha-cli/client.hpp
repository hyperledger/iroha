/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHACLI_CLIENT_HPP
#define IROHACLI_CLIENT_HPP

#include <string>

#include "logger/logger_fwd.hpp"
#include "torii/command_client.hpp"
#include "torii/query_client.hpp"

namespace shared_model {
  namespace interface {
    class Transaction;
    class Query;
  }  // namespace interface
}  // namespace shared_model

namespace iroha_cli {

  class CliClient {
   public:
    template <typename T>
    struct Response {
      grpc::Status status;
      T answer;
    };

    // TODO 13/09/17 luckychess: check if we need more status codes IR-494
    enum TxStatus { OK };

    CliClient(std::string target_ip,
              int port,
              logger::LoggerPtr pb_qry_factory_log);

    /**
     * Send Transaction to Iroha Peer, i.e. target_ip:port
     * @param tx
     * @return
     */
    CliClient::Response<CliClient::TxStatus> sendTx(
        const shared_model::interface::Transaction &tx);

    /**
     * Send Query to Iroha Peer, i.e. target_ip:port
     * @param query
     * @return
     */
    CliClient::Response<iroha::protocol::QueryResponse> sendQuery(
        const shared_model::interface::Query &query);

    CliClient::Response<iroha::protocol::ToriiResponse> getTxStatus(
        std::string tx_hash);

   private:
    torii::CommandSyncClient command_client_;
    torii_utils::QuerySyncClient query_client_;

    logger::LoggerPtr pb_qry_factory_log_;
  };
}  // namespace iroha_cli

#endif  // IROHACLI_CLIENT_CPP_HPP
