/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLI_INTERACTIVE_CLI_HPP
#define IROHA_CLI_INTERACTIVE_CLI_HPP

#include "interactive/interactive_query_cli.hpp"
#include "interactive/interactive_status_cli.hpp"
#include "interactive/interactive_transaction_cli.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha_cli {
  namespace interactive {

    class InteractiveCli {
     public:
      /**
       * Interactive command line client
       * @param account_name registered in Iroha network
       * @param default_peer_ip default peer ip to send transactions/query
       * @param default_port default port of peer's Iroha Torii
       * @param qry_counter synchronized nonce for sending queries
       * @param provider crypto provider to make signatures
       * @param response_handler_log_manager for ResponseHandler messages
       * @param pb_qry_factory_log for PbQueryFactory mesages
       * @param json_qry_factory_log for JsonQueryFactory mesages
       * @param log_manager log manager for interactive CLIs
       */
      InteractiveCli(
          const std::string &account_name,
          const std::string &default_peer_ip,
          int default_port,
          uint64_t qry_counter,
          const std::shared_ptr<iroha::model::ModelCryptoProvider> &provider,
          logger::LoggerManagerTreePtr response_handler_log_manager,
          logger::LoggerPtr pb_qry_factory_log,
          logger::LoggerPtr json_qry_factory_log,
          logger::LoggerManagerTreePtr log_manager);
      /**
       * Run interactive cli. Print menu and parse commands
       */
      void run();

     private:
      /**
       * Create main menu and assign parser for commands
       */
      void assign_main_handlers();
      /**
       * Parse main menu commands
       * @param line, command to parse
       */
      void parseMain(std::string line);

      /**
       * Start new query
       */
      void startQuery();

      /**
       * Start new transaction
       */
      void startTx();

      /**
       * Start new request about tx status
       */
      void startTxStatusRequest();

      const std::string TX_CODE = "tx";
      const std::string QRY_CODE = "qry";
      const std::string ST_CODE = "st";

      /**
       * Account id of creator
       */
      std::string creator_;

      // -- Query, tx cli --
      InteractiveTransactionCli tx_cli_;
      InteractiveQueryCli query_cli_;
      InteractiveStatusCli statusCli_;

      /**
       * Main menu points
       */
      MenuPoints menu_points_;

      using MainHandler = void (InteractiveCli::*)();
      std::unordered_map<std::string, MainHandler> main_handler_map_;
    };

  }  // namespace interactive
}  // namespace iroha_cli

#endif  // IROHA_CLI_INTERACTIVE_CLI_HPP
