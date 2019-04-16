/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLI_INTERACTIVE_TRANSACTION_CLI_HPP
#define IROHA_CLI_INTERACTIVE_TRANSACTION_CLI_HPP

#include <unordered_map>

#include "interactive/interactive_common_cli.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "model/generators/transaction_generator.hpp"

namespace iroha {
  namespace model {
    struct Command;
    class ModelCryptoProvider;
  }  // namespace model
}  // namespace iroha

namespace iroha_cli {
  namespace interactive {
    class InteractiveTransactionCli {
     public:
      /**
       * Class to form and send Iroha transactions  in interactive mode
       * @param creator_account user Iroha account
       * @param default_peer_ip of Iroha peer
       * @param default_port of Iroha peer
       * @param provider for signing transactions
       * @param response_handler_log_manager for ResponseHandler messages
       * @param pb_qry_factory_log for PbQueryFactory mesages
       * @param log for internal messages
       */
      InteractiveTransactionCli(
          const std::string &creator_account,
          const std::string &default_peer_ip,
          int default_port,
          const std::shared_ptr<iroha::model::ModelCryptoProvider> &provider,
          logger::LoggerManagerTreePtr response_handler_log_manager,
          logger::LoggerPtr pb_qry_factory_log,
          logger::LoggerPtr log);
      /**
       * Run interactive query command line
       */
      void run();

     private:
      //  Menu context used in cli
      MenuContext current_context_;

      // Commands menu points
      MenuPoints commands_menu_;

      // Transaction result points
      MenuPoints result_menu_;

      /**
       * Create command menu and assign command handlers for current class
       * object
       */
      void createCommandMenu();
      /**
       * Create result menu and assign result handlers for current class object
       */
      void createResultMenu();

      // --- Shortcut namings for Iroha Commands ---
      const std::string ADD_ASSET_QTY = "add_ast_qty";
      const std::string ADD_PEER = "add_peer";
      const std::string ADD_SIGN = "add_sign";
      const std::string CREATE_ACC = "crt_acc";
      const std::string CREATE_ASSET = "crt_ast";
      const std::string CREATE_DOMAIN = "crt_dmn";
      const std::string REMOVE_SIGN = "rem_sign";
      const std::string SET_QUO = "set_qrm";
      const std::string SET_ACC_KV = "set_acc_kv";
      const std::string SUB_ASSET_QTY = "sub_ast_qty";
      const std::string TRAN_ASSET = "tran_ast";

      const std::string CREATE_ROLE = "crt_role";
      const std::string APPEND_ROLE = "apnd_role";
      const std::string DETACH_ROLE = "detach";
      const std::string GRANT_PERM = "grant_perm";
      const std::string REVOKE_PERM = "revoke_perm";

      // ---- Command parsers ----
      using CommandHandler = std::shared_ptr<iroha::model::Command> (
          InteractiveTransactionCli::*)(std::vector<std::string>);

      // Specific parsers for each Iroha command
      std::unordered_map<std::string, CommandHandler> command_handlers_;

      // Descriptions for commands parameters
      ParamsMap command_params_map_;

      // Descriptions for commands
      DescriptionMap commands_description_map_;

      /**
       * Parse line with iroha Command
       * @param line containg iroha command
       * @return false - if parsing must be stopped, true - if parsing should
       * continue
       */
      bool parseCommand(std::string line);
      // --- Specific model Command parsers -----
      std::shared_ptr<iroha::model::Command> parseAddAssetQuantity(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseAddPeer(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseAddSignatory(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseCreateAccount(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseCreateAsset(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseCreateDomain(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseRemoveSignatory(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseSetQuorum(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseSetAccountDetail(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseSubtractAssetQuantity(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseTransferAsset(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseAppendRole(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseDetachRole(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseCreateRole(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseGrantPermission(
          std::vector<std::string> line);
      std::shared_ptr<iroha::model::Command> parseRevokePermission(
          std::vector<std::string> line);

      // ---- Result parsers ------
      using ResultHandler =
          bool (InteractiveTransactionCli::*)(std::vector<std::string>);
      std::unordered_map<std::string, ResultHandler> result_handlers_;

      // Description for result command
      ParamsMap result_params_map;

      /**
       * Parse line for result
       * @param line - cli command
       * @return True - if parsing process must be continued. False if parsing
       * context should be changed
       */
      bool parseResult(std::string line);
      // --- Specific result parsers ---
      bool parseSendToIroha(std::vector<std::string> params);
      bool parseSaveFile(std::vector<std::string> params);
      bool parseGoBack(std::vector<std::string> params);
      bool parseAddCommand(std::vector<std::string> params);

      /**
       * Prints hash of a transaction for user in a readable form
       */
      void printTxHash(iroha::model::Transaction &tx);

      // ---- Tx data ----

      //  Creator account id
      std::string creator_;
      std::string default_peer_ip_;
      int default_port_;

      // Builder for new commands
      iroha::model::generators::CommandGenerator generator_;

      // Commands to be formed
      std::vector<std::shared_ptr<iroha::model::Command>> commands_;

      // Crypto provider
      std::shared_ptr<iroha::model::ModelCryptoProvider> provider_;

      // Transaction generator
      iroha::model::generators::TransactionGenerator tx_generator_;

      /// Logger manager for ResponseHandler
      logger::LoggerManagerTreePtr response_handler_log_manager_;

      /// Logger for PbQueryFactory
      logger::LoggerPtr pb_qry_factory_log_;

      /// Internal logger
      logger::LoggerPtr log_;
    };
  }  // namespace interactive
}  // namespace iroha_cli

#endif  // IROHA_CLI_INTERACTIVE_TRANSACTION_CLI_HPP
