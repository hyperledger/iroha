/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLI_INTERACTIVE_QUERY_CLI_HPP
#define IROHA_CLI_INTERACTIVE_QUERY_CLI_HPP

#include <memory>
#include <unordered_map>

#include "interactive/interactive_common_cli.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "model/generators/query_generator.hpp"

namespace iroha {
  namespace model {
    class ModelCryptoProvider;
    struct Query;
  }  // namespace model
}  // namespace iroha

namespace iroha_cli {
  namespace interactive {
    class InteractiveQueryCli {
     public:
      /**
       * Class to form and send Iroha queries  in interactive mode
       * @param creator_account creator's account identification
       * @param default_peer_ip of Iroha peer
       * @param default_port of Iroha peer
       * @param query_counter counter associated with creator's account
       * @param provider for signing queries
       * @param response_handler_log_manager for ResponseHandler mesages
       * @param pb_qry_factory_log for PbQueryFactory mesages
       * @param json_qry_factory_log for JsonQueryFactory mesages
       * @param log for internal messages
       */
      InteractiveQueryCli(
          const std::string &account_id,
          const std::string &default_peer_ip,
          int default_port,
          uint64_t query_counter,
          const std::shared_ptr<iroha::model::ModelCryptoProvider> &provider,
          logger::LoggerManagerTreePtr response_handler_log_manager,
          logger::LoggerPtr pb_qry_factory_log,
          logger::LoggerPtr json_qry_factory_log,
          logger::LoggerPtr log);
      /**
       * Run interactive query command line
       */
      void run();

     private:
      using QueryName = std::string;
      using QueryParams = std::vector<std::string>;

      // Menu for Queries
      MenuPoints menu_points_;
      /**
       * Create query menu and assign command handlers for current class
       * object
       */
      void create_queries_menu();

      // Menu for Query result
      MenuPoints result_points_;

      /**
       * Create result menu and assign result handlers for current class object
       */
      void create_result_menu();

      // ------ Query handlers -----------
      const std::string GET_ACC = "get_acc";
      const std::string GET_ACC_AST = "get_acc_ast";
      const std::string GET_ACC_AST_TX = "get_acc_ast_tx";
      const std::string GET_ACC_TX = "get_acc_tx";
      const std::string GET_TX = "get_tx";
      const std::string GET_ACC_SIGN = "get_acc_sign";
      const std::string GET_ROLES = "get_roles";
      const std::string GET_AST_INFO = "get_ast_info";
      const std::string GET_ROLE_PERM = "get_role_perm";

      // ------  Query parsers ---------
      using QueryHandler = std::shared_ptr<iroha::model::Query> (
          InteractiveQueryCli::*)(QueryParams);
      std::unordered_map<QueryName, QueryHandler> query_handlers_;
      // Descriptions of queries
      DescriptionMap description_map_;

      // Parameters descriptions of queries
      ParamsMap query_params_map_;

      /**
       * Parse line for query
       * @param line - line containing query
       * @return True - if parsing process must be continued. False if parsing
       * context should be changed
       */
      bool parseQuery(std::string line);
      //  --- Specific Query parsers ---
      std::shared_ptr<iroha::model::Query> parseGetAccount(QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetAccountAssets(
          QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetAccountAssetTransactions(
          QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetAccountTransactions(
          QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetTransactions(
          QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetSignatories(
          QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetRoles(QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetRolePermissions(
          QueryParams params);
      std::shared_ptr<iroha::model::Query> parseGetAssetInfo(
          QueryParams params);

      // ------ Result parsers -------
      using ResultHandler = bool (InteractiveQueryCli::*)(QueryParams);
      std::unordered_map<QueryName, ResultHandler> result_handlers_;

      // Parameters descriptions of result commands
      ParamsMap result_params_map_;

      /**
       * Parse line for result
       * @param line - cli command
       * @return True - if parsing process must be continued. False if parsing
       * context should be changed
       */
      bool parseResult(std::string line);
      // ---- Specific Result handlers
      bool parseSendToIroha(QueryParams line);
      bool parseSaveFile(QueryParams line);

      // Current context for query forming
      MenuContext current_context_;

      // ------- Query data -----------
      // Creator account id
      std::string creator_;
      // Default Iroha peer address
      std::string default_peer_ip_;
      int default_port_;

      // Local query counter of account creator_
      uint64_t counter_;

      // Local time
      uint64_t local_time_;

      // Processed query
      std::shared_ptr<iroha::model::Query> query_;

      // Query generator for new queries
      iroha::model::generators::QueryGenerator generator_;

      // Crypto provider
      std::shared_ptr<iroha::model::ModelCryptoProvider> provider_;

      /// Logger manager for GrpcResponseHandler
      logger::LoggerManagerTreePtr response_handler_log_manager_;

      /// Logger for PbQueryFactory
      logger::LoggerPtr pb_qry_factory_log_;

      /// Logger for JsonQueryFactory
      logger::LoggerPtr json_qry_factory_log_;

      /// Internal logger
      logger::LoggerPtr log_;
    };
  }  // namespace interactive
}  // namespace iroha_cli
#endif  // IROHA_CLI_INTERACTIVE_QUERY_CLI_HPP
