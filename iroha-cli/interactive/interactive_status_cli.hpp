/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_INTERACTIVE_STATUS_CLI_HPP
#define IROHA_INTERACTIVE_STATUS_CLI_HPP

#include <endpoint.pb.h>
#include <string>

#include "interactive/interactive_common_cli.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha_cli {
  namespace interactive {
    /**
     * A special class for retrieving transaction status.
     * It's not a transaction and not a query so it should be
     * processed separately.
     */
    class InteractiveStatusCli {
     public:
      InteractiveStatusCli(const std::string &default_peer_ip,
                           int default_port,
                           logger::LoggerPtr pb_qry_factory_log);
      void run();

     private:
      using ActionName = std::string;
      using ActionParams = std::vector<std::string>;
      using ActionHandler = std::string (InteractiveStatusCli::*)(ActionParams);
      using ResultHandler = bool (InteractiveStatusCli::*)(ActionParams);
      std::unordered_map<ActionName, ActionHandler> actionHandlers_;

      bool parseAction(std::string &line);
      bool parseResult(std::string &line);

      bool parseSendToIroha(ActionParams line);
      bool parseSaveFile(ActionParams line);

      void createActionsMenu();
      void createResultMenu();

      std::string parseGetHash(ActionParams params);

      const std::string GET_TX_INFO = "get_tx_info";

      std::string default_peer_ip_;
      int default_port_;

      std::unordered_map<ActionName, ResultHandler> resultHandlers_;
      ParamsMap resultParamsDescriptions_;

      DescriptionMap descriptionMap_;
      ParamsMap requestParamsDescriptions_;
      MenuPoints menuPoints_;
      MenuPoints resultPoints_;

      MenuContext currentContext_;
      std::string txHash_;

      logger::LoggerPtr pb_qry_factory_log_;
    };
  }  // namespace interactive
}  // namespace iroha_cli

#endif  // IROHA_INTERACTIVE_STATUS_CLI_HPP
