/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLI_TRANSACTION_RESPONSE_HANDLER_HPP
#define IROHA_CLI_TRANSACTION_RESPONSE_HANDLER_HPP

#include "client.hpp"  // for CliClient::TxStatus (yuck!)

#include "logger/logger_fwd.hpp"

namespace spdlog {
  class logger;
}

namespace iroha_cli {

  class TransactionResponseHandler {
   public:
    explicit TransactionResponseHandler(logger::LoggerPtr log);
    /**
     * Handle response from Iroha
     * @param status of transaction
     */
    void handle(const CliClient::TxStatus status) const;

   private:
    logger::LoggerPtr log_;
  };
}  // namespace iroha_cli

#endif  // IROHA_CLI_TRANSACTION_RESPONSE_HANDLER_HPP
