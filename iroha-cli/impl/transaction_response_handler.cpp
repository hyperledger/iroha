/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "transaction_response_handler.hpp"
#include "logger/logger.hpp"

namespace iroha_cli {

  void TransactionResponseHandler::handle(
      const CliClient::TxStatus status) const {
    switch (status) {
      case iroha_cli::CliClient::OK:
        log_->info("Transaction successfully sent");
        break;
        /*
      case iroha_cli::CliClient::NOT_VALID:
        log_->error("Transaction is not valid");
        break;
         */
    }
  }
  TransactionResponseHandler::TransactionResponseHandler(logger::LoggerPtr log)
      : log_(std::move(log)) {}

}  // namespace iroha_cli
