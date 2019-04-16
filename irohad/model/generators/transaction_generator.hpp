/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_GENERATOR_HPP
#define IROHA_TRANSACTION_GENERATOR_HPP

#include "logger/logger_fwd.hpp"
#include "model/generators/command_generator.hpp"
#include "model/generators/signature_generator.hpp"
#include "model/transaction.hpp"

namespace iroha {
  namespace model {
    namespace generators {
      class TransactionGenerator {
       public:
        /**
         * Generate genesis transaction, contain all necessary commands for new
         * Iroha network
         * @param timestamp
         * @param peers_address
         * @return
         */
        Transaction generateGenesisTransaction(
            ts64_t timestamp,
            std::vector<std::string> peers_address,
            logger::LoggerPtr keys_manager_logger);

        /**
         * Generate transaction from give meta data and commands list
         * @param timestamp
         * @param creator_account_id
         * @param commands
         * @return
         */
        Transaction generateTransaction(
            ts64_t timestamp,
            std::string creator_account_id,
            std::vector<std::shared_ptr<Command>> commands);

        /**
         * Generate transaction from give meta data and commands list
         * @param timestamp
         * @param creator_account_id
         * @param commands
         * @return
         */
        Transaction generateTransaction(
            std::string creator_account_id,
            std::vector<std::shared_ptr<Command>> commands);
      };
    }  // namespace generators
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_TRANSACTION_GENERATOR_HPP
