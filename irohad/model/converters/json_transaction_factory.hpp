/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_JSON_TRANSACTION_FACTORY_HPP
#define IROHA_JSON_TRANSACTION_FACTORY_HPP

#include "model/converters/json_command_factory.hpp"
#include "model/transaction.hpp"

namespace iroha {
  namespace model {
    namespace converters {

      class JsonTransactionFactory {
       public:
        rapidjson::Document serialize(const Transaction &transaction);

        boost::optional<Transaction> deserialize(
            const rapidjson::Value &document);

       private:
        JsonCommandFactory factory_;
      };

    }  // namespace converters
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_JSON_TRANSACTION_FACTORY_HPP
