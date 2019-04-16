/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_JSON_BLOCK_FACTORY_HPP
#define IROHA_JSON_BLOCK_FACTORY_HPP

#include "logger/logger_fwd.hpp"
#include "model/block.hpp"
#include "model/converters/json_transaction_factory.hpp"

namespace iroha {
  namespace model {
    namespace converters {

      class JsonBlockFactory {
       public:
        explicit JsonBlockFactory(logger::LoggerPtr log);
        rapidjson::Document serialize(const Block &block);

        boost::optional<Block> deserialize(const rapidjson::Document &document);

       private:
        JsonTransactionFactory factory_;
        logger::LoggerPtr log_;
      };

    }  // namespace converters
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_JSON_BLOCK_FACTORY_HPP
