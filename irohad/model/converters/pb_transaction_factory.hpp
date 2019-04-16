/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PB_TRANSACTION_FACTORY_HPP
#define IROHA_PB_TRANSACTION_FACTORY_HPP

#include <memory>
#include "model/transaction.hpp"
#include "transaction.pb.h"

namespace iroha {
  namespace model {
    namespace converters {

      /**
       * Converting business objects to protobuf and vice versa
       */
      class PbTransactionFactory {
       public:
        PbTransactionFactory() {}

        /**
         * Convert block to proto block
         * @param block - reference to block
         * @return proto block
         */
        static protocol::Transaction serialize(const model::Transaction &tx);

        /**
         * Convert proto block to model block
         * @param pb_block - reference to proto block
         * @return model block
         */
        static std::shared_ptr<model::Transaction> deserialize(
            const protocol::Transaction &pb_tx);
      };
    }  // namespace converters
  }    // namespace model
}  // namespace iroha
#endif  // IROHA_PB_TRANSACTION_FACTORY_HPP
