/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PBFACTORY_HPP
#define IROHA_PBFACTORY_HPP

#include "block.pb.h"
#include "model/block.hpp"

namespace iroha {
  namespace model {
    namespace converters {

      /**
       * Converting business objects to protobuf and vice versa
       */
      class PbBlockFactory {
       public:
        PbBlockFactory() {}

        /**
         * Convert block to proto block
         * @param block - reference to block
         * @return proto block
         */
        protocol::Block serialize(const model::Block &block) const;

        /**
         * Convert proto block to model block
         * @param pb_block - reference to proto block
         * @return model block
         */
        model::Block deserialize(const protocol::Block &pb_block) const;
      };
    }  // namespace converters
  }    // namespace model
}  // namespace iroha
#endif  // IROHA_PBFACTORY_HPP
