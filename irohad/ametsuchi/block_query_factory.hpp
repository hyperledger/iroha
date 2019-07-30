/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_QUERY_FACTORY_HPP
#define IROHA_BLOCK_QUERY_FACTORY_HPP

#include <boost/optional.hpp>

#include "ametsuchi/block_query.hpp"

namespace iroha {
  namespace ametsuchi {
    class BlockQueryFactory {
     public:
      /**
       * Creates a block query from the current state.
       * @return Created block query
       */
      virtual boost::optional<std::shared_ptr<BlockQuery>> createBlockQuery()
          const = 0;

      virtual ~BlockQueryFactory() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_BLOCK_QUERY_FACTORY_HPP
