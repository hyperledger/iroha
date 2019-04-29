/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wsv_restorer_impl.hpp"

#include <vector>

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/storage.hpp"
#include "interfaces/iroha_internal/block.hpp"

namespace iroha {
  namespace ametsuchi {
    expected::Result<void, std::string> WsvRestorerImpl::restoreWsv(
        Storage &storage) {
      // get all blocks starting from the genesis
      std::vector<std::shared_ptr<shared_model::interface::Block>> blocks =
          storage.getBlockQuery()->getBlocksFrom(1);

      storage.reset();

      if (not storage.insertBlocks(blocks))
        return expected::makeError("cannot insert blocks");

      return expected::Value<void>();
    }
  }  // namespace ametsuchi
}  // namespace iroha
