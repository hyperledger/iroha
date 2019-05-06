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
    iroha::expected::Result<
        boost::optional<std::unique_ptr<iroha::LedgerState>>,
        std::string>
    WsvRestorerImpl::restoreWsv(Storage &storage) {
      auto block_query = storage.getBlockQuery();
      if (not block_query) {
        return expected::makeError("Cannot create BlockQuery");
      }

      // get all blocks starting from the genesis
      std::vector<std::shared_ptr<shared_model::interface::Block>> blocks;
      auto top_height = block_query->getTopBlockHeight();
      for (decltype(top_height) i = 1; i <= top_height; ++i) {
        auto block_result = block_query->getBlock(i);

        if (auto e = boost::get<expected::Error<std::string>>(&block_result)) {
          return expected::makeError(std::move(e)->error);
        }

        auto &block = boost::get<expected::Value<
            std::unique_ptr<shared_model::interface::Block>>>(block_result)
                          .value;
        blocks.push_back(std::move(block));
      }

      storage.reset();

      return storage.insertBlocks(blocks);
    }
  }  // namespace ametsuchi
}  // namespace iroha
