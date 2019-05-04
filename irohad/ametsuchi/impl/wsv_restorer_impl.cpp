/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wsv_restorer_impl.hpp"

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/storage.hpp"
#include "interfaces/iroha_internal/block.hpp"

namespace iroha {
  namespace ametsuchi {
    iroha::expected::Result<
        boost::optional<std::unique_ptr<iroha::LedgerState>>,
        std::string>
    WsvRestorerImpl::restoreWsv(Storage &storage) {
      auto mutable_storage_result =
          storage.createMutableStorageWithoutBlockStorage();
      return mutable_storage_result | [&storage](auto &&mutable_storage)
                 -> iroha::expected::Result<
                     boost::optional<std::unique_ptr<iroha::LedgerState>>,
                     std::string> {
        auto block_query = storage.getBlockQuery();
        if (not block_query) {
          return expected::makeError("Cannot create BlockQuery");
        }

        return storage.resetWsv() |
                   [&storage, &mutable_storage, &block_query]() mutable
               -> iroha::expected::Result<
                   boost::optional<std::unique_ptr<iroha::LedgerState>>,
                   std::string> {
          // apply all blocks starting from the genesis
          auto top_height = block_query->getTopBlockHeight();
          for (decltype(top_height) i = 1; i <= top_height; ++i) {
            auto block_result = block_query->getBlock(i);

            if (auto e =
                    boost::get<expected::Error<std::string>>(&block_result)) {
              return expected::makeError(std::move(e)->error);
            }

            auto &block = boost::get<expected::Value<
                std::unique_ptr<shared_model::interface::Block>>>(block_result)
                              .value;
            if (not mutable_storage->apply(std::move(block))) {
              return expected::makeError("Cannot apply " + block->toString());
            }
          }

          return expected::makeValue(
              storage.commit(std::move(mutable_storage)));
        };
      };
    }
  }  // namespace ametsuchi
}  // namespace iroha
