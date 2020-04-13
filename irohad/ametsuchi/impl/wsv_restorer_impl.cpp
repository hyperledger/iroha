/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wsv_restorer_impl.hpp"

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/block_storage_factory.hpp"
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/storage.hpp"
#include "common/bind.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"

using shared_model::interface::types::HeightType;

namespace {
  /**
   * Stub implementation used to restore WSV. Check the method descriptions for
   * details
   */
  class BlockStorageStub : public iroha::ametsuchi::BlockStorage {
   public:
    /**
     * Returns true - MutableStorage may check if the block was inserted
     * successfully
     */
    bool insert(
        std::shared_ptr<const shared_model::interface::Block> block) override {
      return true;
    }

    /**
     * Returns boost::none - it is not required to fetch individual blocks
     * during WSV reindexing
     */
    boost::optional<std::unique_ptr<shared_model::interface::Block>> fetch(
        HeightType height) const override {
      return boost::none;
    }

    size_t size() const override {
      return 0;
    }

    void clear() override {}

    /**
     * Does not iterate any blocks - it is not required to insert any additional
     * blocks to the existing storage
     */
    void forEach(FunctionType function) const override {}
  };

  /**
   * Factory for BlockStorageStub class
   */
  class BlockStorageStubFactory : public iroha::ametsuchi::BlockStorageFactory {
   public:
    std::unique_ptr<iroha::ametsuchi::BlockStorage> create() override {
      return std::make_unique<BlockStorageStub>();
    }
  };

  /**
   * Reapply blocks from existing storage to WSV
   * @param storage - current storage
   * @param mutable_storage - mutable storage without blocks
   * @param block_query - current block storage
   * @param starting_height - the first block to apply
   * @param ending_height - the last block to apply (inclusive)
   * @return commit status after applying the blocks
   */
  iroha::ametsuchi::CommitResult reindexBlocks(
      iroha::ametsuchi::Storage &storage,
      std::unique_ptr<iroha::ametsuchi::MutableStorage> &mutable_storage,
      std::shared_ptr<iroha::ametsuchi::BlockQuery> &block_query,
      HeightType starting_height,
      HeightType ending_height) {
    for (auto i = starting_height; i <= ending_height; ++i) {
      auto result = block_query->getBlock(i).match(
          [&mutable_storage](
              auto &&block) -> iroha::expected::Result<void, std::string> {
            if (not mutable_storage->apply(std::move(block).value)) {
              return iroha::expected::makeError("Cannot apply block!");
            }
            return iroha::expected::Value<void>();
          },
          [](auto &&err) -> iroha::expected::Result<void, std::string> {
            return std::move(err).error.message;
          });

      if (auto e = iroha::expected::resultToOptionalError(result)) {
        return std::move(e).value();
      }
    }

    return storage.commit(std::move(mutable_storage));
  }
}  // namespace

namespace iroha {
  namespace ametsuchi {
    CommitResult WsvRestorerImpl::restoreWsv(Storage &storage) {
      return storage.createCommandExecutor() |
                 [&storage](auto &&command_executor) -> CommitResult {
        BlockStorageStubFactory storage_factory;

        auto mutable_storage = storage.createMutableStorage(
            std::move(command_executor), storage_factory);
        auto block_query = storage.getBlockQuery();
        if (not block_query) {
          return expected::makeError("Cannot create BlockQuery");
        }

        const auto last_block_in_storage = block_query->getTopBlockHeight();
        const auto wsv_ledger_state = storage.getLedgerState();

        shared_model::interface::types::HeightType wsv_ledger_height;
        if (wsv_ledger_state) {
          const auto &wsv_top_block_info =
              wsv_ledger_state.value()->top_block_info;
          wsv_ledger_height = wsv_top_block_info.height;
          if (wsv_ledger_height > last_block_in_storage) {
            return fmt::format(
                "WSV state (height {}) is more recent "
                "than block storage (height {}).",
                wsv_ledger_height,
                last_block_in_storage);
          }
          // check that a block with that height is present in the block storage
          // and that its hash matches
          auto check_top_block =
              block_query->getBlock(wsv_top_block_info.height)
                  .match(
                      [&wsv_top_block_info](
                          const auto &block_from_block_storage)
                          -> expected::Result<void, std::string> {
                        if (block_from_block_storage.value->hash()
                            != wsv_top_block_info.top_hash) {
                          return fmt::format(
                              "The hash of block applied to WSV ({}) "
                              "does not match the hash of the block "
                              "from block storage ({}).",
                              wsv_top_block_info.top_hash,
                              block_from_block_storage.value->hash());
                        }
                        return expected::Value<void>{};
                      },
                      [](expected::Error<BlockQuery::GetBlockError> &&error)
                          -> expected::Result<void, std::string> {
                        return std::move(error).error.message;
                      });
          if (auto e = expected::resultToOptionalError(check_top_block)) {
            return fmt::format(
                "WSV top block (height {}) check failed: {} "
                "Please check that WSV matches block storage "
                "or avoid reusing WSV.",
                wsv_ledger_height,
                e.value());
          }
        } else {
          wsv_ledger_height = 0;
        }

        return reindexBlocks(storage,
                             mutable_storage,
                             block_query,
                             wsv_ledger_height + 1,
                             last_block_in_storage);
      };
    }
  }  // namespace ametsuchi
}  // namespace iroha
