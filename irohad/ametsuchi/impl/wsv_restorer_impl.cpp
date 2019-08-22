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
#include "interfaces/iroha_internal/block.hpp"

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
    boost::optional<std::shared_ptr<const shared_model::interface::Block>>
    fetch(shared_model::interface::types::HeightType height) const override {
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
   * @return commit status after applying the blocks
   */
  iroha::ametsuchi::CommitResult reindexBlocks(
      iroha::ametsuchi::Storage &storage,
      std::unique_ptr<iroha::ametsuchi::MutableStorage> &mutable_storage,
      std::shared_ptr<iroha::ametsuchi::BlockQuery> &block_query) {
    // apply all blocks starting from the genesis
    auto top_height = block_query->getTopBlockHeight();
    for (decltype(top_height) i = 1; i <= top_height; ++i) {
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

        return storage.resetWsv() |
            [&storage, &mutable_storage, &block_query]() {
              return reindexBlocks(storage, mutable_storage, block_query);
            };
      };
    }
  }  // namespace ametsuchi
}  // namespace iroha
