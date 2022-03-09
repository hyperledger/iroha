/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wsv_restorer_impl.hpp"

#include <chrono>
#include <thread>

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/block_storage_factory.hpp"
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/storage.hpp"
#include "backend/protobuf/block.hpp"
#include "common/bind.hpp"
#include "common/result.hpp"
#include "common/result_try.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "validation/chain_validator.hpp"
#include "validators/abstract_validator.hpp"

using shared_model::interface::types::HeightType;

namespace {
  using namespace std::chrono_literals;

  /**
   * Time to wait for new block in blockstore for wait-for-new-blocks restore
   * mode
   */
  static constexpr std::chrono::milliseconds kWaitForBlockTime = 5000ms;

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

    void reload() override {}

    void clear() override {}

    /**
     * Does not iterate any blocks - it is not required to insert any additional
     * blocks to the existing storage
     */
    iroha::expected::Result<void, std::string> forEach(
        FunctionType function) const override {
      return {};
    }
  };

  /**
   * Factory for BlockStorageStub class
   */
  class BlockStorageStubFactory : public iroha::ametsuchi::BlockStorageFactory {
   public:
    iroha::expected::Result<std::unique_ptr<iroha::ametsuchi::BlockStorage>,
                            std::string>
    create() override {
      return std::make_unique<BlockStorageStub>();
    }
  };

  /**
   * Reapply blocks from existing storage to WSV
   * @param storage - current storage
   * @param mutable_storage - mutable storage without blocks
   * @param block_query - current block storage
   * @param interface_validator - block interface validator
   * @param proto_validator - block proto backend validator
   * @param validator - chain validator
   * @param starting_height - the first block to apply
   * @param ending_height - the last block to apply (inclusive)
   * @return commit status after applying the blocks
   */
  iroha::ametsuchi::CommitResult reindexBlocks(
      iroha::ametsuchi::Storage &storage,
      std::unique_ptr<iroha::ametsuchi::MutableStorage> &&mutable_storage,
      iroha::ametsuchi::BlockQuery &block_query,
      shared_model::validation::AbstractValidator<
          shared_model::interface::Block> &interface_validator,
      shared_model::validation::AbstractValidator<iroha::protocol::Block_v1>
          &proto_validator,
      iroha::validation::ChainValidator &validator,
      HeightType starting_height,
      HeightType ending_height) {
    for (auto height = starting_height; height <= ending_height; ++height) {
      auto result = block_query.getBlock(height);
      if (hasError(result)) {
        return std::move(result.assumeError().message);
      }

      auto block = std::move(result).assumeValue();
      if (height != block->height()) {
        return iroha::expected::makeError(
            "inconsistent block height in block storage");
      }

      // do not validate genesis block - transactions may not have creators,
      // block is not signed
      if (height != 1) {
        if (auto error = proto_validator.validate(
                static_cast<shared_model::proto::Block *>(block.get())
                    ->getTransport())) {
          return iroha::expected::makeError(error->toString());
        }

        if (auto error = interface_validator.validate(*block)) {
          return iroha::expected::makeError(error->toString());
        }
      }

      if (not validator.validateAndApply(std::move(block), *mutable_storage)) {
        return iroha::expected::makeError("Cannot validate and apply blocks!");
      }
    }

    return storage.commit(std::move(mutable_storage));
  }
}  // namespace

namespace iroha::ametsuchi {
  WsvRestorerImpl::WsvRestorerImpl(
      std::unique_ptr<shared_model::validation::AbstractValidator<
          shared_model::interface::Block>> interface_validator,
      std::unique_ptr<shared_model::validation::AbstractValidator<
          iroha::protocol::Block_v1>> proto_validator,
      std::shared_ptr<validation::ChainValidator> validator,
      logger::LoggerPtr log)
      : interface_validator_{std::move(interface_validator)},
        proto_validator_{std::move(proto_validator)},
        validator_{std::move(validator)},
        log_{std::move(log)} {}

  CommitResult WsvRestorerImpl::restoreWsv(
      Storage &storage,
      bool wait_for_new_blocks,
      std::shared_ptr<BlockQuery> bq,
      std::shared_ptr<BlockStorageFactory> bsf) {
    IROHA_EXPECTED_TRY_GET_VALUE(command_executor_uniq,
                                 storage.createCommandExecutor());
    std::shared_ptr<CommandExecutor> command_executor(
        std::move(command_executor_uniq));

    std::shared_ptr<BlockStorageFactory> block_storage_factory{
        bsf ? std::move(bsf) : std::make_shared<BlockStorageStubFactory>()};

    CommitResult res = "restoreWsv(): not executed";
    auto block_query = bq ? bq : storage.getBlockQuery();
    if (not block_query) {
      return expected::makeError("Cannot create BlockQuery");
    }
    auto last_block_in_storage = block_query->getTopBlockHeight();

    do {
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

        auto check_top_block =
            block_query->getBlock(wsv_top_block_info.height)
                .match(
                    [&wsv_top_block_info](const auto &block_from_block_storage)
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
        if (hasError(check_top_block)) {
          return fmt::format(
              "WSV top block (height {}) check failed: {} "
              "Please check that WSV matches block storage "
              "or avoid reusing WSV.",
              wsv_ledger_height,
              check_top_block.assumeError());
        }
      } else {
        wsv_ledger_height = 0;
      }

      /// Commit reindexed blocks every 10 blocks. For reliability.
      /// When doing reindex of huge blockchain and the procedure is interrupted
      /// it is important to continue from last commit point to save time.
      do {
        auto commit_height =
            std::min(wsv_ledger_height + 10, last_block_in_storage);
        IROHA_EXPECTED_TRY_GET_VALUE(
            mutable_storage,
            storage.createMutableStorage(command_executor,
                                         *block_storage_factory));
        res = reindexBlocks(storage,
                            std::move(mutable_storage),
                            *block_query,
                            *interface_validator_,
                            *proto_validator_,
                            *validator_,
                            wsv_ledger_height + 1,
                            commit_height);
        if (hasError(res)) {
          break;
        }
        wsv_ledger_height = commit_height;
        if (commit_height == last_block_in_storage)
          break;
      } while (1);

      /// Periodically poll if there new blocks in block_storage
      /// (on filesystem). When more blocks found, reindex them.
      while (wait_for_new_blocks) {
        std::this_thread::sleep_for(kWaitForBlockTime);
        block_query->reloadBlockstore();
        auto new_last_block = block_query->getTopBlockHeight();

        // Try to load block to ensure it is written completely
        auto block_result = block_query->getBlock(new_last_block);
        while (hasError(block_result)
               && (new_last_block > last_block_in_storage)) {
          --new_last_block;
          block_result = block_query->getBlock(new_last_block);
        };

        if (new_last_block > last_block_in_storage) {
          log_->info("Blockstore has new blocks from {} to {}, restore them.",
                     last_block_in_storage,
                     new_last_block);
          last_block_in_storage = new_last_block;
          break;
        }
      }
    } while (wait_for_new_blocks);
    return res;
  }
}  // namespace iroha::ametsuchi
