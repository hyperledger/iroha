/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_base.hpp"

#include <utility>

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/range/algorithm/replace_if.hpp>
#include <boost/tuple/tuple.hpp>
#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/mutable_storage_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_block_query.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_setting_query.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/temporary_wsv_impl.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "backend/protobuf/permissions.hpp"
#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/subscription.hpp"

namespace iroha::ametsuchi {

  boost::optional<std::shared_ptr<PeerQuery>> StorageBase::createPeerQuery()
      const {
    auto wsv = getWsvQuery();
    if (not wsv) {
      return boost::none;
    }
    return boost::make_optional<std::shared_ptr<PeerQuery>>(
        std::make_shared<PeerQueryWsv>(wsv));
  }

  expected::Result<void, std::string> StorageBase::dropBlockStorage() {
    log_->info("drop block storage");
    block_store_->clear();
    return iroha::expected::Value<void>{};
  }

  boost::optional<std::shared_ptr<const iroha::LedgerState>>
  StorageBase::getLedgerState() const {
    return ledger_state_;
  }

  StorageBase::StorageBase(
      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
      std::shared_ptr<BlockStorage> block_store,
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter,
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory,
      std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
      std::optional<std::reference_wrapper<const VmCaller>> vm_caller_ref,
      logger::LoggerManagerTreePtr log_manager,
      std::string const &prepared_block_name,
      bool prepared_blocks_enabled)
      : block_store_(std::move(block_store)),
        notifier_(notifier_lifetime_),
        perm_converter_(std::move(perm_converter)),
        pending_txs_storage_(std::move(pending_txs_storage)),
        query_response_factory_(std::move(query_response_factory)),
        temporary_block_storage_factory_(
            std::move(temporary_block_storage_factory)),
        vm_caller_ref_(std::move(vm_caller_ref)),
        log_manager_(std::move(log_manager)),
        log_(log_manager_->getLogger()),
        ledger_state_(std::move(ledger_state)),
        prepared_blocks_enabled_(prepared_blocks_enabled),
        block_is_prepared_(false),
        prepared_block_name_(prepared_block_name) {}

  StorageBase::StoreBlockResult StorageBase::storeBlock(
      std::shared_ptr<const shared_model::interface::Block> block) {
    if (blockStore()->insert(block)) {
      notifier().get_subscriber().on_next(block);
      log_->info("StorageImpl::storeBlock()  notify(EventTypes::kOnBlock)");
      getSubscription()->notify(
          EventTypes::kOnBlock,
          std::shared_ptr<const shared_model::interface::Block>(block));
      return {};
    }
    return expected::makeError("Block insertion to storage failed");
  }

  bool StorageBase::preparedCommitEnabled() const {
    return prepared_blocks_enabled_ and block_is_prepared_;
  }

  StorageBase::~StorageBase() {
    notifier_lifetime_.unsubscribe();
  }

  expected::Result<void, std::string> StorageBase::insertBlock(
      std::shared_ptr<const shared_model::interface::Block> block) {
    log_->info("create mutable storage");
    return createCommandExecutor() | [&](auto &&command_executor) {
      return createMutableStorage(std::move(command_executor)) |
                 [&](auto &&mutable_storage)
                 -> expected::Result<void, std::string> {
        const bool is_inserted = mutable_storage->apply(block);
        commit(std::move(mutable_storage));
        if (is_inserted) {
          return {};
        }
        return "Stateful validation failed.";
      };
    };
  }

  CommitResult StorageBase::commit(
      std::unique_ptr<MutableStorage> mutable_storage) {
    auto old_height = blockStore()->size();
    return std::move(*mutable_storage).commit(*blockStore()) |
               [this, old_height](auto commit_result) -> CommitResult {
      ledgerState(commit_result.ledger_state);
      auto new_height = blockStore()->size();
      for (auto height = old_height + 1; height <= new_height; ++height) {
        auto maybe_block = blockStore()->fetch(height);
        if (not maybe_block) {
          return fmt::format("Failed to fetch block {}", height);
        }

        std::shared_ptr<const shared_model::interface::Block> block_ptr =
            std::move(maybe_block.get());
        notifier().get_subscriber().on_next(block_ptr);
        log_->info("StorageImpl::commit()  notify(EventTypes::kOnBlock)");
        getSubscription()->notify(EventTypes::kOnBlock, block_ptr);
      }
      return expected::makeValue(std::move(commit_result.ledger_state));
    };
  }

  rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
  StorageBase::on_commit() {
    return notifier().get_observable();
  }

  void StorageBase::prepareBlock(std::unique_ptr<TemporaryWsv> wsv,
                                 DatabaseTransaction &db_context) {
    if (not prepared_blocks_enabled_) {
      log()->warn("prepared blocks are not enabled");
      return;
    }
    if (block_is_prepared_) {
      log()->warn(
          "Refusing to add new prepared state, because there already is one. "
          "Multiple prepared states are not yet supported.");
    } else {
      try {
        db_context.prepare(prepared_block_name_);
        block_is_prepared_ = true;
      } catch (const std::exception &e) {
        log()->warn("failed to prepare state: {}", e.what());
      }

      log()->info("state prepared successfully");
    }
  }

  CommitResult StorageBase::commitPrepared(
      std::shared_ptr<const shared_model::interface::Block> block,
      DatabaseTransaction &db_context,
      WsvCommand &wsv_command,
      WsvQuery &wsv_query,
      std::unique_ptr<Indexer> indexer) {
    if (not prepared_blocks_enabled_) {
      return expected::makeError(
          std::string{"prepared blocks are not enabled"});
    }

    if (not block_is_prepared_) {
      return expected::makeError("there are no prepared blocks");
    }

    log()->info("applying prepared block");

    try {
      if (not blockStore()->insert(block)) {
        return fmt::format("Failed to insert block {}", *block);
      }

      db_context.commitPrepared(prepared_block_name_);
      BlockIndexImpl block_index(
          std::move(indexer),
          logManager()->getChild("BlockIndex")->getLogger());
      block_index.index(*block);
      block_is_prepared_ = false;

      if (auto e = expected::resultToOptionalError(wsv_command.setTopBlockInfo(
              TopBlockInfo{block->height(), block->hash()}))) {
        throw std::runtime_error(e.value());
      }

      log_->info("StorageImpl::commitPrepared()  notify(EventTypes::kOnBlock)");
      notifier().get_subscriber().on_next(block);
      getSubscription()->notify(
          EventTypes::kOnBlock,
          std::shared_ptr<const shared_model::interface::Block>(block));

      decltype(std::declval<WsvQuery>().getPeers()) opt_ledger_peers;
      {
        if (not(opt_ledger_peers = wsv_query.getPeers())) {
          return expected::makeError(
              std::string{"Failed to get ledger peers! Will retry."});
        }
      }
      assert(opt_ledger_peers);

      ledgerState(std::make_shared<const LedgerState>(
          std::move(*opt_ledger_peers), block->height(), block->hash()));
      return expected::makeValue(ledgerState().value());
    } catch (const std::exception &e) {
      std::string msg((boost::format("failed to apply prepared block %s: %s")
                       % block->hash().hex() % e.what())
                          .str());
      return expected::makeError(msg);
    }
  }

}  // namespace iroha::ametsuchi
