/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_base.hpp"

#include <utility>

#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/temporary_wsv_impl.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "common/result.hpp"
#include "common/result_try.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
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
      std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
          callback,
      bool prepared_blocks_enabled)
      : block_store_(std::move(block_store)),
        callback_(std::move(callback)),
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
      callback_(block);
      return {};
    }
    return expected::makeError("Block insertion to storage failed");
  }

  bool StorageBase::preparedCommitEnabled() const {
    return prepared_blocks_enabled_ and block_is_prepared_;
  }

  StorageBase::~StorageBase() {}

  expected::Result<void, std::string> StorageBase::insertBlock(
      std::shared_ptr<const shared_model::interface::Block> block) {
    log_->info("create mutable storage");
    IROHA_EXPECTED_TRY_GET_VALUE(command_executor, createCommandExecutor());
    IROHA_EXPECTED_TRY_GET_VALUE(
        mutable_storage, createMutableStorage(std::move(command_executor)));
    const bool is_inserted = mutable_storage->apply(block);
    commit(std::move(mutable_storage));
    if (is_inserted) {
      return {};
    }
    return "Stateful validation failed.";
  }

  CommitResult StorageBase::commit(
      std::unique_ptr<MutableStorage> mutable_storage) {
    auto old_height = blockStore()->size();
    IROHA_EXPECTED_TRY_GET_VALUE(
        result, std::move(*mutable_storage).commit(*blockStore()));
    ledgerState(result.ledger_state);
    auto new_height = blockStore()->size();
    for (auto height = old_height + 1; height <= new_height; ++height) {
      auto maybe_block = blockStore()->fetch(height);
      if (not maybe_block) {
        return fmt::format("Failed to fetch block {}", height);
      }
      callback_(*std::move(maybe_block));
    }
    return expected::makeValue(std::move(result.ledger_state));
  }

  void StorageBase::prepareBlockImpl(std::unique_ptr<TemporaryWsv> wsv,
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

  CommitResult StorageBase::commitPreparedImpl(
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

      callback_(block);

      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
          opt_ledger_peers[] = {wsv_query.getPeers(false),  // peers
                                wsv_query.getPeers(true)};  // syncing peers
      for (auto &peer_list : opt_ledger_peers)
        if (!peer_list)
          return expected::makeError(
              std::string{"Failed to get ledger peers! Will retry."});

      ledgerState(
          std::make_shared<const LedgerState>(std::move(*(opt_ledger_peers[0])),
                                              std::move(*(opt_ledger_peers[1])),
                                              block->height(),
                                              block->hash()));
      return expected::makeValue(ledgerState().value());
    } catch (const std::exception &e) {
      std::string msg(fmt::format("failed to apply prepared block {}: {}",
                                  block->hash().hex(),
                                  e.what()));
      return expected::makeError(msg);
    }
  }

}  // namespace iroha::ametsuchi
