/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/mutable_storage_impl.hpp"

#include <fmt/core.h>
#include <boost/variant/apply_visitor.hpp>
#include <stdexcept>
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha::ametsuchi {

  MutableStorageImpl::MutableStorageImpl(
      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
      std::unique_ptr<WsvCommand> wsv_command,
      std::unique_ptr<PeerQuery> peer_query,
      std::unique_ptr<BlockIndex> block_index,
      std::shared_ptr<CommandExecutor> command_executor,
      std::unique_ptr<BlockStorage> block_storage,
      logger::LoggerManagerTreePtr log_manager)
      : ledger_state_(std::move(ledger_state)),
        db_tx_(command_executor->dbSession()),
        wsv_command_(std::move(wsv_command)),
        peer_query_(std::move(peer_query)),
        block_index_(std::move(block_index)),
        transaction_executor_(
            std::make_unique<TransactionExecutor>(std::move(command_executor))),
        block_storage_(std::move(block_storage)),
        committed(false),
        log_(log_manager->getLogger()) {
    db_tx_.begin();
  }

  bool MutableStorageImpl::applyBlockIf(
      std::shared_ptr<const shared_model::interface::Block> block,
      MutableStoragePredicate predicate) {
    auto execute_transaction = [this](auto &transaction) -> bool {
      auto result = transaction_executor_->execute(transaction, false);
      auto error = expected::resultToOptionalError(result);
      if (error) {
        log_->error(error->command_error.toString());
      }
      auto ok = !error;
      return ok;
    };

    log_->info("Applying block: height {}, hash {}",
               block->height(),
               block->hash().hex());

    auto block_applied =
        (not ledger_state_ or predicate(block, *ledger_state_.value()))
        and std::all_of(block->transactions().begin(),
                        block->transactions().end(),
                        execute_transaction);
    if (block_applied) {
      if (auto e =
              expected::resultToOptionalError(wsv_command_->setTopBlockInfo(
                  TopBlockInfo{block->height(), block->hash()}))) {
        log_->error("{}", e.value());
        return false;
      }

      block_storage_->insert(block);
      block_index_->index(*block);

      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
          opt_ledger_peers[] = {peer_query_->getLedgerPeers(false),
                                peer_query_->getLedgerPeers(true)};

      for (auto const &peer_list : opt_ledger_peers)
        if (!peer_list) {
          log_->error("Failed to get ledger peers!");
          return false;
        }

      ledger_state_ = std::make_shared<const LedgerState>(
          std::move(*(opt_ledger_peers[0])),  // peers
          std::move(*(opt_ledger_peers[1])),  // syncing peers
          block->height(),
          block->hash());
    }

    return block_applied;
  }

  template <typename Function>
  bool MutableStorageImpl::withSavepoint(Function &&function) {
    try {
      db_tx_.savepoint("savepoint_");
      auto function_executed = std::forward<Function>(function)();

      if (function_executed) {
        db_tx_.releaseSavepoint("savepoint_");
      } else {
        db_tx_.rollbackToSavepoint("savepoint_");
      }
      return function_executed;
    } catch (std::exception &e) {
      log_->warn("Apply has failed. Reason: {}", e.what());
      return false;
    }
  }

  bool MutableStorageImpl::apply(
      std::shared_ptr<const shared_model::interface::Block> block) {
    return withSavepoint([&] {
      return this->applyBlockIf(block,
                                [](const auto &, auto &) { return true; });
    });
  }

  bool MutableStorageImpl::applyIf(
      std::shared_ptr<const shared_model::interface::Block> block,
      MutableStoragePredicate predicate) {
    return withSavepoint([&] { return this->applyBlockIf(block, predicate); });
  }

  boost::optional<std::shared_ptr<const iroha::LedgerState>>
  MutableStorageImpl::getLedgerState() const {
    return ledger_state_;
  }

  expected::Result<MutableStorage::CommitResult, std::string>
  MutableStorageImpl::commit(BlockStorage &block_storage) && {
    if (committed) {
      assert(not committed);
      return "Tried to commit mutable storage twice.";
    }
    if (not ledger_state_) {
      return "Tried to commit mutable storage with no blocks applied.";
    }
    return block_storage_->forEach([&block_storage](auto const &block)
                                       -> expected::Result<void, std::string> {
      if (not block_storage.insert(block)) {
        return fmt::format("Failed to insert block {}", *block);
      }
      return {};
    }) | [this]()
               -> expected::Result<MutableStorage::CommitResult, std::string> {
      try {
        db_tx_.commit();
        committed = true;
      } catch (std::exception &e) {
        return expected::makeError(e.what());
      }
      return MutableStorage::CommitResult{ledger_state_.value(),
                                          std::move(block_storage_)};
    };
  }

  MutableStorageImpl::~MutableStorageImpl() {
    if (not committed) {
      try {
        db_tx_.rollback();
      } catch (std::exception &e) {
        log_->warn("~MutableStorageImpl(): rollback failed. Reason: {}",
                   e.what());
      }
    }
  }

}  // namespace iroha::ametsuchi
