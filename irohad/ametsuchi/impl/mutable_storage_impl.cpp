/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/mutable_storage_impl.hpp"

#include <fmt/core.h>

#include <boost/variant/apply_visitor.hpp>
#include <rxcpp/operators/rx-all.hpp>
#include <stdexcept>

#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_block_index.hpp"
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

namespace iroha {
  namespace ametsuchi {
    MutableStorageImpl::MutableStorageImpl(
        boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
        std::shared_ptr<PostgresCommandExecutor> command_executor,
        std::unique_ptr<BlockStorage> block_storage,
        logger::LoggerManagerTreePtr log_manager)
        : ledger_state_(std::move(ledger_state)),
          sql_(command_executor->getSession()),
          wsv_command_(std::make_unique<PostgresWsvCommand>(sql_)),
          peer_query_(
              std::make_unique<PeerQueryWsv>(std::make_shared<PostgresWsvQuery>(
                  sql_, log_manager->getChild("WsvQuery")->getLogger()))),
          block_index_(std::make_unique<PostgresBlockIndex>(
              std::make_unique<PostgresIndexer>(sql_),
              log_manager->getChild("PostgresBlockIndex")->getLogger())),
          transaction_executor_(std::make_unique<TransactionExecutor>(
              std::move(command_executor))),
          block_storage_(std::move(block_storage)),
          committed(false),
          log_(log_manager->getLogger()) {
      *sql() << "BEGIN";
    }

    bool MutableStorageImpl::apply(
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

        auto opt_ledger_peers = peer_query_->getLedgerPeers();
        if (not opt_ledger_peers) {
          log_->error("Failed to get ledger peers!");
          return false;
        }

        ledger_state_ = std::make_shared<const LedgerState>(
            std::move(*opt_ledger_peers), block->height(), block->hash());
      }

      return block_applied;
    }

    template <typename Function>
    bool MutableStorageImpl::withSavepoint(Function &&function) {
      try {
        *sql() << "SAVEPOINT savepoint_";

        auto function_executed = std::forward<Function>(function)();

        if (function_executed) {
          *sql() << "RELEASE SAVEPOINT savepoint_";
        } else {
          *sql() << "ROLLBACK TO SAVEPOINT savepoint_";
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
        return this->apply(block, [](const auto &, auto &) { return true; });
      });
    }

    bool MutableStorageImpl::apply(
        rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>
            blocks,
        MutableStoragePredicate predicate) {
      try {
        return blocks
            .all([&](auto block) {
              return withSavepoint(
                  [&] { return this->apply(block, predicate); });
            })
            .as_blocking()
            .first();
      } catch (std::runtime_error const &e) {
        log_->warn("Apply has been failed: {}", e.what());
        return false;
      }
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
        assert(ledger_state_);
        return "Tried to commit mutable storage with no blocks applied.";
      }
      return block_storage_->forEach(
                 [&block_storage](
                     auto const &block) -> expected::Result<void, std::string> {
                   if (not block_storage.insert(block)) {
                     return fmt::format("Failed to insert block {}", *block);
                   }
                   return {};
                 })
                 | [this]() -> expected::Result<MutableStorage::CommitResult,
                                                std::string> {
        try {
          *sql() << "COMMIT";
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
          *sql() << "ROLLBACK";
        } catch (std::exception &e) {
          log_->warn("Apply has been failed. Reason: {}", e.what());
        }
      }
    }
  }  // namespace ametsuchi
}  // namespace iroha
