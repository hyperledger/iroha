/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/mutable_storage_impl.hpp"

#include <boost/variant/apply_visitor.hpp>
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_block_index.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha {
  namespace ametsuchi {
    MutableStorageImpl::MutableStorageImpl(
        shared_model::interface::types::HashType top_hash,
        shared_model::interface::types::HeightType top_height,
        std::shared_ptr<TransactionExecutor> transaction_executor,
        std::unique_ptr<soci::session> sql,
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory,
        std::unique_ptr<BlockStorage> block_storage,
        logger::LoggerManagerTreePtr log_manager)
        : top_hash_(std::move(top_hash)),
          top_height_(top_height),
          sql_(std::move(sql)),
          peer_query_(
              std::make_unique<PeerQueryWsv>(std::make_shared<PostgresWsvQuery>(
                  *sql_,
                  std::move(factory),
                  log_manager->getChild("WsvQuery")->getLogger()))),
          block_index_(std::make_unique<PostgresBlockIndex>(
              *sql_, log_manager->getChild("PostgresBlockIndex")->getLogger())),
          transaction_executor_(std::move(transaction_executor)),
          block_storage_(std::move(block_storage)),
          committed(false),
          log_(log_manager->getLogger()) {
      *sql_ << "BEGIN";
    }

    bool MutableStorageImpl::apply(
        std::shared_ptr<const shared_model::interface::Block> block,
        MutableStoragePredicate predicate) {
      auto execute_transaction = [this](auto &transaction) -> bool {
        return expected::hasValue(
            transaction_executor_->execute(transaction, false));
      };

      log_->info("Applying block: height {}, hash {}",
                 block->height(),
                 block->hash().hex());

      // TODO 09.04.2019 mboldyrev IR-440 add height check to predicate
      auto block_applied = predicate(block, *peer_query_, top_hash_)
          and std::all_of(block->transactions().begin(),
                          block->transactions().end(),
                          execute_transaction);
      if (block_applied) {
        block_storage_->insert(block);
        block_index_->index(*block);

        top_hash_ = block->hash();
        top_height_ = block->height();
      }

      return block_applied;
    }

    template <typename Function>
    bool MutableStorageImpl::withSavepoint(Function &&function) {
      try {
        *sql_ << "SAVEPOINT savepoint_";

        auto function_executed = std::forward<Function>(function)();

        if (function_executed) {
          *sql_ << "RELEASE SAVEPOINT savepoint_";
        } else {
          *sql_ << "ROLLBACK TO SAVEPOINT savepoint_";
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
        return this->apply(
            block, [](const auto &, auto &, const auto &) { return true; });
      });
    }

    bool MutableStorageImpl::apply(
        rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>
            blocks,
        MutableStoragePredicate predicate) {
      return withSavepoint([&] {
        return blocks
            .all([&](auto block) { return this->apply(block, predicate); })
            .as_blocking()
            .first();
      });
    }

    shared_model::interface::types::HeightType
    MutableStorageImpl::getTopBlockHeight() const {
      return top_height_;
    }

    shared_model::interface::types::HashType
    MutableStorageImpl::getTopBlockHash() const {
      return top_hash_;
    }

    MutableStorageImpl::~MutableStorageImpl() {
      if (not committed) {
        try {
          *sql_ << "ROLLBACK";
        } catch (std::exception &e) {
          log_->warn("Apply has been failed. Reason: {}", e.what());
        }
      }
    }
  }  // namespace ametsuchi
}  // namespace iroha
