/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_BASE_HPP
#define IROHA_STORAGE_BASE_HPP

#include "ametsuchi/storage.hpp"

#include <atomic>
#include <shared_mutex>

#include <boost/optional.hpp>
#include "ametsuchi/block_storage_factory.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/indexer.hpp"
#include "ametsuchi/key_value_storage.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/reconnection_strategy.hpp"
#include "ametsuchi/wsv_command.hpp"
#include "interfaces/permission_to_string.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace shared_model::interface {
  class QueryResponseFactory;
}  // namespace shared_model::interface
namespace iroha {
  class PendingTransactionStorage;
}

namespace iroha::ametsuchi {

  class AmetsuchiTest;
  class PostgresOptions;
  class VmCaller;

  class StorageBase : public Storage {
    std::shared_ptr<BlockStorage> block_store_;
    std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
        callback_;
    std::shared_ptr<shared_model::interface::PermissionToString>
        perm_converter_;
    std::shared_ptr<PendingTransactionStorage> pending_txs_storage_;
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        query_response_factory_;
    std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory_;
    std::optional<std::reference_wrapper<const VmCaller>> vm_caller_ref_;
    logger::LoggerManagerTreePtr log_manager_;
    logger::LoggerPtr log_;
    boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state_;
    bool prepared_blocks_enabled_;
    std::atomic<bool> block_is_prepared_;
    std::string prepared_block_name_;

   protected:
    CommitResult commitPreparedImpl(
        std::shared_ptr<const shared_model::interface::Block> block,
        DatabaseTransaction &db_context,
        WsvCommand &wsv_command,
        WsvQuery &wsv_query,
        std::unique_ptr<Indexer> indexer);

   public:
    using StoreBlockResult = iroha::expected::Result<void, std::string>;

    StorageBase(StorageBase &&) = delete;
    StorageBase(StorageBase const &) = delete;

    StorageBase &operator=(StorageBase &&) = delete;
    StorageBase &operator=(StorageBase const &) = delete;

    boost::optional<std::shared_ptr<PeerQuery>> createPeerQuery()
        const override;

    bool preparedCommitEnabled() const override;

    boost::optional<std::shared_ptr<BlockQuery>> createBlockQuery()
        const override {
      auto block_query = getBlockQuery();
      if (not block_query) {
        return boost::none;
      }
      return boost::make_optional(block_query);
    }

    logger::LoggerManagerTreePtr logManager() const {
      return log_manager_;
    }

    auto &blockIsPrepared() {
      return block_is_prepared_;
    }

    std::shared_ptr<BlockStorage> blockStore() const {
      return block_store_;
    }

    std::shared_ptr<shared_model::interface::PermissionToString> permConverter()
        const {
      return perm_converter_;
    }

    logger::LoggerPtr log() const {
      return log_;
    }

    std::shared_ptr<PendingTransactionStorage> pendingTxStorage() const {
      return pending_txs_storage_;
    }

    auto &temporaryBlockStorageFactory() {
      return temporary_block_storage_factory_;
    }

    std::shared_ptr<shared_model::interface::QueryResponseFactory>
    queryResponseFactory() const {
      return query_response_factory_;
    }

    std::optional<std::reference_wrapper<const VmCaller>> vmCaller() const {
      return vm_caller_ref_;
    }

    boost::optional<std::shared_ptr<const iroha::LedgerState>> ledgerState()
        const {
      return ledger_state_;
    }

    void ledgerState(
        boost::optional<std::shared_ptr<const iroha::LedgerState>> const
            &value) {
      ledger_state_ = value;
    }

    expected::Result<void, std::string> insertBlock(
        std::shared_ptr<const shared_model::interface::Block> block) override;

    expected::Result<void, std::string> dropBlockStorage() override;

    boost::optional<std::shared_ptr<const iroha::LedgerState>> getLedgerState()
        const override;

    CommitResult commit(
        std::unique_ptr<MutableStorage> mutable_storage) override;

    void prepareBlockImpl(std::unique_ptr<TemporaryWsv> wsv,
                          DatabaseTransaction &db_context);

    /**
     * add block to block storage
     */
    StoreBlockResult storeBlock(
        std::shared_ptr<const shared_model::interface::Block> block);

    StorageBase(
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
        std::function<void(
            std::shared_ptr<shared_model::interface::Block const>)> callback,
        bool prepared_blocks_enabled);

    ~StorageBase();
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_STORAGE_BASE_HPP
