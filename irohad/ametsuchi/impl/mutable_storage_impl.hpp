/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MUTABLE_STORAGE_IMPL_HPP
#define IROHA_MUTABLE_STORAGE_IMPL_HPP

#include "ametsuchi/mutable_storage.hpp"

#include <soci/soci.h>
#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/impl/db_transaction.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha::ametsuchi {

  class BlockIndex;
  class PeerQuery;
  class CommandExecutor;
  class WsvCommand;
  class TransactionExecutor;

  class MutableStorageImpl : public MutableStorage {
    friend class StorageImpl;

   public:
    MutableStorageImpl(
        boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
        std::unique_ptr<WsvCommand> wsv_command,
        std::unique_ptr<PeerQuery> peer_query,
        std::unique_ptr<BlockIndex> block_index,
        std::shared_ptr<CommandExecutor> command_executor,
        std::unique_ptr<BlockStorage> block_storage,
        logger::LoggerManagerTreePtr log_manager);

    bool apply(
        std::shared_ptr<const shared_model::interface::Block> block) override;

    bool applyIf(std::shared_ptr<const shared_model::interface::Block> block,
                 MutableStoragePredicate predicate) override;

    boost::optional<std::shared_ptr<const iroha::LedgerState>> getLedgerState()
        const;

    expected::Result<CommitResult, std::string> commit(
        BlockStorage &block_storage)
        && override;

    ~MutableStorageImpl() override;

   private:
    /**
     * Performs a function inside savepoint, does a rollback if function
     * returned false, and removes the savepoint otherwise. Returns function
     * result
     */
    template <typename Function>
    bool withSavepoint(Function &&function);

    /**
     * Verifies whether the block is applicable using predicate, and applies
     * the block
     */
    bool applyBlockIf(
        std::shared_ptr<const shared_model::interface::Block> block,
        MutableStoragePredicate predicate);

    boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state_;

    DatabaseTransaction &db_tx_;
    std::unique_ptr<WsvCommand> wsv_command_;
    std::unique_ptr<PeerQuery> peer_query_;
    std::unique_ptr<BlockIndex> block_index_;
    std::shared_ptr<TransactionExecutor> transaction_executor_;
    std::unique_ptr<BlockStorage> block_storage_;

    bool committed;

    logger::LoggerPtr log_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_MUTABLE_STORAGE_IMPL_HPP
