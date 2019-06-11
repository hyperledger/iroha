/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MUTABLE_STORAGE_IMPL_HPP
#define IROHA_MUTABLE_STORAGE_IMPL_HPP

#include "ametsuchi/mutable_storage.hpp"

#include <soci/soci.h>
#include "ametsuchi/block_storage.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class BlockIndex;
    class TransactionExecutor;

    class MutableStorageImpl : public MutableStorage {
      friend class StorageImpl;

     public:
      MutableStorageImpl(
          shared_model::interface::types::HashType top_hash,
          shared_model::interface::types::HeightType top_height,
          std::shared_ptr<TransactionExecutor> transaction_executor,
          std::unique_ptr<soci::session> sql,
          std::shared_ptr<shared_model::interface::CommonObjectsFactory>
              factory,
          std::unique_ptr<BlockStorage> block_storage,
          logger::LoggerManagerTreePtr log_manager);

      bool apply(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      bool apply(rxcpp::observable<
                     std::shared_ptr<shared_model::interface::Block>> blocks,
                 MutableStoragePredicate predicate) override;

      shared_model::interface::types::HeightType getTopBlockHeight() const;

      shared_model::interface::types::HashType getTopBlockHash() const;

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
      bool apply(std::shared_ptr<const shared_model::interface::Block> block,
                 MutableStoragePredicate predicate);

      shared_model::interface::types::HashType top_hash_;
      shared_model::interface::types::HeightType top_height_;

      std::unique_ptr<soci::session> sql_;
      std::unique_ptr<PeerQuery> peer_query_;
      std::unique_ptr<BlockIndex> block_index_;
      std::shared_ptr<TransactionExecutor> transaction_executor_;
      std::unique_ptr<BlockStorage> block_storage_;

      bool committed;

      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MUTABLE_STORAGE_IMPL_HPP
