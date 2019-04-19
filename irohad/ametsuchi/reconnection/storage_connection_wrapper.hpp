/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_CONNECTION_WRAPPER_HPP
#define IROHA_STORAGE_CONNECTION_WRAPPER_HPP

#include <atomic>
#include <functional>
#include <shared_mutex>

#include "ametsuchi/reconnection/reconnection_strategy.hpp"
#include "ametsuchi/reconnection/unsafe_storage.hpp"
#include "ametsuchi/storage.hpp"

namespace iroha {
  namespace ametsuchi {
    class StorageConnectionWrapper : public Storage {
     public:
      StorageConnectionWrapper(
          std::function<std::shared_ptr<UnsafeStorage>()> storage_creator,
          std::shared_ptr<ReconnectionStorageStrategy> recall_strategy);

      // ------------------------- | Storage | ---------------------------------

      std::shared_ptr<WsvQuery> getWsvQuery() const override;

      std::shared_ptr<BlockQuery> getBlockQuery() const override;

      bool insertBlock(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      bool insertBlocks(
          const std::vector<std::shared_ptr<shared_model::interface::Block>>
              &blocks) override;

      rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
      on_commit() override;

      void reset() override;

      void dropStorage() override;

      void freeConnections() override;

      // ------------------------- | TemporaryFactory | ------------------------

      expected::Result<std::unique_ptr<TemporaryWsv>, std::string>
      createTemporaryWsv() override;

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override;

      // ------------------------- | MutableFactory | --------------------------

      expected::Result<std::unique_ptr<MutableStorage>, std::string>
      createMutableStorage() override;

      boost::optional<std::unique_ptr<LedgerState>> commit(
          std::unique_ptr<MutableStorage> mutable_storage) override;

      boost::optional<std::unique_ptr<LedgerState>> commitPrepared(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      // ------------------------- | PeerQueryFactory | ------------------------

      boost::optional<std::shared_ptr<PeerQuery>> createPeerQuery()
          const override;

      // ------------------------- | BlockQueryFactory | -----------------------

      boost::optional<std::shared_ptr<BlockQuery>> createBlockQuery()
          const override;

      // ------------------------- | QueryExecutorFactory | --------------------

      boost::optional<std::shared_ptr<QueryExecutor>> createQueryExecutor(
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              response_factory) const override;

     private:
      /**
       * Method provides a reconnection wrapper for every storage invocation
       * @tparam ReturnValue - return type of original call
       * @tparam Invoker - type of lambda which will invoke db method
       * @param function_call - function which performs invocation of the target
       * db method
       * @param failure_value - value which return on fail of invocation
       * @param tag - identifier of call
       * @return original value from storage
       */
      template <typename ReturnValue, typename Invoker>
      ReturnValue reconnectionLoop(Invoker function_call,
                                   ReturnValue failure_value,
                                   const std::string &tag) const;

      std::function<std::shared_ptr<UnsafeStorage>()> storage_creator_;
      mutable std::shared_ptr<UnsafeStorage> unsafe_storage_;
      mutable std::shared_ptr<ReconnectionStorageStrategy> recall_strategy_;
      mutable std::shared_timed_mutex lock_;
      mutable std::atomic<bool> should_initialize_{false};
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_STORAGE_CONNECTION_WRAPPER_HPP
