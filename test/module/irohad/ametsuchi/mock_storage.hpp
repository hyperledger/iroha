/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_STORAGE_HPP
#define IROHA_MOCK_STORAGE_HPP

#include "ametsuchi/storage.hpp"

#include <gmock/gmock.h>
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/temporary_wsv.hpp"

namespace iroha {
  namespace ametsuchi {

    class MockStorage : public Storage {
     public:
      MOCK_CONST_METHOD0(getWsvQuery, std::shared_ptr<WsvQuery>(void));
      MOCK_CONST_METHOD0(getBlockQuery, std::shared_ptr<BlockQuery>(void));
      MOCK_METHOD0(
          createTemporaryWsv,
          expected::Result<std::unique_ptr<TemporaryWsv>, std::string>(void));
      MOCK_METHOD0(
          createMutableStorage,
          expected::Result<std::unique_ptr<MutableStorage>, std::string>(void));
      MOCK_CONST_METHOD0(createPeerQuery,
                         boost::optional<std::shared_ptr<PeerQuery>>());
      MOCK_CONST_METHOD0(createBlockQuery,
                         boost::optional<std::shared_ptr<BlockQuery>>());
      MOCK_CONST_METHOD2(
          createQueryExecutor,
          boost::optional<std::shared_ptr<QueryExecutor>>(
              std::shared_ptr<PendingTransactionStorage>,
              std::shared_ptr<shared_model::interface::QueryResponseFactory>));
      MOCK_METHOD1(doCommit,
                   boost::optional<std::unique_ptr<LedgerState>>(
                       MutableStorage *storage));
      MOCK_METHOD1(commitPrepared,
                   boost::optional<std::unique_ptr<LedgerState>>(
                       std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD1(insertBlock,
                   bool(std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD0(
          createMutableStorageWithoutBlockStorage,
          expected::Result<std::unique_ptr<MutableStorage>, std::string>());

      MOCK_METHOD1(insertPeer,
                   expected::Result<void, std::string>(
                       const shared_model::interface::Peer &));
      MOCK_METHOD0(reset, void(void));
      MOCK_METHOD0(resetWsv, expected::Result<void, std::string>());
      MOCK_METHOD0(resetPeers, void(void));
      MOCK_METHOD0(dropStorage, void(void));
      MOCK_METHOD0(freeConnections, void(void));
      MOCK_METHOD1(prepareBlock_, void(std::unique_ptr<TemporaryWsv> &));

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override {
        // gmock workaround for non-copyable parameters
        prepareBlock_(wsv);
      }

      rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
      on_commit() override {
        return notifier.get_observable();
      }
      boost::optional<std::unique_ptr<LedgerState>> commit(
          std::unique_ptr<MutableStorage> storage) override {
        return doCommit(storage.get());
      }
      rxcpp::subjects::subject<
          std::shared_ptr<const shared_model::interface::Block>>
          notifier;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_STORAGE_HPP
