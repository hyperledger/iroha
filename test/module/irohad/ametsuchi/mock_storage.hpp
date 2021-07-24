/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_STORAGE_HPP
#define IROHA_MOCK_STORAGE_HPP

#include "ametsuchi/storage.hpp"

#include <gmock/gmock.h>
#include "ametsuchi/block_storage_factory.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/temporary_wsv.hpp"

namespace iroha {
  namespace ametsuchi {

    class MockStorage : public Storage {
     public:
      MOCK_CONST_METHOD0(getWsvQuery, std::shared_ptr<WsvQuery>());
      MOCK_CONST_METHOD0(getBlockQuery, std::shared_ptr<BlockQuery>());
      MOCK_METHOD0(
          createCommandExecutor,
          expected::Result<std::unique_ptr<CommandExecutor>, std::string>());
      MOCK_METHOD1(
          createTemporaryWsv,
          std::unique_ptr<TemporaryWsv>(std::shared_ptr<CommandExecutor>));
      MOCK_METHOD1(
          createMutableStorage,
          iroha::expected::Result<std::unique_ptr<MutableStorage>, std::string>(
              std::shared_ptr<CommandExecutor>));
      MOCK_CONST_METHOD0(createPeerQuery,
                         boost::optional<std::shared_ptr<PeerQuery>>());
      MOCK_CONST_METHOD0(createBlockQuery,
                         boost::optional<std::shared_ptr<BlockQuery>>());
      MOCK_CONST_METHOD0(createSettingQuery,
                         boost::optional<std::unique_ptr<SettingQuery>>());
      MOCK_METHOD(
          (iroha::expected::Result<std::unique_ptr<QueryExecutor>,
                                   std::string>),
          createQueryExecutor,
          (std::shared_ptr<PendingTransactionStorage>,
           std::shared_ptr<shared_model::interface::QueryResponseFactory>),
          (const, override));
      MOCK_METHOD1(doCommit, CommitResult(MutableStorage *storage));
      MOCK_CONST_METHOD0(preparedCommitEnabled, bool());
      MOCK_METHOD1(
          commitPrepared,
          CommitResult(std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD1(insertBlock,
                   iroha::expected::Result<void, std::string>(
                       std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD2(
          createMutableStorage,
          iroha::expected::Result<std::unique_ptr<MutableStorage>, std::string>(
              std::shared_ptr<CommandExecutor>, BlockStorageFactory &));

      MOCK_METHOD1(insertPeer,
                   expected::Result<void, std::string>(
                       const shared_model::interface::Peer &));
      MOCK_METHOD0(dropBlockStorage, expected::Result<void, std::string>());
      MOCK_METHOD0(resetPeers, expected::Result<void, std::string>());
      MOCK_CONST_METHOD0(
          getLedgerState,
          boost::optional<std::shared_ptr<const iroha::LedgerState>>());
      MOCK_METHOD0(freeConnections, void());
      MOCK_METHOD1(prepareBlock_, void(std::unique_ptr<TemporaryWsv> &));

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override {
        // gmock workaround for non-copyable parameters
        prepareBlock_(wsv);
      }

      CommitResult commit(std::unique_ptr<MutableStorage> storage) override {
        return doCommit(storage.get());
      }
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_STORAGE_HPP
