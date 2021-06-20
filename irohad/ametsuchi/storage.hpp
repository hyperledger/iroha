/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_H
#define IROHA_AMETSUCHI_H

#include <vector>

#include "ametsuchi/block_query_factory.hpp"
#include "ametsuchi/mutable_factory.hpp"
#include "ametsuchi/peer_query_factory.hpp"
#include "ametsuchi/query_executor_factory.hpp"
#include "ametsuchi/setting_query_factory.hpp"
#include "ametsuchi/temporary_factory.hpp"
#include "common/result_fwd.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }
}  // namespace shared_model

namespace iroha {

  namespace ametsuchi {

    class BlockStorageFactory;
    class BlockQuery;
    class WsvQuery;

    /**
     * Storage interface, which allows queries on current committed state, and
     * creation of state which can be mutated with blocks and transactions
     */
    class Storage : public TemporaryFactory,
                    public MutableFactory,
                    public PeerQueryFactory,
                    public BlockQueryFactory,
                    public QueryExecutorFactory,
                    public SettingQueryFactory {
     public:
      virtual std::shared_ptr<WsvQuery> getWsvQuery() const = 0;

      virtual std::shared_ptr<BlockQuery> getBlockQuery() const = 0;

      /**
       * Raw insertion of blocks without validation
       * @param block - block for insertion
       * @return true if inserted
       */
      virtual iroha::expected::Result<void, std::string> insertBlock(
          std::shared_ptr<const shared_model::interface::Block> block) = 0;

      /**
       * Create new command executor that holds a database session within.
       * @return The command executor or string error message.
       */
      virtual expected::Result<std::unique_ptr<CommandExecutor>, std::string>
      createCommandExecutor() = 0;

      /**
       * Insert a peer into WSV
       * @param peer - peer to insert
       * @return error reason if not inserted
       */
      virtual expected::Result<void, std::string> insertPeer(
          const shared_model::interface::Peer &peer) = 0;

      using MutableFactory::createMutableStorage;

      /**
       * Creates a mutable storage from the current state
       * @return Created mutable storage.
       */
      virtual iroha::expected::Result<std::unique_ptr<MutableStorage>,
                                      std::string>
      createMutableStorage(std::shared_ptr<CommandExecutor> command_executor,
                           BlockStorageFactory &storage_factory) = 0;

      /**
       * Removes all peers from WSV
       */
      virtual expected::Result<void, std::string> resetPeers() = 0;

      /**
       * Remove all blocks from block storage.
       */
      virtual expected::Result<void, std::string> dropBlockStorage() = 0;

      virtual boost::optional<std::shared_ptr<const iroha::LedgerState>>
      getLedgerState() const = 0;

      virtual void freeConnections() = 0;

      virtual ~Storage() = default;
    };

  }  // namespace ametsuchi

}  // namespace iroha

#endif  // IROHA_AMETSUCHI_H
