/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_WSVRESTORER_HPP
#define IROHA_WSVRESTORER_HPP

#include "ametsuchi/commit_result.hpp"

namespace iroha {
  namespace ametsuchi {

    class Storage;
    class BlockQuery;
    class BlockStorageFactory;

    /**
     * Interface for World State View restoring from the storage
     */
    class WsvRestorer {
     public:
      virtual ~WsvRestorer() = default;

      /**
       * Recover WSV (World State View).
       * @param storage storage of blocks in ledger
       * @param wait_for_new_blocks - flag for wait for new blocks mode.
       * Method waits for new blocks in block storage.
       * @return ledger state after restoration on success, otherwise errors
       * string
       */
      virtual CommitResult restoreWsv(
          Storage &storage,
          bool wait_for_new_blocks,
          std::shared_ptr<BlockQuery> = nullptr,
          std::shared_ptr<BlockStorageFactory> = nullptr) = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSVRESTORER_HPP
