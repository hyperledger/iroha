/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MUTABLE_FACTORY_HPP
#define IROHA_MUTABLE_FACTORY_HPP

#include <memory>

#include <boost/optional.hpp>
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/commit_result.hpp"
#include "common/result_fwd.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    class MutableStorage;

    class MutableFactory {
     public:
      /**
       * Creates a mutable storage from the current state.
       * Mutable storage is the only way to commit the block to the ledger.
       * @return Created mutable storage
       */
      virtual iroha::expected::Result<std::unique_ptr<MutableStorage>,
                                      std::string>
      createMutableStorage(
          std::shared_ptr<CommandExecutor> command_executor) = 0;

      /**
       * Commit mutable storage to Ametsuchi.
       * This transforms Ametsuchi to the new state consistent with
       * MutableStorage.
       * @param mutableStorage
       * @return the status of commit
       */
      virtual CommitResult commit(
          std::unique_ptr<MutableStorage> mutableStorage) = 0;

      /// Check if prepared commits are enabled.
      virtual bool preparedCommitEnabled() const = 0;

      /**
       * Try to apply prepared block to Ametsuchi.
       * @param block The previously prepared block that will be committed now.
       * @return Result of committing the prepared block.
       */
      virtual CommitResult commitPrepared(
          std::shared_ptr<const shared_model::interface::Block> block) = 0;

      virtual ~MutableFactory() = default;
    };

  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_MUTABLE_FACTORY_HPP
