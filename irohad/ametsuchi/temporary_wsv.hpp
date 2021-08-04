/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEMPORARYWSV_HPP
#define IROHA_TEMPORARYWSV_HPP

#include <functional>

#include "ametsuchi/impl/db_transaction.hpp"
#include "common/result.hpp"
#include "validation/stateful_validator_common.hpp"

namespace shared_model {
  namespace interface {
    class Transaction;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    /**
     * Temporary world state view
     * Allows to query the temporary world state view
     */
    class TemporaryWsv {
     public:
      /**
       * Wrapper for savepoints in wsv state; rollbacks to savepoint, if
       * destroyed without explicit release, releases it otherwise
       */
      struct SavepointWrapper {
        /**
         * Release the savepoint
         */
        virtual void release() = 0;

        virtual ~SavepointWrapper() = default;
      };

      /**
       * Applies a transaction to current state
       * @param transaction Transaction to be applied
       * @return True if transaction was successfully applied, false otherwise
       */
      virtual expected::Result<void, validation::CommandError> apply(
          const shared_model::interface::Transaction &transaction) = 0;

      /**
       * Create a savepoint for wsv state
       * @param name of savepoint to be created
       * @return RAII wrapper for savepoints
       */
      virtual std::unique_ptr<TemporaryWsv::SavepointWrapper> createSavepoint(
          const std::string &name) = 0;

      virtual DatabaseTransaction &getDbTransaction() = 0;

      virtual ~TemporaryWsv() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_TEMPORARYWSV_HPP
