/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_PROPAGATOR_HPP
#define IROHA_MST_PROPAGATOR_HPP

#include <memory>
#include <mutex>

#include <rxcpp/rx-observable-fwd.hpp>
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/mst_types.hpp"

namespace iroha {

  /**
   * MstProcessor is responsible for organization of sharing multi-signature
   * transactions in network
   */
  class MstProcessor {
   public:
    // ---------------------------| user interface |----------------------------

    /**
     * Propagate batch in network for signing by other
     * participants
     * @param transaction - transaction for propagation
     */
    void propagateBatch(const DataType &batch);

    /**
     * Check, if passed batch is in pending storage
     * @param batch to be checked
     * @return true, if batch is already in pending storage, false otherwise
     */
    bool batchInStorage(const DataType &batch) const;

    virtual ~MstProcessor() = default;

   protected:
    explicit MstProcessor(logger::LoggerPtr log);

    logger::LoggerPtr log_;

   private:
    // ------------------------| inheritance interface |------------------------

    /**
     * @see propagateTransaction method
     */
    virtual auto propagateBatchImpl(const DataType &batch)
        -> decltype(propagateBatch(batch)) = 0;

    /**
     * @see batchInStorage method
     */
    virtual bool batchInStorageImpl(const DataType &batch) const = 0;
  };
}  // namespace iroha

#endif  // IROHA_MST_PROPAGATOR_HPP
