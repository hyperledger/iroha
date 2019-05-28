/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_PENDING_TRANSACTIONS_HPP
#define IROHA_SHARED_MODEL_GET_PENDING_TRANSACTIONS_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class TxPaginationMeta;

    /**
     * Get all pending (not fully signed) multisignature transactions or batches
     * of transactions.
     */
    class GetPendingTransactions
        : public ModelPrimitive<GetPendingTransactions> {
     public:
      /**
       *  Get the query pagination metadata.
       */
      virtual const TxPaginationMeta &paginationMeta() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_PENDING_TRANSACTIONS_HPP
