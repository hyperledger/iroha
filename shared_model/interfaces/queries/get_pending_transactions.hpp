/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_PENDING_TRANSACTIONS_HPP
#define IROHA_SHARED_MODEL_GET_PENDING_TRANSACTIONS_HPP

#include <optional>
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
      // TODO igor-egorov 2019-06-06 IR-516 make page meta non-optional
      /**
       *  Get the query pagination metadata.
       */
      virtual std::optional<std::reference_wrapper<const TxPaginationMeta>>
      paginationMeta() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_PENDING_TRANSACTIONS_HPP
