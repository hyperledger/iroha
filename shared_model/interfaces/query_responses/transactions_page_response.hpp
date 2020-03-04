/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRANSACTIONS_PAGE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_TRANSACTIONS_PAGE_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include <optional>
#include "interfaces/common_objects/range_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Response for paginated queries
     */
    class TransactionsPageResponse
        : public ModelPrimitive<TransactionsPageResponse> {
     public:
      /**
       * @return transactions from this page
       */
      virtual types::TransactionsCollectionType transactions() const = 0;

      /**
       * @return hash of the first transaction from the next page
       */
      virtual std::optional<interface::types::HashType> nextTxHash() const = 0;

      /**
       * @return total number of transactions for the query
       */
      virtual interface::types::TransactionsNumberType allTransactionsSize()
          const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_TRANSACTIONS_PAGE_RESPONSE_HPP
