/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_INTERFACE_MODEL_QUERY_TX_PAGINATION_META_HPP
#define IROHA_SHARED_INTERFACE_MODEL_QUERY_TX_PAGINATION_META_HPP

#include <optional>

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "ordering.hpp"

namespace shared_model {
  namespace interface {

    /// Provides query metadata for any transaction list pagination.
    class TxPaginationMeta : public ModelPrimitive<TxPaginationMeta> {
     public:
      /// Get the requested page size.
      virtual types::TransactionsNumberType pageSize() const = 0;

      /// Get the first requested transaction hash, if provided.
      virtual std::optional<types::HashType> firstTxHash() const = 0;
      virtual Ordering const &ordering() const = 0;
      virtual std::optional<types::TimestampType> firstTxTime() const = 0;
      virtual std::optional<types::TimestampType> lastTxTime() const = 0;
      virtual std::optional<types::HeightType> firstTxHeight() const = 0;
      virtual std::optional<types::HeightType> lastTxHeight() const = 0;
      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_INTERFACE_MODEL_QUERY_TX_PAGINATION_META_HPP
