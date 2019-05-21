/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP
#define IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP

#include <boost/optional.hpp>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /// Provides query metadata for any transaction list pagination.
    class AccountAssetPaginationMeta
        : public ModelPrimitive<AccountAssetPaginationMeta> {
     public:

      /// Get the requested page size.
      virtual types::TransactionsNumberType pageSize() const = 0;

      /// Get the first requested transaction hash, if provided.
      virtual boost::optional<types::AssetIdType> firstAssetId() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP
