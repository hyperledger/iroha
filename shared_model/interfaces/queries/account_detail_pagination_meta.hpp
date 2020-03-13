/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_DETAIL_PAGINATION_META_HPP
#define IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_DETAIL_PAGINATION_META_HPP

#include <optional>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/account_detail_record_id.hpp"

namespace shared_model {
  namespace interface {

    /// Provides query metadata for account detail list pagination.
    class AccountDetailPaginationMeta
        : public ModelPrimitive<AccountDetailPaginationMeta> {
     public:
      /// Get the requested page size.
      virtual size_t pageSize() const = 0;

      /// Get the first requested record id, if provided.
      virtual std::optional<std::reference_wrapper<const AccountDetailRecordId>>
      firstRecordId() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_DETAIL_PAGINATION_META_HPP
