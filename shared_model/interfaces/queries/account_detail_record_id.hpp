/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP
#define IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP

#include <optional>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /// Provides query metadata for account detail list pagination.
    class AccountDetailRecordId : public ModelPrimitive<AccountDetailRecordId> {
     public:
      /// Get the writer.
      virtual interface::types::AccountIdType writer() const = 0;

      /// Get the key.
      virtual interface::types::AccountDetailKeyType key() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_INTERFACE_MODEL_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP
