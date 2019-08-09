/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP
#define IROHA_SHARED_MODEL_PLAIN_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP

#include "interfaces/queries/account_detail_record_id.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace plain {

    /// Provides query metadata for AccountDetail list pagination.
    class AccountDetailRecordId final
        : public interface::AccountDetailRecordId {
     public:
      AccountDetailRecordId(
          shared_model::interface::types::AccountIdType writer,
          shared_model::interface::types::AccountDetailKeyType key);

      shared_model::interface::types::AccountIdType writer() const override;

      shared_model::interface::types::AccountDetailKeyType key() const override;

     private:
      shared_model::interface::types::AccountIdType writer_;
      shared_model::interface::types::AccountDetailKeyType key_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP
