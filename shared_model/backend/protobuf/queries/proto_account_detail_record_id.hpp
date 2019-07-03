/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP

#include "interfaces/queries/account_detail_record_id.hpp"

#include "interfaces/common_objects/types.hpp"
#include "primitive.pb.h"

namespace shared_model {
  namespace proto {

    /// Provides query metadata for AccountDetail list pagination.
    class AccountDetailRecordId final
        : public interface::AccountDetailRecordId {
     public:
      using TransportType = iroha::protocol::AccountDetailRecordId;

      explicit AccountDetailRecordId(TransportType &proto);

      explicit AccountDetailRecordId(const AccountDetailRecordId &o);

      shared_model::interface::types::AccountIdType writer() const override;

      shared_model::interface::types::AccountDetailKeyType key() const override;

     private:
      TransportType &proto_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_DETAIL_RECORD_ID_HPP
