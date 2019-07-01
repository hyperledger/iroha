/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ACCOUNT_DETAIL_RESPONSE_HPP
#define IROHA_PROTO_ACCOUNT_DETAIL_RESPONSE_HPP

#include "interfaces/query_responses/account_detail_response.hpp"

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/queries/proto_account_detail_record_id.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class AccountDetailResponse final
        : public CopyableProto<interface::AccountDetailResponse,
                               iroha::protocol::QueryResponse,
                               AccountDetailResponse> {
     public:
      template <typename QueryResponseType>
      explicit AccountDetailResponse(QueryResponseType &&queryResponse);

      AccountDetailResponse(const AccountDetailResponse &o);

      AccountDetailResponse(AccountDetailResponse &&o);

      const interface::types::DetailType &detail() const override;

      size_t totalNumber() const override;

      boost::optional<const shared_model::interface::AccountDetailRecordId &>
      nextRecordId() const override;

     private:
      const iroha::protocol::AccountDetailResponse &account_detail_response_;
      const boost::optional<const AccountDetailRecordId> next_record_id_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ACCOUNT_DETAIL_RESPONSE_HPP
