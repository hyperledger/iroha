/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ACCOUNT_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ACCOUNT_RESPONSE_HPP

#include "backend/protobuf/common_objects/account.hpp"
#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class AccountResponse final
        : public CopyableProto<interface::AccountResponse,
                               iroha::protocol::QueryResponse,
                               AccountResponse> {
     public:
      template <typename QueryResponseType>
      explicit AccountResponse(QueryResponseType &&queryResponse);

      AccountResponse(const AccountResponse &o);

      AccountResponse(AccountResponse &&o);

      const interface::Account &account() const override;

      const AccountRolesIdType &roles() const override;

     private:
      const iroha::protocol::AccountResponse &account_response_;

      const AccountRolesIdType account_roles_;

      const shared_model::proto::Account account_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ACCOUNT_RESPONSE_HPP
