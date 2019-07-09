/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ACCOUNT_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ACCOUNT_RESPONSE_HPP

#include "interfaces/query_responses/account_response.hpp"

#include "backend/protobuf/common_objects/account.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class AccountResponse final : public interface::AccountResponse {
     public:
      explicit AccountResponse(iroha::protocol::QueryResponse &query_response);

      const interface::Account &account() const override;

      const AccountRolesIdType &roles() const override;

     private:
      const iroha::protocol::AccountResponse &account_response_;

      const AccountRolesIdType account_roles_;

      Account account_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ACCOUNT_RESPONSE_HPP
