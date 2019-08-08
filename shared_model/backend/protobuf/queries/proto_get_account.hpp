/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ACCOUNT_H
#define IROHA_PROTO_GET_ACCOUNT_H

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_account.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccount final
        : public TrivialProto<interface::GetAccount, iroha::protocol::Query> {
     public:
      template <typename QueryType>
      explicit GetAccount(QueryType &&query);

      GetAccount(const GetAccount &o);

      GetAccount(GetAccount &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

     private:
      // ------------------------------| fields |-------------------------------
      const iroha::protocol::GetAccount &account_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ACCOUNT_H
