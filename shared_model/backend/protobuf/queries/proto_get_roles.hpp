/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ROLES_H
#define IROHA_PROTO_GET_ROLES_H

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetRoles final : public CopyableProto<interface::GetRoles,
                                                iroha::protocol::Query,
                                                GetRoles> {
     public:
      template <typename QueryType>
      explicit GetRoles(QueryType &&query);

      GetRoles(const GetRoles &o);

      GetRoles(GetRoles &&o) noexcept;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ROLES_H
