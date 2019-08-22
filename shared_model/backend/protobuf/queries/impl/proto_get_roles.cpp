/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_roles.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetRoles::GetRoles(QueryType &&query)
        : TrivialProto(std::forward<QueryType>(query)) {}

    template GetRoles::GetRoles(GetRoles::TransportType &);
    template GetRoles::GetRoles(const GetRoles::TransportType &);
    template GetRoles::GetRoles(GetRoles::TransportType &&);

    GetRoles::GetRoles(const GetRoles &o) : GetRoles(o.proto_) {}

    GetRoles::GetRoles(GetRoles &&o) noexcept : GetRoles(std::move(o.proto_)) {}

  }  // namespace proto
}  // namespace shared_model
