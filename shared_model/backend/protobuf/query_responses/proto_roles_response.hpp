/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ROLES_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ROLES_RESPONSE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class RolesResponse final
        : public CopyableProto<interface::RolesResponse,
                               iroha::protocol::QueryResponse,
                               RolesResponse> {
     public:
      template <typename QueryResponseType>
      explicit RolesResponse(QueryResponseType &&queryResponse);

      RolesResponse(const RolesResponse &o);

      RolesResponse(RolesResponse &&o);

      const RolesIdType &roles() const override;

     private:
      const iroha::protocol::RolesResponse &roles_response_;

      const RolesIdType roles_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ROLES_RESPONSE_HPP
