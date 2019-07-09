/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ROLES_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ROLES_RESPONSE_HPP

#include "interfaces/query_responses/roles_response.hpp"

#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class RolesResponse final : public interface::RolesResponse {
     public:
      explicit RolesResponse(iroha::protocol::QueryResponse &query_response);

      const RolesIdType &roles() const override;

     private:
      const iroha::protocol::RolesResponse &roles_response_;

      const RolesIdType roles_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ROLES_RESPONSE_HPP
