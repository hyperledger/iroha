/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_SIGNATORIES_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_SIGNATORIES_RESPONSE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class SignatoriesResponse final
        : public CopyableProto<interface::SignatoriesResponse,
                               iroha::protocol::QueryResponse,
                               SignatoriesResponse> {
     public:
      template <typename QueryResponseType>
      explicit SignatoriesResponse(QueryResponseType &&queryResponse);

      SignatoriesResponse(const SignatoriesResponse &o);

      SignatoriesResponse(SignatoriesResponse &&o);

      const interface::types::PublicKeyCollectionType &keys() const override;

     private:
      const iroha::protocol::SignatoriesResponse &signatories_response_;

      const interface::types::PublicKeyCollectionType keys_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_SIGNATORIES_RESPONSE_HPP
