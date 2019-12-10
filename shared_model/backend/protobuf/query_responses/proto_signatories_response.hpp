/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_SIGNATORIES_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_SIGNATORIES_RESPONSE_HPP

#include "interfaces/query_responses/signatories_response.hpp"

#include "common/result_fwd.hpp"
#include "cryptography/public_key.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class SignatoriesResponse final : public interface::SignatoriesResponse {
     public:
      static iroha::expected::Result<std::unique_ptr<SignatoriesResponse>,
                                     std::string>
      create(const iroha::protocol::QueryResponse &query_response);

      explicit SignatoriesResponse(
          const iroha::protocol::QueryResponse &query_response,
          interface::types::PublicKeyCollectionType keys);

      const interface::types::PublicKeyCollectionType &keys() const override;

     private:
      const iroha::protocol::SignatoriesResponse &signatories_response_;

      const interface::types::PublicKeyCollectionType keys_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_SIGNATORIES_RESPONSE_HPP
