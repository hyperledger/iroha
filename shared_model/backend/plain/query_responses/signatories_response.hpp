/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_SIGNATORIES_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PLAIN_SIGNATORIES_RESPONSE_HPP

#include "interfaces/query_responses/signatories_response.hpp"

namespace shared_model {
  namespace plain {
    class SignatoriesResponse
        : public shared_model::interface::SignatoriesResponse {
     public:
      explicit SignatoriesResponse(
          shared_model::interface::types::PublicKeyCollectionType signatories);

      const shared_model::interface::types::PublicKeyCollectionType &keys()
          const override;

     private:
      shared_model::interface::types::PublicKeyCollectionType signatories_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_SIGNATORIES_RESPONSE_HPP
