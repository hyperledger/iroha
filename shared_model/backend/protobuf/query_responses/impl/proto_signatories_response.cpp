/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_signatories_response.hpp"

namespace shared_model {
  namespace proto {

    SignatoriesResponse::SignatoriesResponse(
        iroha::protocol::QueryResponse &query_response)
        : signatories_response_{query_response.signatories_response()},
          keys_{signatories_response_.keys().begin(),
                signatories_response_.keys().end()} {}

    const interface::types::PublicKeyCollectionType &SignatoriesResponse::keys()
        const {
      return keys_;
    }

  }  // namespace proto
}  // namespace shared_model
