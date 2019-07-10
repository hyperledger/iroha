/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_signatories_response.hpp"

#include <boost/range/numeric.hpp>
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    SignatoriesResponse::SignatoriesResponse(
        iroha::protocol::QueryResponse &query_response)
        : signatories_response_{query_response.signatories_response()},
          keys_{[this] {
            return boost::accumulate(
                signatories_response_.keys(),
                interface::types::PublicKeyCollectionType{},
                [](auto acc, auto key) {
                  acc.emplace_back(crypto::Hash::fromHexString(key));
                  return acc;
                });
          }()} {}

    const interface::types::PublicKeyCollectionType &SignatoriesResponse::keys()
        const {
      return keys_;
    }

  }  // namespace proto
}  // namespace shared_model
