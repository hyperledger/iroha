/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_signatories_response.hpp"

#include <boost/range/numeric.hpp>
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    SignatoriesResponse::SignatoriesResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          signatories_response_{proto_->signatories_response()},
          keys_{[this] {
            return boost::accumulate(
                signatories_response_.keys(),
                interface::types::PublicKeyCollectionType{},
                [](auto acc, auto key) {
                  acc.emplace_back(crypto::Hash::fromHexString(key));
                  return acc;
                });
          }()} {}

    template SignatoriesResponse::SignatoriesResponse(
        SignatoriesResponse::TransportType &);
    template SignatoriesResponse::SignatoriesResponse(
        const SignatoriesResponse::TransportType &);
    template SignatoriesResponse::SignatoriesResponse(
        SignatoriesResponse::TransportType &&);

    SignatoriesResponse::SignatoriesResponse(const SignatoriesResponse &o)
        : SignatoriesResponse(o.proto_) {}

    SignatoriesResponse::SignatoriesResponse(SignatoriesResponse &&o)
        : SignatoriesResponse(std::move(o.proto_)) {}

    const interface::types::PublicKeyCollectionType &SignatoriesResponse::keys()
        const {
      return keys_;
    }

  }  // namespace proto
}  // namespace shared_model
