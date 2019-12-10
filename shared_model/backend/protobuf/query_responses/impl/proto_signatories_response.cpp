/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_signatories_response.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<SignatoriesResponse>, std::string>
    SignatoriesResponse::create(
        const iroha::protocol::QueryResponse &query_response) {
      using namespace iroha::expected;
      interface::types::PublicKeyCollectionType keys;
      for (const auto &hex : query_response.signatories_response().keys()) {
        if (auto e = resultToOptionalError(
                shared_model::crypto::Blob::fromHexString(hex) |
                    [&keys](auto &&blob) -> Result<void, std::string> {
                  keys.emplace_back(std::move(blob));
                  return {};
                })) {
          return e.value();
        }
      }
      return std::make_unique<SignatoriesResponse>(query_response,
                                                   std::move(keys));
    }

    SignatoriesResponse::SignatoriesResponse(
        const iroha::protocol::QueryResponse &query_response,
        interface::types::PublicKeyCollectionType keys)
        : signatories_response_{query_response.signatories_response()},
          keys_{std::move(keys)} {}

    const interface::types::PublicKeyCollectionType &SignatoriesResponse::keys()
        const {
      return keys_;
    }

  }  // namespace proto
}  // namespace shared_model
