/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/query_responses/signatories_response.hpp"

#include "cryptography/public_key.hpp"

using namespace shared_model::interface::types;

using shared_model::plain::SignatoriesResponse;

SignatoriesResponse::SignatoriesResponse(
    shared_model::interface::types::PublicKeyCollectionType signatories)
    : signatories_(std::move(signatories)) {}

const shared_model::interface::types::PublicKeyCollectionType &
SignatoriesResponse::keys() const {
  return signatories_;
}
