/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/verifier.hpp"

#include "common/result.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

using namespace shared_model::crypto::ed25519_sha3;
using namespace shared_model::interface::types;

Verifier::~Verifier() = default;

iroha::expected::Result<void, std::string> Verifier::verify(
    iroha::multihash::Type type,
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange source,
    shared_model::interface::types::PublicKeyByteRangeView public_key) const {
  assert(type == iroha::multihash::Type::ed25519_sha3_256);
  if (verifyEd25519Sha3(signature, source, public_key)) {
    return iroha::expected::Value<void>{};
  }
  return iroha::expected::makeError("Bad signature.");
}

bool Verifier::verifyEd25519Sha3(
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange source,
    shared_model::interface::types::PublicKeyByteRangeView public_key) {
  auto blob_hash = iroha::sha3_256(source);
  return iroha::verify(
      blob_hash.data(), blob_hash.size(), public_key, signature);
}

std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
  return {iroha::multihash::Type::ed25519_sha3_256};
}
