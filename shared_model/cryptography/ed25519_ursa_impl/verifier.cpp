/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/verifier.hpp"

#include "common/result.hpp"
#include "cryptography/ed25519_ursa_impl/common.hpp"
#include "ursa_crypto.h"

using namespace shared_model::crypto::ursa;
using namespace shared_model::interface::types;

iroha::expected::Result<void, std::string> Verifier::verify(
    iroha::multihash::Type type,
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange source,
    shared_model::interface::types::PublicKeyByteRangeView public_key) const {
  assert(type == iroha::multihash::Type::kEd25519Sha2_256);

  ExternError err;

  const ByteBuffer kMessage = irohaToUrsaBuffer(source);
  const ByteBuffer kSignature = irohaToUrsaBuffer(signature);
  const ByteBuffer kPublicKey = irohaToUrsaBuffer(public_key);

  if (not ursa_ed25519_verify(&kMessage, &kSignature, &kPublicKey, &err)) {
    iroha::expected::Error<std::string> error{err.message};
    ursa_ed25519_string_free(err.message);
    return error;
  } else {
    return iroha::expected::Value<void>{};
  }
}

std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
  return {iroha::multihash::Type::kEd25519Sha2_256};
}
