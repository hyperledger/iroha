/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_URSA_VERIFIER_HPP
#define IROHA_SHARED_MODEL_URSA_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_verifier_multihash.hpp"

namespace shared_model::crypto::ursa {
  /**
   * Class for signature verification.
   */
  class Verifier : public shared_model::crypto::CryptoVerifierMultihash {
   public:
    iroha::expected::Result<void, std::string> verify(
        iroha::multihash::Type type,
        shared_model::interface::types::SignatureByteRangeView signature,
        shared_model::interface::types::ByteRange source,
        shared_model::interface::types::PublicKeyByteRangeView public_key)
        const override;

    std::vector<iroha::multihash::Type> getSupportedTypes() const override;
  };
}  // namespace shared_model::crypto::ursa

#endif  // IROHA_SHARED_MODEL_VERIFIER_HPP
