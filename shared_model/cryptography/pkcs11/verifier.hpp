/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PKCS11_CRYPTO_VERIFIER_HPP
#define IROHA_PKCS11_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_verifier_multihash.hpp"

#include <optional>
#include <string>

#include "cryptography/pkcs11/data.hpp"

namespace shared_model::crypto::pkcs11 {

  /**
   * Verifier - verifier
   * cryptographic signatures
   */
  class Verifier : public shared_model::crypto::CryptoVerifierMultihash {
   public:
    Verifier(OperationContextFactory operation_context_factory,
             std::vector<iroha::multihash::Type> supported_types);

    ~Verifier() override;

    iroha::expected::Result<void, std::string> verify(
        iroha::multihash::Type type,
        shared_model::interface::types::SignatureByteRangeView signature,
        shared_model::interface::types::ByteRange source,
        shared_model::interface::types::PublicKeyByteRangeView public_key)
        const override;

    std::vector<iroha::multihash::Type> getSupportedTypes() const override;

   private:
    OperationContextFactory operation_context_factory_;
    std::vector<iroha::multihash::Type> supported_types_;
    std::string description_;
  };

}  // namespace shared_model::crypto::pkcs11

#endif  // IROHA_CRYPTO_VERIFIER_HPP
