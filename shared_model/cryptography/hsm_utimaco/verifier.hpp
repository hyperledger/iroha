/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_HSM_UTIMACO_CRYPTO_VERIFIER_HPP
#define IROHA_HSM_UTIMACO_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_verifier_multihash.hpp"

#include <optional>
#include <string>

#include "cryptography/hsm_utimaco/connection.hpp"

namespace shared_model::crypto::hsm_utimaco {

  /**
   * Verifier - verifier
   * cryptographic signatures
   */
  class Verifier : public shared_model::crypto::CryptoVerifierMultihash {
   public:
    Verifier(std::shared_ptr<Connection> connection,
             std::string temporary_key_name,
             std::optional<std::string> temporary_key_group);

    ~Verifier() override;

    iroha::expected::Result<void, std::string> verify(
        iroha::multihash::Type type,
        shared_model::interface::types::SignatureByteRangeView signature,
        shared_model::interface::types::ByteRange source,
        shared_model::interface::types::PublicKeyByteRangeView public_key)
        const override;

    std::vector<iroha::multihash::Type> getSupportedTypes() const override;

   private:
    std::shared_ptr<Connection> connection_;

    std::string temporary_key_name_;
    std::optional<std::string> temporary_key_group_;
  };

}  // namespace shared_model::crypto::hsm_utimaco

#endif  // IROHA_CRYPTO_VERIFIER_HPP
