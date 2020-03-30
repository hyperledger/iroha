/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_INTERNAL_HPP
#define IROHA_CRYPTO_SIGNER_INTERNAL_HPP

#include "cryptography/crypto_provider/crypto_signer.hpp"

#include "cryptography/blob.hpp"
#include "cryptography/keypair.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * CryptoSignerInternal - wrapper for generalization signing for different
     * internal cryptographic algorithms
     * @tparam Algorithm - cryptographic algorithm for singing
     */
    template <typename Algorithm>
    class CryptoSignerInternal : public CryptoSigner {
     public:
      explicit CryptoSignerInternal(Keypair &&keypair)
          : keypair_(std::move(keypair)) {}

      virtual ~CryptoSignerInternal() = default;

      std::string sign(const Blob &blob) const override {
        return Algorithm::sign(blob, keypair_);
      }

      shared_model::interface::types::PublicKeyHexStringView publicKey()
          const override {
        return keypair_.publicKey();
      }

     private:
      Keypair keypair_;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif
