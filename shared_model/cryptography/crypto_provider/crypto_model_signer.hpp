/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_MODEL_SIGNER_HPP_
#define IROHA_CRYPTO_MODEL_SIGNER_HPP_

#include "cryptography/crypto_provider/abstract_crypto_model_signer.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/keypair.hpp"

#include "interfaces/iroha_internal/block.hpp"

namespace shared_model {

  namespace crypto {
    template <typename Algorithm = CryptoSigner>
    class CryptoModelSigner
        : public AbstractCryptoModelSigner<interface::Block> {
     public:
      explicit CryptoModelSigner(const shared_model::crypto::Keypair &keypair);

      virtual ~CryptoModelSigner() = default;

      template <typename T>
      inline void sign(T &signable) const noexcept {
        auto signature_hex = Algorithm::sign(signable.payload(), keypair_);
        using namespace shared_model::interface::types;
        signable.addSignature(SignedHexStringView{signature_hex},
                              PublicKeyHexStringView{keypair_.publicKey()});
      }

      void sign(interface::Block &m) const override {
        sign<interface::Block>(m);
      }

     private:
      shared_model::crypto::Keypair keypair_;
    };

    template <typename Algorithm>
    CryptoModelSigner<Algorithm>::CryptoModelSigner(
        const shared_model::crypto::Keypair &keypair)
        : keypair_(keypair) {}

  }  // namespace crypto
}  // namespace shared_model

#endif  //  IROHA_CRYPTO_MODEL_SIGNER_HPP_
