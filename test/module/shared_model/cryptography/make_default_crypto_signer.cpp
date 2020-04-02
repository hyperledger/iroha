/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/cryptography/make_default_crypto_signer.hpp"

#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_signer_internal.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

namespace shared_model {
  namespace crypto {
    std::shared_ptr<CryptoSigner> makeDefaultSigner() {
      return std::make_shared<CryptoSignerInternal<DefaultCryptoAlgorithmType>>(
          DefaultCryptoAlgorithmType::generateKeypair());
    }

    std::shared_ptr<CryptoSigner> makeDefaultSigner(
        std::optional<std::shared_ptr<CryptoSigner>> optional_signer) {
      if (optional_signer) {
        return std::move(optional_signer).value();
      }
      return makeDefaultSigner();
    }
  }  // namespace crypto
}  // namespace shared_model
