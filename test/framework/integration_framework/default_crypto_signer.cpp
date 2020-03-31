/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/default_crypto_signer.hpp"

#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_signer_internal.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace shared_model::crypto;

namespace integration_framework {
  std::shared_ptr<CryptoSigner> makeSigner() {
    return std::make_shared<CryptoSignerInternal<DefaultCryptoAlgorithmType>>(
        DefaultCryptoAlgorithmType::generateKeypair());
  }

  std::shared_ptr<CryptoSigner> makeSigner(
      std::optional<std::shared_ptr<CryptoSigner>> optional_signer) {
    if (optional_signer) {
      return std::move(optional_signer).value();
    }
    return makeSigner();
  }
}  // namespace integration_framework
