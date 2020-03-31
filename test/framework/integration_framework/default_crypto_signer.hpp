/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_INTEGRATION_FRAMEWORK_DEFAULT_CRYPTO_SIGNER_HPP
#define IROHA_INTEGRATION_FRAMEWORK_DEFAULT_CRYPTO_SIGNER_HPP

#include <memory>
#include <optional>

namespace shared_model {
  namespace crypto {
    class CryptoSigner;
  }
}  // namespace shared_model

namespace integration_framework {
  std::shared_ptr<shared_model::crypto::CryptoSigner> makeSigner();

  std::shared_ptr<shared_model::crypto::CryptoSigner> makeSigner(
      std::optional<std::shared_ptr<shared_model::crypto::CryptoSigner>>
          optional_signer);
}  // namespace integration_framework

#endif
