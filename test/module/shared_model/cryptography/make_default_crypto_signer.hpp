/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_MAKE_DEFAULT_CRYPTO_SIGNER_HPP
#define IROHA_TEST_MAKE_DEFAULT_CRYPTO_SIGNER_HPP

#include "cryptography/crypto_provider/crypto_signer.hpp"

#include <memory>
#include <optional>

namespace shared_model {
  namespace crypto {

    /// Create a signer of default crypto algorithm with random key.
    std::shared_ptr<shared_model::crypto::CryptoSigner> makeDefaultSigner();

    /// Return provided signer or create a new signer of default crypto
    /// algorithm with random key.
    std::shared_ptr<shared_model::crypto::CryptoSigner> makeDefaultSigner(
        std::optional<std::shared_ptr<shared_model::crypto::CryptoSigner>>
            optional_signer);
  }  // namespace crypto
}  // namespace shared_model

#endif
