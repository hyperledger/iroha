/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_MAKE_DEFAULT_CRYPTO_SIGNER_HPP
#define IROHA_TEST_MAKE_DEFAULT_CRYPTO_SIGNER_HPP
#

#include <memory>
#include <optional>

namespace shared_model {
  namespace crypto {
    class CryptoSigner;

    std::shared_ptr<shared_model::crypto::CryptoSigner> makeDefaultSigner();

    std::shared_ptr<shared_model::crypto::CryptoSigner> makeDefaultSigner(
        std::optional<std::shared_ptr<shared_model::crypto::CryptoSigner>>
            optional_signer);
  }  // namespace crypto
}  // namespace shared_model

#endif
