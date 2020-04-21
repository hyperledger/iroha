/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_PROVIDER_HPP
#define IROHA_CRYPTO_PROVIDER_HPP

#include <memory>

namespace shared_model {
  namespace crypto {

    class CryptoSigner;
    class CryptoVerifier;

    /**
     * CryptoProvider is a complete abstraction of crypto operations
     */
    struct CryptoProvider {
      std::shared_ptr<CryptoSigner> signer;
      std::shared_ptr<CryptoVerifier> verifier;
    };

  }  // namespace crypto
}  // namespace shared_model
#endif
