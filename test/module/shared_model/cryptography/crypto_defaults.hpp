/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_SHARED_MODEL_CRYPTO_DEFAULTS_HPP
#define IROHA_TEST_SHARED_MODEL_CRYPTO_DEFAULTS_HPP

#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"

namespace shared_model {
  namespace crypto {
    /// Default type of crypto algorithm
    using DefaultCryptoAlgorithmType = CryptoProviderEd25519Sha3;
  }  // namespace crypto
}  // namespace shared_model

#endif
