/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_STATELESS_VALID_FIELD_HELPERS_HPP
#define IROHA_TEST_STATELESS_VALID_FIELD_HELPERS_HPP

#include "module/shared_model/cryptography/crypto_defaults.hpp"

namespace framework {

  inline std::string padString(const std::string &str, size_t required_length) {
    assert(str.size() <= required_length);
    std::string padded(required_length, '0');
    std::copy(str.begin(), str.end(), padded.begin());
    return padded;
  }

  // TODO 15.03.2019 mboldyrev IR-402
  // fix the tests that impose requirements on mock public key format
  inline std::string padPubKeyString(const std::string &str) {
    return padString(
        str,
        shared_model::crypto::DefaultCryptoAlgorithmType::kPublicKeyLength);
  }

  // TODO 15.03.2019 mboldyrev IR-402
  // fix the tests that impose requirements on mock public key format
  inline std::string padSignatureString(const std::string &str) {
    return padString(
        str,
        shared_model::crypto::DefaultCryptoAlgorithmType::kSignatureLength);
  }

}  // namespace framework

#endif
