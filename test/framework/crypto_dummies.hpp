/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_CRYPTO_DUMMIES_HPP
#define IROHA_TEST_CRYPTO_DUMMIES_HPP

#include <gmock/gmock.h>

#include "cryptography/blob.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "cryptography/hash.hpp"
#include "cryptography/private_key.hpp"
#include "cryptography/public_key.hpp"
#include "cryptography/signed.hpp"

namespace iroha {
  inline std::string padString(const std::string &str, size_t length) {
    assert(str.size() <= length);
    std::string padded(length, '0');
    std::copy(str.begin(), str.end(), padded.begin());
    return padded;
  }

  inline std::unique_ptr<shared_model::crypto::Blob> padBlob(
      const std::string &str, size_t length) {
    return shared_model::crypto::Blob::fromBinaryString(padString(str, length));
  }

  inline shared_model::crypto::Hash createHash(
      const std::string &str = "hash") {
    using shared_model::crypto::DefaultCryptoAlgorithmType;
    return shared_model::crypto::Hash{
        shared_model::crypto::Blob::fromBinaryString(str)};
  }

  inline shared_model::crypto::Hash createHashPadded(
      const std::string &str = "hash") {
    using shared_model::crypto::DefaultCryptoAlgorithmType;
    return shared_model::crypto::Hash{padBlob(
        str, shared_model::crypto::DefaultCryptoAlgorithmType::kHashLength)};
  }

  inline shared_model::crypto::PublicKey createPublicKey(
      const std::string &str = "public_key") {
    return shared_model::crypto::PublicKey{
        shared_model::crypto::Blob::fromBinaryString(str)};
  }

  inline shared_model::crypto::PublicKey createPublicKeyPadded(
      const std::string &str = "public_key") {
    return shared_model::crypto::PublicKey{padBlob(
        str,
        shared_model::crypto::DefaultCryptoAlgorithmType::kPublicKeyLength)};
  }

  inline shared_model::crypto::PrivateKey createPrivateKey(
      const std::string &str = "public_key") {
    return shared_model::crypto::PrivateKey{
        shared_model::crypto::Blob::fromBinaryString(str)};
  }

  inline shared_model::crypto::PrivateKey createPrivateKeyPadded(
      const std::string &str = "public_key") {
    return shared_model::crypto::PrivateKey{padBlob(
        str,
        shared_model::crypto::DefaultCryptoAlgorithmType::kPrivateKeyLength)};
  }

  inline shared_model::crypto::Signed createSigned(
      const std::string &str = "signed") {
    return shared_model::crypto::Signed{
        shared_model::crypto::Blob::fromBinaryString(str)};
  }

  inline shared_model::crypto::Signed createSignedPadded(
      const std::string &str = "signed") {
    return shared_model::crypto::Signed{padBlob(
        str,
        shared_model::crypto::DefaultCryptoAlgorithmType::kSignatureLength)};
  }

}  // namespace iroha
#endif
