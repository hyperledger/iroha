/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_CRYPTO_DUMMIES_HPP
#define IROHA_TEST_CRYPTO_DUMMIES_HPP

#include <gmock/gmock.h>

#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"
#include "cryptography/private_key.hpp"
#include "cryptography/public_key.hpp"
#include "cryptography/signed.hpp"

namespace iroha {
  namespace dummy {
    inline shared_model::crypto::Hash createHash(
        const std::string &str = "hash") {
      return shared_model::crypto::Hash{shared_model::crypto::Blob{str}};
    }

    inline shared_model::crypto::PublicKey createPublicKey(
        const std::string &str = "public_key") {
      return shared_model::crypto::PublicKey{shared_model::crypto::Blob{str}};
    }

    inline shared_model::crypto::PrivateKey createPrivateKey(
        const std::string &str = "public_key") {
      return shared_model::crypto::PrivateKey{shared_model::crypto::Blob{str}};
    }

    inline shared_model::crypto::Signed createSigned(
        const std::string &str = "signed") {
      return shared_model::crypto::Signed{shared_model::crypto::Blob{str}};
    }
  }  // namespace dummy
}  // namespace iroha
#endif
