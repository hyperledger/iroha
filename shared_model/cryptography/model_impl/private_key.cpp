/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/private_key.hpp"

namespace shared_model {
  namespace crypto {
    PrivateKey::PrivateKey(const Blob &blob) : Blob(blob.blob()) {}

    std::string PrivateKey::toString() const {
      return detail::PrettyStringBuilder()
          .init("PrivateKey")
          .append("<Data is hidden>")
          .finalize();
    }
  }  // namespace crypto
}  // namespace shared_model
