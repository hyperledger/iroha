/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/public_key.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace crypto {

    PublicKey::PublicKey(const std::string &public_key) : Blob(public_key) {}

    PublicKey::PublicKey(const Bytes &blob) : Blob(blob) {}

    PublicKey::PublicKey(const Blob &blob) : Blob(blob.blob()) {}

    std::string PublicKey::toString() const {
      return detail::PrettyStringBuilder()
          .init("PublicKey")
          .append(Blob::hex())
          .finalize();
    }

  }  // namespace crypto
}  // namespace shared_model
