/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/signed.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace crypto {

    std::string Signed::toString() const {
      return detail::PrettyStringBuilder()
          .init("Signed")
          .append(Blob::hex())
          .finalize();
    }

  }  // namespace crypto
}  // namespace shared_model
