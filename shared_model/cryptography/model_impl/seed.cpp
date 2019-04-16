/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/seed.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace crypto {

    Seed::Seed(const std::string &seed) : Blob(seed) {}

    std::string Seed::toString() const {
      return detail::PrettyStringBuilder()
          .init("Seed")
          .append(Blob::hex())
          .finalize();
    }
  }  // namespace crypto
}  // namespace shared_model
