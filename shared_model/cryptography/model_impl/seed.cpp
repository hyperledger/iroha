/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/seed.hpp"

#include "cryptography/bytes_view.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::crypto;

std::string Seed::toString() const {
  return detail::PrettyStringBuilder()
      .init("Seed")
      .append(blob().toString())
      .finalize();
}
