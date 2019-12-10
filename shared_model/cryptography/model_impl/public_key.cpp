/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/public_key.hpp"

#include "cryptography/bytes_view.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::crypto;

std::string PublicKey::toString() const {
  return detail::PrettyStringBuilder()
      .init("PublicKey")
      .append(blob().toString())
      .finalize();
}
