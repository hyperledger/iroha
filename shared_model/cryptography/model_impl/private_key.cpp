/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/private_key.hpp"

#include "cryptography/bytes_view.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::crypto;

std::string PrivateKey::toString() const {
  return detail::PrettyStringBuilder()
      .init("PrivateKey")
      .append("<Data is hidden>")
      .finalize();
}
