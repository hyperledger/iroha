/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/signed.hpp"

#include "cryptography/bytes_view.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::crypto;

std::string Signed::toString() const {
  return detail::PrettyStringBuilder()
      .init("Signed")
      .append(blob().toString())
      .finalize();
}
