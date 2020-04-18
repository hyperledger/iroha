/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_STRONG_TYPE_LITERALS_HPP
#define IROHA_TEST_STRONG_TYPE_LITERALS_HPP

#include "interfaces/common_objects/string_view_types.hpp"

inline shared_model::interface::types::PublicKeyHexStringView operator""_pubkey(
    const char *c, size_t s) {
  return shared_model::interface::types::PublicKeyHexStringView{
      std::string_view{c, s}};
}

#endif  // IROHA_BATCH_HELPER_HPP
