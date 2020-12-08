/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_CRYPTO_LITERALS_HPP
#define IROHA_TEST_CRYPTO_LITERALS_HPP

#include "interfaces/common_objects/string_view_types.hpp"

inline shared_model::interface::types::PublicKeyHexStringView
operator""_hex_pubkey(const char *c, size_t s) {
  return shared_model::interface::types::PublicKeyHexStringView{
      std::string_view{c, s}};
}

inline shared_model::interface::types::SignedHexStringView operator""_hex_sig(
    const char *c, size_t s) {
  return shared_model::interface::types::SignedHexStringView{
      std::string_view{c, s}};
}

inline shared_model::interface::types::ByteRange operator""_byterange(
    const char *c, size_t s) {
  return shared_model::interface::types::ByteRange{
      reinterpret_cast<const std::byte *>(c), s};
}

inline std::basic_string<std::byte> operator""_bytestring(const char *c,
                                                          size_t s) {
  return std::basic_string<std::byte>{reinterpret_cast<const std::byte *>(c),
                                      s};
}

#endif
