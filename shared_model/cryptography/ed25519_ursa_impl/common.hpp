/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_URSA_COMMON_HPP
#define IROHA_CRYPTO_URSA_COMMON_HPP

#include "interfaces/common_objects/string_view_types.hpp"
#include "ursa_crypto.h"

namespace shared_model::crypto::ursa {

  inline ByteBuffer irohaToUrsaBuffer(
      const interface::types::ByteRange buffer) {
    return ByteBuffer{
        static_cast<int64_t>(buffer.size()),
        reinterpret_cast<uint8_t *>(const_cast<std::byte *>(buffer.data()))};
  }

  inline interface::types::ByteRange ursaToIrohaBuffer(
      const ByteBuffer buffer) {
    assert(buffer.len > 0);
    return interface::types::ByteRange{
        reinterpret_cast<std::byte *>(buffer.data),
        static_cast<size_t>(buffer.len)};
  }
}  // namespace shared_model::crypto::ursa

#endif
