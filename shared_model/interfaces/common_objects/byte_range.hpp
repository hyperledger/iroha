/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BYTE_RANGE_HPP
#define IROHA_SHARED_MODEL_BYTE_RANGE_HPP

#include <cstddef>
#include <string_view>

namespace shared_model {
  namespace interface {
    namespace types {

      using ByteRange = std::basic_string_view<std::byte>;

      template <typename Source>
      inline ByteRange makeByteRange(Source const *data, size_t length) {
        static_assert(sizeof(Source) == sizeof(std::byte), "type mismatch");
        return ByteRange{reinterpret_cast<std::byte const *>(data), length};
      }

      template <typename Source>
      inline ByteRange makeByteRange(const Source &str) {
        return makeByteRange(str.data(), str.size());
      }

    }  // namespace types
  }    // namespace interface
}  // namespace shared_model

#endif
