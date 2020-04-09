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
      inline ByteRange makeByteRange(const Source &str) {
        static_assert(
            sizeof(std::byte) == sizeof(std::decay_t<decltype(str.data()[0])>),
            "Type size mismatch!");
        return ByteRange{reinterpret_cast<const std::byte *>(str.data()),
                         str.size()};
      }
    }  // namespace types
  }    // namespace interface
}  // namespace shared_model

#endif
