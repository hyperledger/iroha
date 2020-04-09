/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_BYTE_RANGE_HPP
#define IROHA_MULTIHASH_BYTE_RANGE_HPP

#include <cstddef>
#include <string_view>

namespace shared_model {
  namespace interface {
    namespace types {

      using ByteRange = std::basic_string_view<std::byte>;
    }
  }  // namespace interface
}  // namespace shared_model

#endif
