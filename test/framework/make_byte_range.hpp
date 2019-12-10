/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_MAKE_BYTE_RANGE_HPP
#define IROHA_TEST_MAKE_BYTE_RANGE_HPP

#include "interfaces/common_objects/range_types.hpp"

#include <cstring>
#include <string>

namespace iroha {
  template <typename T>
  shared_model::interface::types::ConstByteRange makeByteRange(const T *data,
                                                               size_t length) {
    auto begin = reinterpret_cast<const unsigned char *>(data);
    return shared_model::interface::types::ConstByteRange{begin,
                                                          begin + length};
  }

  shared_model::interface::types::ConstByteRange makeByteRange(
      const char *str) {
    return makeByteRange(str, std::strlen(str));
  }

  shared_model::interface::types::ConstByteRange makeByteRange(
      const std::string &str) {
    return makeByteRange(str.data(), str.size());
  }
}  // namespace iroha

#endif
