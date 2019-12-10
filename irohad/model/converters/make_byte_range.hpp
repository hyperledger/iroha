/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MODEL_MAKE_BYTE_RANGE_HPP
#define IROHA_MODEL_MAKE_BYTE_RANGE_HPP

#include "interfaces/common_objects/range_types.hpp"

#include <string>

namespace iroha {
  namespace model {
    inline shared_model::interface::types::ConstByteRange makeByteRange(
        const std::string &str) {
      using namespace shared_model::interface::types;

      auto data = reinterpret_cast<const ByteType *>(str.data());
      return ConstByteRange{data, data + str.size()};
    }
  }  // namespace model
}  // namespace iroha

#endif
