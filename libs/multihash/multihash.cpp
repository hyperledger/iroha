/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multihash/multihash.hpp"

using shared_model::interface::types::ByteRange;

namespace iroha {
  namespace multihash {

    iroha::expected::Result<Multihash, const char *> createFromBuffer(
        ByteRange buffer) {
      Multihash result;

      if (not readVarInt(
              buffer,
              reinterpret_cast<std::underlying_type_t<Type> &>(result.type))) {
        return "Could not parse the Multihash data type.";
      }

      size_t length = 0;
      if (not readVarInt(buffer, length)) {
        return "Could not parse the Multihash data length.";
      }

      if (length != buffer.size()) {
        return "The length encoded in the input data header doesn't match the "
               "actual length of the input data";
      }

      result.data = buffer;
      return result;
    }

  }  // namespace multihash
}  // namespace iroha
