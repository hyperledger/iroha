/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_HPP
#define IROHA_MULTIHASH_HPP

#include <cstdint>
#include <vector>

#include "common/result.hpp"

#include "interfaces/common_objects/byte_range.hpp"
#include "type.hpp"

namespace iroha {
  namespace multihash {

    /**
     * Special format of hash used in Libp2p. Allows to differentiate between
     * outputs of different hash functions. More
     * https://github.com/multiformats/multihash
     */
    struct Multihash {
      shared_model::interface::types::ByteRange data;
      Type type;
    };

    /**
     * @brief Creates a multihash from a binary
     * buffer. The first bytes denote the data type, then goes
     * the length, and the following are the data
     * @param buffer - the buffer with the multihash
     * @return result with the multihash in case of success
     */
    iroha::expected::Result<Multihash, const char *> createFromBuffer(
        shared_model::interface::types::ByteRange buffer);

  }  // namespace multihash
}  // namespace iroha

#endif  // IROHA_MULTIHASH_HPP
