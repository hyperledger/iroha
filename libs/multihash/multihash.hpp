/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_HPP
#define IROHA_MULTIHASH_HPP

#include <cstdint>
#include <vector>

#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"
#include "multihash/varint.hpp"

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

    /**
     * Encode and append a multihash type to a buffer.
     * https://github.com/multiformats/multihash
     * @tparam Container destination byte string container type
     * @param[in] type to encode
     * @param[out] buffer to write to
     */
    template <typename Container>
    inline void encodeVarIntType(Type multihash_type, Container &buffer) {
      using NumberType = std::underlying_type_t<Type>;
      encodeVarInt(static_cast<NumberType>(multihash_type), buffer);
    }

    /**
     * Encode data with its type in multihash format and write hex string of
     * result to a buffer.
     * https://github.com/multiformats/multihash
     * @tparam OutputContainer destination byte string container type
     * @param[in] type of data to encode
     * @param[in] input binary data to encode
     * @param[out] output container to write to
     */
    template <typename OutputContainer>
    inline void encodeHexAppend(Type multihash_type,
                                shared_model::interface::types::ByteRange input,
                                OutputContainer &output) {
      std::basic_string<std::byte> prefix_bin;
      encodeVarIntType(multihash_type, prefix_bin);
      encodeVarInt(input.size(), prefix_bin);

      iroha::bytestringToHexstringAppend(
          shared_model::interface::types::ByteRange{prefix_bin.data(),
                                                    prefix_bin.size()},
          output);
      iroha::bytestringToHexstringAppend(input, output);
    }

  }  // namespace multihash
}  // namespace iroha

#endif  // IROHA_MULTIHASH_HPP
