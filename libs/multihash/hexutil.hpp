/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KAGOME_HEXUTIL_HPP
#define KAGOME_HEXUTIL_HPP

#include <vector>

#include "common/result.hpp"

namespace kagome {
  namespace common {

    /**
     * @brief Converts an integer to an uppercase hex representation
     */
    std::string int_to_hex(uint64_t n, size_t fixed_width = 2) noexcept;

    /**
     * @brief Converts bytes to uppercase hex representation
     * @param array bytes
     * @param len length of bytes
     * @return hexstring
     */
    std::string hex_upper(const std::vector<uint8_t> &bytes) noexcept;

    /**
     * @brief Converts hex representation to bytes
     * @param array individual chars
     * @param len length of chars
     * @return result containing array of bytes if input string is hex encoded
     * and has even length
     *
     * @note reads both uppercase and lowercase hexstrings
     *
     * @see
     * https://www.boost.org/doc/libs/1_51_0/libs/algorithm/doc/html/the_boost_algorithm_library/Misc/hex.html
     */
    iroha::expected::Result<std::vector<uint8_t>, std::string> unhex(
        const std::string &hex);

  }  // namespace common
}  // namespace kagome

#endif  // KAGOME_HEXUTIL_HPP
