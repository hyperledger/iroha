/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BYTEUTILS_H
#define IROHA_BYTEUTILS_H

#include <algorithm>
#include <string>
#include <vector>

#include <boost/optional.hpp>

#include "common/bind.hpp"
#include "common/blob.hpp"
#include "common/hexutils.hpp"

namespace iroha {
  /**
   * Convert string to blob vector
   * @param source - string for conversion
   * @return vector<blob>
   */
  inline std::vector<uint8_t> stringToBytes(const std::string &source) {
    return std::vector<uint8_t>(source.begin(), source.end());
  }

  /**
   * blob vector to string
   * @param source - vector for conversion
   * @return result string
   */
  inline std::string bytesToString(const std::vector<uint8_t> &source) {
    return std::string(source.begin(), source.end());
  }

  /**
   * Create blob_t from string of specified size
   * @tparam size - size of blob_t, expected size of string
   * @param s - string to convert
   * @return blob, if conversion was successful, otherwise nullopt
   */
  template <size_t size>
  boost::optional<blob_t<size>> stringToBlob(const std::string &string) {
    if (size != string.size()) {
      return boost::none;
    }
    blob_t<size> array;
    std::copy(string.begin(), string.end(), array.begin());
    return array;
  }

  /**
   * Convert hexstring to array of given size
   * @tparam size - output array size
   * @param string - input string for transform
   * @return array of given size if size matches, nullopt otherwise
   */
  template <size_t size>
  boost::optional<blob_t<size>> hexstringToArray(const std::string &string) {
    return hexstringToBytestring(string) | stringToBlob<size>;
  }

}  // namespace iroha

#endif  // IROHA_BYTEUTILS_H
