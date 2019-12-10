/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_BLOB_HPP
#define IROHA_COMMON_BLOB_HPP

#include "common/blob_view.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  using BadFormatException = std::invalid_argument;

  /// Holds a blob of fixed size.
  template <size_t size_>
  class blob_t
      : public std::array<shared_model::interface::types::ByteType, size_> {
   public:
    using ByteType = shared_model::interface::types::ByteType;

    /**
     * Initialize blob value
     */
    blob_t() {
      this->fill(0);
    }

    /**
     * In compile-time returns size of current blob.
     */
    constexpr static size_t size() {
      return size_;
    }

    template <
        typename ByteType = const shared_model::interface::types::ByteType>
    FixedBlobView<size_, ByteType> getView() const {
      return {
          std::array<shared_model::interface::types::ByteType, size_>::data()};
    }

    static blob_t<size_> from_raw(const ByteType data[size_]) {
      blob_t<size_> b;
      std::copy(data, data + size_, b.begin());
      return b;
    }

    static expected::Result<blob_t<size_>, std::string> from_string(
        const std::string &data) {
      if (data.size() != size_) {
        return expected::makeError(
            std::string{"blob_t: input string has incorrect length. Found: "}
            + std::to_string(data.size())
            + +", required: " + std::to_string(size_));
      }
      return from_raw(reinterpret_cast<const ByteType *>(data.data()));
    }

    static expected::Result<blob_t<size_>, std::string> from_hexstring(
        const std::string &hex) {
      return iroha::hexstringToBytestringResult(hex) |
          [](auto &&bytes) { return from_string(bytes); };
    }
  };
}  // namespace iroha

#endif  // IROHA_COMMON_BLOB_HPP
