/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_BLOB_VIEW_HPP
#define IROHA_COMMON_BLOB_VIEW_HPP

#include "common/hexutils.hpp"
#include "interfaces/common_objects/range_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {

  /// Base type which represents a view on a blob of fixed size.
  template <size_t size_,
            typename ByteType = const shared_model::interface::types::ByteType>
  class FixedBlobView {
   public:
    FixedBlobView(ByteType buffer[size_]) : buffer_(buffer) {}

    FixedBlobView(shared_model::interface::types::ConstByteRange range) {
      assert(boost::size(range) == size_);
      buffer_ = range.begin();
    }

    /**
     * In compile-time returns size of current blob.
     */
    constexpr static size_t size() {
      return size_;
    }

    ByteType *data() const {
      return buffer_;
    }

    FixedBlobView<size_, const ByteType> toConst() const {
      return {buffer_};
    }

    /**
     * Converts current blob to std::string
     */
    std::string to_string() const noexcept {
      return std::string{buffer_, buffer_ + size_};
    }

    using RangeType =
        std::conditional_t<std::is_const<ByteType>::value,
                           shared_model::interface::types::ConstByteRange,
                           shared_model::interface::types::ByteRange>;
    RangeType byteRange() const {
      return RangeType{buffer_, buffer_ + size_};
    }

    /**
     * Converts current blob to hex string. TODO REMOVE?
     */
    std::string to_hexstring() const noexcept {
      return byteRangeToHexstring(byteRange());
    }

   private:
    ByteType *buffer_;
  };
}  // namespace iroha

#endif
