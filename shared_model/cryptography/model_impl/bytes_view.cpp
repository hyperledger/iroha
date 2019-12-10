/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/bytes_view.hpp"

#include <boost/range/algorithm/equal.hpp>
#include "common/byteutils.hpp"
#include "common/hexutils.hpp"
#include "utils/string_builder.hpp"

using shared_model::interface::types::ByteRange;
using shared_model::interface::types::ByteType;
using shared_model::interface::types::ConstByteRange;

namespace shared_model {
  namespace crypto {

    BytesView::BytesView(ByteRange byte_range)
        : range_(std::move(byte_range)) {}

    BytesView::BytesView(ConstByteRange byte_range)
        : range_(std::move(byte_range)) {}

    BytesView::BytesView(const ByteType *begin, size_t length)
        : range_(ConstByteRange(begin, begin + length)) {}

    BytesView::~BytesView() = default;

    bool BytesView::operator==(const BytesView &rhs) const {
      return boost::equal(byteRange(), rhs.byteRange());
    }

    const ConstByteRange &BytesView::byteRange() const {
      return range_;
    }

    const std::string &BytesView::hex() const {
      if (not hex_repr_cache_) {
        hex_repr_cache_ = iroha::byteRangeToHexstring(byteRange());
      }
      return hex_repr_cache_.value();
    }

    const ByteType *BytesView::data() const {
      return range_.begin();
    }

    size_t BytesView::size() const {
      return boost::size(range_);
    }

    std::string BytesView::toString() const {
      return detail::PrettyStringBuilder()
          .init("bytes")
          .append(hex())
          .finalize();
    }

  }  // namespace crypto
}  // namespace shared_model
