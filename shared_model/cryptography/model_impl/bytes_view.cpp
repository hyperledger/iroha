/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/bytes_view.hpp"

#include <boost/functional/hash.hpp>
#include <boost/range/algorithm/equal.hpp>
#include "common/byteutils.hpp"
#include "common/hexutils.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::crypto;

using shared_model::interface::types::ByteRange;
using shared_model::interface::types::ByteType;
using shared_model::interface::types::ConstByteRange;

BytesView::BytesView(ByteRange byte_range) : range_(std::move(byte_range)) {}

BytesView::BytesView(ConstByteRange byte_range)
    : range_(std::move(byte_range)) {}

BytesView::BytesView(const ByteType *begin, size_t length)
    : range_(ConstByteRange(begin, begin + length)) {}

BytesView::BytesView(const char *begin, size_t length)
    : BytesView(reinterpret_cast<const ByteType *>(begin), length) {}

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

const char *BytesView::char_data() const {
  return reinterpret_cast<const char *>(range_.begin());
}

size_t BytesView::size() const {
  return boost::size(range_);
}

std::string BytesView::toString() const {
  return detail::PrettyStringBuilder().init("bytes").append(hex()).finalize();
}

std::size_t BytesView::getSizeTHash() const {
  if (not hash_cache_) {
    hash_cache_ = boost::hash_range(range_.begin(), range_.end());
  }
  return hash_cache_.value();
}

std::size_t BytesViewHasher::operator()(const BytesView &blob) const {
  return blob.getSizeTHash();
}
