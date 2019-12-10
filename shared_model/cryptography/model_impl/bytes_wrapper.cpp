/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/bytes_wrapper.hpp"

#include <boost/functional/hash.hpp>
#include "cryptography/bytes_view.hpp"

using namespace shared_model::crypto;

BytesWrapper::BytesWrapper(std::shared_ptr<BytesView> blob)
    : blob_(std::move(blob)) {}

const BytesView &BytesWrapper::blob() const {
  return *blob_;
}

bool BytesWrapper::operator==(const BytesWrapper &rhs) const {
  return *blob_ == rhs.blob();
}

std::size_t BytesWrapper::Hasher::operator()(const BytesWrapper &o) const {
  auto range = o.blob().byteRange();
  return boost::hash_range(range.begin(), range.end());
}
