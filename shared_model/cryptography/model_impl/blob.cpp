/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/blob.hpp"

#include <boost/optional/optional.hpp>
#include "common/bind.hpp"
#include "common/byteutils.hpp"

using shared_model::interface::types::ByteType;
using shared_model::interface::types::ConstByteRange;
using iroha::operator|;

namespace shared_model {
  namespace crypto {

    Blob::Blob() noexcept : Blob(Bytes{}) {}

    Blob *Blob::clone() const {
      return new Blob(blob_);
    }

    Blob::Blob(Bytes blob) noexcept : blob_(std::move(blob)) {
      updateRange();
    }

    Blob::Blob(ConstByteRange blob) noexcept : blob_(blob.begin(), blob.end()) {
      updateRange();
    }

    Blob::Blob(const Blob &other) noexcept : Blob(other.blob_) {}

    Blob::Blob(Blob &&other) noexcept : Blob(std::move(other.blob_)) {}

    Blob &Blob::operator=(Blob &&other) {
      blob_ = std::move(other.blob_);
      updateRange();
      return *this;
    }

    void Blob::updateRange() {
      const ByteType *begin = blob_.data();
      const ByteType *end = begin + blob_.size();
      BytesView::range_ = ConstByteRange(begin, end);
    }

    std::unique_ptr<Blob> Blob::fromBinaryString(const std::string &binary) {
      auto begin = reinterpret_cast<const ByteType *>(binary.data());
      return std::make_unique<Blob>(
          ConstByteRange(begin, begin + binary.size()));
    }

    boost::optional<Blob> Blob::fromHexString(const std::string &hex) {
      return iroha::hexstringToBytestring(hex) |
          [&](auto &&s) { return boost::make_optional(fromBinaryString(s)); };
    }

  }  // namespace crypto
}  // namespace shared_model
