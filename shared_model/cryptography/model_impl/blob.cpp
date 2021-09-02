/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/blob.hpp"

#include "common/byteutils.hpp"

namespace shared_model {
  namespace crypto {

    std::string toBinaryString(const Blob &b) {
      return std::string(b.blob().begin(), b.blob().end());
    }

    Blob::Blob(std::string_view blob)
        : Blob(shared_model::interface::types::makeByteRange(blob)) {}

    Blob::Blob(const Bytes &blob) : Blob(Bytes(blob)) {}

    Blob::Blob(Bytes &&blob) noexcept : blob_(std::move(blob)) {
      iroha::bytestringToHexstringAppend(range(), hex_);
    }

    Blob::Blob(shared_model::interface::types::ByteRange range)
        : blob_(reinterpret_cast<const Bytes::value_type *>(range.data()),
                reinterpret_cast<const Bytes::value_type *>(range.data())
                    + range.size()) {
      static_assert(sizeof(range.data()[0]) == sizeof(Bytes::value_type),
                    "type mismatch");
      iroha::bytestringToHexstringAppend(range, hex_);
    }

    Blob *Blob::clone() const {
      return new Blob(blob());
    }

    bool Blob::operator==(const Blob &rhs) const {
      return blob() == rhs.blob();
    }

    Blob Blob::fromHexString(std::string_view hex) {
      using iroha::operator|;
      Blob b("");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = Blob(s); };
      return b;
    }

    const Blob::Bytes &Blob::blob() const {
      return blob_;
    }

    shared_model::interface::types::ByteRange Blob::range() const {
      return shared_model::interface::types::makeByteRange(blob());
    }

    const std::string &Blob::hex() const {
      return hex_;
    }

    size_t Blob::size() const {
      return blob_.size();
    }

    std::string Blob::toString() const {
      return detail::PrettyStringBuilder()
          .init("Blob")
          .append(hex())
          .finalize();
    }

  }  // namespace crypto
}  // namespace shared_model
