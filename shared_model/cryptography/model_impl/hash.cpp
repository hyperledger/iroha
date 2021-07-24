/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/hash.hpp"

#include <functional>
#include <string>

namespace shared_model {
  namespace crypto {

    Hash::Hash() : Blob() {}

    Hash::Hash(const std::string &hash) : Blob(hash) {}
    Hash::Hash(std::string_view hash) : Blob(hash) {}
    Hash::Hash(const char *hash) : Blob(std::string(hash)) {}

    Hash::Hash(const Blob &blob) : Blob(blob) {}

    Hash Hash::fromHexString(const std::string &hex) {
      return Hash(Blob::fromHexString(hex));
    }

    std::string Hash::toString() const {
      return detail::PrettyStringBuilder()
          .init("Hash")
          .append(Blob::hex())
          .finalize();
    }

    std::size_t Hash::Hasher::operator()(Hash const &h) const {
      auto const &blob = h.blob();
      std::string_view sv;
      if (!blob.empty()) {
        sv = {reinterpret_cast<std::string_view::const_pointer>(blob.data()),
              blob.size()};
      }
      return std::hash<std::string_view>{}(sv);
    }
  }  // namespace crypto
}  // namespace shared_model
