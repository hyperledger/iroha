/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_HASH_TYPE_CONVERTERS_HPP
#define IROHA_MULTIHASH_HASH_TYPE_CONVERTERS_HPP

#include <cstdint>

#include <fmt/core.h>
#include <optional>
#include <string_view>
#include <vector>
#include "multihash/type.hpp"

namespace iroha {
  namespace multihash {

    char const *toString(Type type);

    std::optional<Type> fromString(std::string_view source);

    std::vector<Type> getAllSignatureTypes();
  }  // namespace multihash
}  // namespace iroha

namespace fmt {
  template <>
  struct formatter<iroha::multihash::Type> {
    // The following functions are not defined intentionally.
    template <typename ParseContext>
    auto parse(ParseContext &ctx) -> decltype(ctx.begin()) {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(iroha::multihash::Type const &val, FormatContext &ctx)
        -> decltype(ctx.out()) {
      return format_to(ctx.out(), "{}", iroha::multihash::toString(val));
    }
  };
}  // namespace fmt

#endif
