/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PKCS11_FORMATTERS_HPP
#define IROHA_PKCS11_FORMATTERS_HPP

#include <fmt/core.h>

#include <string>

#include <botan/exceptn.h>

namespace fmt {
  template <>
  struct formatter<Botan::Exception, char> {
    template <typename ParseContext>
    auto parse(ParseContext &ctx) -> decltype(ctx.begin()) {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(Botan::Exception const &val, FormatContext &ctx)
        -> decltype(ctx.out()) {
      return format_to(ctx.out(), "Exception in Botan library: {}", val.what());
    }
  };
}  // namespace fmt

#endif
