/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_HSM_UTIMACO_FORMATTERS_HPP
#define IROHA_HSM_UTIMACO_FORMATTERS_HPP

#include <fmt/core.h>

#include <string>

#include "cryptography/hsm_utimaco/safe_cxi.hpp"

namespace fmt {
  template <>
  struct formatter<cxi::Exception, char> {
    // The following functions are not defined intentionally.
    template <typename ParseContext>
    auto parse(ParseContext &ctx) -> decltype(ctx.begin()) {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(cxi::Exception const &val, FormatContext &ctx)
        -> decltype(ctx.out()) {
      return format_to(ctx.out(),
                       "CXI Exception: code {} in {} at line {}: {}",
                       val.err,
                       val.where,
                       val.line,
                       val.err_str);
    }
  };
}  // namespace fmt

#endif
