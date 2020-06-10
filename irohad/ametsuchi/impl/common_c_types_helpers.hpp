/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_C_TYPES_HELPERS_HPP
#define IROHA_COMMON_C_TYPES_HELPERS_HPP

#include "ametsuchi/impl/common_c_types.h"

#include <cstddef>
#include <cstring>
#include <optional>
#include <string_view>
#include <type_traits>
#include <vector>

#include "common/result.hpp"

namespace iroha {

  inline void clearCharBuffer(Iroha_CharBuffer &buf) {
    buf.data = nullptr;
    buf.size = 0;
  }

  inline void toCharBuffer(Iroha_CharBuffer &buf, const std::string &string) {
    buf.data = new char[string.length() + 1];
    strncpy(buf.data, string.c_str(), string.length());
    buf.data[string.length()] = 0;
    buf.size = string.length();
  }

  inline void toCharBuffer(Iroha_CharBuffer &buf,
                           std::optional<std::string> const &opt_string) {
    if (opt_string) {
      toCharBuffer(buf, opt_string.value());
    } else {
      clearCharBuffer(buf);
    }
  }

  inline std::string_view charBufferToStringView(Iroha_CharBuffer const &buf) {
    return std::string_view{buf.data, buf.size};
  }

  inline std::vector<std::string_view> charBufferArrayToStringViewVector(
      Iroha_CharBufferArray const &arr) {
    std::vector<std::string_view> result;
    Iroha_CharBuffer const *const end = arr.data + arr.size;
    for (Iroha_CharBuffer *ptr = arr.data; ptr < end; ++ptr) {
      result.emplace_back(charBufferToStringView(*ptr));
    }
    return result;
  }

  using namespace iroha::expected;

  struct ResultVisitor {
    Iroha_Result operator()(Value<void>) const {
      Iroha_Result result;
      result.which = Iroha_Result_Type_Value;
      clearCharBuffer(result.data);
      return {};
    }

    template <typename T, typename = std::enable_if_t<not std::is_void_v<T>>>
    Iroha_Result operator()(Value<T> const &value) const {
      Iroha_Result result;
      result.which = Iroha_Result_Type_Value;
      toCharBuffer(result.data, value.value);
      return result;
    }

    template <typename T, typename = std::enable_if_t<not std::is_void_v<T>>>
    Iroha_Result operator()(Error<T> const &error) const {
      Iroha_Result result;
      result.which = Iroha_Result_Type_Error;
      toCharBuffer(result.data, error.error);
      return result;
    }
  };

}  // namespace iroha

#endif
