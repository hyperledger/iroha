/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_storage.h"

#include <cstddef>
#include <cstring>
#include <optional>
#include <string_view>
#include <type_traits>
#include <vector>

#include "ametsuchi/burrow_storage.hpp"
#include "common/result.hpp"

namespace {
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

  template <typename Func, typename... Args>
  Iroha_Result performQuery(void *storage, Func function, Args... args) {
    return iroha::visit_in_place(
        (reinterpret_cast<iroha::ametsuchi::BurrowStorage *>(storage)
             ->*function)(args...),
        ResultVisitor{});
  }
}  // namespace

using namespace iroha::ametsuchi;

Iroha_Result Iroha_GetAccount(void *storage, Iroha_CharBuffer address) {
  return performQuery(
      storage, &BurrowStorage::getAccount, charBufferToStringView(address));
}

Iroha_Result Iroha_UpdateAccount(void *storage,
                                 Iroha_CharBuffer address,
                                 Iroha_CharBuffer account) {
  return performQuery(storage,
                      &BurrowStorage::updateAccount,
                      charBufferToStringView(address),
                      charBufferToStringView(account));
}

Iroha_Result Iroha_RemoveAccount(void *storage, Iroha_CharBuffer address) {
  return performQuery(
      storage, &BurrowStorage::removeAccount, charBufferToStringView(address));
}

Iroha_Result Iroha_GetStorage(void *storage,
                              Iroha_CharBuffer address,
                              Iroha_CharBuffer key) {
  return performQuery(storage,
                      &BurrowStorage::getStorage,
                      charBufferToStringView(address),
                      charBufferToStringView(key));
}

Iroha_Result Iroha_SetStorage(void *storage,
                              Iroha_CharBuffer address,
                              Iroha_CharBuffer key,
                              Iroha_CharBuffer value) {
  return performQuery(storage,
                      &BurrowStorage::setStorage,
                      charBufferToStringView(address),
                      charBufferToStringView(key),
                      charBufferToStringView(value));
}

Iroha_Result Iroha_StoreLog(void *storage,
                            Iroha_CharBuffer address,
                            Iroha_CharBuffer data,
                            Iroha_CharBufferArray topics) {
  return performQuery(storage,
                      &BurrowStorage::storeLog,
                      charBufferToStringView(address),
                      charBufferToStringView(data),
                      charBufferArrayToStringViewVector(topics));
}
