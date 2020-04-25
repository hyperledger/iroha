/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_storage.h"

#include <cstddef>
#include <cstring>
#include <string_view>
#include <vector>

#include "ametsuchi/burrow_storage.hpp"
#include "common/result.hpp"

namespace {
  char *clone(const std::string &string) {
    char *cstr = new char[string.length() + 1];
    strncpy(cstr, string.c_str(), string.length());
    cstr[string.length()] = 0;
    return cstr;
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
      return {};
    }

    Iroha_Result operator()(
        const Value<std::optional<std::string>> &value) const {
      return {value.value ? clone(*value.value) : nullptr, nullptr};
    }

    Iroha_Result operator()(const Error<std::string> &error) const {
      return {nullptr, clone(error.error)};
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

Iroha_Result Iroha_StoreTxReceipt(void *storage,
                                  Iroha_CharBuffer address,
                                  Iroha_CharBuffer data,
                                  Iroha_CharBufferArray topics) {
  std::vector<std::string_view> topics_vector;
  return performQuery(storage,
                      &BurrowStorage::storeTxReceipt,
                      charBufferToStringView(address),
                      charBufferToStringView(data),
                      charBufferArrayToStringViewVector(topics));
}
