/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_storage.h"

#include <cstring>
#include "ametsuchi/burrow_storage.hpp"
#include "common/result.hpp"

namespace {
  char *clone(const std::string &string) {
    char *cstr = new char[string.length() + 1];
    strncpy(cstr, string.c_str(), string.length());
    cstr[string.length()] = 0;
    return cstr;
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

Iroha_Result Iroha_GetAccount(void *storage, char *address) {
  return performQuery(storage, &BurrowStorage::getAccount, address);
}

Iroha_Result Iroha_UpdateAccount(void *storage, char *address, char *account) {
  return performQuery(storage, &BurrowStorage::updateAccount, address, account);
}

Iroha_Result Iroha_RemoveAccount(void *storage, char *address) {
  return performQuery(storage, &BurrowStorage::removeAccount, address);
}

Iroha_Result Iroha_GetStorage(void *storage, char *address, char *key) {
  return performQuery(storage, &BurrowStorage::getStorage, address, key);
}

Iroha_Result Iroha_SetStorage(void *storage,
                              char *address,
                              char *key,
                              char *value) {
  return performQuery(storage, &BurrowStorage::setStorage, address, key, value);
}
