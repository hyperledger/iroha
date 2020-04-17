/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/reader_writer.h"

#include "ametsuchi/reader_writer.hpp"

namespace {
  char *clone(const std::string &string) {
    char *cstr = new char[string.length() + 1];
    strcpy(cstr, string.c_str());
    return cstr;
  }

  using namespace iroha::expected;

  struct ResultVisitor {
    Iroha_Result operator()(Value<void>) const {
      return {};
    }

    Iroha_Result operator()(Value<std::optional<std::string>> &&value) const {
      return {value.value ? clone(*value.value) : nullptr, nullptr};
    }

    Iroha_Result operator()(Error<std::string> &&error) const {
      return {nullptr, clone(error.error)};
    }
  };

  template <typename Func, typename... Args>
  Iroha_Result performQuery(void *storage, Func function, Args... args) {
    return iroha::visit_in_place(
        (reinterpret_cast<iroha::ametsuchi::ReaderWriter *>(storage)
             ->*function)(args...),
        ResultVisitor{});
  }
}  // namespace

using namespace iroha::ametsuchi;

Iroha_Result Iroha_GetAccount(void *storage, char *address) {
  return performQuery(storage, &ReaderWriter::getAccount, address);
}

Iroha_Result Iroha_UpdateAccount(void *storage, char *address, char *account) {
  return performQuery(storage, &ReaderWriter::updateAccount, address, account);
}

Iroha_Result Iroha_RemoveAccount(void *storage, char *address) {
  return performQuery(storage, &ReaderWriter::removeAccount, address);
}

Iroha_Result Iroha_GetStorage(void *storage, char *address, char *key) {
  return performQuery(storage, &ReaderWriter::getStorage, address, key);
}

Iroha_Result Iroha_SetStorage(void *storage,
                              char *address,
                              char *key,
                              char *value) {
  return performQuery(storage, &ReaderWriter::setStorage, address, key, value);
}
