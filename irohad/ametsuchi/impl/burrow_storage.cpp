/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_storage.h"

#include "ametsuchi/burrow_storage.hpp"
#include "ametsuchi/impl/common_c_types_helpers.hpp"
#include "common/result.hpp"

namespace {
  template <typename Func, typename... Args>
  Iroha_Result performQuery(void *storage, Func function, Args... args) {
    return iroha::visit_in_place(
        (reinterpret_cast<iroha::ametsuchi::BurrowStorage *>(storage)
             ->*function)(args...),
        iroha::ResultVisitor{});
  }
}  // namespace

using namespace iroha::ametsuchi;

Iroha_Result Iroha_GetAccount(void *storage, Iroha_CharBuffer address) {
  return performQuery(storage,
                      &BurrowStorage::getAccount,
                      iroha::charBufferToStringView(address));
}

Iroha_Result Iroha_UpdateAccount(void *storage,
                                 Iroha_CharBuffer address,
                                 Iroha_CharBuffer account) {
  return performQuery(storage,
                      &BurrowStorage::updateAccount,
                      iroha::charBufferToStringView(address),
                      iroha::charBufferToStringView(account));
}

Iroha_Result Iroha_RemoveAccount(void *storage, Iroha_CharBuffer address) {
  return performQuery(storage,
                      &BurrowStorage::removeAccount,
                      iroha::charBufferToStringView(address));
}

Iroha_Result Iroha_GetStorage(void *storage,
                              Iroha_CharBuffer address,
                              Iroha_CharBuffer key) {
  return performQuery(storage,
                      &BurrowStorage::getStorage,
                      iroha::charBufferToStringView(address),
                      iroha::charBufferToStringView(key));
}

Iroha_Result Iroha_SetStorage(void *storage,
                              Iroha_CharBuffer address,
                              Iroha_CharBuffer key,
                              Iroha_CharBuffer value) {
  return performQuery(storage,
                      &BurrowStorage::setStorage,
                      iroha::charBufferToStringView(address),
                      iroha::charBufferToStringView(key),
                      iroha::charBufferToStringView(value));
}

Iroha_Result Iroha_StoreLog(void *storage,
                            Iroha_CharBuffer address,
                            Iroha_CharBuffer data,
                            Iroha_CharBufferArray topics) {
  return performQuery(storage,
                      &BurrowStorage::storeLog,
                      iroha::charBufferToStringView(address),
                      iroha::charBufferToStringView(data),
                      iroha::charBufferArrayToStringViewVector(topics));
}
