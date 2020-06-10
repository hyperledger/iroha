/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_BURROW_STORAGE_HPP
#define IROHA_AMETSUCHI_BURROW_STORAGE_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/result_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    class BurrowStorage {
     public:
      virtual ~BurrowStorage() = default;

      virtual expected::Result<std::optional<std::string>, std::string>
      getAccount(std::string_view address) = 0;

      virtual expected::Result<void, std::string> updateAccount(
          std::string_view address, std::string_view account) = 0;

      virtual expected::Result<void, std::string> removeAccount(
          std::string_view address) = 0;

      virtual expected::Result<std::optional<std::string>, std::string>
      getStorage(std::string_view address, std::string_view key) = 0;

      virtual expected::Result<void, std::string> setStorage(
          std::string_view address,
          std::string_view key,
          std::string_view value) = 0;

      virtual expected::Result<void, std::string> storeLog(
          std::string_view address,
          std::string_view data,
          std::vector<std::string_view> topics) = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif
