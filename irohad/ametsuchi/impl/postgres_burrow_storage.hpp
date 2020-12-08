/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BURROW_STORAGE_HPP
#define IROHA_POSTGRES_BURROW_STORAGE_HPP

#include "ametsuchi/burrow_storage.hpp"

#include "interfaces/common_objects/types.hpp"

namespace soci {
  class session;
}

namespace iroha::ametsuchi {
  class PostgresBurrowStorage : public BurrowStorage {
   public:
    PostgresBurrowStorage(
        soci::session &sql,
        std::string const &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index);

    expected::Result<std::optional<std::string>, std::string> getAccount(
        std::string_view address) override;

    expected::Result<void, std::string> updateAccount(
        std::string_view address, std::string_view account) override;

    expected::Result<void, std::string> removeAccount(
        std::string_view address) override;

    expected::Result<std::optional<std::string>, std::string> getStorage(
        std::string_view address, std::string_view key) override;

    expected::Result<void, std::string> setStorage(
        std::string_view address,
        std::string_view key,
        std::string_view value) override;

    expected::Result<void, std::string> storeLog(
        std::string_view address,
        std::string_view data,
        std::vector<std::string_view> topics) override;

   private:
    soci::session &sql_;
    std::string const &tx_hash_;
    shared_model::interface::types::CommandIndexType cmd_index_;
    std::optional<size_t> call_id_cache_;
  };

}  // namespace iroha::ametsuchi

#endif
