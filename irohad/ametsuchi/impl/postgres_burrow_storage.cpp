/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_burrow_storage.hpp"

#include <optional>

#include <soci/soci.h>
#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_string_view.hpp"
#include "common/obj_utils.hpp"
#include "common/result.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::expected;

PostgresBurrowStorage::PostgresBurrowStorage(
    soci::session &sql,
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index)
    : sql_(sql), tx_hash_(tx_hash), cmd_index_(cmd_index) {}

Result<std::optional<std::string>, std::string>
PostgresBurrowStorage::getAccount(std::string_view address) {
  try {
    std::optional<std::string> data;
    sql_ << "select data from burrow_account_data "
            "where address = lower(:address)",
        soci::use(address, "address"), soci::into(data);
    return data;
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::updateAccount(
    std::string_view address, std::string_view account) {
  try {
    int check = 0;
    sql_ << "insert into burrow_account_data (address, data) "
            "values (lower(:address), :data) "
            "on conflict (address) do update set data = excluded.data "
            "returning 1",
        soci::use(address, "address"), soci::use(account, "data"),
        soci::into(check);
    if (check == 0) {
      return makeError("account data update failed");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::removeAccount(
    std::string_view address) {
  try {
    int check = 0;
    sql_ << "delete from burrow_account_key_value "
            "where address = lower(:address); "
            "delete from burrow_account_data "
            "where address = lower(:address) "
            "returning 1",
        soci::use(address, "address"), soci::into(check);
    if (check == 0) {
      return makeError("account deletion failed");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<std::optional<std::string>, std::string>
PostgresBurrowStorage::getStorage(std::string_view address,
                                  std::string_view key) {
  try {
    std::optional<std::string> value;
    sql_ << "select value from burrow_account_key_value "
            "where address = lower(:address) and key = lower(:key) ",
        soci::use(address, "address"), soci::use(key, "key"), soci::into(value);
    return value;
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::setStorage(
    std::string_view address, std::string_view key, std::string_view value) {
  try {
    int check = 0;
    sql_ << "insert into burrow_account_key_value (address, key, value) "
            "values (lower(:address), lower(:key), :value) "
            "on conflict (address, key) do update set value = excluded.value "
            "returning 1",
        soci::use(address, "address"), soci::use(key, "key"),
        soci::use(value, "value"), soci::into(check);
    if (check == 0) {
      return makeError("account key-value storage update failed");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::storeLog(
    std::string_view address,
    std::string_view data,
    std::vector<std::string_view> topics) {
  try {
    std::optional<size_t> log_idx;

    if (call_id_cache_) {
      sql_ << "insert into burrow_tx_logs (call_id, address, data) "
              "values (:call_id, lower(:address), :data) "
              "returning log_idx",
          soci::use(call_id_cache_.value(), "call_id"),
          soci::use(address, "address"), soci::use(data, "data"),
          soci::into(log_idx);
    } else {
      sql_ << "with inserted_call_id as "
              "("
              "  insert into engine_calls (tx_hash, cmd_index)"
              "  values (:tx_hash, :cmd_index)"
              "  on conflict (tx_hash, cmd_index) do nothing"
              "  returning call_id"
              ")"
              "insert into burrow_tx_logs (call_id, address, data) "
              "select call_id, :address, :data from "
              "("
              "  ("
              "    select * from inserted_call_id"
              "  ) union ("
              "    select call_id from engine_calls"
              "    where tx_hash = :tx_hash and cmd_index = :cmd_index"
              "  )"
              ") t0 "
              "returning call_id, log_idx",
          soci::use(tx_hash_, "tx_hash"), soci::use(cmd_index_, "cmd_index"),
          soci::use(address, "address"), soci::use(data, "data"),
          soci::into(call_id_cache_), soci::into(log_idx);
    }

    assert(call_id_cache_);
    assert(log_idx);
    if (not call_id_cache_ or not log_idx) {
      return makeError("could not insert log data");
    }
    if (not topics.empty()) {
      std::vector<size_t> log_idxs(topics.size(), log_idx.value());
      sql_ << "insert into burrow_tx_logs_topics (topic, log_idx) "
              "values (lower(:topic), :log_idx)",
          soci::use(topics, "topic"), soci::use(log_idxs, "log_idx");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}
