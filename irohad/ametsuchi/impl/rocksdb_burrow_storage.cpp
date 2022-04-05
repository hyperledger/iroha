/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_burrow_storage.hpp"

#include <cassert>
#include <optional>

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/obj_utils.hpp"
#include "common/result.hpp"
#include "common/to_lower.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::expected;

#define MAKE_LOWER_ON_STACK(name, source, sz)       \
  static_assert(sz > 0ull, "Unexpected size " #sz); \
  assert(source.size() <= sz);                      \
  char name##_buffer[sz];                           \
  auto name = toLower(source, name##_buffer);

RocksdbBurrowStorage::RocksdbBurrowStorage(
    std::shared_ptr<RocksDBContext> db_context,
    std::string_view tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index)
    : db_context_(std::move(db_context)),
      tx_hash_(tx_hash),
      cmd_index_(cmd_index) {}

Result<std::optional<std::string>, std::string>
RocksdbBurrowStorage::getAccount(std::string_view address) {
  RocksDbCommon common(db_context_);

  MAKE_LOWER_ON_STACK(address_lc, address, 128);
  RDB_TRY_GET_VALUE_OR_STR_ERR(
      opt_data,
      forCallEngineAccount<kDbOperation::kGet, kDbEntry::kCanExist>(
          common, address_lc));
  if (opt_data)
    return expected::makeValue(std::string(opt_data->data(), opt_data->size()));

  return std::nullopt;
}

Result<void, std::string> RocksdbBurrowStorage::updateAccount(
    std::string_view address, std::string_view account) {
  RocksDbCommon common(db_context_);

  MAKE_LOWER_ON_STACK(address_lc, address, 128);
  common.valueBuffer().assign(account.data(), account.size());
  RDB_ERROR_CHECK_TO_STR(
      forCallEngineAccount<kDbOperation::kPut>(common, address_lc));
  return {};
}

Result<void, std::string> RocksdbBurrowStorage::removeAccount(
    std::string_view address) {
  RocksDbCommon common(db_context_);

  MAKE_LOWER_ON_STACK(address_lc, address, 128);
  RDB_ERROR_CHECK_TO_STR(
      forCallEngineAccount<kDbOperation::kDel, kDbEntry::kCanExist>(
          common, address_lc));

  auto const &[_, status] =
      common.filterDelete(std::numeric_limits<uint64_t>::max(),
                          RocksDBPort::ColumnFamilyType::kWsv,
                          fmtstrings::kPathEngineStorage,
                          address_lc);

  if (!status.ok() && !status.IsNotFound())
    return expected::makeError(fmt::format(
        "Delete CallEngine storage with address '{}' failed.", address_lc));

  return {};
}

Result<std::optional<std::string>, std::string>
RocksdbBurrowStorage::getStorage(std::string_view address,
                                 std::string_view key) {
  RocksDbCommon common(db_context_);
  MAKE_LOWER_ON_STACK(address_lc, address, 128);

  std::string key_lc;
  toLowerAppend(key, key_lc);

  RDB_TRY_GET_VALUE_OR_STR_ERR(
      opt_value,
      forCallEngineStorage<kDbOperation::kGet, kDbEntry::kCanExist>(
          common, address_lc, key_lc));
  if (opt_value)
    return expected::makeValue(
        std::string(opt_value->data(), opt_value->size()));

  return std::nullopt;
}

Result<void, std::string> RocksdbBurrowStorage::setStorage(
    std::string_view address, std::string_view key, std::string_view value) {
  RocksDbCommon common(db_context_);
  MAKE_LOWER_ON_STACK(address_lc, address, 128);

  std::string key_lc;
  toLowerAppend(key, key_lc);

  common.valueBuffer().assign(value.data(), value.size());
  RDB_ERROR_CHECK_TO_STR(
      forCallEngineStorage<kDbOperation::kPut>(common, address_lc, key_lc));
  return {};
}

Result<void, std::string> RocksdbBurrowStorage::storeLog(
    std::string_view address,
    std::string_view data,
    std::vector<std::string_view> topics) {
  RocksDbCommon common(db_context_);

  if (!call_id_cache_) {
    RDB_ERROR_CHECK_TO_STR(
        forCallEngineCallIds<kDbOperation::kCheck, kDbEntry::kMustNotExist>(
            common, tx_hash_, cmd_index_));
    RDB_TRY_GET_VALUE_OR_STR_ERR(
        opt_call_id,
        forCallEngineNextCallIds<kDbOperation::kGet, kDbEntry::kCanExist>(
            common));
    if (opt_call_id)
      call_id_cache_ = std::make_pair(*opt_call_id, 0ull);
    else
      call_id_cache_ = std::make_pair(0ull, 0ull);

    common.encode(call_id_cache_->first);
    RDB_ERROR_CHECK_TO_STR(
        forCallEngineCallIds<kDbOperation::kPut>(common, tx_hash_, cmd_index_));

    common.encode(call_id_cache_->first + 1ull);
    RDB_ERROR_CHECK_TO_STR(
        forCallEngineNextCallIds<kDbOperation::kPut>(common));
  }

  uint64_t log_idx = 0ull;
  RDB_TRY_GET_VALUE_OR_STR_ERR(
      opt_log_idx,
      forCallEngineNextLogIx<kDbOperation::kGet, kDbEntry::kCanExist>(common));
  if (opt_log_idx)
    log_idx = *opt_log_idx;

  common.encode(log_idx + 1ull);
  RDB_ERROR_CHECK_TO_STR(forCallEngineNextLogIx<kDbOperation::kPut>(common));

  MAKE_LOWER_ON_STACK(address_lc, address, 128);
  common.valueBuffer() = std::to_string(log_idx);
  common.valueBuffer() += '#';
  common.valueBuffer() += address_lc;
  common.valueBuffer() += '#';
  common.valueBuffer() += data;
  RDB_ERROR_CHECK_TO_STR(forCallEngineLogs<kDbOperation::kPut>(
      common, call_id_cache_->first, call_id_cache_->second++));

  for (uint64_t ix = 0; ix < topics.size(); ++ix) {
    auto const &topic = topics[ix];
    common.valueBuffer().assign(topic.data(), topic.size());
    RDB_ERROR_CHECK_TO_STR(
        forCallEngineTopics<kDbOperation::kPut>(common, log_idx, ix));
  }

  return {};
}
