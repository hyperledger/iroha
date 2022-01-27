/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_settings_query.hpp"

#include <boost/lexical_cast.hpp>
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;

namespace {

  expected::Result<bool, std::string> getValueFromDb(
      std::shared_ptr<RocksDBContext> db_context,
      const shared_model::interface::types::SettingKeyType &key,
      uint64_t &destination) {
    RocksDbCommon common(db_context);
    auto status = common.get(RocksDBPort::ColumnFamilyType::kWsv,
                             fmtstrings::kSetting,
                             kMaxDescriptionSizeKey);

    if (auto result = iroha::ametsuchi::canExist(
            status, [&] { return fmt::format("Max description size key"); });
        expected::hasError(result))
      return expected::makeError(result.assumeError().description);

    if (status.ok()) {
      common.decode(destination);
      return true;
    }

    return false;
  }

}  // namespace

namespace iroha::ametsuchi {

  RocksDbSettingQuery::RocksDbSettingQuery(
      std::shared_ptr<RocksDBContext> db_context, logger::LoggerPtr log)
      : db_context_(std::move(db_context)), log_(std::move(log)) {}

  iroha::expected::Result<
      std::unique_ptr<const shared_model::validation::Settings>,
      std::string>
  RocksDbSettingQuery::get() {
    return update(shared_model::validation::getDefaultSettings());
  }

  iroha::expected::Result<
      std::unique_ptr<const shared_model::validation::Settings>,
      std::string>
  RocksDbSettingQuery::update(
      std::unique_ptr<shared_model::validation::Settings> base) {
    uint64_t value;
    if (auto res = getValueFromDb(db_context_, kMaxDescriptionSizeKey, value);
        expected::hasError(res))
      return expected::makeError(res.assumeError());
    else if (res.assumeValue()) {
      base->max_description_size = static_cast<size_t>(value);
      log_->info("Updated value for " + kMaxDescriptionSizeKey + ": {}",
                 base->max_description_size);
    } else {
      log_->info("Kept value for " + kMaxDescriptionSizeKey + ": {}",
                 base->max_description_size);
    }

    return base;
  }

}  // namespace iroha::ametsuchi
