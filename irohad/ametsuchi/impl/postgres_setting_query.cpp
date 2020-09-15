/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_setting_query.hpp"

#include <boost/lexical_cast.hpp>
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

namespace {
  template <typename T>
  bool getValueFromDb(soci::session &sql,
                      const shared_model::interface::types::SettingKeyType &key,
                      T &destination) {
    boost::optional<shared_model::interface::types::SettingValueType> value;

    sql << "SELECT setting_value FROM setting WHERE setting_key = :key",
        soci::into(value), soci::use(key, "key");

    if (value) {
      destination = boost::lexical_cast<T>(value.get());
      return true;
    }
    return false;
  }
}  // namespace

PostgresSettingQuery::PostgresSettingQuery(std::unique_ptr<soci::session> sql,
                                           logger::LoggerPtr log)
    : psql_(std::move(sql)), sql_(*psql_), log_(std::move(log)) {}

iroha::expected::Result<
    std::unique_ptr<const shared_model::validation::Settings>,
    std::string>
PostgresSettingQuery::get() {
  return update(shared_model::validation::getDefaultSettings());
}

iroha::expected::Result<
    std::unique_ptr<const shared_model::validation::Settings>,
    std::string>
PostgresSettingQuery::update(
    std::unique_ptr<shared_model::validation::Settings> base) {
  auto get_and_log =
      [this](const shared_model::interface::types::SettingKeyType &key,
             auto &destination) {
        if (getValueFromDb(sql_, key, destination)) {
          log_->info("Updated value for " + key + ": {}", destination);
        } else {
          log_->info("Kept value for " + key + ": {}", destination);
        }
      };

  try {
    get_and_log(kMaxDescriptionSizeKey, base->max_description_size);
  } catch (std::exception &e) {
    return expected::makeError(e.what());
  }

  return base;
}
