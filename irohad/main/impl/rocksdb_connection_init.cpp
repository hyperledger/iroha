/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/rocksdb_connection_init.hpp"

#include <boost/functional/hash.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "common/irohad_version.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

using namespace iroha::ametsuchi;

namespace {

  /// WSV schema version is identified by compatibile irohad version.
  using SchemaVersion = iroha::IrohadVersion;

  /**
   * Checks schema compatibility.
   * @return value of true if the schema in the provided database is
   * compatibile with this code, false if not and an error message if the
   * check could not be performed.
   */
  iroha::expected::Result<bool, std::string> isSchemaCompatible(
      RocksDbCommon &common, const RocksDbOptions &options) {
    RDB_TRY_GET_VALUE_OR_STR_ERR(
        version,
        forWSVVersion<kDbOperation::kGet, kDbEntry::kMustExist>(common));
    return *version == iroha::getIrohadVersion();
  }

  iroha::expected::Result<void, std::string> createSchema(
      RocksDbCommon &common, const RocksDbOptions &options) {
    auto const version = iroha::getIrohadVersion();
    common.valueBuffer() = std::to_string(version.major);
    common.valueBuffer() += '#';
    common.valueBuffer() += std::to_string(version.minor);
    common.valueBuffer() += '#';
    common.valueBuffer() += std::to_string(version.patch);

    RDB_ERROR_CHECK_TO_STR(forStoreVersion<kDbOperation::kPut>(common));
    RDB_ERROR_CHECK_TO_STR(forWSVVersion<kDbOperation::kPut>(common));

    return {};
  }

}  // namespace

iroha::expected::Result<std::shared_ptr<RocksDBPort>, std::string>
RdbConnectionInit::init(StartupWsvDataPolicy startup_wsv_data_policy,
                        iroha::ametsuchi::RocksDbOptions const &opt,
                        logger::LoggerManagerTreePtr log_manager) {
  log_manager->getLogger()->info(
      "Working database prepare started(with 'drop_state' flag it can take a "
      "long time)...");
  return prepareWorkingDatabase(startup_wsv_data_policy, opt);
}

iroha::expected::Result<std::shared_ptr<RocksDBPort>, std::string>
RdbConnectionInit::prepareWorkingDatabase(
    StartupWsvDataPolicy startup_wsv_data_policy,
    const iroha::ametsuchi::RocksDbOptions &options) {
  auto port = std::make_shared<RocksDBPort>();
  if (auto result = port->initialize(options.dbPath());
      expected::hasError(result))
    return expected::makeError(
        fmt::format("Initialize db failed. Error code: {}, description: {}",
                    result.assumeError().code,
                    result.assumeError().description));

  auto db_context = std::make_shared<RocksDBContext>(port);
  RocksDbCommon common(db_context);

  std::optional<IrohadVersion> wsv_version;
  if (auto result =
          forWSVVersion<kDbOperation::kGet, kDbEntry::kCanExist>(common);
      expected::hasError(result))
    return expected::makeError(
        fmt::format("Request schema failed. Error code: {}, description: {}",
                    result.assumeError().code,
                    result.assumeError().description));
  else
    wsv_version = std::move(result.assumeValue());

  std::optional<IrohadVersion> store_version;
  if (auto result =
          forStoreVersion<kDbOperation::kGet, kDbEntry::kCanExist>(common);
      expected::hasError(result))
    return expected::makeError(
        fmt::format("Request schema failed. Error code: {}, description: {}",
                    result.assumeError().code,
                    result.assumeError().description));
  else
    store_version = std::move(result.assumeValue());

  if (!wsv_version || !store_version
      || startup_wsv_data_policy == StartupWsvDataPolicy::kDrop) {
    RDB_ERROR_CHECK(dropWorkingDatabase(common, options));
    RDB_ERROR_CHECK(createSchema(common, options));
    common.commit();
    return port;
  }

  return isSchemaCompatible(common, options) | [port](bool is_compatible)
             -> iroha::expected::Result<std::shared_ptr<RocksDBPort>,
                                        std::string> {
    if (not is_compatible) {
      return "The schema is not compatible. "
             "Either overwrite the ledger or use a compatible binary "
             "version.";
    }
    return port;
  };
}

iroha::expected::Result<void, std::string>
RdbConnectionInit::dropWorkingDatabase(
    RocksDbCommon &common, const iroha::ametsuchi::RocksDbOptions &options) {
  RDB_ERROR_CHECK_TO_STR(dropWSV(common));
  return {};
}
