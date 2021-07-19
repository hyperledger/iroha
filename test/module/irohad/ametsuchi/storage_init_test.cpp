/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_impl.hpp"

#include <gtest/gtest.h>
#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "ametsuchi/impl/in_memory_block_storage.hpp"
#include "ametsuchi/impl/in_memory_block_storage_factory.hpp"
#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "common/result.hpp"
#include "framework/config_helper.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "module/irohad/ametsuchi/truncate_postgres_wsv.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "validators/field_validator.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::expected;

class StorageInitTest : public ::testing::Test {
 public:
  StorageInitTest() {
    pg_opt_without_dbname_ = integration_framework::getPostgresCredsOrDefault();
    pgopt_ = pg_opt_without_dbname_ + " dbname=" + dbname_;
  }

 protected:
  // generate random valid dbname
  std::string dbname_ = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);

  std::string pg_opt_without_dbname_;
  std::string pgopt_;

  std::shared_ptr<shared_model::interface::PermissionToString> perm_converter_ =
      std::make_shared<shared_model::proto::ProtoPermissionToString>();

  std::shared_ptr<iroha::MockPendingTransactionStorage> pending_txs_storage_ =
      std::make_shared<iroha::MockPendingTransactionStorage>();

  std::shared_ptr<shared_model::interface::QueryResponseFactory>
      query_response_factory_ =
          std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();

  std::unique_ptr<BlockStorageFactory> block_storage_factory_ =
      std::make_unique<InMemoryBlockStorageFactory>();
  std::unique_ptr<BlockStorage> block_storage_ =
      std::make_unique<InMemoryBlockStorage>();

  std::unique_ptr<iroha::ametsuchi::ReconnectionStrategyFactory>
      reconnection_strategy_factory_;

  const int pool_size_ = 10;

  void SetUp() override {
    reconnection_strategy_factory_ =
        std::make_unique<iroha::ametsuchi::KTimesReconnectionStrategyFactory>(
            0);
  }

  void TearDown() override {
    soci::session sql(*soci::factory_postgresql(), pg_opt_without_dbname_);
    std::string query = "DROP DATABASE IF EXISTS " + dbname_;
    sql << query;
  }

  logger::LoggerManagerTreePtr storage_log_manager_{
      getTestLoggerManager()->getChild("Storage")};
};

/**
 * @given Postgres options string with dbname param
 * @when Create storage using that options string
 * @then Database is created
 */
TEST_F(StorageInitTest, CreateStorageWithDatabase) {
  auto options = std::make_unique<PostgresOptions>(
      pgopt_,
      integration_framework::kDefaultWorkingDatabaseName,
      storage_log_manager_->getLogger());

  PgConnectionInit::prepareWorkingDatabase(iroha::StartupWsvDataPolicy::kDrop,
                                           *options)
      .match([](auto &&val) {}, [&](auto &&error) { FAIL() << error.error; });
  auto pool = PgConnectionInit::prepareConnectionPool(
      *reconnection_strategy_factory_,
      *options,
      pool_size_,
      getTestLoggerManager()->getChild("Storage"));

  if (auto e = boost::get<iroha::expected::Error<std::string>>(&pool)) {
    FAIL() << e->error;
  }

  auto pool_wrapper = std::move(
      boost::get<iroha::expected::Value<std::shared_ptr<PoolWrapper>>>(pool)
          .value);

  std::shared_ptr<StorageImpl> storage;
  StorageImpl::create(*options,
                      std::move(pool_wrapper),
                      perm_converter_,
                      pending_txs_storage_,
                      query_response_factory_,
                      std::move(block_storage_factory_),
                      std::move(block_storage_),
                      std::nullopt,
                      [](auto) {},
                      storage_log_manager_)
      .match(
          [&storage](const auto &value) {
            storage = value.value;
            SUCCEED();
          },
          [](const auto &error) { FAIL() << error.error; });

  soci::session sql(*soci::factory_postgresql(), pg_opt_without_dbname_);
  int size;
  sql << "SELECT COUNT(datname) FROM pg_catalog.pg_database WHERE datname = "
         ":dbname",
      soci::into(size), soci::use(dbname_);
  ASSERT_EQ(size, 1);
  storage->dropBlockStorage();
  PgConnectionInit::dropWorkingDatabase(*options);
}

/**
 * @given Bad Postgres options string with nonexisting user in it
 * @when Create storage using that options string
 * @then Database is not created and error case is executed
 */
TEST_F(StorageInitTest, CreateStorageWithInvalidPgOpt) {
  std::string pg_opt =
      "host=localhost port=5432 user=nonexistinguser password=wrong "
      "dbname=test";

  PostgresOptions options(pg_opt,
                          integration_framework::kDefaultWorkingDatabaseName,
                          storage_log_manager_->getLogger());

  auto pool = PgConnectionInit::prepareConnectionPool(
      *reconnection_strategy_factory_,
      options,
      pool_size_,
      getTestLoggerManager()->getChild("Storage"));

  pool.match([](const auto &) { FAIL() << "storage created, but should not"; },
             [](const auto &) { SUCCEED(); });
}
