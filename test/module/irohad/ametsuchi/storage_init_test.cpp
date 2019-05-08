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
#include "ametsuchi/impl/in_memory_block_storage_factory.hpp"
#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "framework/config_helper.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/common/validators_config.hpp"
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
  std::string block_store_path = (boost::filesystem::temp_directory_path()
                                  / boost::filesystem::unique_path())
                                     .string();

  // generate random valid dbname
  std::string dbname_ = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);

  std::string pg_opt_without_dbname_;
  std::string pgopt_;

  std::shared_ptr<shared_model::proto::ProtoCommonObjectsFactory<
      shared_model::validation::FieldValidator>>
      factory = std::make_shared<shared_model::proto::ProtoCommonObjectsFactory<
          shared_model::validation::FieldValidator>>(
          iroha::test::kTestsValidatorsConfig);

  std::shared_ptr<shared_model::proto::ProtoBlockJsonConverter> converter =
      std::make_shared<shared_model::proto::ProtoBlockJsonConverter>();

  std::shared_ptr<shared_model::interface::PermissionToString> perm_converter_ =
      std::make_shared<shared_model::proto::ProtoPermissionToString>();

  std::unique_ptr<BlockStorageFactory> block_storage_factory_ =
      std::make_unique<InMemoryBlockStorageFactory>();

  std::unique_ptr<iroha::ametsuchi::ReconnectionStrategyFactory>
      reconnection_strategy_factory_;

  void SetUp() override {
    ASSERT_FALSE(boost::filesystem::exists(block_store_path))
        << "Temporary block store " << block_store_path
        << " directory already exists";

    reconnection_strategy_factory_ =
        std::make_unique<iroha::ametsuchi::KTimesReconnectionStrategyFactory>(
            0);
  }

  void TearDown() override {
    soci::session sql(*soci::factory_postgresql(), pg_opt_without_dbname_);
    std::string query = "DROP DATABASE IF EXISTS " + dbname_;
    sql << query;
    boost::filesystem::remove_all(block_store_path);
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
  std::shared_ptr<StorageImpl> storage;
  StorageImpl::create(block_store_path,
                      pgopt_,
                      factory,
                      converter,
                      perm_converter_,
                      std::move(block_storage_factory_),
                      std::move(reconnection_strategy_factory_),
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
  storage->dropStorage();
}

/**
 * @given Bad Postgres options string with nonexisting user in it
 * @when Create storage using that options string
 * @then Database is not created and error case is executed
 */
TEST_F(StorageInitTest, CreateStorageWithInvalidPgOpt) {
  std::string pg_opt =
      "host=localhost port=5432 users=nonexistinguser dbname=test";
  StorageImpl::create(block_store_path,
                      pg_opt,
                      factory,
                      converter,
                      perm_converter_,
                      std::move(block_storage_factory_),
                      std::move(reconnection_strategy_factory_),
                      storage_log_manager_)
      .match([](const auto &) { FAIL() << "storage created, but should not"; },
             [](const auto &) { SUCCEED(); });
}
