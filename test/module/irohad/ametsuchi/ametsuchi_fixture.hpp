/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_FIXTURE_HPP
#define IROHA_AMETSUCHI_FIXTURE_HPP

#include <gtest/gtest.h>
#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "ametsuchi/impl/in_memory_block_storage_factory.hpp"
#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "ametsuchi/impl/storage_impl.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "common/files.hpp"
#include "framework/config_helper.hpp"
#include "framework/sql_query.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/field_validator.hpp"

namespace iroha {
  namespace ametsuchi {
    /**
     * Class with ametsuchi initialization
     */
    class AmetsuchiTest : public ::testing::Test {
     public:
      static void SetUpTestCase() {
        ASSERT_FALSE(boost::filesystem::exists(block_store_path))
            << "Temporary block store " << block_store_path
            << " directory already exists";
        factory =
            std::make_shared<shared_model::proto::ProtoCommonObjectsFactory<
                shared_model::validation::FieldValidator>>(
                iroha::test::kTestsValidatorsConfig);
        perm_converter_ =
            std::make_shared<shared_model::proto::ProtoPermissionToString>();
        converter_ =
            std::make_shared<shared_model::proto::ProtoBlockJsonConverter>();

        reconnection_strategy_factory_ = std::make_unique<
            iroha::ametsuchi::KTimesReconnectionStrategyFactory>(0);

        options_ = std::make_unique<PostgresOptions>(
            pgopt_,
            integration_framework::kDefaultWorkingDatabaseName,
            storage_logger_);

        initializeStorage();
      }

      static void initializeStorage() {
        bool wsv_is_dirty = false;
        auto db_result =
            PgConnectionInit::prepareWorkingDatabase(true, *options_);
        if (iroha::expected::hasError(db_result)) {
          db_result = db_result.or_res(
              PgConnectionInit::prepareWorkingDatabase(false, *options_));
          wsv_is_dirty = true;
        }

        (std::move(db_result) |
         [&] {
           return PgConnectionInit::prepareConnectionPool(
               *reconnection_strategy_factory_,
               *options_,
               pool_size_,
               getTestLoggerManager()->getChild("Storage"));
         }
         |
         [&](auto &&pool_wrapper) {
           sql = std::make_shared<soci::session>(*soci::factory_postgresql(),
                                                 pgopt_);
           sql_query =
               std::make_unique<framework::ametsuchi::SqlQuery>(*sql, factory);

           if (wsv_is_dirty) {
             truncateWsv();
           }

           return StorageImpl::create(
               block_store_path,
               *options_,
               std::move(pool_wrapper),
               converter_,
               perm_converter_,
               std::make_unique<InMemoryBlockStorageFactory>(),
               getTestLoggerManager()->getChild("Storage"));
         })
            .match([&](const auto &_storage) { storage = _storage.value; },
                   [](const auto &error) {
                     storage_logger_->error(
                         "Storage initialization has failed: {}", error.error);
                     // TODO: 2019-05-29 @muratovv find assert workaround IR-522
                     std::terminate();
                   });
      }

      static void TearDownTestCase() {
        storage_logger_->info("TearDownTestCase()");
        sql->close();
        sql.reset();
        storage->dropBlockStorage();
        storage.reset();
        PgConnectionInit::dropSchema(*options_);
        boost::filesystem::remove_all(block_store_path);
      }

      static void truncateWsv() {
        storage_logger_->info("truncateWsv()");
        assert(sql);
        *sql <<
            R"(
              TRUNCATE TABLE top_block_info RESTART IDENTITY CASCADE;
              TRUNCATE TABLE account_has_signatory RESTART IDENTITY CASCADE;
              TRUNCATE TABLE account_has_asset RESTART IDENTITY CASCADE;
              TRUNCATE TABLE role_has_permissions RESTART IDENTITY CASCADE;
              TRUNCATE TABLE account_has_roles RESTART IDENTITY CASCADE;
              TRUNCATE TABLE account_has_grantable_permissions RESTART IDENTITY CASCADE;
              TRUNCATE TABLE account RESTART IDENTITY CASCADE;
              TRUNCATE TABLE asset RESTART IDENTITY CASCADE;
              TRUNCATE TABLE domain RESTART IDENTITY CASCADE;
              TRUNCATE TABLE signatory RESTART IDENTITY CASCADE;
              TRUNCATE TABLE peer RESTART IDENTITY CASCADE;
              TRUNCATE TABLE role RESTART IDENTITY CASCADE;
              TRUNCATE TABLE position_by_hash RESTART IDENTITY CASCADE;
              TRUNCATE TABLE tx_status_by_hash RESTART IDENTITY CASCADE;
              TRUNCATE TABLE height_by_account_set RESTART IDENTITY CASCADE;
              TRUNCATE TABLE index_by_creator_height RESTART IDENTITY CASCADE;
              TRUNCATE TABLE position_by_account_asset RESTART IDENTITY CASCADE;
            )";
      }

      void TearDown() override {
        storage_logger_->info("TearDown()");
        storage->dropBlockStorage();
        assert(sql);
        storage->tryRollback(*sql);
        truncateWsv();
      }

#define PROXY_STORAGE_IMPL_FUNCTION(function)                               \
  template <typename... T>                                                  \
  auto function(T &&... args)                                               \
      ->decltype(                                                           \
          std::declval<StorageImpl>().function(std::forward<T>(args)...)) { \
    return storage->function(std::forward<T>(args)...);                     \
  }

      PROXY_STORAGE_IMPL_FUNCTION(storeBlock)
      PROXY_STORAGE_IMPL_FUNCTION(tryRollback)

#undef PROXY_STORAGE_IMPL_FUNCTION

     protected:
      static std::shared_ptr<soci::session> sql;

      static std::shared_ptr<shared_model::proto::ProtoCommonObjectsFactory<
          shared_model::validation::FieldValidator>>
          factory;

      /*  Since
       *  - both the storage and the logger config it uses are static
       *  - storage uses the logger at destruction
       *  we need to ensure the static logger config is destroyed after the
       *  static storage
       */
      static logger::LoggerPtr storage_logger_;
      static std::shared_ptr<shared_model::interface::BlockJsonConverter>
          converter_;
      static std::shared_ptr<StorageImpl> storage;
      static std::unique_ptr<framework::ametsuchi::SqlQuery> sql_query;

      static std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      static std::unique_ptr<iroha::ametsuchi::ReconnectionStrategyFactory>
          reconnection_strategy_factory_;

      static const int pool_size_ = 10;

      // generate random valid dbname
      static std::string dbname_;

      static std::string pgopt_;
      static std::unique_ptr<PostgresOptions> options_;

      static std::string block_store_path;
    };

    std::shared_ptr<shared_model::proto::ProtoCommonObjectsFactory<
        shared_model::validation::FieldValidator>>
        AmetsuchiTest::factory = nullptr;
    std::string AmetsuchiTest::block_store_path =
        (boost::filesystem::temp_directory_path()
         / boost::filesystem::unique_path())
            .string();
    std::string AmetsuchiTest::dbname_ = "d"
        + boost::uuids::to_string(boost::uuids::random_generator()())
              .substr(0, 8);
    std::string AmetsuchiTest::pgopt_ = "dbname=" + AmetsuchiTest::dbname_ + " "
        + integration_framework::getPostgresCredsOrDefault();
    std::unique_ptr<PostgresOptions> AmetsuchiTest::options_ = nullptr;

    std::shared_ptr<shared_model::interface::BlockJsonConverter>
        AmetsuchiTest::converter_ = nullptr;

    std::shared_ptr<shared_model::interface::PermissionToString>
        AmetsuchiTest::perm_converter_ = nullptr;

    std::unique_ptr<iroha::ametsuchi::ReconnectionStrategyFactory>
        AmetsuchiTest::reconnection_strategy_factory_ = nullptr;

    std::shared_ptr<soci::session> AmetsuchiTest::sql = nullptr;
    // hold the storage static logger while the static storage is alive
    logger::LoggerPtr AmetsuchiTest::storage_logger_ =
        getTestLoggerManager()->getChild("Storage")->getLogger();
    std::shared_ptr<StorageImpl> AmetsuchiTest::storage = nullptr;
    std::unique_ptr<framework::ametsuchi::SqlQuery> AmetsuchiTest::sql_query =
        nullptr;
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_FIXTURE_HPP
