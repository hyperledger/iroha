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
#include "ametsuchi/mutable_storage.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "common/files.hpp"
#include "common/result.hpp"
#include "framework/config_helper.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/sql_query.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "module/irohad/ametsuchi/truncate_postgres_wsv.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
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
        pending_txs_storage_ =
            std::make_shared<MockPendingTransactionStorage>();
        query_response_factory_ =
            std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();

        reconnection_strategy_factory_ = std::make_unique<
            iroha::ametsuchi::KTimesReconnectionStrategyFactory>(0);

        options_ = std::make_unique<PostgresOptions>(
            pgopt_,
            integration_framework::kDefaultWorkingDatabaseName,
            storage_logger_);

        block_storage_ = InMemoryBlockStorageFactory{}.create().assumeValue();

        initializeStorage();
      }

      static void initializeStorage(bool keep_wsv_data = false) {
        bool wsv_is_dirty = true;
        auto db_result = PgConnectionInit::prepareWorkingDatabase(
            iroha::StartupWsvDataPolicy::kReuse, *options_);
        if (iroha::expected::hasError(db_result)) {
          db_result = db_result.or_res(PgConnectionInit::prepareWorkingDatabase(
              iroha::StartupWsvDataPolicy::kDrop, *options_));
          wsv_is_dirty = false;
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

           if (wsv_is_dirty and not keep_wsv_data) {
             truncateWsv();
           }

           prepared_blocks_enabled =
               pool_wrapper->enable_prepared_transactions_;

           return StorageImpl::create(
               *options_,
               std::move(pool_wrapper),
               perm_converter_,
               pending_txs_storage_,
               query_response_factory_,
               std::make_unique<InMemoryBlockStorageFactory>(),
               block_storage_,
               std::nullopt,
               [](auto block) { committed_blocks_.push_back(block); },
               getTestLoggerManager()->getChild("Storage"));
         }
         |
         [&](auto &&_storage) {
           storage = std::move(_storage);
           return storage->createCommandExecutor();
         }
         |
         [&](auto &&_command_executor) {
           command_executor = std::move(_command_executor);
           return iroha::expected::Value<void>{};
         })
            .match([&](const auto &) {},
                   [](const auto &error) {
                     storage_logger_->error(
                         "Storage initialization has failed: {}", error.error);
                     // TODO: 2019-05-29 @muratovv find assert workaround IR-522
                     std::terminate();
                   });
        assert(sql);
        assert(sql_query);
        assert(storage);
        assert(command_executor);
      }

      static void destroyWsvStorage() {
        command_executor.reset();
        sql_query.reset();
        sql->close();
        sql.reset();
        storage.reset();
      }

      static void TearDownTestCase() {
        storage_logger_->info("TearDownTestCase()");
        storage->dropBlockStorage();
        destroyWsvStorage();
        PgConnectionInit::dropWorkingDatabase(*options_);
        boost::filesystem::remove_all(block_store_path);
      }

      static void truncateWsv() {
        storage_logger_->info("truncateWsv()");
        assert(sql);
        ::iroha::ametsuchi::truncateWsv(*sql);
      }

      void TearDown() override {
        storage_logger_->info("TearDown()");
        block_storage_->clear();
        assert(sql);
        storage->tryRollback(*sql);
        destroyWsvStorage();
        committed_blocks_.clear();
        initializeStorage();
      }

      /**
       * Apply block to given storage
       * @param storage storage object
       * @param block to apply
       */
      void apply(const std::shared_ptr<StorageImpl> &storage,
                 std::shared_ptr<const shared_model::interface::Block> block) {
        auto ms = createMutableStorage();
        ASSERT_TRUE(ms->apply(block));
        IROHA_ASSERT_RESULT_VALUE(storage->commit(std::move(ms)));
      }

      /// Create mutable storage from initialized storage
      std::unique_ptr<ametsuchi::MutableStorage> createMutableStorage() {
        return storage->createMutableStorage(command_executor).assumeValue();
      }

      // this is for resolving private visibility issues
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
      static std::shared_ptr<BlockStorage> block_storage_;
      static std::shared_ptr<StorageImpl> storage;
      static std::shared_ptr<CommandExecutor> command_executor;
      static std::unique_ptr<framework::ametsuchi::SqlQuery> sql_query;

      static std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      static std::shared_ptr<MockPendingTransactionStorage>
          pending_txs_storage_;

      static std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory_;

      static std::unique_ptr<iroha::ametsuchi::ReconnectionStrategyFactory>
          reconnection_strategy_factory_;

      static const int pool_size_ = 10;

      // generate random valid dbname
      static std::string dbname_;

      static std::string pgopt_;
      static std::unique_ptr<PostgresOptions> options_;

      static std::string block_store_path;

      static bool prepared_blocks_enabled;

      static std::vector<std::shared_ptr<shared_model::interface::Block const>>
          committed_blocks_;
    };

    std::shared_ptr<shared_model::proto::ProtoCommonObjectsFactory<
        shared_model::validation::FieldValidator>>
        AmetsuchiTest::factory = nullptr;
    std::string AmetsuchiTest::block_store_path =
        (boost::filesystem::temp_directory_path()
         / boost::filesystem::unique_path())
            .string();
    bool AmetsuchiTest::prepared_blocks_enabled = false;
    std::vector<std::shared_ptr<shared_model::interface::Block const>>
        AmetsuchiTest::committed_blocks_;
    std::string AmetsuchiTest::dbname_ = "d"
        + boost::uuids::to_string(boost::uuids::random_generator()())
              .substr(0, 8);
    std::string AmetsuchiTest::pgopt_ = "dbname=" + AmetsuchiTest::dbname_ + " "
        + integration_framework::getPostgresCredsOrDefault();
    std::unique_ptr<PostgresOptions> AmetsuchiTest::options_ = nullptr;

    std::shared_ptr<shared_model::interface::PermissionToString>
        AmetsuchiTest::perm_converter_ = nullptr;

    std::shared_ptr<MockPendingTransactionStorage>
        AmetsuchiTest::pending_txs_storage_ = nullptr;

    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        AmetsuchiTest::query_response_factory_ = nullptr;

    std::unique_ptr<iroha::ametsuchi::ReconnectionStrategyFactory>
        AmetsuchiTest::reconnection_strategy_factory_ = nullptr;

    std::shared_ptr<soci::session> AmetsuchiTest::sql = nullptr;
    // hold the storage static logger while the static storage is alive
    logger::LoggerPtr AmetsuchiTest::storage_logger_ =
        getTestLoggerManager()->getChild("Storage")->getLogger();
    std::shared_ptr<StorageImpl> AmetsuchiTest::storage = nullptr;
    std::shared_ptr<BlockStorage> AmetsuchiTest::block_storage_ = nullptr;
    std::shared_ptr<CommandExecutor> AmetsuchiTest::command_executor = nullptr;
    std::unique_ptr<framework::ametsuchi::SqlQuery> AmetsuchiTest::sql_query =
        nullptr;
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_FIXTURE_HPP
