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
        auto converter =
            std::make_shared<shared_model::proto::ProtoBlockJsonConverter>();
        auto block_storage_factory =
            std::make_unique<InMemoryBlockStorageFactory>();
        StorageImpl::create(block_store_path,
                            pgopt_,
                            factory,
                            converter,
                            perm_converter_,
                            std::move(block_storage_factory),
                            getTestLoggerManager()->getChild("Storage"))
            .match([&](const auto &_storage) { storage = _storage.value; },
                   [](const auto &error) {
                     FAIL() << "StorageImpl: " << error.error;
                   });
        sql = std::make_shared<soci::session>(*soci::factory_postgresql(),
                                              pgopt_);
        sql_query =
            std::make_unique<framework::ametsuchi::SqlQuery>(*sql, factory);
      }

      static void TearDownTestCase() {
        sql->close();
        storage->dropStorage();
        boost::filesystem::remove_all(block_store_path);
      }

      void TearDown() override {
        storage->reset();
      }

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
      static std::shared_ptr<StorageImpl> storage;
      static std::unique_ptr<framework::ametsuchi::SqlQuery> sql_query;

      static std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      // generate random valid dbname
      static std::string dbname_;

      static std::string pgopt_;

      static std::string block_store_path;

      // TODO(warchant): IR-1019 hide SQLs under some interface

      const std::string init_ = R"(
CREATE TABLE IF NOT EXISTS role (
    role_id character varying(32),
    PRIMARY KEY (role_id)
);
CREATE TABLE IF NOT EXISTS domain (
    domain_id character varying(255),
    default_role character varying(32) NOT NULL REFERENCES role(role_id),
    PRIMARY KEY (domain_id)
);
CREATE TABLE IF NOT EXISTS signatory (
    public_key varchar NOT NULL,
    PRIMARY KEY (public_key)
);
CREATE TABLE IF NOT EXISTS account (
    account_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    quorum int NOT NULL,
    data JSONB,
    PRIMARY KEY (account_id)
);
CREATE TABLE IF NOT EXISTS account_has_signatory (
    account_id character varying(288) NOT NULL REFERENCES account,
    public_key varchar NOT NULL REFERENCES signatory,
    PRIMARY KEY (account_id, public_key)
);
CREATE TABLE IF NOT EXISTS peer (
    public_key varchar NOT NULL,
    address character varying(261) NOT NULL UNIQUE,
    PRIMARY KEY (public_key)
);
CREATE TABLE IF NOT EXISTS asset (
    asset_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    precision int NOT NULL,
    data json,
    PRIMARY KEY (asset_id)
);
CREATE TABLE IF NOT EXISTS account_has_asset (
    account_id character varying(288) NOT NULL REFERENCES account,
    asset_id character varying(288) NOT NULL REFERENCES asset,
    amount decimal NOT NULL,
    PRIMARY KEY (account_id, asset_id)
);
CREATE TABLE IF NOT EXISTS role_has_permissions (
    role_id character varying(32) NOT NULL REFERENCES role,
    permission_id character varying(45),
    PRIMARY KEY (role_id, permission_id)
);
CREATE TABLE IF NOT EXISTS account_has_roles (
    account_id character varying(288) NOT NULL REFERENCES account,
    role_id character varying(32) NOT NULL REFERENCES role,
    PRIMARY KEY (account_id, role_id)
);
CREATE TABLE IF NOT EXISTS account_has_grantable_permissions (
    permittee_account_id character varying(288) NOT NULL REFERENCES account,
    account_id character varying(288) NOT NULL REFERENCES account,
    permission_id character varying(45),
    PRIMARY KEY (permittee_account_id, account_id, permission_id)
);
CREATE TABLE IF NOT EXISTS position_by_hash (
    hash varchar,
    height text,
    index text
);

CREATE TABLE IF NOT EXISTS tx_status_by_hash (
    hash varchar,
    status boolean
);
CREATE INDEX IF NOT EXISTS tx_status_by_hash_hash_index ON tx_status_by_hash USING hash (hash);

CREATE TABLE IF NOT EXISTS height_by_account_set (
    account_id text,
    height text
);
CREATE TABLE IF NOT EXISTS index_by_creator_height (
    id serial,
    creator_id text,
    height text,
    index text
);
CREATE TABLE IF NOT EXISTS index_by_id_height_asset (
    id text,
    height text,
    asset_id text,
    index text
);
)";
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

    std::shared_ptr<shared_model::interface::PermissionToString>
        AmetsuchiTest::perm_converter_ = nullptr;

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
