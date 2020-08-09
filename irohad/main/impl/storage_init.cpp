/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/storage_init.hpp"

#include <stdexcept>

#include <fmt/core.h>
#include "ametsuchi/impl/flat_file_block_storage.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"
#include "ametsuchi/impl/storage_impl.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "common/result.hpp"
#include "generator/generator.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "validators/always_valid_validator.hpp"
#include "validators/protobuf/proto_block_validator.hpp"

using namespace iroha::ametsuchi;

using namespace std::chrono_literals;

using shared_model::interface::types::PublicKeyHexStringView;

class StorageInitException : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

namespace {
  std::unique_ptr<BlockStorage> makeFlatFileBlockStorage(
      std::string const &block_storage_dir,
      logger::LoggerManagerTreePtr log_manager) {
    auto flat_file = FlatFile::create(
        block_storage_dir, log_manager->getChild("FlatFile")->getLogger());
    if (not flat_file) {
      throw StorageInitException{
          "Unable to create FlatFile for persistent storage"};
    }
    std::shared_ptr<shared_model::interface::BlockJsonConverter>
        block_converter =
            std::make_shared<shared_model::proto::ProtoBlockJsonConverter>();
    return std::make_unique<FlatFileBlockStorage>(
        std::move(flat_file.get()),
        block_converter,
        log_manager->getChild("FlatFileBlockStorage")->getLogger());
  }

  std::unique_ptr<BlockStorage> makePostgresBlockStorage(
      std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper,
      std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory,
      logger::LoggerManagerTreePtr log_manager) {
    auto sql = std::make_unique<soci::session>(*pool_wrapper->connection_pool_);
    const std::string persistent_table("blocks");

    PostgresBlockStorageFactory::createTable(*sql, persistent_table);
    if (auto err = iroha::expected::resultToOptionalError(
            PostgresBlockStorageFactory::createTable(*sql, persistent_table))) {
      throw StorageInitException{err.value()};
    }
    return std::make_unique<PostgresBlockStorage>(std::move(pool_wrapper),
                                                  block_factory,
                                                  persistent_table,
                                                  log_manager->getLogger());
  }
}  // namespace

iroha::expected::Result<std::shared_ptr<iroha::ametsuchi::Storage>, std::string>
iroha::initStorage(
    iroha::ametsuchi::PostgresOptions const &pg_opt,
    std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper,
    std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage,
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        query_response_factory,
    boost::optional<std::string> block_storage_dir,
    std::optional<std::reference_wrapper<const iroha::ametsuchi::VmCaller>>
        vm_caller_ref,
    logger::LoggerManagerTreePtr log_manager) {
  try {
    auto perm_converter =
        std::make_shared<shared_model::proto::ProtoPermissionToString>();

    // TODO: luckychess IR-308 05.08.2019 stateless validation for genesis
    // block
    auto block_transport_factory =
        std::make_shared<shared_model::proto::ProtoBlockFactory>(
            std::make_unique<shared_model::validation::AlwaysValidValidator<
                shared_model::interface::Block>>(),
            std::make_unique<shared_model::validation::ProtoBlockValidator>());

    std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory =
        std::make_unique<PostgresBlockStorageFactory>(
            pool_wrapper,
            block_transport_factory,
            []() { return generator::randomString(20); },
            log_manager->getChild("TemporaryBlockStorage")->getLogger());

    auto persistent_block_storage = block_storage_dir
        ? makeFlatFileBlockStorage(block_storage_dir.value(), log_manager)
        : makePostgresBlockStorage(
              pool_wrapper, block_transport_factory, log_manager);
    return StorageImpl::create(pg_opt,
                               pool_wrapper,
                               perm_converter,
                               std::move(pending_txs_storage),
                               std::move(query_response_factory),
                               std::move(temporary_block_storage_factory),
                               std::move(persistent_block_storage),
                               vm_caller_ref,
                               log_manager->getChild("Storage"));
  } catch (StorageInitException const &e) {
    return iroha::expected::makeError(
        fmt::format("Storage initialization failed: ", e.what()));
  }
}
