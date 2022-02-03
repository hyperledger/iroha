/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/storage_init.hpp"

#include <stdexcept>

#include <fmt/core.h>
#include "ametsuchi/impl/flat_file_block_storage.hpp"
#include "ametsuchi/impl/in_memory_block_storage_factory.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"
#include "ametsuchi/impl/rocksdb_block_storage.hpp"
#include "ametsuchi/impl/rocksdb_block_storage_factory.hpp"
#include "ametsuchi/impl/rocksdb_storage_impl.hpp"
#include "ametsuchi/impl/storage_base.hpp"
#include "ametsuchi/impl/storage_impl.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "common/result.hpp"
#include "generator/generator.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/subscription.hpp"
#include "validators/always_valid_validator.hpp"
#include "validators/protobuf/proto_block_validator.hpp"

namespace ametsuchi = iroha::ametsuchi;

using shared_model::interface::types::PublicKeyHexStringView;

class StorageInitException : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

namespace {
  std::unique_ptr<ametsuchi::BlockStorage> makeFlatFileBlockStorage(
      std::string const &block_storage_dir,
      logger::LoggerManagerTreePtr log_manager) {
    auto flat_file = ametsuchi::FlatFile::create(
        block_storage_dir, log_manager->getChild("FlatFile")->getLogger());
    if (auto err = iroha::expected::resultToOptionalError(flat_file)) {
      throw StorageInitException{err.value()};
    }
    return std::make_unique<ametsuchi::FlatFileBlockStorage>(
        std::move(flat_file.assumeValue()),
        std::make_shared<shared_model::proto::ProtoBlockJsonConverter>(),
        log_manager->getChild("FlatFileBlockStorage")->getLogger());
  }

  std::unique_ptr<ametsuchi::BlockStorage> makeRocksDbBlockStorage(
      std::shared_ptr<ametsuchi::RocksDBContext> db_context,
      logger::LoggerManagerTreePtr log_manager) {
    return std::make_unique<ametsuchi::RocksDbBlockStorage>(
        std::move(db_context),
        std::make_shared<shared_model::proto::ProtoBlockJsonConverter>(),
        log_manager->getChild("RocksDbBlockStorage")->getLogger());
  }

  std::unique_ptr<ametsuchi::BlockStorage> makePostgresBlockStorage(
      std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper,
      std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory,
      logger::LoggerManagerTreePtr log_manager) {
    auto sql = std::make_unique<soci::session>(*pool_wrapper->connection_pool_);
    const std::string persistent_table("blocks");

    if (auto err = iroha::expected::resultToOptionalError(
            ametsuchi::PostgresBlockStorageFactory::createTable(
                *sql, persistent_table))) {
      throw StorageInitException{err.value()};
    }

    auto block_storage =
        ametsuchi::PostgresBlockStorage::create(std::move(pool_wrapper),
                                                block_factory,
                                                persistent_table,
                                                false,
                                                log_manager->getLogger());
    if (auto err = iroha::expected::resultToOptionalError(block_storage)) {
      throw StorageInitException{err.value()};
    }

    return std::move(block_storage).assumeValue();
  }
}  // namespace

iroha::expected::Result<std::shared_ptr<iroha::ametsuchi::Storage>, std::string>
iroha::initStorage(
    std::shared_ptr<ametsuchi::RocksDBContext> db_context,
    std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage,
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        query_response_factory,
    boost::optional<std::string> block_storage_dir,
    std::optional<std::reference_wrapper<const iroha::ametsuchi::VmCaller>>
        vm_caller_ref,
    std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
        callback,
    logger::LoggerManagerTreePtr log_manager) {
  auto perm_converter =
      std::make_shared<shared_model::proto::ProtoPermissionToString>();

  auto block_transport_factory =
      std::make_shared<shared_model::proto::ProtoBlockFactory>(
          std::make_unique<shared_model::validation::AlwaysValidValidator<
              shared_model::interface::Block>>(),
          std::make_unique<shared_model::validation::ProtoBlockValidator>());

  std::unique_ptr<ametsuchi::BlockStorageFactory>
      temporary_block_storage_factory =
          std::make_unique<ametsuchi::InMemoryBlockStorageFactory>();

  auto persistent_block_storage =
      makeRocksDbBlockStorage(db_context, log_manager);

  return ametsuchi::RocksDbStorageImpl::create(
      std::move(db_context),
      perm_converter,
      std::move(pending_txs_storage),
      std::move(query_response_factory),
      std::move(temporary_block_storage_factory),
      std::move(persistent_block_storage),
      vm_caller_ref,
      std::move(callback),
      log_manager->getChild("Storage"));
}

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
    std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
        callback,
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

    std::unique_ptr<ametsuchi::BlockStorageFactory>
        temporary_block_storage_factory =
            std::make_unique<ametsuchi::PostgresBlockStorageFactory>(
                pool_wrapper,
                block_transport_factory,
                []() { return generator::randomString(20); },
                log_manager->getChild("TemporaryBlockStorage")->getLogger());

    auto persistent_block_storage = block_storage_dir
        ? makeFlatFileBlockStorage(block_storage_dir.value(), log_manager)
        : makePostgresBlockStorage(
              pool_wrapper, block_transport_factory, log_manager);
    return ametsuchi::StorageImpl::create(
        pg_opt,
        pool_wrapper,
        perm_converter,
        std::move(pending_txs_storage),
        std::move(query_response_factory),
        std::move(temporary_block_storage_factory),
        std::move(persistent_block_storage),
        vm_caller_ref,
        std::move(callback),
        log_manager->getChild("Storage"));
  } catch (StorageInitException const &e) {
    return iroha::expected::makeError(
        fmt::format("Storage initialization failed: ", e.what()));
  }
}
