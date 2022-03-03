/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/iroha_instance.hpp"

#include <boost/filesystem.hpp>
#include <cstdlib>
#include <sstream>

#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/storage.hpp"
#include "cryptography/keypair.hpp"
#include "framework/config_helper.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "logger/logger.hpp"
#include "main/impl/pg_connection_init.hpp"

namespace fs = boost::filesystem;
using namespace std::chrono_literals;
static constexpr std::chrono::milliseconds kMstEmissionPeriod = 100ms;

namespace integration_framework {

  IrohaInstance::IrohaInstance(
      const IrohadConfig &config,
      const std::string &listen_ip,
      logger::LoggerManagerTreePtr irohad_log_manager,
      logger::LoggerPtr log,
      iroha::StartupWsvDataPolicy startup_wsv_data_policy,
      const boost::optional<std::string> &dbname)
      : config_(config),
        working_dbname_(dbname.value_or(getRandomDbName())),
        rocksdb_filepath_(
            config_.database_config
                ? config_.database_config->path
                : (fs::temp_directory_path() / fs::unique_path()).string()),
        listen_ip_(listen_ip),
        irohad_log_manager_(std::move(irohad_log_manager)),
        log_(std::move(log)),
        startup_wsv_data_policy_(startup_wsv_data_policy) {}

  void IrohaInstance::init() {
    auto init_result = test_irohad_->init();
    if (auto error =
            boost::get<iroha::expected::Error<std::string>>(&init_result)) {
      std::string error_msg("Irohad startup failed: ");
      error_msg.append(error->error);
      log_->critical("{}", error_msg);
      throw(std::runtime_error(error_msg));
    }
  }

  void IrohaInstance::makeGenesis(
      std::shared_ptr<const shared_model::interface::Block> block) {
    if (auto e = iroha::expected::resultToOptionalError(
            test_irohad_->dropStorage())) {
      throw std::runtime_error(e.value());
    }
    rawInsertBlock(block);
  }

  void IrohaInstance::rawInsertBlock(
      std::shared_ptr<const shared_model::interface::Block> block) {
    if (auto e = iroha::expected::resultToOptionalError(
            test_irohad_->storage->insertBlock(block))) {
      log_->warn("Could not insert block {}: {}", block->height(), e.value());
    }
  }

  void IrohaInstance::printDbStatus() {
    test_irohad_->printDbStatus();
  }

  void IrohaInstance::initPipeline(
      const shared_model::crypto::Keypair &key_pair, size_t max_proposal_size) {
    config_.max_proposal_size = max_proposal_size;
    test_irohad_ = std::make_shared<TestIrohad>(
        config_,
        std::make_unique<iroha::ametsuchi::PostgresOptions>(
            getPostgresCredsOrDefault(), working_dbname_, log_),
        std::make_unique<iroha::ametsuchi::RocksDbOptions>(rocksdb_filepath_),
        listen_ip_,
        key_pair,
        irohad_log_manager_,
        log_,
        startup_wsv_data_policy_);
  }

  void IrohaInstance::run() {
    test_irohad_->run().match(
        [](const auto &) {},
        [this](const auto &error) {
          log_->error("{}", error.error);
          BOOST_THROW_EXCEPTION(std::runtime_error(error.error));
        });
  }

  std::shared_ptr<TestIrohad> &IrohaInstance::getTestIrohad() {
    return test_irohad_;
  }

  void IrohaInstance::terminateAndCleanup() {
    if (not test_irohad_ or not test_irohad_->storage) {
      log_->warn("Iroha instance or its storage are not initialized");
      return;
    }
    const auto pg_opt = *test_irohad_->pg_opt_;
    log_->info("stopping irohad");
    test_irohad_.reset();
    log_->info("removing storage");
    iroha::ametsuchi::PgConnectionInit::dropWorkingDatabase(pg_opt);
    if (config_.block_store_path) {
      boost::filesystem::remove_all(config_.block_store_path.value());
    }
  }

}  // namespace integration_framework
