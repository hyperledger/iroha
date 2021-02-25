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
        listen_ip_(listen_ip),
        opt_mst_gossip_params_(boost::make_optional(
            config_.mst_support,
            [] {
              iroha::GossipPropagationStrategyParams params;
              params.emission_period = kMstEmissionPeriod;
              return params;
            }())),
        irohad_log_manager_(std::move(irohad_log_manager)),
        log_(std::move(log)),
        startup_wsv_data_policy_(startup_wsv_data_policy) {}

  void IrohaInstance::init() {
    auto init_result = instance_->init();
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
    if (auto e =
            iroha::expected::resultToOptionalError(instance_->dropStorage())) {
      throw std::runtime_error(e.value());
    }
    rawInsertBlock(block);
  }

  void IrohaInstance::rawInsertBlock(
      std::shared_ptr<const shared_model::interface::Block> block) {
    if (auto e = iroha::expected::resultToOptionalError(
            instance_->storage->insertBlock(block))) {
      log_->warn("Could not insert block {}: {}", block->height(), e.value());
    }
  }

  void IrohaInstance::setMstGossipParams(
      std::chrono::milliseconds mst_gossip_emitting_period,
      uint32_t mst_gossip_amount_per_once) {
    BOOST_ASSERT_MSG(
        not instance_,
        "Gossip propagation params must be set before Irohad is started!");
    iroha::GossipPropagationStrategyParams gossip_params;
    gossip_params.emission_period = mst_gossip_emitting_period;
    gossip_params.amount_per_once = mst_gossip_amount_per_once;
    opt_mst_gossip_params_ = gossip_params;
  }

  void IrohaInstance::initPipeline(
      const shared_model::crypto::Keypair &key_pair, size_t max_proposal_size) {
    config_.max_proposal_size = max_proposal_size;
    instance_ = std::make_shared<TestIrohad>(
        config_,
        std::make_unique<iroha::ametsuchi::PostgresOptions>(
            getPostgresCredsOrDefault(), working_dbname_, log_),
        listen_ip_,
        key_pair,
        irohad_log_manager_,
        log_,
        startup_wsv_data_policy_,
        opt_mst_gossip_params_);
  }

  void IrohaInstance::run() {
    instance_->run().match(
        [](const auto &) {},
        [](const auto &error) {
          BOOST_THROW_EXCEPTION(std::runtime_error(error.error));
        });
  }

  std::shared_ptr<TestIrohad> &IrohaInstance::getIrohaInstance() {
    return instance_;
  }

  void IrohaInstance::terminateAndCleanup() {
    if (not instance_ or not instance_->storage) {
      log_->warn("Iroha instance or its storage are not initialized");
      return;
    }
    const auto pg_opt = *instance_->pg_opt_;
    log_->info("stopping irohad");
    instance_.reset();
    log_->info("removing storage");
    iroha::ametsuchi::PgConnectionInit::dropWorkingDatabase(pg_opt);
    if (config_.block_store_path) {
      boost::filesystem::remove_all(config_.block_store_path.value());
    }
  }

}  // namespace integration_framework
