/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_IROHA_INSTANCE_HPP
#define IROHA_IROHA_INSTANCE_HPP

#include <boost/optional.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <memory>
#include <string>

#include "ametsuchi/impl/postgres_options.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/iroha_conf_loader.hpp"
#include "main/startup_params.hpp"
#include "torii/tls_params.hpp"

namespace shared_model {
  namespace interface {
    class Block;
    class Peer;
  }  // namespace interface
  namespace crypto {
    class Keypair;
  }  // namespace crypto
}  // namespace shared_model

namespace integration_framework {
  class TestIrohad;

  class IrohaInstance {
   public:
    /**
     * @param listen_ip - ip address for opening ports (internal & torii)
     * @param irohad_log_manager - the log manager for irohad
     * @param log - the log for internal messages
     * @param startup_wsv_data_policy - @see StartupWsvDataPolicy
     * @param dbname is a name of postgres database
     */
    IrohaInstance(const IrohadConfig &config,
                  const std::string &listen_ip,
                  logger::LoggerManagerTreePtr irohad_log_manager,
                  logger::LoggerPtr log,
                  iroha::StartupWsvDataPolicy startup_wsv_data_policy,
                  const boost::optional<std::string> &dbname = boost::none);

    /// Initialize Irohad. Throws on error.
    void init();

    void makeGenesis(
        std::shared_ptr<const shared_model::interface::Block> block);

    void rawInsertBlock(
        std::shared_ptr<const shared_model::interface::Block> block);

    void initPipeline(const shared_model::crypto::Keypair &key_pair,
                      size_t max_proposal_size = 10);

    void run();

    void printDbStatus();

    std::shared_ptr<TestIrohad> &getTestIrohad();

    /// Terminate Iroha instance and clean the resources up.
    void terminateAndCleanup();

    // config area
    IrohadConfig config_;
    const std::string working_dbname_;
    const std::string rocksdb_filepath_;
    const std::string listen_ip_;

   private:
    std::shared_ptr<TestIrohad> test_irohad_;
    logger::LoggerManagerTreePtr irohad_log_manager_;

    logger::LoggerPtr log_;

    const iroha::StartupWsvDataPolicy startup_wsv_data_policy_;
  };
}  // namespace integration_framework
#endif  // IROHA_IROHA_INSTANCE_HPP
