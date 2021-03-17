/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TESTIROHAD_HPP
#define IROHA_TESTIROHAD_HPP

#include "cryptography/keypair.hpp"
#include "framework/test_client_factory.hpp"
#include "main/application.hpp"
#include "main/server_runner.hpp"
#include "main/subscription.hpp"

namespace integration_framework {
  /**
   * Class for integration testing of Irohad.
   */
  class TestIrohad : public Irohad {
   public:
    TestIrohad(const IrohadConfig &config,
               std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt,
               const std::string &listen_ip,
               const shared_model::crypto::Keypair &keypair,
               logger::LoggerManagerTreePtr irohad_log_manager,
               logger::LoggerPtr log,
               iroha::StartupWsvDataPolicy startup_wsv_data_policy,
               const boost::optional<iroha::GossipPropagationStrategyParams>
                   &opt_mst_gossip_params = boost::none)
        : Irohad(config,
                 std::move(pg_opt),
                 listen_ip,
                 keypair,
                 std::move(irohad_log_manager),
                 startup_wsv_data_policy,
                 iroha::StartupWsvSynchronizationPolicy::kSyncUpAndGo,
                 iroha::network::getDefaultTestChannelParams(),
                 opt_mst_gossip_params,
                 boost::none),
          log_(std::move(log)) {}

    auto &getCommandService() {
      return command_service;
    }

    auto &getCommandServiceTransport() {
      return command_service_transport;
    }

    auto &getQueryService() {
      return query_service;
    }

    auto &getMstProcessor() {
      return mst_processor;
    }

    auto &getConsensusGate() {
      return consensus_gate;
    }

    auto &getPeerCommunicationService() {
      return pcs;
    }

    auto &getCryptoSigner() {
      return crypto_signer_;
    }

    auto getStatusBus() {
      return status_bus_;
    }

    const auto &getStorage() {
      return storage;
    }

    void terminate() {
      if (internal_server) {
        internal_server->shutdown();
      } else {
        log_->warn("Tried to terminate without internal server");
      }
    }

    void terminate(const std::chrono::system_clock::time_point &deadline) {
      if (internal_server) {
        internal_server->shutdown(deadline);
      } else {
        log_->warn("Tried to terminate without internal server");
      }
    }

   private:
    std::shared_ptr<iroha::Subscription> se_ = iroha::getSubscription();
    logger::LoggerPtr log_;
  };
}  // namespace integration_framework

#endif  // IROHA_TESTIROHAD_HPP
