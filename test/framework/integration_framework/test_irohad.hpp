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

namespace integration_framework {
  /**
   * Class for integration testing of Irohad.
   */
  class TestIrohad : public Irohad {
   public:
    TestIrohad(const std::optional<std::string> &block_store_dir,
               std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt,
               const std::string &listen_ip,
               size_t torii_port,
               size_t internal_port,
               size_t max_proposal_size,
               std::chrono::milliseconds proposal_delay,
               std::chrono::milliseconds vote_delay,
               std::chrono::minutes mst_expiration_time,
               const shared_model::crypto::Keypair &keypair,
               std::chrono::milliseconds max_rounds_delay,
               size_t stale_stream_max_rounds,
               std::optional<shared_model::interface::types::PeerList>
                   opt_alternative_peers,
               logger::LoggerManagerTreePtr irohad_log_manager,
               logger::LoggerPtr log,
               iroha::StartupWsvDataPolicy startup_wsv_data_policy,
               const std::optional<iroha::GossipPropagationStrategyParams>
                   &opt_mst_gossip_params = std::nullopt,
               const std::optional<iroha::torii::TlsParams>
                   &torii_tls_params = std::nullopt)
        : Irohad(block_store_dir,
                 std::move(pg_opt),
                 listen_ip,
                 torii_port,
                 internal_port,
                 max_proposal_size,
                 proposal_delay,
                 vote_delay,
                 mst_expiration_time,
                 keypair,
                 max_rounds_delay,
                 stale_stream_max_rounds,
                 std::move(opt_alternative_peers),
                 std::move(irohad_log_manager),
                 startup_wsv_data_policy,
                 iroha::network::getDefaultTestChannelParams(),
                 opt_mst_gossip_params,
                 torii_tls_params,
                 std::nullopt),
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
    logger::LoggerPtr log_;
  };
}  // namespace integration_framework

#endif  // IROHA_TESTIROHAD_HPP
