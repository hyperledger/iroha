/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TESTIROHAD_HPP
#define IROHA_TESTIROHAD_HPP

#include "ametsuchi/impl/rocksdb_options.hpp"
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
    TestIrohad(const IrohadConfig &config,
               std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt,
               std::unique_ptr<iroha::ametsuchi::RocksDbOptions> rdb_opt,
               const std::string &listen_ip,
               const shared_model::crypto::Keypair &keypair,
               logger::LoggerManagerTreePtr irohad_log_manager,
               logger::LoggerPtr log,
               iroha::StartupWsvDataPolicy startup_wsv_data_policy)
        : Irohad(config,
                 std::move(pg_opt),
                 std::move(rdb_opt),
                 listen_ip,
                 keypair,
                 std::move(irohad_log_manager),
                 startup_wsv_data_policy,
                 iroha::StartupWsvSynchronizationPolicy::kSyncUpAndGo,
                 std::nullopt,
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
