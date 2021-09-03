/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <libfuzzer/libfuzzer_macro.h>

#include "common/common.hpp"
#include "consensus/round.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"
#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"
#include "consensus/yac/transport/impl/consensus_service_impl.hpp"
#include "consensus/yac/yac.hpp"
#include "framework/test_logger.hpp"
#include "fuzzing/grpc_servercontext_dtor_segv_workaround.hpp"
#include "logger/dummy_logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/ametsuchi/mock_client_factory.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/consensus/yac/mock_yac_network.hpp"
#include "module/irohad/consensus/yac/mock_yac_timer.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/field_validator.hpp"

#include "yac_mock.grpc.pb.h"

using namespace testing;

namespace fuzzing {
  struct ConsensusFixture {
    const shared_model::crypto::Keypair keypair_;
    std::shared_ptr<iroha::consensus::yac::Timer> timer_;
    std::shared_ptr<iroha::consensus::yac::YacCryptoProvider> crypto_provider_;
    std::shared_ptr<iroha::consensus::yac::CleanupStrategy> cleanup_strategy_;
    std::shared_ptr<iroha::consensus::yac::YacNetworkNotifications> yac_;
    std::shared_ptr<iroha::consensus::yac::YacNetwork> network_;
    std::shared_ptr<iroha::consensus::yac::ServiceImpl> service_;
    iroha::consensus::Round initial_round_;

    ConsensusFixture()
        : keypair_(shared_model::crypto::DefaultCryptoAlgorithmType::
                       generateKeypair()),
          timer_(std::make_shared<iroha::consensus::yac::MockTimer>()),
          crypto_provider_(
              std::make_shared<iroha::consensus::yac::CryptoProviderImpl>(
                  keypair_, logger::getDummyLoggerPtr())),
          cleanup_strategy_(std::make_shared<
                            iroha::consensus::yac::BufferedCleanupStrategy>()),
          network_(std::make_shared<iroha::consensus::yac::MockYacNetwork>()),
          initial_round_{1, 1} {
      std::vector<std::shared_ptr<shared_model::interface::Peer>>
          default_peers = [] {
            std::vector<std::shared_ptr<shared_model::interface::Peer>> result;
            for (size_t i = 0; i < 1; ++i) {
              result.push_back(
                  iroha::consensus::yac::makePeer(std::to_string(i)));
            }
            return result;
          }();
      auto initial_order =
          iroha::consensus::yac::ClusterOrdering::create(default_peers);

      if (not initial_order) {
        throw "Initial peers order is not initialized";
      }

      yac_ = iroha::consensus::yac::Yac::create(
          iroha::consensus::yac::YacVoteStorage(
              cleanup_strategy_,
              getSupermajorityChecker(
                  iroha::consensus::yac::ConsistencyModel::kBft),
              getTestLoggerManager(logger::LogLevel::kCritical)
                  ->getChild("YacVoteStorage")),
          network_,
          crypto_provider_,
          timer_,
          initial_order->getPeers(),
          initial_round_,
          getTestLoggerManager(logger::LogLevel::kCritical)
              ->getChild("Yac")
              ->getLogger());

      service_ = std::make_shared<iroha::consensus::yac::ServiceImpl>(
          getTestLoggerManager(logger::LogLevel::kCritical)
              ->getChild("Service")
              ->getLogger(),
          [yac(iroha::utils::make_weak(yac_))](
              std::vector<iroha::consensus::yac::VoteMessage> state) {
            if (auto maybe_yac = yac.lock()) {
              maybe_yac->onState(std::move(state));
            }
          });
    }
  };
}  // namespace fuzzing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
  static fuzzing::ConsensusFixture fixture;

  if (size < 1) {
    return 0;
  }

  iroha::consensus::yac::proto::State request;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(true, data, size, &request)) {
    grpc::ServerContext context;
    google::protobuf::Empty response;
    fixture.service_->SendState(&context, &request, &response);
  }

  return 0;
}
