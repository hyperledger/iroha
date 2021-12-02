/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/consensus_init.hpp"

#include "common/bind.hpp"
#include "consensus/yac/consistency_model.hpp"
#include "consensus/yac/impl/peer_orderer_impl.hpp"
#include "consensus/yac/impl/timer_impl.hpp"
#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"
#include "consensus/yac/impl/yac_gate_impl.hpp"
#include "consensus/yac/impl/yac_hash_provider_impl.hpp"
#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "consensus/yac/yac.hpp"
#include "logger/logger_manager.hpp"
#include "main/subscription.hpp"
#include "network/impl/client_factory_impl.hpp"

using iroha::consensus::yac::YacInit;

namespace {
  auto createCryptoProvider(const shared_model::crypto::Keypair &keypair,
                            logger::LoggerPtr log) {
    auto crypto = std::make_shared<iroha::consensus::yac::CryptoProviderImpl>(
        keypair, std::move(log));

    return crypto;
  }

  auto createHashProvider() {
    return std::make_shared<iroha::consensus::yac::YacHashProviderImpl>();
  }

  auto createNetwork(
      std::shared_ptr<iroha::network::GenericClientFactory> client_factory,
      logger::LoggerPtr log) {
    return std::make_shared<iroha::consensus::yac::NetworkImpl>(
        std::make_unique<iroha::network::ClientFactoryImpl<
            iroha::consensus::yac::NetworkImpl::Service>>(
            std::move(client_factory)),
        log);
  }

  std::shared_ptr<iroha::consensus::yac::Yac> createYac(
      shared_model::interface::types::PeerList initial_order,
      iroha::consensus::Round initial_round,
      const shared_model::crypto::Keypair &keypair,
      std::shared_ptr<iroha::consensus::yac::Timer> timer,
      std::shared_ptr<iroha::consensus::yac::YacNetwork> network,
      iroha::consensus::yac::ConsistencyModel consistency_model,
      const logger::LoggerManagerTreePtr &consensus_log_manager) {
    std::shared_ptr<iroha::consensus::yac::CleanupStrategy> cleanup_strategy =
        std::make_shared<iroha::consensus::yac::BufferedCleanupStrategy>();
    return iroha::consensus::yac::Yac::create(
        iroha::consensus::yac::YacVoteStorage(
            cleanup_strategy,
            getSupermajorityChecker(consistency_model),
            consensus_log_manager->getChild("VoteStorage")),
        std::move(network),
        createCryptoProvider(
            keypair, consensus_log_manager->getChild("Crypto")->getLogger()),
        std::move(timer),
        initial_order,
        initial_round,
        consensus_log_manager->getChild("HashGate")->getLogger());
  }
}  // namespace

std::shared_ptr<iroha::consensus::yac::ServiceImpl>
YacInit::getConsensusNetwork() const {
  BOOST_ASSERT_MSG(initialized_,
                   "YacInit::initConsensusGate(...) must be called prior "
                   "to YacInit::getConsensusNetwork()!");
  return consensus_network_;
}

void YacInit::subscribe(std::function<void(GateObject const &)> callback) {
  BOOST_ASSERT_MSG(initialized_,
                   "YacInit::initConsensusGate(...) must be called prior "
                   "to YacInit::subscribe()!");
  states_subscription_ =
      SubscriberCreator<bool, std::vector<VoteMessage>>::template create<
          EventTypes::kOnState>(
          iroha::SubscriptionEngineHandlers::kYac,
          [yac(utils::make_weak(yac_)),
           yac_gate(utils::make_weak(yac_gate_)),
           callback(std::move(callback))](auto, auto state) {
            auto maybe_yac = yac.lock();
            auto maybe_yac_gate = yac_gate.lock();
            if (not(maybe_yac and maybe_yac_gate)) {
              return;
            }
            auto maybe_answer = maybe_yac->onState(std::move(state));
            if (not maybe_answer) {
              return;
            }
            auto maybe_outcome =
                maybe_yac_gate->processOutcome(*std::move(maybe_answer));
            if (maybe_outcome) {
              callback(*std::move(maybe_outcome));
            }
          });
}

std::optional<iroha::consensus::GateObject> YacInit::processRoundSwitch(
    consensus::Round const &round,
    std::shared_ptr<LedgerState const> ledger_state) {
  return yac_gate_->processRoundSwitch(round, std::move(ledger_state));
}

auto YacInit::createTimer(std::chrono::milliseconds delay_milliseconds) {
  return std::make_shared<TimerImpl>(delay_milliseconds);
}

std::shared_ptr<iroha::consensus::yac::YacGate> YacInit::initConsensusGate(
    Round initial_round,
    std::optional<shared_model::interface::types::PeerList> alternative_peers,
    std::shared_ptr<const LedgerState> ledger_state,
    std::shared_ptr<network::BlockLoader> block_loader,
    const shared_model::crypto::Keypair &keypair,
    std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
    std::chrono::milliseconds vote_delay_milliseconds,
    ConsistencyModel consistency_model,
    const logger::LoggerManagerTreePtr &consensus_log_manager,
    std::shared_ptr<iroha::network::GenericClientFactory> client_factory,
    bool /*syncing_mode*/) {
  consensus_network_ = std::make_shared<ServiceImpl>(
      consensus_log_manager->getChild("Service")->getLogger(),
      [](std::vector<VoteMessage> state) {
        getSubscription()->notify(EventTypes::kOnState, std::move(state));
      });

  yac_ = createYac(
      ledger_state->ledger_peers,
      initial_round,
      keypair,
      createTimer(vote_delay_milliseconds),
      createNetwork(client_factory,
                    consensus_log_manager->getChild("Network")->getLogger()),
      consistency_model,
      consensus_log_manager);
  auto hash_provider = createHashProvider();
  initialized_ = true;
  yac_gate_ = std::make_shared<YacGateImpl>(
      yac_,
      std::make_shared<PeerOrdererImpl>(),
      alternative_peers |
          [](auto &peers) { return ClusterOrdering::create(peers); },
      std::move(ledger_state),
      hash_provider,
      std::move(consensus_result_cache),
      consensus_log_manager->getChild("Gate")->getLogger());

  return yac_gate_;
}
