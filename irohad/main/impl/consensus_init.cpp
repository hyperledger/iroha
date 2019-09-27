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
#include "network/impl/grpc_channel_builder.hpp"

using namespace iroha::consensus;
using namespace iroha::consensus::yac;

namespace {
  auto createPeerOrderer(
      std::shared_ptr<iroha::ametsuchi::PeerQueryFactory> peer_query_factory) {
    return std::make_shared<PeerOrdererImpl>(peer_query_factory);
  }

  auto createCryptoProvider(const shared_model::crypto::Keypair &keypair) {
    auto crypto = std::make_shared<CryptoProviderImpl>(keypair);

    return crypto;
  }

  auto createHashProvider() {
    return std::make_shared<YacHashProviderImpl>();
  }

  std::shared_ptr<Yac> createYac(
      ClusterOrdering initial_order,
      Round initial_round,
      const shared_model::crypto::Keypair &keypair,
      std::shared_ptr<Timer> timer,
      std::shared_ptr<YacNetwork> network,
      ConsistencyModel consistency_model,
      rxcpp::observe_on_one_worker coordination,
      const logger::LoggerManagerTreePtr &consensus_log_manager) {
    std::shared_ptr<iroha::consensus::yac::CleanupStrategy> cleanup_strategy =
        std::make_shared<iroha::consensus::yac::BufferedCleanupStrategy>();
    return Yac::create(
        YacVoteStorage(cleanup_strategy,
                       getSupermajorityChecker(consistency_model),
                       consensus_log_manager->getChild("VoteStorage")),
        std::move(network),
        createCryptoProvider(keypair),
        std::move(timer),
        initial_order,
        initial_round,
        coordination,
        consensus_log_manager->getChild("HashGate")->getLogger());
  }
}  // namespace

namespace iroha {
  namespace consensus {
    namespace yac {

      std::shared_ptr<NetworkImpl> YacInit::getConsensusNetwork() const {
        BOOST_ASSERT_MSG(initialized_,
                         "YacInit::initConsensusGate(...) must be called prior "
                         "to YacInit::getConsensusNetwork()!");
        return consensus_network_;
      }

      auto YacInit::createTimer(std::chrono::milliseconds delay_milliseconds) {
        return std::make_shared<TimerImpl>(
            delay_milliseconds,
            // TODO 2019-04-10 andrei: IR-441 Share a thread between MST and YAC
            rxcpp::observe_on_new_thread());
      }

      std::shared_ptr<YacGate> YacInit::initConsensusGate(
          Round initial_round,
          std::shared_ptr<iroha::ametsuchi::PeerQueryFactory>
              peer_query_factory,
          boost::optional<shared_model::interface::types::PeerList>
              alternative_peers,
          std::shared_ptr<simulator::BlockCreator> block_creator,
          std::shared_ptr<network::BlockLoader> block_loader,
          const shared_model::crypto::Keypair &keypair,
          std::shared_ptr<consensus::ConsensusResultCache>
              consensus_result_cache,
          std::chrono::milliseconds vote_delay_milliseconds,
          std::shared_ptr<
              iroha::network::AsyncGrpcClient<google::protobuf::Empty>>
              async_call,
          ConsistencyModel consistency_model,
          const logger::LoggerManagerTreePtr &consensus_log_manager) {
        auto peer_orderer = createPeerOrderer(peer_query_factory);
        auto peers = peer_query_factory->createPeerQuery() |
            [](auto &&peer_query) { return peer_query->getLedgerPeers(); };

        consensus_network_ = std::make_shared<NetworkImpl>(
            async_call,
            [](const shared_model::interface::Peer &peer) {
              return network::createClient<proto::Yac>(peer.address());
            },
            consensus_log_manager->getChild("Network")->getLogger());

        auto yac = createYac(*ClusterOrdering::create(peers.value()),
                             initial_round,
                             keypair,
                             createTimer(vote_delay_milliseconds),
                             consensus_network_,
                             consistency_model,
                             rxcpp::observe_on_new_thread(),
                             consensus_log_manager);
        consensus_network_->subscribe(yac);

        auto hash_provider = createHashProvider();

        initialized_ = true;

        return std::make_shared<YacGateImpl>(
            std::move(yac),
            std::move(peer_orderer),
            alternative_peers |
                [](auto &peers) { return ClusterOrdering::create(peers); },
            hash_provider,
            block_creator,
            std::move(consensus_result_cache),
            consensus_log_manager->getChild("Gate")->getLogger());
      }
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
