/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/on_demand_ordering_init.hpp"

#include "common/bind.hpp"
#include "common/delay.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "datetime/time.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/impl/on_demand_connection_manager.hpp"
#include "ordering/impl/on_demand_ordering_gate.hpp"
#include "ordering/impl/on_demand_ordering_service_impl.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"
#include "ordering/impl/on_demand_os_server_grpc.hpp"
#include "ordering/impl/ordering_gate_cache/on_demand_cache.hpp"

namespace {
  /// match event and call corresponding lambda depending on sync_outcome
  template <typename OnBlocks, typename OnNothing>
  auto matchEvent(const iroha::synchronizer::SynchronizationEvent &event,
                  OnBlocks &&on_blocks,
                  OnNothing &&on_nothing) {
    using iroha::synchronizer::SynchronizationOutcomeType;
    switch (event.sync_outcome) {
      case SynchronizationOutcomeType::kCommit:
        return std::forward<OnBlocks>(on_blocks)(event);
      case SynchronizationOutcomeType::kReject:
      case SynchronizationOutcomeType::kNothing:
        return std::forward<OnNothing>(on_nothing)(event);
      default:
        BOOST_ASSERT_MSG(false, "Unknown value");
    }
  }
}  // namespace

namespace iroha {
  namespace network {

    OnDemandOrderingInit::OnDemandOrderingInit(logger::LoggerPtr log)
        : sync_event_notifier(sync_event_notifier_lifetime_),
          commit_notifier(commit_notifier_lifetime_),
          log_(std::move(log)) {}

    auto OnDemandOrderingInit::createNotificationFactory(
        std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
            async_call,
        std::shared_ptr<TransportFactoryType> proposal_transport_factory,
        std::chrono::milliseconds delay,
        const logger::LoggerManagerTreePtr &ordering_log_manager) {
      return std::make_shared<ordering::transport::OnDemandOsClientGrpcFactory>(
          std::move(async_call),
          std::move(proposal_transport_factory),
          [] { return std::chrono::system_clock::now(); },
          delay,
          ordering_log_manager->getChild("NetworkClient")->getLogger());
    }

    auto OnDemandOrderingInit::createConnectionManager(
        std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
            async_call,
        std::shared_ptr<TransportFactoryType> proposal_transport_factory,
        std::chrono::milliseconds delay,
        std::vector<shared_model::interface::types::HashType> initial_hashes,
        const logger::LoggerManagerTreePtr &ordering_log_manager) {
      // since top block will be the first in commit_notifier observable,
      // hashes of two previous blocks are prepended
      const size_t kBeforePreviousTop = 0, kPreviousTop = 1;

      // flat map hashes from committed blocks
      auto all_hashes = commit_notifier.get_observable()
                            .map([](auto block) { return block->hash(); })
                            // prepend hashes for the first two rounds
                            .start_with(initial_hashes.at(kBeforePreviousTop),
                                        initial_hashes.at(kPreviousTop));

      // emit last k + 1 hashes, where k is the delay parameter
      // current implementation assumes k = 2
      // first hash is used for kCurrentRound
      // second hash is used for kNextRound
      // third hash is used for kRoundAfterNext
      auto latest_hashes =
          all_hashes.zip(all_hashes.skip(1), all_hashes.skip(2));

      auto map_peers = [this](auto &&latest_data)
          -> ordering::OnDemandConnectionManager::CurrentPeers {
        auto &latest_commit = std::get<0>(latest_data);
        auto &current_hashes = std::get<1>(latest_data);

        consensus::Round current_round = latest_commit.round;

        auto on_blocks =
            [this, current_hashes, &current_round](const auto &commit) {
              current_round = ordering::nextCommitRound(current_round);
              current_peers_ = commit.ledger_state->ledger_peers;

              // generate permutation of peers list from corresponding round
              // hash
              auto generate_permutation = [&](auto round) {
                auto &hash = std::get<round()>(current_hashes);
                log_->debug("Using hash: {}", hash.toString());
                auto &permutation = permutations_[round()];

                std::seed_seq seed(hash.blob().begin(), hash.blob().end());
                gen_.seed(seed);

                permutation.resize(current_peers_.size());
                std::iota(permutation.begin(), permutation.end(), 0);

                std::shuffle(permutation.begin(), permutation.end(), gen_);
              };

              generate_permutation(RoundTypeConstant<kCurrentRound>{});
              generate_permutation(RoundTypeConstant<kNextRound>{});
              generate_permutation(RoundTypeConstant<kRoundAfterNext>{});
            };
        auto on_nothing = [&current_round](const auto &) {
          current_round = ordering::nextRejectRound(current_round);
        };

        matchEvent(latest_commit, on_blocks, on_nothing);

        auto getOsPeer = [this, &current_round](auto block_round_advance,
                                                auto reject_round) {
          auto &permutation = permutations_[block_round_advance];
          // since reject round can be greater than number of peers, wrap it
          // with number of peers
          auto &peer =
              current_peers_[permutation[reject_round % permutation.size()]];
          log_->debug(
              "For {}, using OS on peer: {}",
              consensus::Round{current_round.block_round + block_round_advance,
                               reject_round},
              *peer);
          return peer;
        };

        using ordering::OnDemandConnectionManager;
        OnDemandConnectionManager::CurrentPeers peers;
        /*
         * See detailed description in
         * irohad/ordering/impl/on_demand_connection_manager.cpp
         *
         *    0 1 2         0 1 2         0 1 2         0 1 2
         *  0 o x v       0 o . .       0 o x .       0 o . .
         *  1 . . .       1 x v .       1 v . .       1 x . .
         *  2 . . .       2 . . .       2 . . .       2 v . .
         * RejectReject  CommitReject  RejectCommit  CommitCommit
         *
         * o - current round, x - next round, v - target round
         *
         * v, round 0,2 - kRejectRejectConsumer
         * v, round 1,1 - kCommitRejectConsumer
         * v, round 1,0 - kRejectCommitConsumer
         * v, round 2,0 - kCommitCommitConsumer
         * o, round 0,0 - kIssuer
         */
        peers.peers.at(OnDemandConnectionManager::kRejectRejectConsumer) =
            getOsPeer(kCurrentRound,
                      ordering::currentRejectRoundConsumer(
                          current_round.reject_round));
        peers.peers.at(OnDemandConnectionManager::kRejectCommitConsumer) =
            getOsPeer(kNextRound, ordering::kNextCommitRoundConsumer);
        peers.peers.at(OnDemandConnectionManager::kCommitRejectConsumer) =
            getOsPeer(kNextRound, ordering::kNextRejectRoundConsumer);
        peers.peers.at(OnDemandConnectionManager::kCommitCommitConsumer) =
            getOsPeer(kRoundAfterNext, ordering::kNextCommitRoundConsumer);
        peers.peers.at(OnDemandConnectionManager::kIssuer) =
            getOsPeer(kCurrentRound, current_round.reject_round);
        return peers;
      };

      auto peers = sync_event_notifier.get_observable()
                       .with_latest_from(latest_hashes)
                       .map(map_peers);

      return std::make_shared<ordering::OnDemandConnectionManager>(
          createNotificationFactory(std::move(async_call),
                                    std::move(proposal_transport_factory),
                                    delay,
                                    ordering_log_manager),
          peers,
          ordering_log_manager->getChild("ConnectionManager")->getLogger());
    }

    auto OnDemandOrderingInit::createGate(
        std::shared_ptr<ordering::OnDemandOrderingService> ordering_service,
        std::shared_ptr<ordering::transport::OdOsNotification> network_client,
        std::shared_ptr<ordering::cache::OrderingGateCache> cache,
        std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
            proposal_factory,
        std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
        std::shared_ptr<ordering::ProposalCreationStrategy> creation_strategy,
        std::function<std::chrono::milliseconds(
            const synchronizer::SynchronizationEvent &)> delay_func,
        size_t max_number_of_transactions,
        const logger::LoggerManagerTreePtr &ordering_log_manager) {
      return std::make_shared<ordering::OnDemandOrderingGate>(
          std::move(ordering_service),
          std::move(network_client),
          commit_notifier.get_observable().map(
              [this](auto block)
                  -> std::shared_ptr<
                      const ordering::cache::OrderingGateCache::HashesSetType> {
                // take committed & rejected transaction hashes from committed
                // block
                log_->debug("Committed block handle: height {}.",
                            block->height());
                auto hashes = std::make_shared<
                    ordering::cache::OrderingGateCache::HashesSetType>();
                const auto &committed = block->transactions();
                std::transform(
                    committed.begin(),
                    committed.end(),
                    std::inserter(*hashes, hashes->end()),
                    [](const auto &transaction) { return transaction.hash(); });
                const auto &rejected = block->rejected_transactions_hashes();
                std::copy(rejected.begin(),
                          rejected.end(),
                          std::inserter(*hashes, hashes->end()));
                return hashes;
              }),
          sync_event_notifier.get_observable()
              .tap([this](const synchronizer::SynchronizationEvent &event) {
                if (not last_received_round_
                    or *last_received_round_ < event.round) {
                  last_received_round_ = event.round;
                } else {
                  log_->debug("Dropping {}, since {} is already processed",
                              event.round,
                              *last_received_round_);
                }
              })
              .lift<iroha::synchronizer::SynchronizationEvent>(
                  iroha::makeDelay<iroha::synchronizer::SynchronizationEvent>(
                      delay_func, rxcpp::identity_current_thread()))
              .filter([this](const auto &event) {
                assert(last_received_round_);
                if (not last_received_round_) {
                  log_->error("Cannot continue without last received round");
                  return false;
                }
                if (event.round < *last_received_round_) {
                  log_->debug("Dropping {}, since {} is already processed",
                              event.round,
                              *last_received_round_);
                  return false;
                }
                return true;
              })
              .map([this](const auto &event) {
                consensus::Round current_round;
                switch (event.sync_outcome) {
                  case iroha::synchronizer::SynchronizationOutcomeType::kCommit:
                    log_->debug("Sync event on {}: commit.",
                                *last_received_round_);
                    current_round =
                        ordering::nextCommitRound(*last_received_round_);
                    break;
                  case iroha::synchronizer::SynchronizationOutcomeType::kReject:
                    log_->debug("Sync event on {}: reject.",
                                *last_received_round_);
                    current_round =
                        ordering::nextRejectRound(*last_received_round_);
                    break;
                  case iroha::synchronizer::SynchronizationOutcomeType::
                      kNothing:
                    log_->debug("Sync event on {}: nothing.",
                                *last_received_round_);
                    current_round =
                        ordering::nextRejectRound(*last_received_round_);
                    break;
                  default:
                    log_->error("unknown SynchronizationOutcomeType");
                    assert(false);
                }
                return ordering::OnDemandOrderingGate::RoundSwitch{
                    std::move(current_round), event.ledger_state};
              }),
          std::move(cache),
          std::move(proposal_factory),
          std::move(tx_cache),
          std::move(creation_strategy),
          max_number_of_transactions,
          ordering_log_manager->getChild("Gate")->getLogger());
    }

    auto OnDemandOrderingInit::createService(
        size_t max_number_of_transactions,
        std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
            proposal_factory,
        std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
        std::shared_ptr<ordering::ProposalCreationStrategy> creation_strategy,
        const logger::LoggerManagerTreePtr &ordering_log_manager) {
      return std::make_shared<ordering::OnDemandOrderingServiceImpl>(
          max_number_of_transactions,
          std::move(proposal_factory),
          std::move(tx_cache),
          creation_strategy,
          ordering_log_manager->getChild("Service")->getLogger());
    }

    OnDemandOrderingInit::~OnDemandOrderingInit() {
      sync_event_notifier_lifetime_.unsubscribe();
      commit_notifier_lifetime_.unsubscribe();
    }

    std::shared_ptr<iroha::network::OrderingGate>
    OnDemandOrderingInit::initOrderingGate(
        size_t max_number_of_transactions,
        std::chrono::milliseconds delay,
        std::vector<shared_model::interface::types::HashType> initial_hashes,
        std::shared_ptr<
            ordering::transport::OnDemandOsServerGrpc::TransportFactoryType>
            transaction_factory,
        std::shared_ptr<shared_model::interface::TransactionBatchParser>
            batch_parser,
        std::shared_ptr<shared_model::interface::TransactionBatchFactory>
            transaction_batch_factory,
        std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
            async_call,
        std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
            proposal_factory,
        std::shared_ptr<TransportFactoryType> proposal_transport_factory,
        std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
        std::shared_ptr<ordering::ProposalCreationStrategy> creation_strategy,
        std::function<std::chrono::milliseconds(
            const synchronizer::SynchronizationEvent &)> delay_func,
        logger::LoggerManagerTreePtr ordering_log_manager) {
      auto ordering_service = createService(max_number_of_transactions,
                                            proposal_factory,
                                            tx_cache,
                                            creation_strategy,
                                            ordering_log_manager);
      service = std::make_shared<ordering::transport::OnDemandOsServerGrpc>(
          ordering_service,
          std::move(transaction_factory),
          std::move(batch_parser),
          std::move(transaction_batch_factory),
          ordering_log_manager->getChild("Server")->getLogger());
      return createGate(
          ordering_service,
          createConnectionManager(std::move(async_call),
                                  std::move(proposal_transport_factory),
                                  delay,
                                  std::move(initial_hashes),
                                  ordering_log_manager),
          std::make_shared<ordering::cache::OnDemandCache>(),
          std::move(proposal_factory),
          std::move(tx_cache),
          std::move(creation_strategy),
          std::move(delay_func),
          max_number_of_transactions,
          ordering_log_manager);
    }

  }  // namespace network
}  // namespace iroha
