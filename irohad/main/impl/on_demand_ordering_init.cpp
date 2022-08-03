/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/on_demand_ordering_init.hpp"

#include "common/mem_operations.hpp"
#include "common/permutation_generator.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/iroha_status.hpp"
#include "main/subscription.hpp"
#include "network/impl/client_factory_impl.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/impl/on_demand_connection_manager.hpp"
#include "ordering/impl/on_demand_ordering_gate.hpp"
#include "ordering/impl/on_demand_ordering_service_impl.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"
#include "ordering/impl/on_demand_os_server_grpc.hpp"
#include "ordering/impl/os_executor_keepers.hpp"
#include "synchronizer/synchronizer_common.hpp"

using iroha::ordering::OnDemandOrderingInit;

namespace {
  /// indexes to permutations for corresponding rounds
  enum RoundType { kCurrentRound, kNextRound, kCount };

  template <RoundType V>
  using RoundTypeConstant = std::integral_constant<RoundType, V>;
}  // namespace

OnDemandOrderingInit::OnDemandOrderingInit(logger::LoggerPtr log)
    : log_(std::move(log)),
      os_execution_keepers_(std::make_shared<ExecutorKeeper>()) {}

/**
 * Creates notification factory for individual connections to peers with
 * gRPC backend. \see initOrderingGate for parameters
 */
auto createNotificationFactory(
    std::shared_ptr<OnDemandOrderingInit::TransportFactoryType>
        proposal_transport_factory,
    std::chrono::milliseconds delay,
    const logger::LoggerManagerTreePtr &ordering_log_manager,
    std::shared_ptr<iroha::network::GenericClientFactory> client_factory,
    std::shared_ptr<iroha::ordering::ExecutorKeeper> os_execution_keepers) {
  return std::make_shared<
      iroha::ordering::transport::OnDemandOsClientGrpcFactory>(
      std::move(proposal_transport_factory),
      [] { return std::chrono::system_clock::now(); },
      delay,
      ordering_log_manager->getChild("NetworkClient")->getLogger(),
      std::make_unique<iroha::network::ClientFactoryImpl<
          iroha::ordering::transport::OnDemandOsClientGrpcFactory::Service>>(
          std::move(client_factory)),
      std::move(os_execution_keepers));
}

auto OnDemandOrderingInit::createConnectionManager(
    std::shared_ptr<TransportFactoryType> proposal_transport_factory,
    std::chrono::milliseconds delay,
    const logger::LoggerManagerTreePtr &ordering_log_manager,
    std::shared_ptr<iroha::network::GenericClientFactory> client_factory) {
  connection_manager_ = std::make_unique<OnDemandConnectionManager>(
      createNotificationFactory(std::move(proposal_transport_factory),
                                delay,
                                ordering_log_manager,
                                std::move(client_factory),
                                os_execution_keepers_),
      ordering_log_manager->getChild("ConnectionManager")->getLogger());
  return connection_manager_;
}

auto OnDemandOrderingInit::createGate(
    std::shared_ptr<OnDemandOrderingService> ordering_service,
    std::shared_ptr<transport::OdOsNotification> network_client,
    std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
        proposal_factory,
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_cache,
    size_t max_number_of_transactions,
    const logger::LoggerManagerTreePtr &ordering_log_manager,
    bool syncing_mode) {
  auto og = std::make_shared<OnDemandOrderingGate>(
      std::move(ordering_service),
      std::move(network_client),
      std::move(proposal_factory),
      std::move(tx_cache),
      max_number_of_transactions,
      ordering_log_manager->getChild("Gate")->getLogger(),
      syncing_mode);
  og->initialize();
  return og;
}

auto OnDemandOrderingInit::createService(
    size_t max_number_of_transactions,
    uint32_t max_proposal_pack,
    std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
        proposal_factory,
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_cache,
    const logger::LoggerManagerTreePtr &ordering_log_manager) {
  ordering_service_ = std::make_shared<OnDemandOrderingServiceImpl>(
      max_number_of_transactions,
      max_proposal_pack,
      std::move(proposal_factory),
      std::move(tx_cache),
      ordering_log_manager->getChild("Service")->getLogger());
  return ordering_service_;
}

std::shared_ptr<iroha::network::OrderingGate>
OnDemandOrderingInit::initOrderingGate(
    size_t max_number_of_transactions,
    uint32_t max_proposal_pack,
    std::chrono::milliseconds delay,
    std::shared_ptr<transport::OnDemandOsServerGrpc::TransportFactoryType>
        transaction_factory,
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser,
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory,
    std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
        proposal_factory,
    std::shared_ptr<TransportFactoryType> proposal_transport_factory,
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_cache,
    logger::LoggerManagerTreePtr ordering_log_manager,
    std::shared_ptr<iroha::network::GenericClientFactory> client_factory,
    std::chrono::milliseconds proposal_creation_timeout,
    bool syncing_mode) {
  std::shared_ptr<OnDemandOrderingService> ordering_service;
  if (!syncing_mode) {
    ordering_service = createService(max_number_of_transactions,
                                     max_proposal_pack,
                                     proposal_factory,
                                     tx_cache,
                                     ordering_log_manager);
    service = std::make_shared<transport::OnDemandOsServerGrpc>(
        ordering_service,
        std::move(transaction_factory),
        std::move(batch_parser),
        std::move(transaction_batch_factory),
        ordering_log_manager->getChild("Server")->getLogger(),
        proposal_creation_timeout);
  }

  ordering_gate_ =
      createGate(ordering_service,
                 createConnectionManager(std::move(proposal_transport_factory),
                                         delay,
                                         ordering_log_manager,
                                         std::move(client_factory)),
                 std::move(proposal_factory),
                 std::move(tx_cache),
                 max_number_of_transactions,
                 ordering_log_manager,
                 syncing_mode);

  getSubscription()->dispatcher()->repeat(
      iroha::SubscriptionEngineHandlers::kMetrics,
      std::max(delay * 4, std::chrono::milliseconds(1000ull)),
      [round(consensus::Round(0ull, 0ull)),
       wgate(utils::make_weak(ordering_gate_))]() mutable {
        if (auto gate = wgate.lock()) {
          auto const new_round = gate->getRound();
          iroha::IrohaStatus status;
          status.is_healthy = (new_round != round);
          status.last_round = new_round;
          iroha::getSubscription()->notify(iroha::EventTypes::kOnIrohaStatus,
                                           status);
          round = new_round;
        }
      },
      [wgate(utils::make_weak(ordering_gate_))]() { return !wgate.expired(); });

  getSubscription()->dispatcher()->repeat(
      iroha::SubscriptionEngineHandlers::kMetrics,
      std::chrono::minutes(1ull),
      []() {
        iroha::IrohaStatus status;
        status.memory_consumption = getMemoryUsage();
        iroha::getSubscription()->notify(iroha::EventTypes::kOnIrohaStatus,
                                         status);
      },
      []() { return true; });

  return ordering_gate_;
}

iroha::ordering::RoundSwitch OnDemandOrderingInit::processSynchronizationEvent(
    synchronizer::SynchronizationEvent event) {
  iroha::consensus::Round current_round = event.round;

  auto &current_peers = event.ledger_state->ledger_peers;
  os_execution_keepers_->syncronize(
      current_peers.data(), current_peers.data() + current_peers.size());

  /// permutations for peers lists
  std::array<std::vector<size_t>, kCount> permutations;

  // generate permutation of peers list from corresponding round
  // hash
  auto generate_permutation = [&](auto &hash, auto round) {
    log_->debug("Using hash: {}", hash.toString());

    auto prng = iroha::makeSeededPrng(hash.blob().data(), hash.blob().size());
    iroha::generatePermutation(
        permutations[round()], std::move(prng), current_peers.size());
  };

  generate_permutation(previous_hash_, RoundTypeConstant<kCurrentRound>{});
  generate_permutation(current_hash_, RoundTypeConstant<kNextRound>{});

  using iroha::synchronizer::SynchronizationOutcomeType;
  switch (event.sync_outcome) {
    case SynchronizationOutcomeType::kCommit:
      current_round = nextCommitRound(current_round);
      break;
    case SynchronizationOutcomeType::kReject:
    case SynchronizationOutcomeType::kNothing:
      current_round = nextRejectRound(current_round);
      break;
    default:
      BOOST_ASSERT_MSG(false, "Unknown value");
  }

  auto getOsPeer = [&](auto block_round_advance, auto reject_round) {
    auto &permutation = permutations[block_round_advance];
    // since reject round can be greater than number of peers, wrap it
    // with number of peers
    auto &peer = current_peers[permutation[reject_round % permutation.size()]];
    log_->debug(
        "For {}, using OS on peer: {}",
        iroha::consensus::Round{current_round.block_round + block_round_advance,
                                reject_round},
        *peer);
    return peer;
  };

  OnDemandConnectionManager::CurrentPeers peers;
  /*
   * See detailed description in
   * irohad/ordering/impl/on_demand_connection_manager.cpp
   *
   *    0 1         0 1         0 1
   *  0 o .       0 o x       0 o .
   *  1 . .       1 . .       1 x .
   * Issuer      Reject      Commit
   *
   * o - current round, x - next round, v - target round
   *
   * v, round 0,1 - kRejectConsumer
   * v, round 1,0 - kCommitConsumer
   * o, round 0,0 - kIssuer
   */
  peers.peers.at(OnDemandConnectionManager::kRejectConsumer) =
      getOsPeer(kCurrentRound, nextRejectRound(current_round).reject_round);
  peers.peers.at(OnDemandConnectionManager::kCommitConsumer) =
      getOsPeer(kNextRound, nextCommitRound(current_round).reject_round);
  peers.peers.at(OnDemandConnectionManager::kIssuer) =
      getOsPeer(kCurrentRound, current_round.reject_round);

  connection_manager_->initializeConnections(peers, current_peers);

  return {std::move(current_round), event.ledger_state};
}

void OnDemandOrderingInit::processRoundSwitch(
    iroha::ordering::RoundSwitch const &event) {
  ordering_gate_->processRoundSwitch(event);
}

void OnDemandOrderingInit::processCommittedBlock(
    std::shared_ptr<shared_model::interface::Block const> block) {
  previous_hash_ = block->prevHash();
  current_hash_ = block->hash();

  // take committed & rejected transaction hashes from committed block
  log_->debug("Committed block handle: height {}.", block->height());
  if (!ordering_service_)
    return;

  auto hashes = std::make_shared<OnDemandOrderingService::HashesSetType>();
  for (shared_model::interface::Transaction const &tx : block->transactions()) {
    hashes->insert(tx.hash());
  }
  for (shared_model::crypto::Hash const &hash :
       block->rejected_transactions_hashes()) {
    hashes->insert(hash);
  }
  ordering_service_->onTxsCommitted(*hashes);
}

void OnDemandOrderingInit::subscribe(
    std::function<void(network::OrderingEvent const &)> callback) {
  proposals_subscription_ =
      SubscriberCreator<bool, ProposalEvent>::template create<
          EventTypes::kOnProposalResponse>(
          iroha::SubscriptionEngineHandlers::kYac,
          [ordering_gate(utils::make_weak(ordering_gate_))](auto, auto event) {
            if (auto maybe_ordering_gate = ordering_gate.lock())
              maybe_ordering_gate->processProposalRequest(std::move(event));
          });

  single_proposal_event_subscription_ =
      SubscriberCreator<bool, SingleProposalEvent>::template create<
          EventTypes::kOnProposalSingleEvent>(
          iroha::SubscriptionEngineHandlers::kYac,
          [ordering_gate(utils::make_weak(ordering_gate_)),
           callback(std::move(callback))](auto, auto event) {
            if (auto maybe_ordering_gate = ordering_gate.lock())
              if (auto maybe_event = maybe_ordering_gate->processProposalEvent(
                      std::move(event)))
                callback(*std::move(maybe_event));
          });
}
