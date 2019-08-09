/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_INIT_HPP
#define IROHA_ON_DEMAND_ORDERING_INIT_HPP

#include <random>

#include "ametsuchi/storage.hpp"
#include "ametsuchi/tx_presence_cache.hpp"
#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "network/ordering_gate.hpp"
#include "network/peer_communication_service.hpp"
#include "ordering.grpc.pb.h"
#include "ordering/impl/on_demand_os_server_grpc.hpp"
#include "ordering/impl/ordering_gate_cache/ordering_gate_cache.hpp"
#include "ordering/on_demand_ordering_service.hpp"
#include "ordering/ordering_service_proposal_creation_strategy.hpp"

namespace iroha {
  namespace network {

    /**
     * Encapsulates initialization logic for on-demand ordering gate and service
     */
    class OnDemandOrderingInit {
     public:
      using TransportFactoryType =
          shared_model::interface::AbstractTransportFactory<
              shared_model::interface::Proposal,
              iroha::protocol::Proposal>;

     private:
      /**
       * Creates notification factory for individual connections to peers with
       * gRPC backend. \see initOrderingGate for parameters
       */
      auto createNotificationFactory(
          std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
              async_call,
          std::shared_ptr<TransportFactoryType> proposal_transport_factory,
          std::chrono::milliseconds delay,
          const logger::LoggerManagerTreePtr &ordering_log_manager);

      /**
       * Creates connection manager which redirects requests to appropriate
       * ordering services in the current round. \see initOrderingGate for
       * parameters
       */
      auto createConnectionManager(
          std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
              async_call,
          std::shared_ptr<TransportFactoryType> proposal_transport_factory,
          std::chrono::milliseconds delay,
          std::vector<shared_model::interface::types::HashType> initial_hashes,
          const logger::LoggerManagerTreePtr &ordering_log_manager);

      /**
       * Creates on-demand ordering gate. \see initOrderingGate for parameters
       * TODO andrei 31.10.18 IR-1825 Refactor ordering gate observable
       */
      auto createGate(
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
          const logger::LoggerManagerTreePtr &ordering_log_manager);

      /**
       * Creates on-demand ordering service. \see initOrderingGate for
       * parameters
       */
      auto createService(
          size_t max_number_of_transactions,
          std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
              proposal_factory,
          std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
          std::shared_ptr<ordering::ProposalCreationStrategy> creation_strategy,
          const logger::LoggerManagerTreePtr &ordering_log_manager);

      rxcpp::composite_subscription sync_event_notifier_lifetime_;
      rxcpp::composite_subscription commit_notifier_lifetime_;

     public:
      /// Constructor.
      /// @param log - the logger to use for internal messages.
      OnDemandOrderingInit(logger::LoggerPtr log);

      ~OnDemandOrderingInit();

      /**
       * Initializes on-demand ordering gate and ordering sevice components
       *
       * @param max_number_of_transactions maximum number of transactions in a
       * proposal
       * @param delay timeout for ordering service response on proposal request
       * @param initial_hashes seeds for peer list permutations for first k
       * rounds they are required since hash of block i defines round i + k
       * @param transaction_factory transport factory for transactions required
       * by ordering service network endpoint
       * @param batch_parser transaction batch parser required by ordering
       * service network endpoint
       * @param transaction_batch_factory transport factory for transaction
       * batch candidates produced by parser
       * @param async_call asynchronous gRPC client required for sending batches
       * requests to ordering service and processing responses
       * @param proposal_factory factory required by ordering service to produce
       * proposals
       * @param creation_strategy - provides a strategy for creating proposals
       * in OS
       * @return initialized ordering gate
       */
      std::shared_ptr<network::OrderingGate> initOrderingGate(
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
          logger::LoggerManagerTreePtr ordering_log_manager);

      /// gRPC service for ordering service
      std::shared_ptr<ordering::proto::OnDemandOrdering::Service> service;

      /// commit notifier from peer communication service
      rxcpp::subjects::subject<decltype(std::declval<PeerCommunicationService>()
                                            .onSynchronization())::value_type>
          sync_event_notifier;
      rxcpp::subjects::subject<decltype(
          std::declval<iroha::ametsuchi::Storage>().on_commit())::value_type>
          commit_notifier;

     private:
      logger::LoggerPtr log_;

      boost::optional<consensus::Round> last_received_round_;

      std::vector<std::shared_ptr<shared_model::interface::Peer>>
          current_peers_;

      /// indexes to permutations for corresponding rounds
      enum RoundType { kCurrentRound, kNextRound, kRoundAfterNext, kCount };

      template <RoundType V>
      using RoundTypeConstant = std::integral_constant<RoundType, V>;

      /// permutations for peers lists
      std::array<std::vector<size_t>, kCount> permutations_;

      /// random generator for peer list permutations
      // TODO andrei 08.11.2018 IR-1850 Refactor default_random_engine usages
      // with platform-independent class
      std::default_random_engine gen_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_INIT_HPP
