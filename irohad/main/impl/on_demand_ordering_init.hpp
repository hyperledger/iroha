/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_INIT_HPP
#define IROHA_ON_DEMAND_ORDERING_INIT_HPP

#include <chrono>
#include <vector>

#include <rxcpp/rx-lite.hpp>
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace google {
  namespace protobuf {
    class Empty;
  }
}  // namespace google

namespace grpc {
  class Service;
}

namespace shared_model {
  namespace interface {
    class Proposal;
    class Transaction;
    class Block;
    template <typename Interface, typename Transport>
    class AbstractTransportFactory;
    class UnsafeProposalFactory;
    class TransactionBatchParser;
    class TransactionBatchFactory;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace network {
    class GenericClientFactory;
    template <typename Response>
    class AsyncGrpcClient;
    class OrderingGate;
  }  // namespace network
  namespace protocol {
    class Proposal;
    class Transaction;
  }  // namespace protocol
  namespace ametsuchi {
    class TxPresenceCache;
  }
  namespace synchronizer {
    struct SynchronizationEvent;
  }
  namespace ordering {
    class OnDemandOrderingService;
    class ProposalCreationStrategy;
    namespace transport {
      class OdOsNotification;
    }
    namespace cache {
      class OrderingGateCache;
    }

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
          const logger::LoggerManagerTreePtr &ordering_log_manager,
          std::shared_ptr<iroha::network::GenericClientFactory> client_factory);

      /**
       * Creates on-demand ordering gate. \see initOrderingGate for parameters
       * TODO andrei 31.10.18 IR-1825 Refactor ordering gate observable
       */
      auto createGate(
          std::shared_ptr<OnDemandOrderingService> ordering_service,
          std::unique_ptr<transport::OdOsNotification> network_client,
          std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
              proposal_factory,
          std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
          std::shared_ptr<ProposalCreationStrategy> creation_strategy,
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
          std::shared_ptr<ProposalCreationStrategy> creation_strategy,
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
       * @param client_factory - a factory of client stubs
       * @return initialized ordering gate
       */
      std::shared_ptr<network::OrderingGate> initOrderingGate(
          size_t max_number_of_transactions,
          std::chrono::milliseconds delay,
          std::vector<shared_model::interface::types::HashType> initial_hashes,
          std::shared_ptr<shared_model::interface::AbstractTransportFactory<
              shared_model::interface::Transaction,
              iroha::protocol::Transaction>> transaction_factory,
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
          std::shared_ptr<ProposalCreationStrategy> creation_strategy,
          logger::LoggerManagerTreePtr ordering_log_manager,
          std::shared_ptr<iroha::network::GenericClientFactory> client_factory);

      /// gRPC service for ordering service
      std::shared_ptr<grpc::Service> service;

      /// commit notifier from peer communication service
      rxcpp::subjects::subject<synchronizer::SynchronizationEvent>
          sync_event_notifier;
      rxcpp::subjects::subject<
          std::shared_ptr<shared_model::interface::Block const>>
          commit_notifier;

     private:
      logger::LoggerPtr log_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_INIT_HPP
