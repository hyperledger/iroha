/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_INIT_HPP
#define IROHA_ON_DEMAND_ORDERING_INIT_HPP

#include <chrono>
#include <vector>

#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/subscription_fwd.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/impl/round_switch.hpp"

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
    struct OrderingEvent;
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
}  // namespace iroha

namespace iroha::ordering {
  class OnDemandConnectionManager;
  class OnDemandOrderingGate;
  class OnDemandOrderingService;
  class ExecutorKeeper;
  struct ProposalEvent;
  namespace transport {
    class OdOsNotification;
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
        std::shared_ptr<TransportFactoryType> proposal_transport_factory,
        std::chrono::milliseconds delay,
        const logger::LoggerManagerTreePtr &ordering_log_manager,
        std::shared_ptr<iroha::network::GenericClientFactory> client_factory);

    /**
     * Creates on-demand ordering gate. \see initOrderingGate for parameters
     * TODO andrei 31.10.18 IR-1825 Refactor ordering gate observable
     */
    auto createGate(
        std::shared_ptr<OnDemandOrderingService> ordering_service,
        std::shared_ptr<transport::OdOsNotification> network_client,
        std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
            proposal_factory,
        std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
        size_t max_number_of_transactions,
        const logger::LoggerManagerTreePtr &ordering_log_manager,
        bool syncing_mode);

    /**
     * Creates on-demand ordering service. \see initOrderingGate for
     * parameters
     */
    auto createService(
        size_t max_number_of_transactions,
        uint32_t max_proposal_pack,
        std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
            proposal_factory,
        std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
        const logger::LoggerManagerTreePtr &ordering_log_manager);

   public:
    /// Constructor.
    /// @param log - the logger to use for internal messages.
    OnDemandOrderingInit(logger::LoggerPtr log);

    /**
     * Initializes on-demand ordering gate and ordering sevice components
     *
     * @param max_number_of_transactions maximum number of transactions in a
     * proposal
     * @param delay timeout for ordering service response on proposal request
     * @param transaction_factory transport factory for transactions required
     * by ordering service network endpoint
     * @param batch_parser transaction batch parser required by ordering
     * service network endpoint
     * @param transaction_batch_factory transport factory for transaction
     * batch candidates produced by parser
     * @param proposal_factory factory required by ordering service to produce
     * proposals
     * @param client_factory - a factory of client stubs
     * @return initialized ordering gate
     */
    std::shared_ptr<network::OrderingGate> initOrderingGate(
        size_t max_number_of_transactions,
        uint32_t max_proposal_pack,
        std::chrono::milliseconds delay,
        std::shared_ptr<shared_model::interface::AbstractTransportFactory<
            shared_model::interface::Transaction,
            iroha::protocol::Transaction>> transaction_factory,
        std::shared_ptr<shared_model::interface::TransactionBatchParser>
            batch_parser,
        std::shared_ptr<shared_model::interface::TransactionBatchFactory>
            transaction_batch_factory,
        std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
            proposal_factory,
        std::shared_ptr<TransportFactoryType> proposal_transport_factory,
        std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
        logger::LoggerManagerTreePtr ordering_log_manager,
        std::shared_ptr<iroha::network::GenericClientFactory> client_factory,
        std::chrono::milliseconds proposal_creation_timeout,
        bool syncing_mode);

    iroha::ordering::RoundSwitch processSynchronizationEvent(
        synchronizer::SynchronizationEvent event);

    void processRoundSwitch(iroha::ordering::RoundSwitch const &event);

    void processCommittedBlock(
        std::shared_ptr<shared_model::interface::Block const> block);

    void subscribe(
        std::function<void(network::OrderingEvent const &)> callback);

    /// gRPC service for ordering service
    std::shared_ptr<grpc::Service> service;

   private:
    shared_model::crypto::Hash previous_hash_, current_hash_;
    logger::LoggerPtr log_;
    std::shared_ptr<OnDemandOrderingService> ordering_service_;
    std::shared_ptr<OnDemandConnectionManager> connection_manager_;
    std::shared_ptr<OnDemandOrderingGate> ordering_gate_;
    std::shared_ptr<BaseSubscriber<bool, ProposalEvent>>
        proposals_subscription_;
    std::shared_ptr<BaseSubscriber<bool, SingleProposalEvent>>
        single_proposal_event_subscription_;
    std::shared_ptr<ExecutorKeeper> os_execution_keepers_;
  };
}  // namespace iroha::ordering

#endif  // IROHA_ON_DEMAND_ORDERING_INIT_HPP
