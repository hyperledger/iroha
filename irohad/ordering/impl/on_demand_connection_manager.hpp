/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_CONNECTION_MANAGER_HPP
#define IROHA_ON_DEMAND_CONNECTION_MANAGER_HPP

#include "ordering/on_demand_os_transport.hpp"

#include <atomic>
#include <shared_mutex>

#include <rxcpp/rx.hpp>
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ordering {

    /**
     * Proxy class which redirects requests to appropriate peers
     */
    class OnDemandConnectionManager : public transport::OdOsNotification {
     public:
      /**
       * Responsibilities of individual peers from the peers array
       * Transactions are sent to three ordering services:
       * reject round for current block, reject round for next block, and
       * commit for subsequent next round
       * Proposal is requested from the current ordering service: issuer
       */
      enum PeerType {
        kRejectRejectConsumer = 0,
        kRejectCommitConsumer,
        kCommitRejectConsumer,
        kCommitCommitConsumer,
        kIssuer,
        kCount
      };

      /// Collection with value types which represent peers
      template <typename T>
      using PeerCollectionType = std::array<T, kCount>;

      /**
       * Current peers to send transactions and request proposals
       * @see PeerType for individual descriptions
       */
      struct CurrentPeers {
        PeerCollectionType<std::shared_ptr<shared_model::interface::Peer>>
            peers;
      };

      OnDemandConnectionManager(
          std::shared_ptr<transport::OdOsNotificationFactory> factory,
          rxcpp::observable<CurrentPeers> peers,
          logger::LoggerPtr log);

      OnDemandConnectionManager(
          std::shared_ptr<transport::OdOsNotificationFactory> factory,
          rxcpp::observable<CurrentPeers> peers,
          CurrentPeers initial_peers,
          logger::LoggerPtr log);

      ~OnDemandConnectionManager() override;

      void onBatches(CollectionType batches) override;

      boost::optional<std::shared_ptr<const ProposalType>> onRequestProposal(
          consensus::Round round) override;

     private:
      /**
       * Corresponding connections created by OdOsNotificationFactory
       * @see PeerType for individual descriptions
       */
      struct CurrentConnections {
        PeerCollectionType<std::unique_ptr<transport::OdOsNotification>> peers;
      };

      /**
       * Initialize corresponding peers in connections_ using factory_
       * @param peers to initialize connections with
       */
      void initializeConnections(const CurrentPeers &peers);

      logger::LoggerPtr log_;
      std::shared_ptr<transport::OdOsNotificationFactory> factory_;
      rxcpp::composite_subscription subscription_;

      CurrentConnections connections_;

      std::shared_timed_mutex mutex_;
      std::atomic_bool stop_requested_{false};
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_CONNECTION_MANAGER_HPP
