/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_CONNECTION_MANAGER_HPP
#define IROHA_ON_DEMAND_CONNECTION_MANAGER_HPP

#include <array>
#include <atomic>
#include <shared_mutex>

#include "logger/logger_fwd.hpp"
#include "ordering/on_demand_os_transport.hpp"

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
       * current round (issuer), reject round, and commit round
       * Proposal is requested from the current ordering service: issuer
       */
      enum PeerType { kRejectConsumer = 0, kCommitConsumer, kIssuer, kCount };

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
          logger::LoggerPtr log);

      OnDemandConnectionManager(
          std::shared_ptr<transport::OdOsNotificationFactory> factory,
          CurrentPeers initial_peers,
          logger::LoggerPtr log);

      ~OnDemandConnectionManager() override;

      void onBatches(CollectionType batches) override;

      void onRequestProposal(consensus::Round,
                             shared_model::crypto::Hash const &) override;

      /**
       * Initialize corresponding peers in connections_ using factory_
       * @param peers to initialize connections with
       */
      void initializeConnections(const CurrentPeers &peers);

     private:
      /**
       * Corresponding connections created by OdOsNotificationFactory
       * @see PeerType for individual descriptions
       */
      struct CurrentConnections {
        PeerCollectionType<
            std::optional<std::unique_ptr<transport::OdOsNotification>>>
            peers;
      };

      logger::LoggerPtr log_;
      std::shared_ptr<transport::OdOsNotificationFactory> factory_;

      CurrentConnections connections_;

      std::shared_timed_mutex mutex_;
      std::atomic_bool stop_requested_{false};
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_CONNECTION_MANAGER_HPP
