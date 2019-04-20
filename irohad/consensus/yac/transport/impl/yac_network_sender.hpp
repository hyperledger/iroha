/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_NETWORK_SENDER_HPP
#define IROHA_YAC_NETWORK_SENDER_HPP

#include "consensus/yac/transport/yac_network_interface.hpp"

#include <memory>
#include <rxcpp/rx.hpp>
#include <unordered_map>

namespace iroha {
  namespace consensus {
    namespace yac {
      /**
       * Transport layer wrapper which retries to send messages if the network
       * shut down
       */
      class YacNetworkSender : public YacNetwork {
       public:
        /// type of low transport level
        using TransportType = YacNetworkWithFeedBack;

        /// type of peer structure
        using PeerType = std::shared_ptr<shared_model::interface::Peer>;

        /// type of state
        using StateType = std::vector<VoteMessage>;

        YacNetworkSender(const YacNetworkSender &) = delete;
        YacNetworkSender(YacNetworkSender &&) = delete;
        YacNetworkSender &operator=(const YacNetworkSender &) = delete;
        YacNetworkSender &operator=(YacNetworkSender &&) = delete;

        /**
         * Creates transport with redelivery property
         * @param transport - instance of effective transport
         */
        YacNetworkSender(std::shared_ptr<TransportType> transport);

        void subscribe(
            std::shared_ptr<YacNetworkNotifications> handler) override;

        void sendState(PeerType to, StateType state) override;

       private:
        using StateInCollectionType = std::shared_ptr<StateType>;
        using StatesCollection =
            std::unordered_map<PeerType, StateInCollectionType>;

        static void sendStateViaTransport(
            PeerType to,
            StateInCollectionType state,
            std::shared_ptr<TransportType> transport);

        // ------------------------| Global state | ----------------------------
        std::shared_ptr<TransportType> transport_;

        // ------------------------| Current state | ---------------------------
        StatesCollection undelivered_states_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_YAC_NETWORK_SENDER_HPP
