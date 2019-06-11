/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_NETWORK_INTERFACE_HPP
#define IROHA_YAC_NETWORK_INTERFACE_HPP

#include <boost/variant.hpp>
#include <memory>
#include <rxcpp/rx.hpp>
#include <vector>

namespace shared_model {
  namespace interface {
    class Peer;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace consensus {
    namespace yac {

      struct VoteMessage;

      class YacNetworkNotifications {
        // TODO: 2019-03-20 @muratovv add method virtual void
        // updatePeerList(...) IR-412
       public:
        /**
         * Callback on receiving collection of votes
         * @param state - provided message
         */
        virtual void onState(std::vector<VoteMessage> state) = 0;

        virtual ~YacNetworkNotifications() = default;
      };

      class YacNetwork {
        // TODO: 2019-03-20 @muratovv add method virtual void
        // updatePeerList(...) IR-412
       public:
        virtual void subscribe(
            std::shared_ptr<YacNetworkNotifications> handler) = 0;

        /**
         * Directly share collection of votes
         * @param to - peer recipient
         * @param state - message for sending
         */
        virtual void sendState(
            std::shared_ptr<shared_model::interface::Peer> to,
            std::vector<VoteMessage> state) = 0;

        // TODO: add method virtual void updatePeerList();

        /**
         * Virtual destructor required for inheritance
         */
        virtual ~YacNetwork() = default;
      };

      /// namespace contains statuses of sending messages
      namespace sending_statuses {
        /// status presents successful delivery of a message
        struct SuccessfulSent {};

        /// status presents that something happens with our network connection
        struct UnavailableNetwork {};

        /// status presents that recipient peer shut down or has bad connection
        struct UnavailableReceiver {};
      }  // namespace sending_statuses

      /**
       * The interface introduces blocking approach for YAC transport
       */
      class YacNetworkWithFeedBack {
        // TODO: 2019-03-20 @muratovv add method virtual void
        // updatePeerList(...) IR-412
       public:
        virtual void subscribe(
            std::shared_ptr<YacNetworkNotifications> handler) = 0;

        using StatusSentType =
            boost::variant<sending_statuses::SuccessfulSent,
                           sending_statuses::UnavailableNetwork,
                           sending_statuses::UnavailableReceiver>;
        using CallbackType = std::function<void(StatusSentType)>;
        /**
         * Directly share collection of votes.
         * Note: method assumes blocking approach for the propagation
         * @param to - peer recipient
         * @param state - message for sending
         * @return status of sending
         */
        virtual void sendState(const shared_model::interface::Peer &to,
                               const std::vector<VoteMessage> &state,
                               CallbackType) = 0;

        // TODO: add method virtual void updatePeerList();

        ~YacNetworkWithFeedBack() = default;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_NETWORK_INTERFACE_HPP
