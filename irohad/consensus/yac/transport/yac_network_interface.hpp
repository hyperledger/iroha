/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_NETWORK_INTERFACE_HPP
#define IROHA_YAC_NETWORK_INTERFACE_HPP

#include <memory>
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
       public:
        /**
         * Callback on receiving collection of votes
         * @param state - provided message
         */
        virtual void onState(std::vector<VoteMessage> state) = 0;

        virtual ~YacNetworkNotifications() = default;
      };

      class YacNetwork {
       public:
        virtual void subscribe(
            std::shared_ptr<YacNetworkNotifications> handler) = 0;

        /**
         * Directly share collection of votes
         * @param to - peer recipient
         * @param state - message for sending
         */
        virtual void sendState(const shared_model::interface::Peer &to,
                               const std::vector<VoteMessage> &state) = 0;

        /**
         * Virtual destructor required for inheritance
         */
        virtual ~YacNetwork() = default;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_NETWORK_INTERFACE_HPP
