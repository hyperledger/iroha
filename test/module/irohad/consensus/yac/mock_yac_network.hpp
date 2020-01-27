/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_NETWORK_HPP
#define IROHA_MOCK_YAC_NETWORK_HPP

#include <gmock/gmock.h>

#include "consensus/yac/transport/yac_network_interface.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class MockYacNetwork : public YacNetwork {
       public:
        void subscribe(
            std::shared_ptr<YacNetworkNotifications> handler) override {
          notification = std::move(handler);
        };

        void release() {
          notification.reset();
        }

        MOCK_METHOD2(sendState,
                     void(const shared_model::interface::Peer &,
                          const std::vector<VoteMessage> &));

        MockYacNetwork() = default;

        MockYacNetwork(const MockYacNetwork &rhs)
            : notification(rhs.notification) {}

        MockYacNetwork &operator=(const MockYacNetwork &rhs) {
          notification = rhs.notification;
          return *this;
        }

        MockYacNetwork(MockYacNetwork &&rhs) {
          std::swap(notification, rhs.notification);
        }

        MockYacNetwork &operator=(MockYacNetwork &&rhs) {
          std::swap(notification, rhs.notification);
          return *this;
        }

        std::shared_ptr<YacNetworkNotifications> notification;
      };

      class MockYacNetworkNotifications : public YacNetworkNotifications {
       public:
        MOCK_METHOD1(onState, void(std::vector<VoteMessage>));
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_NETWORK_HPP
