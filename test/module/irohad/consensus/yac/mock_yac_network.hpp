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
        MOCK_METHOD2(sendState,
                     void(const shared_model::interface::Peer &,
                          const std::vector<VoteMessage> &));

        MOCK_METHOD0(stop, void());
      };

      class MockYacNetworkNotifications : public YacNetworkNotifications {
       public:
        MOCK_METHOD1(onState, std::optional<Answer>(std::vector<VoteMessage>));
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_NETWORK_HPP
