/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_MST_TRANSPORT_HPP
#define IROHA_MOCK_MST_TRANSPORT_HPP

#include <gmock/gmock.h>
#include "network/mst_transport.hpp"

namespace iroha {
  class MockMstTransport : public network::MstTransport {
   public:
    MOCK_METHOD1(subscribe,
                 void(std::shared_ptr<network::MstTransportNotification>));
    MOCK_METHOD2(
        sendState,
        rxcpp::observable<bool>(const shared_model::interface::Peer &to,
                                const MstState &providing_state));
  };
}  // namespace iroha

#endif  // IROHA_MOCK_MST_TRANSPORT_HPP
