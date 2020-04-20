/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_MST_TRANSPORT_NOTIFICATION_HPP
#define IROHA_MOCK_MST_TRANSPORT_NOTIFICATION_HPP

#include <gmock/gmock.h>
#include "network/mst_transport.hpp"

namespace iroha {
  /**
   * Transport notification mock
   */
  class MockMstTransportNotification
      : public network::MstTransportNotification {
   public:
    MOCK_METHOD2(onNewState,
                 void(shared_model::interface::types::PublicKeyHexStringView,
                      MstState &&));
  };
}  // namespace iroha

#endif  // IROHA_MOCK_MST_TRANSPORT_NOTIFICATION_HPP
