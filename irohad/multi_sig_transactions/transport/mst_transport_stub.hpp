/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TRANSPORT_STUB_HPP
#define IROHA_MST_TRANSPORT_STUB_HPP

#include "network/mst_transport.hpp"

namespace iroha {
  namespace network {
    class MstTransportStub : public MstTransport {
     public:
      void subscribe(std::shared_ptr<MstTransportNotification>) override;

      rxcpp::observable<bool> sendState(
          std::shared_ptr<shared_model::interface::Peer const>,
          MstState const &) override;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_MST_TRANSPORT_STUB_HPP
