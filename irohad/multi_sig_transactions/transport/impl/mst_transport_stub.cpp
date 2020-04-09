/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/transport/mst_transport_stub.hpp"

#include <rxcpp/rx-lite.hpp>

namespace iroha {
  namespace network {

    void MstTransportStub::subscribe(
        std::shared_ptr<MstTransportNotification>) {}

    rxcpp::observable<bool> MstTransportStub::sendState(
        const shared_model::interface::Peer &, MstState const &) {
      return rxcpp::observable<>::just(true);
    }
  }  // namespace network
}  // namespace iroha
