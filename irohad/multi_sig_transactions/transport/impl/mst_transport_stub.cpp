/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/transport/mst_transport_stub.hpp"

namespace iroha {
  namespace network {

    void MstTransportStub::subscribe(
        std::shared_ptr<MstTransportNotification>) {}

    void MstTransportStub::sendState(const shared_model::interface::Peer &,
                                     ConstRefState) {}
  }  // namespace network
}  // namespace iroha
