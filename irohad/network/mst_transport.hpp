/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TRANSPORT_HPP
#define IROHA_MST_TRANSPORT_HPP

#include <memory>

#include <rxcpp/rx-observable-fwd.hpp>
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace iroha {

  class MstState;

  namespace network {

    /**
     * Interface represents handler for multi-signature notifications
     */
    class MstTransportNotification {
     public:
      /**
       * Handler method for updating state, when new data received
       * @param from - key of the peer emitted the state
       * @param new_state - state propagated from peer
       */
      virtual void onNewState(
          shared_model::interface::types::PublicKeyHexStringView from,
          MstState &&new_state) = 0;

      virtual ~MstTransportNotification() = default;
    };

    /**
     * Interface of transport
     * for propagating multi-signature transactions in network
     */
    class MstTransport {
     public:
      /**
       * Subscribe object for receiving notifications
       * @param notification - object that will be notified on updates
       */
      virtual void subscribe(
          std::shared_ptr<MstTransportNotification> notification) = 0;

      /**
       * Share state with other peer
       * @param to - peer recipient of message
       * @param providing_state - state for transmitting
       * @return true if transmission was successful, false otherwise
       */
      virtual rxcpp::observable<bool> sendState(
          std::shared_ptr<shared_model::interface::Peer const> to,
          MstState const &providing_state) = 0;

      virtual ~MstTransport() = default;
    };
  }  // namespace network
}  // namespace iroha
#endif  // IROHA_MST_TRANSPORT_HPP
