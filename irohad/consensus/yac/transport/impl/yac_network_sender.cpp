/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/transport/impl/yac_network_sender.hpp"

#include "common/visitor.hpp"
#include "consensus/yac/vote_message.hpp"

using namespace iroha::consensus::yac;

YacNetworkSender::YacNetworkSender(std::shared_ptr<TransportType> transport)
    : transport_(std::move(transport)) {}

void YacNetworkSender::subscribe(
    std::shared_ptr<YacNetworkNotifications> handler) {
  transport_->subscribe(std::move(handler));
}

void YacNetworkSender::sendState(PeerType to, StateType state) {
  sendStateViaTransport(
      to, std::make_shared<StateType>(std::move(state)), transport_);
}

void YacNetworkSender::sendStateViaTransport(
    PeerType to,
    StateInCollectionType state,
    std::shared_ptr<TransportType> transport) {
  transport->sendState(*to, *state)
      .subscribe([transport = transport, to, state](const auto &result) {
        iroha::visit_in_place(
            result,
            [transport, to, state](
                const sending_statuses::UnavailableNetwork &) {
              // assume the message is undelivered if troubles occur with our
              // connection then it will resend the message

              sendStateViaTransport(to, state, transport);
            },
            [&](const auto &) {
              // if message delivers or recipient peer goes down then it
              // will stop resending the message
            });
      });
}
