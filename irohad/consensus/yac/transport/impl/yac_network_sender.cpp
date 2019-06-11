/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/transport/impl/yac_network_sender.hpp"

#include "common/visitor.hpp"
#include "consensus/yac/vote_message.hpp"
#include "logger/logger.hpp"

using namespace iroha::consensus::yac;

YacNetworkSender::YacNetworkSender(std::shared_ptr<TransportType> transport,
                                   logger::LoggerPtr log)
    : transport_(std::move(transport)), log_(std::move(log)) {}

void YacNetworkSender::subscribe(
    std::shared_ptr<YacNetworkNotifications> handler) {
  transport_->subscribe(std::move(handler));
}

void YacNetworkSender::sendState(PeerType to, StateType state) {
  sendStateViaTransportAsync(
      to, std::make_shared<StateType>(state), transport_, log_, 1);
}

void YacNetworkSender::sendStateViaTransportAsync(
    PeerType to,
    StateInCollectionType state,
    std::weak_ptr<TransportType> transport,
    logger::LoggerPtr log,
    uint64_t rest_attempts) {
  auto reconnect =
      [to, state, transport, log = std::move(log), rest_attempts](auto status) {
        iroha::visit_in_place(
            status,
            [=](const sending_statuses::UnavailableNetwork &) {
              // assume the message is undelivered if troubles
              // occur with our connection then it will resend the
              // message
              if (rest_attempts > 0) {
                log->info("Retry to send a message");
                sendStateViaTransportAsync(std::move(to),
                                           std::move(state),
                                           std::move(transport),
                                           std::move(log),
                                           rest_attempts - 1);
              } else {
                log->info("exceeded number of reconnection attempts");
              }
            },
            [log = std::move(log)](const auto &) {
              // if message delivers or recipient peer goes down
              // then it will stop resending the message
              log->info("On transport call - done");
            });
      };
  if (auto t = transport.lock()) {
    t->sendState(*to, *state, reconnect);
  }
}
