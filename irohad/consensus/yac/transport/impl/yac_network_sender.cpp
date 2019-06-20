/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/transport/impl/yac_network_sender.hpp"

#include "common/visitor.hpp"
#include "consensus/yac/vote_message.hpp"
#include "logger/logger.hpp"

using namespace iroha::consensus::yac;

namespace {
  const uint64_t kMaxResendingAttempts = 1;

  void sendStateViaTransportAsync(
      YacNetworkSender::PeerType to,
      std::shared_ptr<YacNetworkSender::StateType> state,
      std::weak_ptr<YacNetworkSender::TransportType> transport,
      logger::LoggerPtr log,
      uint64_t remaining_attempts) {
    auto reconnect =
        [to, state, transport, log = std::move(log), remaining_attempts](
            auto status) {
          static const auto is_problem_with_our_network =
              [](const auto &result) -> bool {
            return boost::strict_get<sending_statuses::UnavailableNetwork &>(
                &result);
          };
          if (is_problem_with_our_network(status)) {
            if (remaining_attempts > 0) {
              log->debug("Retrying to send the message to {}.", *to);
              sendStateViaTransportAsync(std::move(to),
                                         std::move(state),
                                         std::move(transport),
                                         std::move(log),
                                         remaining_attempts - 1);
            } else {
              log->info(
                  "The number of resending attempts exceeded {}. "
                  "Dropping message to {}.",
                  kMaxResendingAttempts,
                  *to);
            }
          } else {
            log->debug("Message to {} sent successfully.", *to);
          }
        };
    if (auto t = transport.lock()) {
      t->sendState(*to, *state, reconnect);
    }
  }
}  // namespace

YacNetworkSender::YacNetworkSender(std::shared_ptr<TransportType> transport,
                                   logger::LoggerPtr log)
    : transport_(std::move(transport)), log_(std::move(log)) {}

void YacNetworkSender::subscribe(
    std::shared_ptr<YacNetworkNotifications> handler) {
  transport_->subscribe(std::move(handler));
}

void YacNetworkSender::sendState(PeerType to, StateType state) {
  sendStateViaTransportAsync(to,
                             std::make_shared<StateType>(state),
                             transport_,
                             log_,
                             kMaxResendingAttempts);
}
