/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/soci_reconnection_hacks.hpp"

#include <soci/callbacks.h>
#include <soci/soci.h>
#include "ametsuchi/impl/failover_callback.hpp"
#include "common/bind.hpp"

using namespace iroha::ametsuchi;

using iroha::operator|;

std::optional<std::reference_wrapper<FailoverCallback>>
iroha::ametsuchi::getFailoverCallback(soci::session &session) {
  auto maybe_callback = session.get_backend()->failoverCallback_;
  if (maybe_callback) {
    return static_cast<FailoverCallback &>(*maybe_callback);
  }
  return std::nullopt;
}

ReconnectionThrowerHack::ReconnectionThrowerHack(soci::session &session)
    : maybe_failover_callback_(getFailoverCallback(session)),
      session_reconnections_count_(
          maybe_failover_callback_ | [](auto callback) {
            return callback.get().getSessionReconnectionsCount();
          }){};

void ReconnectionThrowerHack::throwIfReconnected(char const *message) const {
  maybe_failover_callback_ | [&](auto callback) {
    auto const new_session_reconnections_count =
        callback.get().getSessionReconnectionsCount();
    if (session_reconnections_count_ < new_session_reconnections_count) {
      throw SessionRenewedException{message};
    }
  };
}
