/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/soci_reconnection_hacks.hpp"

#include <algorithm>
#include <string_view>

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

void ReconnectionThrowerHack::throwIfReconnected(
    std::string_view message) const {
  // check message blacklist
  std::array<std::string_view, 2> const kExceptionBlacklist = {
      "contains unexpected zero page", "Connection failed."};

  if (std::any_of(kExceptionBlacklist.begin(),
                  kExceptionBlacklist.end(),
                  [&](std::string_view substr) {
                    return message.find(substr) != std::string_view::npos;
                  })) {
    throw SessionRenewedException{message.data()};
  }

  maybe_failover_callback_ | [&](auto callback) {
    auto const new_session_reconnections_count =
        callback.get().getSessionReconnectionsCount();
    if (session_reconnections_count_ < new_session_reconnections_count) {
      throw SessionRenewedException{message.data()};
    }
  };
}
