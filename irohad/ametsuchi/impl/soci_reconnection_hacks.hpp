/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SOCI_RECONNECTION_HACKS_HPP
#define IROHA_SOCI_RECONNECTION_HACKS_HPP

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string_view>

#include <soci/soci.h>

namespace iroha::ametsuchi {
  class FailoverCallback;

  class SessionRenewedException : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
  };

  /// HACK! Gets the FailoverCallback from session.
  std::optional<std::reference_wrapper<FailoverCallback>> getFailoverCallback(
      soci::session &session);

  /// HACK! Checks number of times this session was reconnected.
  class ReconnectionThrowerHack {
   public:
    ReconnectionThrowerHack(soci::session &session);

    void throwIfReconnected(std::string_view message) const;

   private:
    std::optional<std::reference_wrapper<FailoverCallback>>
        maybe_failover_callback_;
    size_t session_reconnections_count_;
  };

}  // namespace iroha::ametsuchi

#define IROHA_SOCI_SQL_EXECUTE_THROW_IF_RECONNECTED(session, statement) \
  ReconnectionThrowerHack reconnection_checker{session};                \
  try {                                                                 \
    (session) << (statement);                                           \
  } catch (std::exception & e) {                                        \
    /* if there was a reconnection, throw specific exception */         \
    reconnection_checker.throwIfReconnected(e.what());                  \
    /* otherwise rethrow the original exception */                      \
    throw e;                                                            \
  }

#endif
