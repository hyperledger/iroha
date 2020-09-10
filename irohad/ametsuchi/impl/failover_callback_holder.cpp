/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/failover_callback_holder.hpp"

using namespace iroha::ametsuchi;

void FailoverCallbackHolder::addOnReconnectedHandler(
    std::shared_ptr<FailoverCallback::OnReconnectedHandler> handler) {
  reconnection_handlers_.emplace_back(std::move(handler));
}

FailoverCallback &FailoverCallbackHolder::makeFailoverCallback(
    soci::session &connection,
    std::string connection_options,
    std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
    logger::LoggerPtr log) {
  FailoverCallback &the_callback = *callbacks_.emplace_back(
      std::make_unique<FailoverCallback>(connection,
                                         std::move(connection_options),
                                         std::move(reconnection_strategy),
                                         std::move(log)));
  for (auto const &handler : reconnection_handlers_) {
    the_callback.addOnReconnectedHandler(handler);
  }
  return the_callback;
}
