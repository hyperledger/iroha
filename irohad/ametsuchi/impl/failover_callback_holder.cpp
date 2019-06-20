/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/failover_callback_holder.hpp"

using namespace iroha::ametsuchi;

FailoverCallback &FailoverCallbackHolder::makeFailoverCallback(
    soci::session &connection,
    FailoverCallback::InitFunctionType init,
    std::string connection_options,
    std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
    logger::LoggerPtr log) {
  callbacks_.push_back(
      std::make_unique<FailoverCallback>(connection,
                                         std::move(init),
                                         std::move(connection_options),
                                         std::move(reconnection_strategy),
                                         std::move(log)));
  return *callbacks_.back();
}
