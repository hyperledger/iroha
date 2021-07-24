/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/subscription.hpp"

#include "subscription/async_dispatcher_impl.hpp"

namespace iroha {

  std::shared_ptr<Dispatcher> getDispatcher() {
    return std::make_shared<
        subscription::AsyncDispatcher<SubscriptionEngineHandlers::kTotalCount,
                                      kThreadPoolSize>>();
  }

}  // namespace iroha
