/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/subscription.hpp"

#include <mutex>

namespace iroha {

  std::shared_ptr<Subscription> getSubscription() {
    static std::weak_ptr<Subscription> engine;
    if (auto ptr = engine.lock())
      return ptr;

    static std::mutex engine_cs;
    std::lock_guard<std::mutex> lock(engine_cs);
    if (auto ptr = engine.lock())
      return ptr;

    auto ptr = std::make_shared<Subscription>(getDispatcher());
    engine = ptr;
    return ptr;
  }

}  // namespace iroha
