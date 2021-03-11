/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/subscription.hpp"

#include <fstream>

namespace iroha {

  std::shared_ptr<Subscription> getSubscription() {
    static std::shared_ptr<Subscription> engine =
        std::make_shared<Subscription>();
    return engine;
  }

}  // namespace iroha
