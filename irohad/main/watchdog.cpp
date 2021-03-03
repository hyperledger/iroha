/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/watchdog.hpp"

namespace iroha {
  std::shared_ptr<Watchdog> getWatchdog() {
    static std::shared_ptr<Watchdog> wd = std::make_shared<Watchdog>();
    return wd;
  }

}
