/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MAIN_WATCHDOG_HPP
#define IROHA_MAIN_WATCHDOG_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <boost/optional/optional_fwd.hpp>
#include "common/result_fwd.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha {

  struct Watchdog final {
    Watchdog(Watchdog const &) = delete;
    Watchdog &operator=(Watchdog const &) = delete;

    Watchdog(Watchdog &&) = delete;
    Watchdog &operator=(Watchdog &&) = delete;

    Watchdog() {
      work_.test_and_set();
      worker_ = std::thread(
          [](auto *_this) {
            _this->reset();
            while (_this->work_.test_and_set(std::memory_order_relaxed)) {
              if (_this->bitten_.test_and_set())
                __builtin_trap();
              std::this_thread::sleep_for(std::chrono::minutes(1ull));
            }
          },
          this);
    }

    ~Watchdog() {
      work_.clear();
      worker_.join();
    }

    void reset() {
      bitten_.clear();
    }

   private:
    std::thread worker_;
    std::atomic_flag bitten_;
    std::atomic_flag work_;
  };

  std::shared_ptr<Watchdog> getWatchdog();

}  // namespace iroha

#endif //IROHA_MAIN_WATCHDOG_HPP
