/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STUBBORN_CALLER_HPP
#define IROHA_STUBBORN_CALLER_HPP

#include <utility>

#include "logger/logger.hpp"

namespace iroha {

  /**
   * Invokes callable with args until given exception is not thrown.
   * @tparam Exception whith exception to catch for retry
   * @param Callable type
   * @param Args types
   * @param callable to invoke
   * @param args to pass to @a callable
   * @return whatever @a callable returns when it does not throw
   */
  template <typename Exception, typename Callable, typename... Args>
  inline auto retryOnException(logger::LoggerPtr log,
                               Callable &&callable,
                               Args &&... args) {
    while (true) {
      try {
        return std::forward<Callable>(callable)(std::forward<Args>(args)...);
      } catch (Exception const &e) {
        log->warn("Retrying after exception: {}", e.what());
      }
    }
  }
}  // namespace iroha

#endif
