/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_COMMON_HPP
#define IROHA_SUBSCRIPTION_COMMON_HPP

#include <chrono>
#include <mutex>
#include <shared_mutex>

namespace iroha::utils {

  struct NoCopy {
    NoCopy(NoCopy const &) = delete;
    NoCopy &operator=(NoCopy const &) = delete;
    NoCopy() = default;
  };

  struct NoMove {
    NoMove(NoMove &&) = delete;
    NoMove &operator=(NoMove &&) = delete;
    NoMove() = default;
  };

  template <typename T>
  struct RWObjectHolder {
    template <typename... Args>
    RWObjectHolder(Args &&... args) : t_(std::forward<Args>(args)...) {}

    template <typename F>
    inline void exclusive(F &&f) {
      std::unique_lock lock(cs_);
      std::forward<F>(f)(t_);
    }

    template <typename F>
    inline void shared(F &&f) const {
      std::shared_lock lock(cs_);
      std::forward<F>(f)(t_);
    }

   private:
    T t_;
    mutable std::shared_mutex cs_;
  };

  class waitForSingleObject : NoMove, NoCopy {
    std::condition_variable wait_cv_;
    std::mutex wait_m_;
    std::atomic_flag wait_lock_;

   public:
    waitForSingleObject() {
      wait_lock_.test_and_set();
    }

    bool wait(uint64_t const wait_timeout_us) {
      std::unique_lock<std::mutex> _lock(wait_m_);
      return wait_cv_.wait_for(_lock,
                               std::chrono::microseconds(wait_timeout_us),
                               [&]() { return !wait_lock_.test_and_set(); });
    }

    void set() {
      wait_lock_.clear();
      wait_cv_.notify_one();
    }
  };
}  // namespace iroha::utils

#endif  // IROHA_SUBSCRIPTION_COMMON_HPP
