/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_COMMON_HPP
#define IROHA_SUBSCRIPTION_COMMON_HPP

#include <chrono>
#include <mutex>
#include <shared_mutex>

#if __clang__
namespace std {

  template <typename To, typename From>
  inline std::shared_ptr<To> reinterpret_pointer_cast(
      std::shared_ptr<From> const &ptr) noexcept {
    return std::shared_ptr<To>(ptr, reinterpret_cast<To *>(ptr.get()));
  }

}  // namespace std
#endif

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

  /**
   * Protected object wrapper. Allow read-write access.
   * @tparam T object type
   * Example:
   * @code
   * ReadWriteObject<std::string> obj("1");
   * bool const is_one_att1 = obj.sharedAccess([](auto const &str) { return str
   * == "1"; }); obj.exclusiveAccess([](auto &str) { str = "2"; }); bool const
   * is_one_att2 = obj.sharedAccess([](auto const &str) { return str == "1"; });
   * std::cout <<
   *   "Attempt 1: " << is_one_att1 << std::endl <<
   *   "Attempt 2: " << is_one_att2;
   * @endcode
   */
  template <typename T>
  struct ReadWriteObject {
    template <typename... Args>
    ReadWriteObject(Args &&... args) : t_(std::forward<Args>(args)...) {}

    template <typename F>
    inline auto exclusiveAccess(F &&f) {
      std::unique_lock lock(cs_);
      return std::forward<F>(f)(t_);
    }

    template <typename F>
    inline auto sharedAccess(F &&f) const {
      std::shared_lock lock(cs_);
      return std::forward<F>(f)(t_);
    }

   private:
    T t_;
    mutable std::shared_mutex cs_;
  };

  class WaitForSingleObject final : NoMove, NoCopy {
    std::condition_variable wait_cv_;
    std::mutex wait_m_;
    std::atomic_flag flag_;

   public:
    WaitForSingleObject() {
      flag_.test_and_set();
    }

    bool wait(std::chrono::microseconds wait_timeout) {
      std::unique_lock<std::mutex> _lock(wait_m_);
      return wait_cv_.wait_for(
          _lock, wait_timeout, [&]() { return !flag_.test_and_set(); });
    }

    void wait() {
      std::unique_lock<std::mutex> _lock(wait_m_);
      wait_cv_.wait(_lock, [&]() { return !flag_.test_and_set(); });
    }

    void set() {
      flag_.clear();
      wait_cv_.notify_one();
    }
  };
}  // namespace iroha::utils

#endif  // IROHA_SUBSCRIPTION_COMMON_HPP
