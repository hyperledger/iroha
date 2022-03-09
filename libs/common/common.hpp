/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_COMMON_HPP
#define IROHA_LIBS_COMMON_HPP

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>

namespace iroha::utils {

  template <typename To, typename From>
  inline std::shared_ptr<To> reinterpret_pointer_cast(
      std::shared_ptr<From> const &ptr) noexcept {
    return std::shared_ptr<To>(ptr, reinterpret_cast<To *>(ptr.get()));
  }

  template <typename T>
  inline std::weak_ptr<T> make_weak(std::shared_ptr<T> const &ptr) noexcept {
    return ptr;
  }

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

  // clang-format off
  /**
   * Protected object wrapper. Allow read-write access.
   * @tparam T object type
   * Example:
   * @code
   *  ReadWriteObject<std::string> obj("1");
   *  bool const is_one_att1 =
   *      obj.sharedAccess([](auto const &str) {
   *          return str == "1";
   *      });
   *  obj.exclusiveAccess([](auto &str) {
   *      str = "2";
   *  });
   *  bool const is_one_att2 =
   *      obj.sharedAccess([](auto const &str) {
   *          return str == "1";
   *      });
   *
   * std::cout <<
   *   "Attempt 1: " << is_one_att1 << std::endl <<
   *   "Attempt 2: " << is_one_att2;
   * @endcode
   */
  // clang-format on
  template <typename T, typename M = std::shared_mutex>
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
    mutable M cs_;
  };

  class WaitForSingleObject final : NoMove, NoCopy {
    std::condition_variable wait_cv_;
    std::mutex wait_m_;
    bool flag_;

   public:
    WaitForSingleObject() : flag_{true} {}

    bool wait(std::chrono::microseconds wait_timeout) {
      std::unique_lock<std::mutex> _lock(wait_m_);
      return wait_cv_.wait_for(_lock, wait_timeout, [&]() {
        auto prev = !flag_;
        flag_ = true;
        return prev;
      });
    }

    void wait() {
      std::unique_lock<std::mutex> _lock(wait_m_);
      wait_cv_.wait(_lock, [&]() {
        auto prev = !flag_;
        flag_ = true;
        return prev;
      });
    }

    void set() {
      {
        std::unique_lock<std::mutex> _lock(wait_m_);
        flag_ = false;
      }
      wait_cv_.notify_one();
    }
  };
}  // namespace iroha::utils

#endif  // IROHA_LIBS_COMMON_HPP
