/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP
#define IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP

#include <functional>
#include <thread>
#include <deque>
#include <mutex>
#include <shared_mutex>

namespace iroha::utils {

  template <typename T>
  struct RWObjectHolder {
    template <typename... Args>
    RWObjectHolder(Args... &&args) : t(std::forward<Args>(args)...) {}

    template <typename F>
    void exclusive(F &&f) {
      std::unique_lock lock(cs_);
      std::forward<F>(f)(t_);
    }

    template <typename F>
    void shared(F &&f) const {
      std::shared_lock lock(cs_);
      std::forward<F>(f)(t_);
    }

   private:
    T t_;
    mutable std::shared_mutex cs_;
  };

  template <typename T>
  struct ObjectHolder {
    template <typename... Args>
    ObjectHolder(Args... &&args) : t(std::forward<Args>(args)...) {}

    template <typename F>
    void exclusive(F &&f) {
      std::lock_guard lock(cs_);
      std::forward<F>(f)(t_);
    }

   private:
    T t_;
    std::mutex cs_;
  };

}

namespace iroha::subscription {

  struct thread_handler final {
    using Task = std::function<void()>;

   private:
    using TaskContainer = std::deque<Task>;

    utils::ObjectHolder<TaskContainer> tasks_;
  };

}

#endif//IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP