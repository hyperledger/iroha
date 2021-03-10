/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP
#define IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP

#include <assert.h>
#include <chrono>
#include <deque>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "subscription/common.hpp"

namespace iroha::subscription {

  class ThreadHandler final : utils::NoCopy, utils::NoMove {
   public:
    using Task = std::function<void()>;

   private:
    using Time = std::chrono::high_resolution_clock;
    using Timepoint = std::chrono::time_point<Time>;
    struct TimedTask {
      Timepoint timepoint;
      Task task;
    };
    using TaskContainer = std::deque<TimedTask>;

    std::atomic_flag proceed_;
    mutable std::mutex tasks_cs_;
    TaskContainer tasks_;
    std::thread worker_;
    utils::WaitForSingleObject event_;

   private:
    inline void checkLocked() {
      assert(!tasks_cs_.try_lock());
    }

    inline Timepoint now() const {
      return Time::now();
    }

    TaskContainer::const_iterator after(Timepoint const &tp) {
      checkLocked();
      return std::upper_bound(
          tasks_.begin(), tasks_.end(), tp, [](auto const &l, auto const &r) {
            return l < r.timepoint;
          });
    }

    template <typename F>
    void insert(TaskContainer::const_iterator after, F &&f) {
      checkLocked();
      tasks_.insert(after, std::forward<F>(f));
    }

    bool extractExpired(Task &task, Timepoint const &before) {
      std::lock_guard lock(tasks_cs_);
      if (!tasks_.empty()) {
        auto &first_task = tasks_.front();
        if (first_task.timepoint <= before) {
          first_task.task.swap(task);
          tasks_.pop_front();
          return true;
        }
      }
      return false;
    }

    ///@returns time duration from now till first task will be executed
    std::chrono::microseconds untilFirst() const {
      auto const before = now();
      std::lock_guard lock(tasks_cs_);
      if (!tasks_.empty()) {
        auto const &first = tasks_.front();
        if (first.timepoint > before) {
          return std::chrono::duration_cast<std::chrono::microseconds>(
                     first.timepoint - before);
        }
        return std::chrono::microseconds(0ull);
      }
      return std::chrono::minutes(10ull);
    }

    uint32_t process() {
      Task task;
      do {
        while (extractExpired(task, now())) {
          try {
            if (task)
              task();
          } catch (...) {
          }
        }
        event_.wait(untilFirst());
      } while (proceed_.test_and_set());
      return 0;
    }

   public:
    ThreadHandler() {
      proceed_.test_and_set();
      worker_ = std::thread(
          [](ThreadHandler *__this) { return __this->process(); }, this);
    }

    ~ThreadHandler() {
      proceed_.clear();
      event_.set();
      worker_.join();
    }

    template <typename F>
    void add(F &&f) {
      addDelayed(std::chrono::microseconds(0ull), std::forward<F>(f));
    }

    template <typename F>
    void addDelayed(std::chrono::microseconds timeout, F &&f) {
      auto const tp = now() + timeout;
      std::lock_guard lock(tasks_cs_);
      insert(after(tp), TimedTask{tp, std::forward<F>(f)});
      event_.set();
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP
