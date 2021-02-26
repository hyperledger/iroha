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

  class threadHandler final : utils::NoCopy, utils::NoMove {
   public:
    using Task = std::function<void()>;

   private:
    using Time = std::chrono::high_resolution_clock;
    using Timepoint = std::chrono::time_point<Time>;
    using TimedTask = std::pair<Timepoint, Task>;
    using TaskContainer = std::deque<TimedTask>;

    std::atomic_flag proceed_;
    mutable std::mutex tasks_cs_;
    TaskContainer tasks_;
    std::thread worker_;
    utils::waitForSingleObject event_;

   private:
    inline void checkLocked() {
      assert(!tasks_cs_.try_lock());
    }

    inline Timepoint now() const {
      return Time::now();
    }

    static inline Timepoint &tpFromTimedTask(TimedTask &t) {
      return t.first;
    }

    static inline Timepoint const &tpFromTimedTask(TimedTask const &t) {
      return t.first;
    }

    static inline Task &taskFromTimedTask(TimedTask &t) {
      return t.second;
    }

    TaskContainer::const_iterator after(Timepoint const &tp) {
      checkLocked();
      return std::upper_bound(
          tasks_.begin(), tasks_.end(), tp, [](auto const &l, auto const &r) {
            return l < tpFromTimedTask(r);
          });
    }

    template <typename F>
    void insert(TaskContainer::const_iterator after, F &&f) {
      checkLocked();
      tasks_.insert(after, std::forward<F>(f));
    }

    bool extract(Task &task, Timepoint const &before) {
      std::lock_guard lock(tasks_cs_);
      if (!tasks_.empty()) {
        auto &first_task = tasks_.front();
        if (tpFromTimedTask(first_task) <= before) {
          taskFromTimedTask(first_task).swap(task);
          tasks_.pop_front();
          return true;
        }
      }
      return false;
    }

    uint64_t untilFirst() const {
      auto const before = now();
      std::lock_guard lock(tasks_cs_);
      if (!tasks_.empty()) {
        auto const &first = tasks_.front();
        if (tpFromTimedTask(first) > before) {
          return std::chrono::duration_cast<std::chrono::microseconds>(
                     tpFromTimedTask(first) - before)
              .count();
        }
        return 0ull;
      }
      return 10ull * 60 * 1000'000;
    }

    uint32_t proc() {
      Task task;
      do {
        while (extract(task, now())) {
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
    threadHandler() {
      proceed_.test_and_set();
      worker_ = std::thread(
          [](threadHandler *__this) { return __this->proc(); }, this);
    }

    ~threadHandler() {
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
      insert(after(tp), std::make_pair(tp, std::forward<F>(f)));
      event_.set();
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP
