/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SCHEDULER_IMPL_HPP
#define IROHA_SUBSCRIPTION_SCHEDULER_IMPL_HPP

#include <assert.h>
#include <algorithm>
#include <chrono>
#include <deque>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "subscription/scheduler.hpp"

#include "common/common.hpp"

namespace iroha::subscription {

  class SchedulerBase : public IScheduler, utils::NoCopy, utils::NoMove {
   private:
    using Time = std::chrono::high_resolution_clock;
    using Timepoint = std::chrono::time_point<Time>;
    struct TimedTask {
      Timepoint timepoint;
      Task task;
    };
    using TaskContainer = std::deque<TimedTask>;

    /// Flag shows if thread loop should continue processing or exit
    std::atomic_flag proceed_;

    mutable std::mutex tasks_cs_;

    /// List of tasks to be performed
    TaskContainer tasks_;

    /// Event that is set when loop should make some work or exit
    utils::WaitForSingleObject event_;

    /// Flag that shows if current handler is in task execution state
    bool is_busy_;

    std::thread::id id_;

   private:
    inline void checkLocked() {
      /// Need to check that we are locked in debug.
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

    void insert(TaskContainer::const_iterator after, TimedTask &&t) {
      checkLocked();
      tasks_.insert(after, std::move(t));
    }

    bool extractExpired(Task &task) {
      std::lock_guard lock(tasks_cs_);
      Timepoint const before = now();
      if (!tasks_.empty()) {
        auto &first_task = tasks_.front();
        if (first_task.timepoint <= before) {
          first_task.task.swap(task);
          tasks_.pop_front();
          is_busy_ = true;
          return true;
        }
      }
      is_busy_ = false;
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

    void add(std::chrono::microseconds timeout, Task &&task) {
      assert(!tasks_cs_.try_lock());
      if (timeout == std::chrono::microseconds(0ull))
        is_busy_ = true;

      auto const tp = now() + timeout;
      insert(after(tp), TimedTask{tp, std::move(task)});
      event_.set();
    }

   public:
    SchedulerBase() : is_busy_(false) {
      proceed_.test_and_set();
    }

    uint32_t process() {
      id_ = std::this_thread::get_id();
      Task task;
      do {
        if (extractExpired(task)) {
          try {
            if (task)
              task();
          } catch (...) {
          }
        } else
          event_.wait(untilFirst());

      } while (proceed_.test_and_set());
      return 0;
    }

    void dispose(bool wait_for_release = true) override {
      proceed_.clear();
      event_.set();
    }

    bool isBusy() const override {
      std::lock_guard lock(tasks_cs_);
      return is_busy_;
    }

    std::optional<Task> uploadIfFree(std::chrono::microseconds timeout,
                                     Task &&task) override {
      std::lock_guard lock(tasks_cs_);
      if (is_busy_)
        return std::move(task);

      add(timeout, std::move(task));
      return std::nullopt;
    }

    void addDelayed(std::chrono::microseconds timeout, Task &&t) override {
      std::lock_guard lock(tasks_cs_);
      add(timeout, std::move(t));
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SCHEDULER_IMPL_HPP
