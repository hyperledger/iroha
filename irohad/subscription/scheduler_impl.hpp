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
      Timepoint created;
      std::chrono::microseconds timeout;
      Predicate predic;
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
            return l < (r.created + r.timeout);
          });
    }

    void insert(TaskContainer::const_iterator after, TimedTask &&t) {
      checkLocked();
      tasks_.insert(after, std::move(t));
    }

    bool extractExpired(TimedTask &task) {
      std::lock_guard lock(tasks_cs_);
      Timepoint const before = now();
      if (!tasks_.empty()) {
        auto &first_task = tasks_.front();
        auto const timepoint = first_task.created + first_task.timeout;
        if (timepoint <= before) {
          task = std::move(first_task);
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
      std::lock_guard lock(tasks_cs_);
      auto const before = now();
      if (!tasks_.empty()) {
        auto const &first = tasks_.front();
        auto const timepoint = first.created + first.timeout;
        if (timepoint > before)
          return std::chrono::duration_cast<std::chrono::microseconds>(
              timepoint - before);

        return std::chrono::microseconds(0ull);
      }
      return std::chrono::minutes(10ull);
    }

    void add(TimedTask &&task) {
      assert(!tasks_cs_.try_lock());
      if (task.timeout == std::chrono::microseconds(0ull))
        is_busy_ = true;

      insert(after(task.created + task.timeout), std::move(task));
      event_.set();
    }

   public:
    SchedulerBase() : is_busy_(false) {
      proceed_.test_and_set();
    }

    uint32_t process() {
      id_ = std::this_thread::get_id();
      TimedTask task{};
      do {
        if (extractExpired(task)) {
          try {
            if (task.task) {
              if (!task.predic)
                task.task();
              else if (task.predic()) {
                task.task();
                std::lock_guard lock(tasks_cs_);
                task.created = now();
                add(std::move(task));
              }
            }
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

      add(TimedTask{now(), timeout, nullptr, std::move(task)});
      return std::nullopt;
    }

    void addDelayed(std::chrono::microseconds timeout, Task &&t) override {
      std::lock_guard lock(tasks_cs_);
      add(TimedTask{now(), timeout, nullptr, std::move(t)});
    }

    void repeat(std::chrono::microseconds timeout,
                Task &&t,
                Predicate &&pred) override {
      std::lock_guard lock(tasks_cs_);
      add(TimedTask{now(), timeout, std::move(pred), std::move(t)});
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SCHEDULER_IMPL_HPP
