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
#include <chrono>

namespace iroha::utils {

  struct NoCopy {
    NoCopy(NoCopy const&) = delete;
    NoCopy& operator=(NoCopy const&) = delete;
    NoCopy() = default;
  };

  struct NoMove {
    NoMove(NoMove&&) = delete;
    NoMove& operator=(NoMove&&) = delete;
    NoMove() = default;
  };

}

namespace iroha::subscription {

  class thread_handler final : utils::NoCopy, utils::NoMove {
   public:
    using Task = std::function<void()>;

   private:
    using Time = std::chrono::high_resolution_clock;
    using Timepoint = std::chrono::time_point<Time>;
    using TimedTask = std::pair<Timepoint, Task>;
    using TaskContainer = std::deque<TimedTask>;

    std::mutex tasks_cs_;
    TaskContainer tasks_;

   private:
    inline void checkLocked() {
      assert(!tasks_cs_.try_lock());
    }

    inline Timepoint now() {
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

   public:
    thread_handler() = default;

    template <typename F>
    void add(F &&f) {
      auto const tp = now();
      std::lock_guard lock(tasks_cs_);
      insert(after(tp), std::make_pair(tp, std::forward<F>(f)));
    }

    template <typename F>
    void addDelayed(size_t timeoutUs, F &&f) {
      auto const tp = now() + std::chrono::microseconds(timeoutUs);
      std::lock_guard lock(tasks_cs_);
      insert(after(tp), std::make_pair(tp, std::forward<F>(f)));
    }
  };

  /*std::deque<int> s;
s.push_back(1);
s.push_back(2);
s.push_back(4);
s.push_back(5);

auto const it = std::upper_bound(s.begin(), s.end(), 3, [](auto const &l, auto
const &r){ return l < r;
});
s.insert(it, 3);*/

}

#endif//IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP