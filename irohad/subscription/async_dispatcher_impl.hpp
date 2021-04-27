/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_ASYNC_DISPATCHER_IMPL_HPP
#define IROHA_SUBSCRIPTION_ASYNC_DISPATCHER_IMPL_HPP

#include "subscription/dispatcher.hpp"

#include "subscription/common.hpp"
#include "subscription/thread_handler.hpp"

namespace iroha::subscription {

  template <uint32_t kCount, uint32_t kPoolSize>
  class AsyncDispatcher final : public IDispatcher,
                                utils::NoCopy,
                                utils::NoMove {
   public:
    static constexpr uint32_t kHandlersCount = kCount;
    static constexpr uint32_t kPoolThreadsCount = kPoolSize;

   private:
    using Parent = IDispatcher;

    struct SchedulerContext {
      /// Scheduler to execute tasks
      std::shared_ptr<IScheduler> handler;

      /// Shows if this handler is static or if it was created to
      /// execute a single task and should be deleted after performing it
      bool is_temporary;
    };

    SchedulerContext handlers_[kHandlersCount];
    SchedulerContext pool_[kPoolThreadsCount];

    struct BoundContexts {
      typename Parent::Tid next_tid_offset = 0u;
      std::unordered_map<typename Parent::Tid, SchedulerContext> contexts;
    };
    utils::ReadWriteObject<BoundContexts> bound_;

    inline SchedulerContext findHandler(typename Parent::Tid const tid) {
      if (tid < kHandlersCount)
        return handlers_[tid];

      if (auto context =
              bound_.sharedAccess([tid](BoundContexts const &bound)
                                      -> std::optional<SchedulerContext> {
                if (auto it = bound.contexts.find(tid);
                    it != bound.contexts.end())
                  return it->second;
                return std::nullopt;
              }))
        return *context;

      for (auto &handler : pool_)
        if (!handler.handler->isBusy())
          return handler;

      return SchedulerContext{
          std::make_shared<ThreadHandler>(),
          true  // temporary
      };
    }

   public:
    AsyncDispatcher() {
      for (auto &h : handlers_) {
        h.handler = std::make_shared<ThreadHandler>();
        h.is_temporary = false;
      }
      for (auto &h : pool_) {
        h.handler = std::make_shared<ThreadHandler>();
        h.is_temporary = false;
      }
    }

    void dispose() override {
      for (auto &h : handlers_) h.handler->dispose();
      for (auto &h : pool_) h.handler->dispose();
    }

    void add(typename Parent::Tid tid, typename Parent::Task &&task) override {
      auto h = findHandler(tid);
      if (!h.is_temporary)
        h.handler->add(std::move(task));
      else {
        h.handler->add([h, task{std::move(task)}]() mutable {
          task();
          h.handler->dispose(false);
        });
      }
    }

    void addDelayed(typename Parent::Tid tid,
                    std::chrono::microseconds timeout,
                    typename Parent::Task &&task) override {
      auto h = findHandler(tid);
      if (!h.is_temporary)
        h.handler->addDelayed(timeout, std::move(task));
      else {
        h.handler->addDelayed(timeout, [h, task{std::move(task)}]() mutable {
          task();
          h.handler->dispose(false);
        });
      }
    }

    std::optional<Tid> bind(std::shared_ptr<IScheduler> scheduler) override {
      if (!scheduler)
        return std::nullopt;

      return bound_.exclusiveAccess(
          [scheduler(std::move(scheduler))](BoundContexts &bound) {
            auto const execution_tid = kHandlersCount + bound.next_tid_offset;
            assert(bound.contexts.find(execution_tid) == bound.contexts.end());
            bound.contexts[execution_tid] = SchedulerContext{scheduler, false};
            ++bound.next_tid_offset;
            return execution_tid;
          });
    }

    bool unbind(Tid tid) override {
      return bound_.exclusiveAccess([tid](BoundContexts &bound) {
        return bound.contexts.erase(tid) == 1;
      });
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_ASYNC_DISPATCHER_IMPL_HPP
