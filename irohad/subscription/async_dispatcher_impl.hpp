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
  class AsyncDispatcher final : public IDispatcher<kCount, kPoolSize>,
                                utils::NoCopy,
                                utils::NoMove {
   private:
    using Parent = IDispatcher<kCount, kPoolSize>;

    struct ThreadHandlerContext {
      /// Worker thread to execute tasks
      std::shared_ptr<ThreadHandler> handler;

      /// Shows if this handler is static or if it was created to
      /// execute a single task and should be deleted after performing it
      bool is_temporary;
    };

    ThreadHandlerContext handlers_[Parent::kHandlersCount];
    ThreadHandlerContext pool_[Parent::kPoolThreadsCount];

    inline ThreadHandlerContext findHandler(typename Parent::Tid const tid) {
      assert(tid < Parent::kHandlersCount || tid == Parent::kExecuteInPool);
      if (tid < Parent::kHandlersCount)
        return handlers_[tid];

      for (auto &handler : pool_)
        if (!handler.handler->isBusy())
          return handler;

      return ThreadHandlerContext{
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
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_ASYNC_DISPATCHER_IMPL_HPP
