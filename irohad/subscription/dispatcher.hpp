/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_DISPATCHER_HPP
#define IROHA_SUBSCRIPTION_DISPATCHER_HPP

#include "subscription/common.hpp"
#include "subscription/thread_handler.hpp"

namespace iroha::subscription {

  template <uint32_t kCount, uint32_t kPoolSize>
  class Dispatcher final : utils::NoCopy, utils::NoMove {
   public:
    static constexpr uint32_t kHandlersCount = kCount;
    static constexpr uint32_t kPoolThreadsCount = kPoolSize;
    using Task = ThreadHandler::Task;
    using Tid = uint32_t;
    static constexpr Tid kExecuteInPool = std::numeric_limits<Tid>::max();

   private:
    struct ThreadHandlerContext {
      std::shared_ptr<ThreadHandler> handler;
      bool is_temporary;
    };

    ThreadHandlerContext handlers_[kHandlersCount];
    ThreadHandlerContext pool_[kPoolThreadsCount];

    inline ThreadHandlerContext findHandler(Tid const tid) {
      assert(tid < kHandlersCount || tid == kExecuteInPool);
      if (tid < kHandlersCount)
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
    Dispatcher() {
      for (auto &h : handlers_) {
        h.handler = std::make_shared<ThreadHandler>();
        h.is_temporary = false;
      }
      for (auto &h : pool_) {
        h.handler = std::make_shared<ThreadHandler>();
        h.is_temporary = false;
      }
    }

    void dispose() {
      for (auto &h : handlers_) h.handler->dispose();
      for (auto &h : pool_) h.handler->dispose();
    }

    template <Tid kId>
    static constexpr void checkTid() {
      static_assert(kId < kHandlersCount || kId == kExecuteInPool,
                    "Unexpected TID handler.");
    }

    template <typename F>
    void add(Tid tid, F &&f) {
      auto h = findHandler(tid);
      if (!h.is_temporary)
        h.handler->add(std::forward<F>(f));
      else {
        h.handler->add([h, f{std::forward<F>(f)}]() mutable {
          std::forward<F>(f)();
          h.handler->dispose(false);
        });
      }
    }

    template <typename F>
    void addDelayed(Tid tid, std::chrono::microseconds timeout, F &&f) {
      auto h = findHandler(tid);
      if (!h.is_temporary)
        h.handler->addDelayed(timeout, std::forward<F>(f));
      else {
        h.handler->addDelayed(timeout, [h, f{std::forward<F>(f)}]() mutable {
          std::forward<F>(f)();
          h.handler->dispose(false);
        });
      }
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_DISPATCHER_HPP
