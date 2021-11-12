/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_OS_EXECUTOR_KEEPERS_HPP
#define IROHA_OS_EXECUTOR_KEEPERS_HPP

#include <memory>
#include <mutex>
#include <unordered_map>

#include "main/subscription.hpp"
#include "subscription/scheduler.hpp"
#include "subscription/thread_handler.hpp"

namespace iroha::ordering {

  class ExecutorKeeper final : iroha::utils::NoCopy, iroha::utils::NoMove {
    static void schedulerDeleter(subscription::IScheduler *obj) {
      obj->dispose();
      delete obj;
    }

    using Executor =
        std::unique_ptr<subscription::IScheduler, decltype(schedulerDeleter) *>;
    using ExecutorList = std::unordered_map<std::string, Executor>;

    std::mutex peers_cs_;
    ExecutorList peers_;

   public:
    ExecutorKeeper() = default;

    template <typename Task>
    void executeFor(std::string const &pubkey, Task &&task) {
      std::lock_guard lock(peers_cs_);
      Executor *executor;
      if (auto it = peers_.find(pubkey); it != peers_.end())
        executor = &it->second;
      else
        executor = &peers_
                        .insert({pubkey,
                                 Executor(new subscription::ThreadHandler(),
                                          &schedulerDeleter)})
                        .first->second;

      assert(executor);
      (*executor)->addDelayed(std::chrono::microseconds(0ull),
                              std::forward<Task>(task));
    }

    template <typename Peer, typename Task>
    void executeFor(std::shared_ptr<Peer> &peer, Task &&task) {
      assert(peer);
      executeFor(peer->pubkey(), std::forward<Task>(task));
    }

    template <typename Peer>
    void syncronize(std::shared_ptr<Peer> const *begin,
                    std::shared_ptr<Peer> const *end) {
      ExecutorList data;
      std::lock_guard lock(peers_cs_);
      while (begin != end) {
        auto const &pubkey = (*begin)->pubkey();
        if (auto it = peers_.find(pubkey); it != peers_.end())
          data.insert({pubkey, std::move(it->second)});
        ++begin;
      }
      data.swap(peers_);
    }
  };

}  // namespace iroha::ordering

#endif  // IROHA_OS_EXECUTOR_KEEPERS_HPP
