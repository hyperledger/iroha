/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TIMEOUT_HPP
#define IROHA_TIMEOUT_HPP

#include <rxcpp/operators/rx-timeout.hpp>

namespace iroha {

  /**
   * This class is mostly the same as rxcpp::operators::timeout,
   * the only change is that it accepts a selector lambda which generates
   * a duration based on observable value instead of a fixed duration
   * Return an observable that terminates with timeout_error if a particular
   * timespan has passed without emitting another item from the source
   * observable
   * Timespan is generated with selector from the last received value
   * @tparam T value type
   * @tparam Selector the type of the transforming function
   * which returns time interval
   * @tparam Coordination the type of the scheduler
   */
  template <class T, class Selector, class Coordination>
  struct timeout {
    typedef rxcpp::util::decay_t<T> source_value_type;
    typedef rxcpp::util::decay_t<Coordination> coordination_type;
    typedef typename coordination_type::coordinator_type coordinator_type;
    typedef rxcpp::util::decay_t<Selector> select_type;

    struct timeout_values {
      timeout_values(select_type s, coordination_type c)
          : selector(std::move(s)), coordination(c) {}

      select_type selector;
      coordination_type coordination;
    };
    timeout_values initial;

    timeout(select_type s, coordination_type coordination)
        : initial(std::move(s), coordination) {}

    template <class Subscriber>
    struct timeout_observer {
      typedef timeout_observer<Subscriber> this_type;
      typedef rxcpp::util::decay_t<T> value_type;
      typedef rxcpp::util::decay_t<Subscriber> dest_type;
      typedef rxcpp::observer<T, this_type> observer_type;

      struct timeout_subscriber_values : public timeout_values {
        timeout_subscriber_values(rxcpp::composite_subscription cs,
                                  dest_type d,
                                  timeout_values v,
                                  coordinator_type c)
            : timeout_values(v),
              cs(std::move(cs)),
              dest(std::move(d)),
              coordinator(std::move(c)),
              worker(coordinator.get_worker()),
              index(0) {}

        rxcpp::composite_subscription cs;
        dest_type dest;
        coordinator_type coordinator;
        rxcpp::schedulers::worker worker;
        mutable std::size_t index;
      };
      typedef std::shared_ptr<timeout_subscriber_values> state_type;
      state_type state;

      timeout_observer(rxcpp::composite_subscription cs,
                       dest_type d,
                       timeout_values v,
                       coordinator_type c)
          : state(std::make_shared<timeout_subscriber_values>(
                timeout_subscriber_values(
                    std::move(cs), std::move(d), v, std::move(c)))) {
        auto localState = state;

        auto disposer = [=](const rxcpp::schedulers::schedulable &) {
          localState->cs.unsubscribe();
          localState->dest.unsubscribe();
          localState->worker.unsubscribe();
        };
        auto selectedDisposer = on_exception(
            [&]() { return localState->coordinator.act(disposer); },
            localState->dest);
        if (selectedDisposer.empty()) {
          return;
        }

        localState->dest.add(
            [=]() { localState->worker.schedule(selectedDisposer.get()); });
        localState->cs.add(
            [=]() { localState->worker.schedule(selectedDisposer.get()); });
      }

      static std::function<void(const rxcpp::schedulers::schedulable &)>
      produce_timeout(std::size_t id, state_type state) {
        auto produce = [id, state](const rxcpp::schedulers::schedulable &) {
          if (id != state->index)
            return;

          state->dest.on_error(std::make_exception_ptr(
              rxcpp::timeout_error("timeout has occurred")));
        };

        auto selectedProduce = on_exception(
            [&]() { return state->coordinator.act(produce); }, state->dest);
        if (selectedProduce.empty()) {
          return std::function<void(const rxcpp::schedulers::schedulable &)>();
        }

        return std::function<void(const rxcpp::schedulers::schedulable &)>(
            selectedProduce.get());
      }

      template <class Value>
      void on_next(Value &&v) const {
        auto localState = state;

        auto selected = on_exception(
            [&]() { return localState->selector(std::forward<Value>(v)); },
            localState->dest);
        if (selected.empty()) {
          return;
        }

        auto work = [v, localState, period = std::move(selected.get())](
                        const rxcpp::schedulers::schedulable &) {
          auto new_id = ++localState->index;
          auto produce_time = localState->worker.now() + period;

          localState->dest.on_next(v);
          localState->worker.schedule(produce_time,
                                      produce_timeout(new_id, localState));
        };
        auto selectedWork =
            on_exception([&]() { return localState->coordinator.act(work); },
                         localState->dest);
        if (selectedWork.empty()) {
          return;
        }
        localState->worker.schedule(selectedWork.get());
      }

      void on_error(std::exception_ptr e) const {
        auto localState = state;
        auto work = [e, localState](const rxcpp::schedulers::schedulable &) {
          localState->dest.on_error(e);
        };
        auto selectedWork =
            on_exception([&]() { return localState->coordinator.act(work); },
                         localState->dest);
        if (selectedWork.empty()) {
          return;
        }
        localState->worker.schedule(selectedWork.get());
      }

      void on_completed() const {
        auto localState = state;
        auto work = [localState](const rxcpp::schedulers::schedulable &) {
          localState->dest.on_completed();
        };
        auto selectedWork =
            on_exception([&]() { return localState->coordinator.act(work); },
                         localState->dest);
        if (selectedWork.empty()) {
          return;
        }
        localState->worker.schedule(selectedWork.get());
      }

      static rxcpp::subscriber<T, observer_type> make(dest_type d,
                                                      timeout_values v) {
        auto cs = rxcpp::composite_subscription();
        auto coordinator = v.coordination.create_coordinator();

        return rxcpp::make_subscriber<T>(
            cs,
            observer_type(this_type(
                cs, std::move(d), std::move(v), std::move(coordinator))));
      }
    };

    template <class Subscriber>
    auto operator()(Subscriber dest) const
        -> decltype(timeout_observer<Subscriber>::make(std::move(dest),
                                                       initial)) {
      return timeout_observer<Subscriber>::make(std::move(dest), initial);
    }
  };

  template <
      typename T,
      typename Selector,
      typename Coordination,
      class ResolvedSelector = rxcpp::util::decay_t<Selector>,
      class Duration = decltype(
          std::declval<ResolvedSelector>()((std::declval<std::decay_t<T>>()))),
      class Enabled = rxcpp::util::enable_if_all_true_type_t<
          rxcpp::is_coordination<Coordination>,
          rxcpp::util::is_duration<Duration>>,
      class Timeout =
          timeout<T, ResolvedSelector, rxcpp::util::decay_t<Coordination>>>
  static auto makeTimeout(Selector &&s, Coordination &&cn) {
    return Timeout(std::forward<Selector>(s), std::forward<Coordination>(cn));
  }

}  // namespace iroha

#endif  // IROHA_TIMEOUT_HPP
