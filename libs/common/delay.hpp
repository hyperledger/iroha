/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_DELAY_HPP
#define IROHA_DELAY_HPP

#include <rxcpp/operators/rx-delay.hpp>

namespace iroha {

  /**
   * This class is mostly the same as rxcpp::operators::delay,
   * the only change is that it accepts a selector lambda which generates
   * a duration based on observable value instead of a fixed duration.  The
   * delay from selector is only used if it does not change the order of values.
   * Return an observable that emits each item emitted by the source observable
   * after the specified delay
   * Delay is generated with selector from the last received value
   * @tparam T value type
   * @tparam Selector the type of the transforming function
   * which returns time interval
   * @tparam Coordination the type of the scheduler
   */
  template <class T, class Selector, class Coordination>
  struct delay {
    typedef rxcpp::util::decay_t<T> source_value_type;
    typedef rxcpp::util::decay_t<Coordination> coordination_type;
    typedef typename coordination_type::coordinator_type coordinator_type;
    typedef rxcpp::util::decay_t<Selector> select_type;

    struct delay_values {
      delay_values(select_type s, coordination_type c)
          : selector(std::move(s)), coordination(c) {}

      select_type selector;
      coordination_type coordination;
    };
    delay_values initial;

    delay(select_type s, coordination_type coordination)
        : initial(std::move(s), coordination) {}

    template <class Subscriber>
    struct delay_observer {
      typedef delay_observer<Subscriber> this_type;
      typedef rxcpp::util::decay_t<T> value_type;
      typedef rxcpp::util::decay_t<Subscriber> dest_type;
      typedef rxcpp::observer<T, this_type> observer_type;
      typedef rxcpp::schedulers::scheduler::clock_type clock_type;

      struct delay_subscriber_values : public delay_values {
        delay_subscriber_values(rxcpp::composite_subscription cs,
                                dest_type d,
                                delay_values v,
                                coordinator_type c)
            : delay_values(v),
              cs(std::move(cs)),
              dest(std::move(d)),
              coordinator(std::move(c)),
              worker(coordinator.get_worker()),
              monotonous_time_next(worker.now()) {}

        rxcpp::composite_subscription cs;
        dest_type dest;
        coordinator_type coordinator;
        rxcpp::schedulers::worker worker;
        clock_type::time_point monotonous_time_next;
      };
      std::shared_ptr<delay_subscriber_values> state;

      delay_observer(rxcpp::composite_subscription cs,
                     dest_type d,
                     delay_values v,
                     coordinator_type c)
          : state(std::make_shared<delay_subscriber_values>(
                delay_subscriber_values(
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

      template <class Value>
      static inline clock_type::time_point selectNext(
          delay_subscriber_values &state, Value &&v) {
        auto const next_selected_time_point = std::max(
            state.monotonous_time_next,
            state.worker.now() + state.selector(std::forward<Value>(v)));
        state.monotonous_time_next =
            next_selected_time_point + clock_type::duration{1};
        return next_selected_time_point;
      }

      template <class Value>
      void on_next(Value &&v) const {
        auto localState = state;

        auto selected = on_exception(
            [&]() { return selectNext(*localState, std::forward<Value>(v)); },
            localState->dest);
        if (selected.empty()) {
          return;
        }

        auto work = [v, localState](const rxcpp::schedulers::schedulable &) {
          localState->dest.on_next(v);
        };
        auto selectedWork =
            on_exception([&]() { return localState->coordinator.act(work); },
                         localState->dest);
        if (selectedWork.empty()) {
          return;
        }
        localState->worker.schedule(selected.get(), selectedWork.get());
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
                                                      delay_values v) {
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
        -> decltype(delay_observer<Subscriber>::make(std::move(dest),
                                                     initial)) {
      return delay_observer<Subscriber>::make(std::move(dest), initial);
    }
  };

  template <typename T,
            typename Selector,
            typename Coordination,
            class ResolvedSelector = rxcpp::util::decay_t<Selector>,
            class Duration = decltype(std::declval<ResolvedSelector>()(
                (std::declval<std::decay_t<T>>()))),
            class Enabled = rxcpp::util::enable_if_all_true_type_t<
                rxcpp::is_coordination<Coordination>,
                rxcpp::util::is_duration<Duration>>,
            class Delay =
                delay<T, ResolvedSelector, rxcpp::util::decay_t<Coordination>>>
  static auto makeDelay(Selector &&s, Coordination &&cn) {
    return Delay(std::forward<Selector>(s), std::forward<Coordination>(cn));
  }

}  // namespace iroha

#endif  // IROHA_DELAY_HPP
