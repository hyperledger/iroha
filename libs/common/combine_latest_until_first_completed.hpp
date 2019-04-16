/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMBINE_LATEST_UNTIL_FIRST_COMPLETED_HPP
#define IROHA_COMBINE_LATEST_UNTIL_FIRST_COMPLETED_HPP

#include <rxcpp/operators/rx-combine_latest.hpp>

namespace iroha {

  /**
   * This class is mostly the same as rxcpp::operators::combine_latest,
   * the only change is that it completes when the first of observables is
   * completed instead of all observables
   * For each item from all of the observables select a value to emit from the
   * new observable that is returned
   * @tparam Coordination the type of the scheduler
   * @tparam Selector the type of the aggregation function
   * @tparam ObservableN types of source observables
   */
  template <class Coordination, class Selector, class... ObservableN>
  struct combine_latest_until_first_completed
      : public rxcpp::operators::operator_base<rxcpp::util::value_type_t<
            rxcpp::operators::detail::combine_latest_traits<Coordination,
                                                            Selector,
                                                            ObservableN...>>> {
    typedef combine_latest_until_first_completed<Coordination,
                                                 Selector,
                                                 ObservableN...>
        this_type;

    typedef rxcpp::operators::detail::
        combine_latest_traits<Coordination, Selector, ObservableN...>
            traits;

    typedef typename traits::tuple_source_type tuple_source_type;
    typedef typename traits::tuple_source_value_type tuple_source_value_type;

    typedef typename traits::selector_type selector_type;

    typedef typename traits::coordination_type coordination_type;
    typedef typename coordination_type::coordinator_type coordinator_type;

    struct values {
      values(tuple_source_type o, selector_type s, coordination_type sf)
          : source(std::move(o)),
            selector(std::move(s)),
            coordination(std::move(sf)) {}
      tuple_source_type source;
      selector_type selector;
      coordination_type coordination;
    };
    values initial;

    combine_latest_until_first_completed(coordination_type sf,
                                         selector_type s,
                                         tuple_source_type ts)
        : initial(std::move(ts), std::move(s), std::move(sf)) {}

    template <int Index, class State>
    void subscribe_one(std::shared_ptr<State> state) const {
      typedef typename std::tuple_element<Index,
                                          tuple_source_type>::type::value_type
          source_value_type;

      rxcpp::composite_subscription innercs;

      // when the out observer is unsubscribed all the
      // inner subscriptions are unsubscribed as well
      state->out.add(innercs);

      auto source = on_exception(
          [&]() {
            return state->coordinator.in(std::get<Index>(state->source));
          },
          state->out);
      if (source.empty()) {
        return;
      }

      // this subscribe does not share the observer subscription
      // so that when it is unsubscribed the observer can be called
      // until the inner subscriptions have finished
      auto sink = rxcpp::make_subscriber<source_value_type>(
          state->out,
          innercs,
          // on_next
          [state](source_value_type st) {
            auto &value = std::get<Index>(state->latest);

            if (value.empty()) {
              ++state->valuesSet;
            }

            value.reset(st);

            if (state->valuesSet == sizeof...(ObservableN)) {
              auto values = rxcpp::util::surely(state->latest);
              auto selectedResult = rxcpp::util::apply(values, state->selector);
              state->out.on_next(selectedResult);
            }
          },
          // on_error
          [state](std::exception_ptr e) { state->out.on_error(e); },
          // on_completed
          [state]() { state->out.on_completed(); });
      auto selectedSink = on_exception(
          [&]() { return state->coordinator.out(sink); }, state->out);
      if (selectedSink.empty()) {
        return;
      }
      source->subscribe(std::move(selectedSink.get()));
    }

    template <class State, int... IndexN>
    void subscribe_all(std::shared_ptr<State> state,
                       rxcpp::util::values<int, IndexN...>) const {
      bool subscribed[] = {(subscribe_one<IndexN>(state), true)...};
      subscribed[0] = (*subscribed);  // silence warning
    }

    template <class Subscriber>
    void on_subscribe(Subscriber scbr) const {
      static_assert(rxcpp::is_subscriber<Subscriber>::value,
                    "subscribe must be passed a subscriber");

      typedef Subscriber output_type;

      struct combine_latest_until_first_completed_state_type
          : public std::enable_shared_from_this<
                combine_latest_until_first_completed_state_type>,
            public values {
        combine_latest_until_first_completed_state_type(values i,
                                                        coordinator_type coor,
                                                        output_type oarg)
            : values(std::move(i)),
              valuesSet(0),
              coordinator(std::move(coor)),
              out(std::move(oarg)) {}

        mutable int valuesSet;
        mutable tuple_source_value_type latest;
        coordinator_type coordinator;
        output_type out;
      };

      auto coordinator =
          initial.coordination.create_coordinator(scbr.get_subscription());

      // take a copy of the values for each subscription
      auto state =
          std::make_shared<combine_latest_until_first_completed_state_type>(
              initial, std::move(coordinator), std::move(scbr));

      subscribe_all(
          state,
          typename rxcpp::util::values_from<int,
                                            sizeof...(ObservableN)>::type());
    }
  };

  template <
      class Coordination,
      class Selector,
      class Observable,
      class... ObservableN,
      class Enabled = rxcpp::util::enable_if_all_true_type_t<
          rxcpp::is_coordination<Coordination>,
          rxcpp::operators::detail::
              is_combine_latest_selector<Selector, Observable, ObservableN...>,
          rxcpp::all_observables<Observable, ObservableN...>>,
      class ResolvedSelector = rxcpp::util::decay_t<Selector>,
      class combine_latest = combine_latest_until_first_completed<
          Coordination,
          ResolvedSelector,
          rxcpp::util::decay_t<Observable>,
          rxcpp::util::decay_t<ObservableN>...>,
      class Value = rxcpp::util::value_type_t<combine_latest>,
      class Result = rxcpp::observable<Value, combine_latest>>
  static Result makeCombineLatestUntilFirstCompleted(Observable &&o,
                                                     Coordination &&cn,
                                                     Selector &&s,
                                                     ObservableN &&... on) {
    return Result(
        combine_latest(std::forward<Coordination>(cn),
                       std::forward<Selector>(s),
                       std::make_tuple(std::forward<Observable>(o),
                                       std::forward<ObservableN>(on)...)));
  }

}  // namespace iroha

#endif  // IROHA_COMBINE_LATEST_UNTIL_FIRST_COMPLETED_HPP
