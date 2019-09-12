/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_WSV_COMMON_HPP
#define IROHA_POSTGRES_WSV_COMMON_HPP

#include <soci/soci.h>
#include <boost/optional.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tuple/tuple.hpp>
#include "common/bind.hpp"

namespace iroha {
  namespace ametsuchi {

    template <typename ParamType, typename Function>
    inline void processSoci(soci::statement &st,
                            soci::indicator &ind,
                            ParamType &row,
                            Function f) {
      while (st.fetch()) {
        switch (ind) {
          case soci::i_ok:
            f(row);
          case soci::i_null:
          case soci::i_truncated:
            break;
        }
      }
    }

    /// tuple length shortcut
    template <typename T>
    constexpr std::size_t length_v = boost::tuples::length<T>::value;

    /// tuple element type shortcut
    template <std::size_t N, typename T>
    using element_t = typename boost::tuples::element<N, T>::type;

    /// index sequence helper for concat
    template <class Tuple1, class Tuple2, std::size_t... Is, std::size_t... Js>
    auto concat_impl(std::index_sequence<Is...>, std::index_sequence<Js...>)
        -> boost::tuple<element_t<Is, std::decay_t<Tuple1>>...,
                        element_t<Js, std::decay_t<Tuple2>>...>;

    /// tuple with types from two given tuples
    template <class Tuple1, class Tuple2>
    using concat = decltype(concat_impl<Tuple1, Tuple2>(
        std::make_index_sequence<length_v<std::decay_t<Tuple1>>>{},
        std::make_index_sequence<length_v<std::decay_t<Tuple2>>>{}));

    /// index sequence helper for index_apply
    template <typename F, std::size_t... Is>
    constexpr decltype(auto) index_apply_impl(F &&f,
                                              std::index_sequence<Is...>) {
      return std::forward<F>(f)(std::integral_constant<std::size_t, Is>{}...);
    }

    /// apply F to an integer sequence [0, N)
    template <size_t N, typename F>
    constexpr decltype(auto) index_apply(F &&f) {
      return index_apply_impl(std::forward<F>(f),
                              std::make_index_sequence<N>{});
    }

    /// apply F to Tuple
    template <typename Tuple, typename F>
    constexpr decltype(auto) apply(Tuple &&t, F &&f) {
      return index_apply<length_v<std::decay_t<Tuple>>>(
          [&](auto... Is) -> decltype(auto) {
            return std::forward<F>(f)(
                boost::get<Is>(std::forward<Tuple>(t))...);
          });
    }

    /// view first length_v<R> elements of T without copying
    template <typename R, typename T>
    constexpr auto viewQuery(T &&t) {
      return index_apply<length_v<std::decay_t<R>>>([&](auto... Is) {
        return boost::make_tuple(std::forward<T>(t).template get<Is>()...);
      });
    }

    /// view last length_v<R> elements of T without copying
    template <typename R, typename T>
    constexpr auto viewPermissions(T &&t) {
      return index_apply<length_v<std::decay_t<R>>>([&](auto... Is) {
        return boost::make_tuple(
            std::forward<T>(t)
                .template get<Is
                              + length_v<std::decay_t<
                                    T>> - length_v<std::decay_t<R>>>()...);
      });
    }

    /// map tuple<optional<Ts>...> to optional<tuple<Ts...>>
    template <typename T>
    constexpr auto rebind(T &&t) {
      auto transform = [](auto &&... vals) {
        return boost::make_tuple(*std::forward<decltype(vals)>(vals)...);
      };

      using ReturnType = decltype(boost::make_optional(
          iroha::ametsuchi::apply(std::forward<T>(t), transform)));

      return iroha::ametsuchi::apply(
                 std::forward<T>(t),
                 [&](auto &&... vals) {
                   bool temp[] = {static_cast<bool>(
                       std::forward<decltype(vals)>(vals))...};
                   return std::all_of(std::begin(temp),
                                      std::end(temp),
                                      [](auto b) { return b; });
                 })
          ? boost::make_optional(
                iroha::ametsuchi::apply(std::forward<T>(t), transform))
          : ReturnType{};
    }

    template <typename C, typename T, typename F>
    auto mapValues(T &t, F &&f) {
      return t | [&](auto &st) -> boost::optional<C> {
        return boost::copy_range<C>(
            st | boost::adaptors::transformed([&](auto &t) {
              return iroha::ametsuchi::apply(t, std::forward<F>(f));
            }));
      };
    }

    template <typename C, typename T, typename F>
    boost::optional<C> flatMapValues(T &t, F &&f) {
      if (t) {
        C map_result;
        for (auto &inp_el : *t) {
          iroha::ametsuchi::apply(inp_el, std::forward<F>(f)) |
              [&map_result](auto &&transformed_el) {
                map_result.emplace_back(std::move(transformed_el));
              };
        }
        return map_result;
      }
      return boost::none;
    }

    template <typename R, typename T, typename F>
    auto flatMapValue(T &t, F &&f) {
      return t | [&](auto &st) -> R {
        auto range = boost::make_iterator_range(st);

        if (range.empty()) {
          return boost::none;
        }

        return iroha::ametsuchi::apply(range.front(), std::forward<F>(f));
      };
    }

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_WSV_COMMON_HPP
