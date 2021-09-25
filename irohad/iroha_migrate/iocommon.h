/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

// clang-format off
template <typename NonContainer> struct is_container : std::false_type { };
template <typename... Ts> struct is_container<std::list<Ts...> > : std::true_type { };
template <typename... Ts> struct is_container<std::vector<Ts...> > : std::true_type { };
template <typename... Ts> struct is_container<std::set<Ts...> > : std::true_type { };
// clang-format on

template <class C>
auto operator<<(std::ostream& os, C const& coll) -> std::enable_if_t<is_container<C>::value, std::ostream&> {
   os << "[";
   auto comma = "";
   for (auto const& element : coll) {
      os << comma << element;
      comma = ", ";
   }
   return os << "]";
}
