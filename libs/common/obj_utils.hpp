/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_OBJ_UTILS_HPP
#define IROHA_COMMON_OBJ_UTILS_HPP

#include <boost/optional.hpp>

namespace iroha {

  /**
   * Create map get function for value retrieval by key
   * @tparam K - map key type
   * @tparam V - map value type
   * @param map - map for value retrieval
   * @return function which takes key, returns value if key exists,
   * nullopt otherwise
   */
  template <typename C>
  auto makeOptionalGet(C &map) {
    return [&map](auto key) -> boost::optional<typename C::mapped_type> {
      auto it = map.find(key);
      if (it != std::end(map)) {
        return it->second;
      }
      return boost::none;
    };
  }

  /**
   * Return function which invokes class method by pointer to member with
   * provided arguments
   *
   * class A {
   * int f(int, double);
   * }
   *
   * A a;
   * int i = makeMethodInvoke(a, 1, 1.0);
   *
   * @tparam T - provided class type
   * @tparam Args - provided arguments types
   * @param object - class object
   * @param args - function arguments
   * @return described function
   */
  template <typename T, typename... Args>
  auto makeMethodInvoke(T &object, Args &&... args) {
    return [&](auto f) { return (object.*f)(std::forward<Args>(args)...); };
  }

  /**
   * Assign the value to the object member
   * @tparam V - object member type
   * @tparam B - object type
   * @param object - object value for member assignment
   * @param member - pointer to member in block
   * @return object with deserialized member on success, nullopt otherwise
   */
  template <typename V, typename B>
  auto assignObjectField(B object, V B::*member) {
    return [=](auto value) mutable {
      object.*member = value;
      return boost::make_optional(object);
    };
  }

  /**
   * Assign the value to the object member. Block is wrapped in monad
   * @tparam P - monadic type
   * @tparam V - object member type
   * @tparam B - object type
   * @param object - object value for member assignment
   * @param member - pointer to member in object
   * @return object with deserialized member on success, nullopt otherwise
   */
  template <template <typename C> class P, typename V, typename B>
  auto assignObjectField(P<B> object, V B::*member) {
    return [=](auto value) mutable {
      (*object).*member = value;
      return boost::make_optional(object);
    };
  }
}  // namespace iroha

#endif  // IROHA_COMMON_OBJ_UTILS_HPP
