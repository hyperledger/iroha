/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLONEABLE_HPP
#define IROHA_CLONEABLE_HPP

#include <memory>

/**
 * Functions and interface for creation cloneable classes with
 * smart pointers.
 *
 * Usage:
 * struct Base : object::cloneable<Base> {
 *   // ... other methods
 * };
 *
 * struct Derived : Base {
 *   // ... other methods
 * protected:
 *   Derived* clone() const override {
 *     return new Derived(*this);
 *   }
 * };
 *
 * Derived derived;
 * auto c1 = clone(derived);
 */

template <typename T>
class Cloneable;

/**
 * Function to clone from Cloneable.
 * @tparam T - derived from Cloneable
 * @param object - object to clone
 * @return clone of object
 */
template <typename T>
std::unique_ptr<T> clone(const T &object) {
  using base_type = typename T::base_type;
  static_assert(std::is_base_of<base_type, T>::value,
                "T object has to derived from T::base_type");
  auto ptr = static_cast<const Cloneable<base_type> &>(object).clone();
  return std::unique_ptr<T>(static_cast<T *>(ptr));
}

/**
 * Helper function to copy from pointer to Cloneable.
 * @tparam T - derived from Cloneable
 * @param object - object to clone
 * @return clone of object
 */
template <typename T>
auto clone(T *object) {
  return clone(*object);
}

/**
 * Interface for cloneable classes.
 * @tparam T
 */
template <typename T>
class Cloneable {
 public:
  using base_type = T;

  virtual ~Cloneable() = default;

 protected:
  /**
   * Polymorphic clone constructor.
   * Method guarantees deep-copy.
   * @return pointer to cloned object
   */
  virtual T *clone() const = 0;

  template <typename X>
  friend std::unique_ptr<X> clone(const X &);
};

#endif  // IROHA_CLONEABLE_HPP
