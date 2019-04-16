/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_INSTANCEOF_HPP
#define IROHA_COMMON_INSTANCEOF_HPP

#include <typeinfo>

// check the type of the derived class
template <typename Base, typename T>
inline bool instanceof (const T *ptr) {
  return typeid(Base) == typeid(*ptr);
}

template <typename Base, typename T>
inline bool instanceof (const T &ptr) {
  return typeid(Base) == typeid(ptr);
}

#endif  // IROHA_COMMON_INSTANCEOF_HPP
