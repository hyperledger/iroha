/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RANGE_TOOLS_HPP
#define RANGE_TOOLS_HPP

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>

namespace iroha {

  template <typename T>
  auto dereferenceOptionals(T range) {
    return range | boost::adaptors::filtered([](const auto &t) {
             return static_cast<bool>(t);
           })
        | boost::adaptors::transformed([](auto t) { return *t; });
  }

}  // namespace iroha

#endif
