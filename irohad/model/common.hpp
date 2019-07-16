/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_HPP
#define IROHA_COMMON_HPP

#include <boost/optional.hpp>
#include <memory>

namespace iroha {
  namespace model {
    // Optional over shared pointer
    template <typename T>
    using optional_ptr = boost::optional<std::shared_ptr<T>>;

    template <typename T, typename... Args>
    optional_ptr<T> make_optional_ptr(Args &&... args) {
      return std::make_shared<T>(std::forward<Args>(args)...);
    }
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_COMMON_HPP
