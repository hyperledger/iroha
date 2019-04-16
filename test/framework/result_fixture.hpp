/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_FIXTURE_HPP
#define IROHA_RESULT_FIXTURE_HPP

#include "common/result.hpp"

namespace framework {
  namespace expected {
    template <typename ResultType>
    using ValueOf = iroha::expected::ValueOf<ResultType>;
    template <typename ResultType>
    using ErrorOf = iroha::expected::ErrorOf<ResultType>;
    /**
     * @return optional with value if present
     *         otherwise none
     */
    template <typename ResultType>
    boost::optional<ValueOf<std::decay_t<ResultType>>> val(
        ResultType &&res) noexcept {
      if (auto *val = boost::get<ValueOf<std::decay_t<ResultType>>>(&res)) {
        return std::move(*val);
      }
      return {};
    }

    /**
     * @return optional with error if present
     *         otherwise none
     */
    template <typename ResultType>
    boost::optional<ErrorOf<std::decay_t<ResultType>>> err(
        ResultType &&res) noexcept {
      if (auto *val = boost::get<ErrorOf<std::decay_t<ResultType>>>(&res)) {
        return std::move(*val);
      }
      return {};
    }
  }  // namespace expected
}  // namespace framework

#endif  // IROHA_RESULT_FIXTURE_HPP
