/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RETURN_WRAPPER_HPP
#define IROHA_RETURN_WRAPPER_HPP

#include <boost/optional.hpp>

namespace iroha {
  namespace ametsuchi {

    /**
     * Common wrapper type for raw storage methods
     */
    template <typename RV>
    using ReturnWrapperType = boost::optional<RV>;

    /// default value of wrapper
    static boost::none_t DefaultError = boost::none;

    template <typename RV>
    inline boost::optional<RV>  wrapValue(RV &&rv) {
      return boost::make_optional(rv);
    }

  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_RETURN_WRAPPER_HPP
