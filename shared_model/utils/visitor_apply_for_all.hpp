/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VISITOR_APPLY_FOR_ALL_HPP
#define IROHA_VISITOR_APPLY_FOR_ALL_HPP

#include <boost/variant/static_visitor.hpp>
#include <string>

namespace shared_model {
  namespace detail {

    /**
     * Class provides generic toString visitor for objects
     */
    class ToStringVisitor : public boost::static_visitor<std::string> {
     public:
      template <typename InputType>
      auto operator()(const InputType &operand) const {
        return operand.toString();
      }
    };

  }  // namespace detail
}  // namespace shared_model
#endif  // IROHA_VISITOR_APPLY_FOR_ALL_HPP
