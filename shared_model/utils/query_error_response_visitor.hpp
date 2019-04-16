/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_ERROR_RESPONSE_VISITOR_HPP
#define IROHA_QUERY_ERROR_RESPONSE_VISITOR_HPP

#include <boost/variant.hpp>
#include "common/visitor.hpp"
#include "interfaces/query_responses/error_query_response.hpp"

namespace shared_model {
  namespace interface {
    template <typename Error>
    class QueryErrorResponseChecker : public boost::static_visitor<bool> {
     public:
      bool operator()(
          const shared_model::interface::ErrorQueryResponse &status) const {
        return iroha::visit_in_place(status.get(),
                                     [](const Error &) { return true; },
                                     [](const auto &) { return false; });
      }

      template <typename T>
      bool operator()(const T &) const {
        return false;
      }
    };

    template <typename Error, typename QueryVariant>
    bool checkForQueryError(QueryVariant &&query) {
      return boost::apply_visitor(
          shared_model::interface::QueryErrorResponseChecker<Error>(),
          std::forward<QueryVariant>(query));
    }
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_QUERY_ERROR_RESPONSE_VISITOR_HPP
