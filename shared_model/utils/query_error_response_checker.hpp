/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_ERROR_RESPONSE_VISITOR_HPP
#define IROHA_QUERY_ERROR_RESPONSE_VISITOR_HPP

#include <gtest/gtest.h>
#include <boost/optional.hpp>
#include <boost/variant/get.hpp>
#include "interfaces/iroha_internal/error_query_response_reason.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/query_response.hpp"

namespace shared_model {
  namespace interface {
    inline void checkForQueryError(
        const shared_model::interface::QueryResponse &query,
        shared_model::interface::QueryErrorType reason,
        boost::optional<
            shared_model::interface::ErrorQueryResponse::ErrorCodeType>
            error_code = boost::none) {
      using namespace shared_model::interface;
      auto *error_response =
          boost::get<const ErrorQueryResponse &>(&query.get());
      ASSERT_NE(error_response, nullptr)
          << "ErrorQueryResponse expected, but got " << query.toString();
      EXPECT_EQ(error_response->reason(), reason);
      if (error_code) {
        EXPECT_EQ(error_response->errorCode(), *error_code);
      }
    }
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_QUERY_ERROR_RESPONSE_VISITOR_HPP
