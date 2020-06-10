/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/error_query_response.hpp"

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/variant.hpp>
#include "interfaces/query_responses/error_responses/no_account_assets_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_account_detail_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_account_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_asset_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_roles_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_signatories_error_response.hpp"
#include "interfaces/query_responses/error_responses/not_supported_error_response.hpp"
#include "interfaces/query_responses/error_responses/stateful_failed_error_response.hpp"
#include "interfaces/query_responses/error_responses/stateless_failed_error_response.hpp"
#include "utils/visitor_apply_for_all.hpp"

namespace shared_model {
  namespace interface {

    std::string ErrorQueryResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("ErrorQueryResponse")
          .append(boost::apply_visitor(detail::ToStringVisitor(), get()))
          .appendNamed("errorMessage", errorMessage())
          .finalize();
    }

    bool ErrorQueryResponse::operator==(const ModelType &rhs) const {
      return get() == rhs.get();
    }

  }  // namespace interface
}  // namespace shared_model
