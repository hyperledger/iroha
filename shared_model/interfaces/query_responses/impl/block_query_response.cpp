/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/block_query_response.hpp"

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/variant.hpp>
#include "interfaces/query_responses/block_error_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "utils/visitor_apply_for_all.hpp"

namespace shared_model {
  namespace interface {
    std::string BlockQueryResponse::toString() const {
      return boost::apply_visitor(detail::ToStringVisitor(), get());
    }

    bool BlockQueryResponse::operator==(const ModelType &rhs) const {
      return get() == rhs.get();
    }
  }  // namespace interface
}  // namespace shared_model
