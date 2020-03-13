/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/blocks_query.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string BlocksQuery::toString() const {
      return detail::PrettyStringBuilder()
          .init("BlocksQuery")
          .appendNamed("creatorId", creatorAccountId())
          .appendNamed("queryCounter", queryCounter())
          .append(Signable::toString())
          .finalize();
    }

    bool BlocksQuery::operator==(const ModelType &rhs) const {
      return creatorAccountId() == rhs.creatorAccountId()
          and queryCounter() == rhs.queryCounter()
          and createdTime() == rhs.createdTime()
          and signatures() == rhs.signatures();
    }

  }  // namespace interface
}  // namespace shared_model
