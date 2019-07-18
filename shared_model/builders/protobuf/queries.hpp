/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_QUERY_BUILDER_HPP
#define IROHA_PROTO_QUERY_BUILDER_HPP

#include "builders/protobuf/builder_templates/blocks_query_template.hpp"
#include "builders/protobuf/builder_templates/query_template.hpp"

namespace shared_model {
  namespace proto {

    using QueryBuilder = TemplateQueryBuilder<>;
    using BlocksQueryBuilder = TemplateBlocksQueryBuilder<>;

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_QUERY_BUILDER_HPP
