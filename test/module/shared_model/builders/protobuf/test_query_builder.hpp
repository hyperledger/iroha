/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_QUERY_BUILDER_HPP
#define IROHA_TEST_QUERY_BUILDER_HPP

#include "builders/protobuf/builder_templates/blocks_query_template.hpp"
#include "builders/protobuf/builder_templates/query_template.hpp"
#include "module/shared_model/validators/validators.hpp"

/**
 * Builder alias, to build shared model proto query object avoiding validation
 * and "required fields" check
 */
using TestQueryBuilder = shared_model::proto::TemplateQueryBuilder<
    (1 << shared_model::proto::TemplateQueryBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator,
    shared_model::proto::Query>;

using TestUnsignedQueryBuilder = shared_model::proto::TemplateQueryBuilder<
    (1 << shared_model::proto::TemplateQueryBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator,
    shared_model::proto::UnsignedWrapper<shared_model::proto::Query>>;

using TestBlocksQueryBuilder = shared_model::proto::TemplateBlocksQueryBuilder<
    (1 << shared_model::proto::TemplateBlocksQueryBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator,
    shared_model::proto::BlocksQuery>;

using TestUnsignedBlocksQueryBuilder =
    shared_model::proto::TemplateBlocksQueryBuilder<
        (1 << shared_model::proto::TemplateBlocksQueryBuilder<>::total) - 1,
        shared_model::validation::AlwaysValidValidator,
        shared_model::proto::UnsignedWrapper<shared_model::proto::BlocksQuery>>;

#endif  // IROHA_TEST_QUERY_BUILDER_HPP
