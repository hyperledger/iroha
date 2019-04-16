/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCK_BUILDER_HPP
#define IROHA_PROTO_BLOCK_BUILDER_HPP

#include "module/shared_model/builders/protobuf/builder_templates/block_template.hpp"

namespace shared_model {
  namespace proto {

    using BlockBuilder = TemplateBlockBuilder<>;

    using UnsignedBlockBuilder = TemplateBlockBuilder<
        0,
        shared_model::validation::DefaultUnsignedBlockValidator,
        shared_model::proto::Block>;
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCK_BUILDER_HPP
