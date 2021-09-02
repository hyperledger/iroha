/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_BLOCK_BUILDER_HPP
#define IROHA_TEST_BLOCK_BUILDER_HPP

#include "module/shared_model/builders/protobuf/builder_templates/block_template.hpp"
#include "module/shared_model/validators/validators.hpp"

/**
 * Builder alias, to build shared model proto block object avoiding validation
 * and "required fields" check
 */
using TestBlockBuilder = shared_model::proto::TemplateBlockBuilder<
    (1 << shared_model::proto::TemplateBlockBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator,
    shared_model::proto::Block>;

/**
 * Builder alias, which allows to build proto block object without validation,
 * "required fields" and signs checks
 */
using TestUnsignedBlockBuilder = shared_model::proto::TemplateBlockBuilder<
    (1 << shared_model::proto::TemplateBlockBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator,
    shared_model::proto::UnsignedWrapper<shared_model::proto::Block>>;

std::shared_ptr<const shared_model::interface::Block> createBlock(
    std::vector<shared_model::proto::Transaction> txs,
    size_t height = 1,
    shared_model::crypto::Hash prev_hash =
        shared_model::crypto::Hash(std::string{""})) {
  return clone(
      TestBlockBuilder()
          .transactions(std::vector<shared_model::proto::Transaction>(txs))
          .height(height)
          .prevHash(prev_hash)
          .createdTime(iroha::time::now())
          .build());
}

#endif  // IROHA_TEST_BLOCK_BUILDER_HPP
