/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_VALIDATOR_HPP
#define IROHA_BLOCK_VALIDATOR_HPP

#include <boost/format.hpp>
#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/answer.hpp"
#include "validators/container_validator.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Class that validates block
     */
    template <typename FieldValidator, typename TransactionsCollectionValidator>
    class BlockValidator
        : public ContainerValidator<interface::Block,
                                    FieldValidator,
                                    TransactionsCollectionValidator>,
          public AbstractValidator<interface::Block> {
     public:
      using ContainerValidator<
          interface::Block,
          FieldValidator,
          TransactionsCollectionValidator>::ContainerValidator;
      /**
       * Applies validation on block
       * @param block
       * @return Answer containing found error if any
       */
      Answer validate(const interface::Block &block) const override {
        return ContainerValidator<interface::Block,
                                  FieldValidator,
                                  TransactionsCollectionValidator>::
            validate(block, "Block", [this](auto &reason, const auto &cont) {
              this->field_validator_.validateHash(reason, cont.prevHash());
            });
      }
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_BLOCK_VALIDATOR_HPP
