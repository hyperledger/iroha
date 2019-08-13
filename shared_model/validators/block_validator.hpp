/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_VALIDATOR_HPP
#define IROHA_BLOCK_VALIDATOR_HPP

#include <boost/format.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/transaction.hpp"
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
        Answer answer = ContainerValidator<interface::Block,
                                           FieldValidator,
                                           TransactionsCollectionValidator>::
            validate(block, "Block", [this](auto &reason, const auto &cont) {
              this->field_validator_.validateHash(reason, cont.prevHash());
            });

        validation::ReasonsGroupType block_reason;
        std::unordered_set<std::string> hashes = {};

        auto rejected_hashes = block.rejected_transactions_hashes();

        for (const auto &hash : rejected_hashes | boost::adaptors::indexed(0)) {
          if (hashes.count(hash.value().hex())) {
            block_reason.second.emplace_back(
                (boost::format("Rejected hash '%s' with index "
                               "'%d' has already appeared in a block")
                 % hash.value().hex() % hash.index())
                    .str());
          } else {
            hashes.insert(hash.value().hex());
          }
        }

        auto transaction = block.transactions();

        for (const auto &tx : transaction | boost::adaptors::indexed(0)) {
          auto hex = tx.value().hash().hex();
          if (hashes.count(hex)) {
            block_reason.second.emplace_back(
                (boost::format("Hash '%s' of transaction "
                               "'%d' has already appeared in rejected hashes")
                 % hex % tx.index())
                    .str());
          }
        }

        if (not block_reason.second.empty()) {
          answer.addReason(std::move(block_reason));
        }

        return answer;
      }
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_BLOCK_VALIDATOR_HPP
