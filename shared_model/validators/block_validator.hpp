/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_VALIDATOR_HPP
#define IROHA_BLOCK_VALIDATOR_HPP

#include <unordered_map>

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/transaction.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Class that validates block
     */
    template <typename FieldValidator, typename TransactionsCollectionValidator>
    class BlockValidator : public AbstractValidator<interface::Block> {
     public:
      BlockValidator(std::shared_ptr<ValidatorsConfig> config)
          : transactions_collection_validator_(
                TransactionsCollectionValidator{config}),
            field_validator_(FieldValidator{config}) {}

      /**
       * Applies validation on block
       * @param block
       * @return found error if any
       */
      std::optional<ValidationError> validate(
          const interface::Block &block) const override {
        ValidationErrorCreator error_creator;

        error_creator |= field_validator_.validateHeight(block.height());
        error_creator |= field_validator_.validateHash(block.prevHash());
        error_creator |= transactions_collection_validator_.validate(
            block.transactions(), block.createdTime());

        std::unordered_map<shared_model::crypto::Hash,
                           size_t,
                           shared_model::crypto::Hash::Hasher>
            rejected_hashes;
        for (auto hash : block.rejected_transactions_hashes()
                 | boost::adaptors::indexed(1)) {
          ValidationErrorCreator hash_error_creator;
          auto emplace_result =
              rejected_hashes.emplace(hash.value(), hash.index());
          if (not emplace_result.second) {
            hash_error_creator.addReason(fmt::format(
                "Duplicates hash #{}", emplace_result.first->second));
          }
          hash_error_creator |= field_validator_.validateHash(hash.value());
          error_creator |=
              std::move(hash_error_creator)
                  .getValidationErrorWithGeneratedName([&] {
                    return fmt::format("Rejected transaction hash #{} {}",
                                       hash.index(),
                                       hash.value().hex());
                  });
        }

        for (auto tx : block.transactions() | boost::adaptors::indexed(1)) {
          auto it = rejected_hashes.find(tx.value().hash());
          if (it != rejected_hashes.end()) {
            error_creator.addReason(
                fmt::format("Hash '{}' of transaction #{} has already "
                            "appeared in rejected hashes (#{}).",
                            tx.value().hash().hex(),
                            tx.index(),
                            it->second));
          }
        }

        return std::move(error_creator).getValidationError("Block");
      }

     private:
      TransactionsCollectionValidator transactions_collection_validator_;
      FieldValidator field_validator_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_BLOCK_VALIDATOR_HPP
