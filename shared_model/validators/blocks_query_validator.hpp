/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BLOCKS_QUERY_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_BLOCKS_QUERY_VALIDATOR_HPP

#include "interfaces/queries/blocks_query.hpp"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {
    /**
     * Class that validates blocks query field from query
     * @tparam FieldValidator - field validator type
     */
    template <typename FieldValidator>
    class BlocksQueryValidator
        : public AbstractValidator<interface::BlocksQuery> {
      BlocksQueryValidator(FieldValidator field_validator)
          : field_validator_(std::move(field_validator)) {}

     public:
      BlocksQueryValidator(std::shared_ptr<ValidatorsConfig> config)
          : BlocksQueryValidator(FieldValidator(std::move(config))) {}

      /**
       * Applies validation to given query
       * @param qry - query to validate
       * @return found error if any
       */
      std::optional<ValidationError> validate(
          const interface::BlocksQuery &qry) const {
        ValidationErrorCreator error_creator;

        error_creator |=
            field_validator_.validateCreatorAccountId(qry.creatorAccountId());
        error_creator |=
            field_validator_.validateCreatedTime(qry.createdTime());
        error_creator |= field_validator_.validateCounter(qry.queryCounter());

        return std::move(error_creator).getValidationError("Blocks query");
      }

     protected:
      FieldValidator field_validator_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_BLOCKS_QUERY_VALIDATOR_HPP
