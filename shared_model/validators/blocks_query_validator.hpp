/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BLOCKS_QUERY_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_BLOCKS_QUERY_VALIDATOR_HPP

#include "interfaces/queries/blocks_query.hpp"
#include "validators/answer.hpp"

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
       * @return Answer containing found error if any
       */
      Answer validate(const interface::BlocksQuery &qry) const {
        Answer answer;
        std::string qry_reason_name = "Blocks query";
        ReasonsGroupType qry_reason(qry_reason_name, GroupedReasons());

        field_validator_.validateCreatorAccountId(qry_reason,
                                                  qry.creatorAccountId());
        field_validator_.validateCreatedTime(qry_reason, qry.createdTime());
        field_validator_.validateCounter(qry_reason, qry.queryCounter());

        if (not qry_reason.second.empty()) {
          answer.addReason(std::move(qry_reason));
        }
        return answer;
      }

     protected:
      Answer answer_;
      FieldValidator field_validator_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_BLOCKS_QUERY_VALIDATOR_HPP
