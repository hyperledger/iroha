/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONTAINER_VALIDATOR_HPP
#define IROHA_CONTAINER_VALIDATOR_HPP

#include <boost/format.hpp>
#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "validators/answer.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Class that validates blocks and proposal common fields
     */
    template <typename Iface,
              typename FieldValidator,
              typename TransactionsCollectionValidator>
    class ContainerValidator {
     protected:
      void validateTransactions(
          ReasonsGroupType &reason,
          const interface::types::TransactionsCollectionType &transactions,
          interface::types::TimestampType current_timestamp) const {
        auto answer = transactions_collection_validator_.validate(
            transactions, current_timestamp);
        if (answer.hasErrors()) {
          reason.second.push_back(answer.reason());
        }
      }

      explicit ContainerValidator(
          FieldValidator field_validator,
          TransactionsCollectionValidator transactions_collection_validator)
          : transactions_collection_validator_(
                std::move(transactions_collection_validator)),
            field_validator_(std::move(field_validator)) {}

     public:
      explicit ContainerValidator(std::shared_ptr<ValidatorsConfig> config,
                                  FieldValidator field_validator)
          : field_validator_{std::move(field_validator)},
            transactions_collection_validator_{std::move(config)} {}

      explicit ContainerValidator(std::shared_ptr<ValidatorsConfig> config)
          : ContainerValidator(FieldValidator(config),
                               TransactionsCollectionValidator(config)) {}

      template <typename Validator>
      Answer validate(const Iface &cont,
                      const std::string &reason_name,
                      Validator &&validator) const {
        Answer answer;
        ReasonsGroupType reason;
        reason.first = reason_name;
        field_validator_.validateHeight(reason, cont.height());
        std::forward<Validator>(validator)(reason, cont);

        validateTransactions(reason, cont.transactions(), cont.createdTime());
        if (not reason.second.empty()) {
          answer.addReason(std::move(reason));
        }
        return answer;
      }

      Answer validate(const Iface &cont, const std::string &reason_name) const {
        return validate(cont, reason_name, [](auto &, const auto &) {});
      }

     private:
      TransactionsCollectionValidator transactions_collection_validator_;

     protected:
      FieldValidator field_validator_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_CONTAINER_VALIDATOR_HPP
