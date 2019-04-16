/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ANSWER_HPP
#define IROHA_ANSWER_HPP

#include <ciso646>
#include <map>
#include <vector>

#include <boost/range/numeric.hpp>
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace validation {

    using ConcreteReasonType = std::string;
    using GroupedReasons = std::vector<ConcreteReasonType>;
    using ReasonsGroupName = std::string;
    using ReasonsGroupType = std::pair<ReasonsGroupName, GroupedReasons>;

    /**
     * Class which represents the answer to stateless validation: whether
     * validation is done right and if not it explains the reason
     */
    class Answer {
     public:
      operator bool() const {
        return not reasons_map_.empty();
      }

      /**
       * @return string representation of errors
       */
      std::string reason() const {
        return boost::accumulate(
            reasons_map_,
            std::string{},
            [](auto &&acc, const auto &command_reasons) {
              acc += detail::PrettyStringBuilder()
                         .init(command_reasons.first)
                         .appendAll(command_reasons.second,
                                    [](auto &element) { return element; })
                         .finalize()
                  + "\n";
              return std::forward<decltype(acc)>(acc);
            });
      }

      /**
       * Check if any error has been recorded to the answer
       * @return true if there are any errors, false otherwise
       */
      bool hasErrors() {
        return not reasons_map_.empty();
      }

      /**
       * Adds error to map
       * @param reasons
       */
      void addReason(ReasonsGroupType &&reasons) {
        reasons_map_.insert(std::move(reasons));
      }

      std::map<ReasonsGroupName, GroupedReasons> getReasonsMap() {
        return reasons_map_;
      };

     private:
      std::map<ReasonsGroupName, GroupedReasons> reasons_map_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_ANSWER_HPP
