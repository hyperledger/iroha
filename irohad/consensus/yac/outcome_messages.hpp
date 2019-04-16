/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MESSAGES_HPP
#define IROHA_MESSAGES_HPP

#include <vector>

#include "consensus/yac/vote_message.hpp"
#include "utils/string_builder.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      /**
       * CommitMsg means consensus on cluster achieved.
       * All nodes deals on some solution
       */
      struct CommitMessage {
        explicit CommitMessage(std::vector<VoteMessage> votes)
            : votes(std::move(votes)) {}

        std::vector<VoteMessage> votes;

        bool operator==(const CommitMessage &rhs) const {
          return votes == rhs.votes;
        }

        std::string toString() const {
          return shared_model::detail::PrettyStringBuilder()
              .init("CommitMessage")
              .appendAll(
                  "votes", votes, [](auto vote) { return vote.toString(); })
              .finalize();
        }
      };

      /**
       * Reject means that there is impossible
       * to collect supermajority for any block
       */
      struct RejectMessage {
        explicit RejectMessage(std::vector<VoteMessage> votes)
            : votes(std::move(votes)) {}

        std::vector<VoteMessage> votes;

        bool operator==(const RejectMessage &rhs) const {
          return votes == rhs.votes;
        }

        std::string toString() const {
          return shared_model::detail::PrettyStringBuilder()
              .init("RejectMessage")
              .appendAll(
                  "votes", votes, [](auto vote) { return vote.toString(); })
              .finalize();
        }
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MESSAGES_HPP
