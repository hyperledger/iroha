/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/yac_common.hpp"

#include <algorithm>

#include "consensus/yac/outcome_messages.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      bool sameKeys(const std::vector<VoteMessage> &votes) {
        if (votes.empty()) {
          return false;
        }

        auto first = votes.at(0);
        return std::all_of(
            votes.begin(), votes.end(), [&first](const auto &current) {
              return first.hash.vote_round == current.hash.vote_round;
            });
      }

      boost::optional<Round> getKey(const std::vector<VoteMessage> &votes) {
        if (not sameKeys(votes)) {
          return boost::none;
        }
        return votes[0].hash.vote_round;
      }

      boost::optional<YacHash> getHash(const std::vector<VoteMessage> &votes) {
        if (not sameKeys(votes)) {
          return boost::none;
        }

        return votes.at(0).hash;
      }
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
