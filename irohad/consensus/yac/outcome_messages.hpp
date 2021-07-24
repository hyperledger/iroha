/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MESSAGES_HPP
#define IROHA_MESSAGES_HPP

#include <vector>

#include "consensus/yac/vote_message.hpp"
#include "utils/string_builder.hpp"

namespace iroha::consensus::yac {
  template <typename>
  struct OutcomeMessage {
    explicit OutcomeMessage(std::vector<VoteMessage> votes)
        : votes(std::move(votes)) {}

    OutcomeMessage(std::initializer_list<VoteMessage> votes) : votes(votes) {}

    std::vector<VoteMessage> votes;

    bool operator==(const OutcomeMessage &rhs) const {
      return votes == rhs.votes;
    }

    std::string toString() const {
      return shared_model::detail::PrettyStringBuilder()
          .init(typeName())
          .appendNamed("votes", votes)
          .finalize();
    }

    virtual const std::string &typeName() const = 0;

   protected:
    ~OutcomeMessage() = default;
  };

  /**
   * CommitMsg means consensus on cluster achieved.
   * All nodes deals on some solution
   */
  struct CommitMessage final : OutcomeMessage<CommitMessage> {
    using OutcomeMessage::OutcomeMessage;
    const std::string &typeName() const override {
      const static std::string name{"CommitMessage"};
      return name;
    }
  };

  /**
   * Reject means that there is impossible
   * to collect supermajority for any block
   */
  struct RejectMessage final : OutcomeMessage<RejectMessage> {
    using OutcomeMessage::OutcomeMessage;
    const std::string &typeName() const override {
      const static std::string name{"RejectMessage"};
      return name;
    }
  };

  /**
   * Represents the case when the round number is greater than the current,
   * and the quorum is unknown
   */
  struct FutureMessage final : OutcomeMessage<FutureMessage> {
    using OutcomeMessage::OutcomeMessage;
    const std::string &typeName() const override {
      const static std::string name{"FutureMessage"};
      return name;
    }
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_MESSAGES_HPP
