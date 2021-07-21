/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/round.hpp"

#include <ciso646>
#include <tuple>
#include <utility>

#include <boost/functional/hash.hpp>
#include "utils/string_builder.hpp"

namespace iroha {
  namespace consensus {
    Round::Round(BlockRoundType block_r, RejectRoundType reject_r)
        : block_round{block_r}, reject_round{reject_r} {}

    bool Round::operator<(const Round &rhs) const {
      return std::tie(block_round, reject_round)
          < std::tie(rhs.block_round, rhs.reject_round);
    }

    bool Round::operator==(const Round &rhs) const {
      return std::tie(block_round, reject_round)
          == std::tie(rhs.block_round, rhs.reject_round);
    }

    bool Round::operator!=(const Round &rhs) const {
      return not(*this == rhs);
    }

    std::string Round::toString() const {
      return shared_model::detail::PrettyStringBuilder()
          .init("Round")
          .appendNamed("block", block_round)
          .appendNamed("reject", reject_round)
          .finalize();
    }

    std::size_t hash_value(Round const &val) {
      size_t seed = 0;
      boost::hash_combine(seed, val.block_round);
      boost::hash_combine(seed, val.reject_round);
      return seed;
    }
  }  // namespace consensus
}  // namespace iroha

namespace std {
  std::size_t hash<iroha::consensus::Round>::operator()(
      iroha::consensus::Round const &val) const noexcept {
    return hash_value(val);
  }
}  // namespace std
