/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROUND_HPP
#define IROHA_ROUND_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include <boost/operators.hpp>

namespace iroha {
  namespace consensus {

    /**
     * Type of round indexing by blocks
     */
    using BlockRoundType = uint64_t;

    /**
     * Type of round indexing by reject before new block commit
     */
    using RejectRoundType = uint32_t;

    /**
     * Type of proposal round
     */
    struct Round : public boost::less_than_comparable<Round> {
      BlockRoundType block_round;
      RejectRoundType reject_round;

      Round() = default;

      Round(BlockRoundType block_r, RejectRoundType reject_r);

      bool operator<(const Round &rhs) const;

      bool operator==(const Round &rhs) const;

      bool operator!=(const Round &rhs) const;

      std::string toString() const;
    };

    std::size_t hash_value(Round const &val);

  }  // namespace consensus
}  // namespace iroha

namespace std {
  template <>
  struct hash<iroha::consensus::Round> {
    std::size_t operator()(iroha::consensus::Round const &val) const noexcept;
  };
}  // namespace std

#endif  // IROHA_ROUND_HPP
