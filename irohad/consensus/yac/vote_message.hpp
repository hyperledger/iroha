/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VOTE_MESSAGE_HPP
#define IROHA_VOTE_MESSAGE_HPP

#include <memory>

#include <boost/functional/hash.hpp>
#include "consensus/yac/yac_hash_provider.hpp"  // for YacHash
#include "interfaces/common_objects/signature.hpp"
#include "utils/string_builder.hpp"

namespace iroha::consensus::yac {
  /**
   * VoteMessage represents voting for some block;
   */
  struct VoteMessage {
    YacHash hash;
    std::shared_ptr<shared_model::interface::Signature> signature;

    bool operator==(const VoteMessage &rhs) const {
      return hash == rhs.hash and *signature == *rhs.signature;
    }

    bool operator!=(const VoteMessage &rhs) const {
      return not(*this == rhs);
    }

    std::string toString() const {
      return shared_model::detail::PrettyStringBuilder()
          .init("VoteMessage")
          .appendNamed("yac hash", hash)
          .appendNamed("signature", signature)
          .finalize();
    }
  };
}  // namespace iroha::consensus::yac

namespace std {
  template <>
  struct hash<iroha::consensus::yac::VoteMessage> {
    std::size_t operator()(iroha::consensus::yac::VoteMessage const &m) const
        noexcept {
      std::size_t seed = 0;
      boost::hash_combine(seed, m.signature->publicKey());
      boost::hash_combine(seed, m.hash.vote_round);
      boost::hash_combine(seed, m.hash.vote_hashes.proposal_hash);
      boost::hash_combine(seed, m.hash.vote_hashes.block_hash);
      return seed;
    }
  };
}  // namespace std

#endif  // IROHA_VOTE_MESSAGE_HPP
