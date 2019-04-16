/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VOTE_MESSAGE_HPP
#define IROHA_VOTE_MESSAGE_HPP

#include <memory>

#include "consensus/yac/yac_hash_provider.hpp"  // for YacHash
#include "interfaces/common_objects/signature.hpp"
#include "utils/string_builder.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

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
              .append("yac hash", hash.toString())
              .append("signature",
                      signature ? signature->toString() : "not set")
              .finalize();
        }
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_VOTE_MESSAGE_HPP
