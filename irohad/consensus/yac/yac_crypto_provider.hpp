/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_CRYPTO_PROVIDER_HPP
#define IROHA_YAC_CRYPTO_PROVIDER_HPP

#include "consensus/yac/yac_hash_provider.hpp"  // for YacHash (passed by copy)

namespace iroha::consensus::yac {
  struct VoteMessage;

  class YacCryptoProvider {
   public:
    /**
     * Verify signatory of message
     * @param msg - for verification
     * @return true if signature correct
     */
    virtual bool verify(const std::vector<VoteMessage> &msg) = 0;

    /**
     * Generate vote for provided hash;
     * @param hash - hash for signing
     * @return vote
     */
    virtual VoteMessage getVote(YacHash hash) = 0;

    virtual ~YacCryptoProvider() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_CRYPTO_PROVIDER_HPP
