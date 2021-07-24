/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_HASH_PROVIDER_IMPL_HPP
#define IROHA_YAC_HASH_PROVIDER_IMPL_HPP

#include "consensus/yac/yac_hash_provider.hpp"

namespace iroha::consensus::yac {
  class YacHashProviderImpl : public YacHashProvider {
   public:
    YacHash makeHash(const simulator::BlockCreatorEvent &event) const override;

    shared_model::interface::types::HashType toModelHash(
        const YacHash &hash) const override;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_HASH_PROVIDER_IMPL_HPP
