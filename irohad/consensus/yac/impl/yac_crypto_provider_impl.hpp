/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
#define IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP

#include "consensus/yac/yac_crypto_provider.hpp"

#include "cryptography/keypair.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      class CryptoProviderImpl : public YacCryptoProvider {
       public:
        CryptoProviderImpl(
            const shared_model::crypto::Keypair &keypair,
            std::shared_ptr<shared_model::interface::CommonObjectsFactory>
                factory);

        bool verify(const std::vector<VoteMessage> &msg) override;

        VoteMessage getVote(YacHash hash) override;

       private:
        shared_model::crypto::Keypair keypair_;
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
