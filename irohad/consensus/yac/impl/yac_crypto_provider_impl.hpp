/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
#define IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP

#include "consensus/yac/yac_crypto_provider.hpp"

#include "cryptography/crypto_provider/crypto_provider.hpp"
#include "cryptography/keypair.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      class CryptoProviderImpl : public YacCryptoProvider {
       public:
        CryptoProviderImpl(shared_model::crypto::CryptoProvider crypto_provider,
                           logger::LoggerPtr log);

        // TODO 18.04.2020 IR-710 @mboldyrev: make it return Result
        bool verify(const std::vector<VoteMessage> &msg) override;

        VoteMessage getVote(YacHash hash) override;

       private:
        shared_model::crypto::CryptoProvider crypto_provider_;
        logger::LoggerPtr log_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
