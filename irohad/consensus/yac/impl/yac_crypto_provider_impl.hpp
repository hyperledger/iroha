/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
#define IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP

#include "consensus/yac/yac_crypto_provider.hpp"

#include "cryptography/keypair.hpp"
#include "logger/logger_fwd.hpp"

namespace shared_model {
  namespace crypto {
    class CryptoSigner;
  }
}  // namespace shared_model

namespace iroha {
  namespace consensus {
    namespace yac {
      class CryptoProviderImpl : public YacCryptoProvider {
       public:
        CryptoProviderImpl(
            std::shared_ptr<shared_model::crypto::CryptoSigner> crypto_signer,
            logger::LoggerPtr log);

        // TODO 18.04.2020 IR-710 @mboldyrev: make it return Result
        bool verify(const std::vector<VoteMessage> &msg) override;

        VoteMessage getVote(YacHash hash) override;

       private:
        std::shared_ptr<shared_model::crypto::CryptoSigner> crypto_signer_;
        logger::LoggerPtr log_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
