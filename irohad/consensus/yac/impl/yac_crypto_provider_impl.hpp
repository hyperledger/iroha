/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
#define IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP

#include "consensus/yac/yac_crypto_provider.hpp"

#include "cryptography/keypair.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha::consensus::yac {
  class CryptoProviderImpl : public YacCryptoProvider {
   public:
    CryptoProviderImpl(const shared_model::crypto::Keypair &keypair,
                       logger::LoggerPtr log);

    // TODO 18.04.2020 IR-710 @mboldyrev: make it return Result
    bool verify(const std::vector<VoteMessage> &msg) override;

    VoteMessage getVote(YacHash hash) override;

   private:
    shared_model::crypto::Keypair keypair_;
    logger::LoggerPtr log_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_CRYPTO_PROVIDER_IMPL_HPP
