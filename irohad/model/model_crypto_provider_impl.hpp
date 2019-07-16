/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MODEL_CRYPTO_PROVIDER_IMPL_HPP
#define IROHA_MODEL_CRYPTO_PROVIDER_IMPL_HPP

#include "model_crypto_provider.hpp"
#include "sha3_hash.hpp"

namespace iroha {
  namespace model {

    /** [[deprecated]] Use irohad/crypto_provider with shared_model instead this
     * class. It is for compatibility with cli.
     */
    class ModelCryptoProviderImpl : public ModelCryptoProvider {
     public:
      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      explicit ModelCryptoProviderImpl(const keypair_t &keypair);

      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      bool verify(const Transaction &tx) const override;

      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      bool verify(const Query &query) const override;

      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      bool verify(const Block &block) const override;

      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      void sign(Block &block) const override;

      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      void sign(Transaction &transaction) const override;

      /**
       * [[deprecated]] Use irohad/crypto_provider with shared_model instead
       * this class. It is for compatibility with cli.
       */
      void sign(Query &query) const override;

     private:
      keypair_t keypair_;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_MODEL_CRYPTO_PROVIDER_IMPL_HPP
