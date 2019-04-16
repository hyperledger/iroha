/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"

#include "consensus/yac/transport/yac_pb_converters.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      CryptoProviderImpl::CryptoProviderImpl(
          const shared_model::crypto::Keypair &keypair,
          std::shared_ptr<shared_model::interface::CommonObjectsFactory>
              factory)
          : keypair_(keypair), factory_(std::move(factory)) {}

      bool CryptoProviderImpl::verify(const std::vector<VoteMessage> &msg) {
        return std::all_of(
            std::begin(msg), std::end(msg), [](const auto &vote) {
              auto serialized =
                  PbConverters::serializeVote(vote).hash().SerializeAsString();
              auto blob = shared_model::crypto::Blob(serialized);

              return shared_model::crypto::CryptoVerifier<>::verify(
                  vote.signature->signedData(),
                  blob,
                  vote.signature->publicKey());
            });
      }

      VoteMessage CryptoProviderImpl::getVote(YacHash hash) {
        VoteMessage vote;
        vote.hash = hash;
        auto serialized =
            PbConverters::serializeVotePayload(vote).hash().SerializeAsString();
        auto blob = shared_model::crypto::Blob(serialized);
        const auto &pubkey = keypair_.publicKey();
        const auto &privkey = keypair_.privateKey();
        auto signature = shared_model::crypto::CryptoSigner<>::sign(
            blob, shared_model::crypto::Keypair(pubkey, privkey));

        // TODO 30.08.2018 andrei: IR-1670 Remove optional from YAC
        // CryptoProviderImpl::getVote
        factory_->createSignature(pubkey, signature)
            .match(
                [&](iroha::expected::Value<
                    std::unique_ptr<shared_model::interface::Signature>> &sig) {
                  vote.signature = std::move(sig.value);
                },
                [](iroha::expected::Error<std::string> &reason) {
                });

        return vote;
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
