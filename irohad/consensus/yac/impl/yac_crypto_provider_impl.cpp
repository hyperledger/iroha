/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"

#include "backend/plain/signature.hpp"
#include "consensus/yac/transport/yac_pb_converters.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      CryptoProviderImpl::CryptoProviderImpl(
          const shared_model::crypto::Keypair &keypair)
          : keypair_(keypair) {}

      bool CryptoProviderImpl::verify(const std::vector<VoteMessage> &msg) {
        return std::all_of(
            std::begin(msg), std::end(msg), [](const auto &vote) {
              auto serialized =
                  PbConverters::serializeVote(vote).hash().SerializeAsString();
              auto signed_message = shared_model::crypto::BytesView(
                  serialized.data(), serialized.size());

              return shared_model::crypto::CryptoVerifier<>::verify(
                  vote.signature->signedData(),
                  signed_message,
                  vote.signature->publicKey());
            });
      }

      VoteMessage CryptoProviderImpl::getVote(YacHash hash) {
        VoteMessage vote;
        vote.hash = hash;
        auto serialized =
            PbConverters::serializeVotePayload(vote).hash().SerializeAsString();
        auto signed_message = shared_model::crypto::BytesView(
            serialized.data(), serialized.size());
        const auto &pubkey = keypair_.publicKey();
        const auto &privkey = keypair_.privateKey();
        auto signature = shared_model::crypto::CryptoSigner<>::sign(
            signed_message, shared_model::crypto::Keypair(pubkey, privkey));

        // TODO 30.08.2018 andrei: IR-1670 Remove optional from YAC
        // CryptoProviderImpl::getVote
        vote.signature =
            std::make_shared<shared_model::plain::Signature>(signature, pubkey);

        return vote;
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
