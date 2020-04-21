/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"

#include "backend/plain/signature.hpp"
#include "common/result.hpp"
#include "consensus/yac/transport/yac_pb_converters.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      CryptoProviderImpl::CryptoProviderImpl(
          shared_model::crypto::CryptoProvider crypto_provider,
          logger::LoggerPtr log)
          : crypto_provider_(std::move(crypto_provider)),
            log_(std::move(log)) {}

      bool CryptoProviderImpl::verify(const std::vector<VoteMessage> &msg) {
        return std::all_of(
            std::begin(msg), std::end(msg), [this](const auto &vote) {
              auto serialized =
                  PbConverters::serializeVote(vote).hash().SerializeAsString();
              auto blob = shared_model::crypto::Blob(serialized);

              using namespace shared_model::interface::types;
              return crypto_provider_.verifier
                  ->verify(SignedHexStringView{vote.signature->signedData()},
                           blob,
                           PublicKeyHexStringView{vote.signature->publicKey()})
                  .match([](const auto &) { return true; },
                         [this](const auto &error) {
                           log_->debug("Vote signature verification failed: {}",
                                       error.error);
                           return false;
                         });
            });
      }

      VoteMessage CryptoProviderImpl::getVote(YacHash hash) {
        VoteMessage vote;
        vote.hash = hash;
        auto serialized =
            PbConverters::serializeVotePayload(vote).hash().SerializeAsString();
        auto blob = shared_model::crypto::Blob(serialized);
        const auto &pubkey = crypto_provider_.signer->publicKey();
        auto signature = crypto_provider_.signer->sign(blob);

        // TODO 30.08.2018 andrei: IR-1670 Remove optional from YAC
        // CryptoProviderImpl::getVote
        using namespace shared_model::interface::types;
        vote.signature = std::make_shared<shared_model::plain::Signature>(
            SignedHexStringView{signature}, PublicKeyHexStringView{pubkey});

        return vote;
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
