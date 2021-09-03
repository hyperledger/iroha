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

using iroha::consensus::yac::CryptoProviderImpl;

CryptoProviderImpl::CryptoProviderImpl(
    const shared_model::crypto::Keypair &keypair, logger::LoggerPtr log)
    : keypair_(keypair), log_(std::move(log)) {}

bool CryptoProviderImpl::verify(const std::vector<VoteMessage> &msg) {
  return std::all_of(std::begin(msg), std::end(msg), [this](const auto &vote) {
    auto serialized =
        PbConverters::serializeVote(vote).hash().SerializeAsString();
    auto blob = shared_model::crypto::Blob(serialized);

    using namespace shared_model::interface::types;
    return shared_model::crypto::CryptoVerifier::verify(
               SignedHexStringView{vote.signature->signedData()},
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

iroha::consensus::yac::VoteMessage CryptoProviderImpl::getVote(YacHash hash) {
  VoteMessage vote;
  vote.hash = hash;
  auto serialized =
      PbConverters::serializeVotePayload(vote).hash().SerializeAsString();
  auto blob = shared_model::crypto::Blob(serialized);
  const auto &pubkey = keypair_.publicKey();
  const auto &privkey = keypair_.privateKey();
  using namespace shared_model::interface::types;
  auto signature = shared_model::crypto::CryptoSigner::sign(
      blob,
      shared_model::crypto::Keypair(PublicKeyHexStringView{pubkey}, privkey));

  // TODO 30.08.2018 andrei: IR-1670 Remove optional from YAC
  // CryptoProviderImpl::getVote
  vote.signature = std::make_shared<shared_model::plain::Signature>(
      SignedHexStringView{signature}, PublicKeyHexStringView{pubkey});

  return vote;
}
