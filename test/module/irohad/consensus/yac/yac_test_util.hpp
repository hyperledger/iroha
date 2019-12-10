/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_TEST_UTIL_HPP
#define IROHA_YAC_TEST_UTIL_HPP

#include <gmock/gmock.h>

#include "consensus/yac/vote_message.hpp"
#include "consensus/yac/yac_hash_provider.hpp"

#include "framework/crypto_dummies.hpp"
#include "module/irohad/consensus/yac/mock_yac_crypto_provider.hpp"
#include "module/shared_model/interface_mocks.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      inline std::shared_ptr<shared_model::interface::Peer> makePeer(
          const std::string &address) {
        auto peer = std::make_shared<MockPeer>();
        EXPECT_CALL(*peer, address())
            .WillRepeatedly(::testing::ReturnRefOfCopy(address));
        EXPECT_CALL(*peer, pubkey())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                iroha::createPublicKeyPadded(address)));
        EXPECT_CALL(*peer, tlsCertificate())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                boost::optional<
                    shared_model::interface::types::TLSCertificateType>()));

        return peer;
      }

      inline VoteMessage createVote(
          YacHash hash, std::shared_ptr<shared_model::crypto::Blob> pub_key) {
        VoteMessage vote;

        auto block_signature = std::make_shared<MockSignature>();
        EXPECT_CALL(*block_signature, publicKey())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                shared_model::crypto::PublicKey(pub_key)));
        EXPECT_CALL(*block_signature, signedData())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                shared_model::crypto::Signed(pub_key)));
        hash.block_signature = block_signature;
        vote.hash = std::move(hash);

        auto signature = std::make_shared<MockSignature>();
        EXPECT_CALL(*signature, publicKey())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                shared_model::crypto::PublicKey(pub_key)));
        EXPECT_CALL(*signature, signedData())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                shared_model::crypto::Signed(pub_key)));

        vote.signature = signature;
        return vote;
      }

      inline VoteMessage createVote(
          YacHash hash, const shared_model::crypto::BytesView &pub_key) {
        return createVote(
            std::move(hash),
            std::make_shared<shared_model::crypto::Blob>(pub_key.byteRange()));
      }

      inline VoteMessage createVote(YacHash hash, const std::string &pub_key) {
        return createVote(std::move(hash),
                          shared_model::crypto::Blob::fromBinaryString(
                              padPubKeyString(pub_key)));
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_TEST_UTIL_HPP
