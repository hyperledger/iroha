/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_hash_provider_impl.hpp"

#include <string>

#include <gtest/gtest.h>

#include <boost/make_shared.hpp>
#include <boost/range/adaptor/indirected.hpp>
#include <boost/shared_container_iterator.hpp>
#include <boost/shared_ptr.hpp>
#include "framework/crypto_literals.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha;
using namespace iroha::consensus::yac;
using namespace shared_model::interface::types;

using ::testing::Return;
using ::testing::ReturnRefOfCopy;

auto makeSignature() {
  auto signature = std::make_unique<MockSignature>();
  EXPECT_CALL(*signature, publicKey())
      .WillRepeatedly(ReturnRefOfCopy(std::string{"key"}));
  EXPECT_CALL(*signature, signedData())
      .WillRepeatedly(ReturnRefOfCopy(std::string{"data"}));
  return signature;
}

auto signature() {
  auto signature = makeSignature();
  EXPECT_CALL(*signature, clone())
      .WillRepeatedly(Return(makeSignature().release()));
  return signature;
}

TEST(YacHashProviderTest, MakeYacHashTest) {
  YacHashProviderImpl hash_provider;
  iroha::consensus::Round round{1, 0};
  shared_model::crypto::Hash block_hash(std::string{"hash"});

  auto ledger_state = std::make_shared<LedgerState>(
      shared_model::interface::types::PeerList{
          makePeer("127.0.0.1", "111"_hex_pubkey)},
      shared_model::interface::types::PeerList{
          makePeer("127.0.0.2", "222"_hex_pubkey)},
      1,
      block_hash);
  auto proposal = std::make_shared<const MockProposal>();
  EXPECT_CALL(*proposal, hash())
      .WillRepeatedly(
          ReturnRefOfCopy(shared_model::crypto::Hash(std::string())));
  auto block = std::make_shared<MockBlock>();
  EXPECT_CALL(*block, payload())
      .WillRepeatedly(
          ReturnRefOfCopy(shared_model::crypto::Blob(std::string())));
  EXPECT_CALL(*block, hash())
      .WillRepeatedly(testing::ReturnRefOfCopy(block_hash));

  EXPECT_CALL(*block, signatures())
      .WillRepeatedly(
          Return(boost::make_shared_container_range(
                     boost::make_shared<std::vector<
                         std::shared_ptr<shared_model::interface::Signature>>>(
                         1, signature()))
                 | boost::adaptors::indirected));

  auto hex_proposal_hash = proposal->hash().hex();
  auto hex_block_hash = block->hash().hex();

  auto yac_hash = hash_provider.makeHash(iroha::simulator::BlockCreatorEvent{
      iroha::simulator::RoundData{proposal, block}, round, ledger_state});

  ASSERT_EQ(round, yac_hash.vote_round);
  ASSERT_EQ(hex_proposal_hash, yac_hash.vote_hashes.proposal_hash);
  ASSERT_EQ(hex_block_hash, yac_hash.vote_hashes.block_hash);
}

TEST(YacHashProviderTest, ToModelHashTest) {
  YacHashProviderImpl hash_provider;
  iroha::consensus::Round round{1, 0};

  shared_model::crypto::Hash block_hash(std::string{"hash"});
  auto ledger_state = std::make_shared<LedgerState>(
      shared_model::interface::types::PeerList{
          makePeer("127.0.0.1", "111"_hex_pubkey)},
      shared_model::interface::types::PeerList{
          makePeer("127.0.0.2", "222"_hex_pubkey)},
      1,
      block_hash);
  auto proposal = std::make_shared<MockProposal>();
  EXPECT_CALL(*proposal, hash())
      .WillRepeatedly(
          ReturnRefOfCopy(shared_model::crypto::Hash(std::string())));
  auto block = std::make_shared<MockBlock>();
  EXPECT_CALL(*block, payload())
      .WillRepeatedly(
          ReturnRefOfCopy(shared_model::crypto::Blob(std::string())));

  EXPECT_CALL(*block, signatures())
      .WillRepeatedly(
          Return(boost::make_shared_container_range(
                     boost::make_shared<std::vector<
                         std::shared_ptr<shared_model::interface::Signature>>>(
                         1, signature()))
                 | boost::adaptors::indirected));
  EXPECT_CALL(*block, hash())
      .WillRepeatedly(testing::ReturnRefOfCopy(block_hash));

  auto yac_hash = hash_provider.makeHash(iroha::simulator::BlockCreatorEvent{
      iroha::simulator::RoundData{proposal, block}, round, ledger_state});

  auto model_hash = hash_provider.toModelHash(yac_hash);

  ASSERT_EQ(model_hash, block->hash());
}
