/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validation/impl/chain_validator_impl.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/mock_mutable_storage.hpp"
#include "module/irohad/consensus/yac/mock_yac_supermajority_checker.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha;
using namespace iroha::validation;
using namespace iroha::ametsuchi;

using ::testing::_;
using ::testing::A;
using ::testing::ByRef;
using ::testing::DoAll;
using ::testing::InvokeArgument;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;
using ::testing::SaveArg;

class ChainValidationTest : public ::testing::Test {
 public:
  void SetUp() override {
    validator = std::make_shared<ChainValidatorImpl>(
        supermajority_checker, getTestLogger("ChainValidator"));
    storage = std::make_shared<MockMutableStorage>();
    peers = std::vector<std::shared_ptr<shared_model::interface::Peer>>();
    sync_peers = std::vector<std::shared_ptr<shared_model::interface::Peer>>();

    {
      auto peer = std::make_shared<MockPeer>();
      EXPECT_CALL(*peer, pubkey())
          .WillRepeatedly(ReturnRefOfCopy(
              iroha::bytestringToHexstring(std::string(32, '0'))));
      peers.push_back(peer);
    }

    {
      auto peer = std::make_shared<MockPeer>();
      EXPECT_CALL(*peer, pubkey())
          .WillRepeatedly(ReturnRefOfCopy(
              iroha::bytestringToHexstring(std::string(32, '1'))));
      sync_peers.push_back(peer);
    }

    auto signature = std::make_shared<MockSignature>();
    EXPECT_CALL(*signature, publicKey())
        .WillRepeatedly(ReturnRefOfCopy(
            iroha::bytestringToHexstring(std::string(32, '0'))));
    signatures.push_back(signature);

    EXPECT_CALL(*mock_block, height()).WillRepeatedly(Return(height));
    EXPECT_CALL(*mock_block, prevHash())
        .WillRepeatedly(testing::ReturnRef(prev_hash));
    EXPECT_CALL(*mock_block, signatures())
        .WillRepeatedly(Return(signatures | boost::adaptors::indirected));
    EXPECT_CALL(*mock_block, payload())
        .WillRepeatedly(ReturnRefOfCopy(shared_model::crypto::Blob{"blob"}));
    EXPECT_CALL(*mock_block, hash())
        .WillRepeatedly(testing::ReturnRefOfCopy(
            shared_model::crypto::Hash(std::string("hash"))));
  }

  std::shared_ptr<iroha::consensus::yac::MockSupermajorityChecker>
      supermajority_checker =
          std::make_shared<iroha::consensus::yac::MockSupermajorityChecker>();
  std::shared_ptr<ChainValidatorImpl> validator;
  std::shared_ptr<MockMutableStorage> storage;

  std::vector<std::shared_ptr<shared_model::interface::Signature>> signatures;
  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers;
  std::vector<std::shared_ptr<shared_model::interface::Peer>> sync_peers;
  shared_model::crypto::Hash prev_hash =
      shared_model::crypto::Hash(std::string{"previous top hash"});
  shared_model::interface::types::HeightType prev_height = 1;
  shared_model::interface::types::HeightType height = prev_height + 1;
  std::shared_ptr<MockBlock> mock_block = std::make_shared<MockBlock>();
  std::shared_ptr<const shared_model::interface::Block> block = mock_block;
};

/**
 * @given valid block signed by peers
 * @when apply block
 * @then block is validated
 */
TEST_F(ChainValidationTest, ValidCase) {
  // Valid previous hash, has supermajority, correct peers subset => valid
  size_t block_signatures_amount;
  EXPECT_CALL(*supermajority_checker, hasSupermajority(_, _))
      .WillOnce(DoAll(SaveArg<0>(&block_signatures_amount), Return(true)));

  EXPECT_CALL(*storage, applyIf(block, _))
      .WillOnce(InvokeArgument<1>(
          block, LedgerState{peers, sync_peers, prev_height, prev_hash}));

  ASSERT_TRUE(validator->validateAndApply(block, *storage));
  ASSERT_EQ(boost::size(block->signatures()), block_signatures_amount);
}

/**
 * @given block with wrong hash
 * @when apply block
 * @then block is not validated
 */
TEST_F(ChainValidationTest, FailWhenDifferentPrevHash) {
  // Invalid previous hash, has supermajority, correct peers subset => invalid
  shared_model::crypto::Hash another_hash =
      shared_model::crypto::Hash(std::string(32, '1'));

  EXPECT_CALL(*supermajority_checker, hasSupermajority(_, _))
      .WillRepeatedly(Return(true));

  EXPECT_CALL(*storage, applyIf(block, _))
      .WillOnce(InvokeArgument<1>(
          block, LedgerState{peers, sync_peers, prev_height, another_hash}));

  ASSERT_FALSE(validator->validateAndApply(block, *storage));
}

/**
 * @given block with wrong peers
 * @when supermajority is not achieved
 * @then block is not validated
 */
TEST_F(ChainValidationTest, FailWhenNoSupermajority) {
  // Valid previous hash, no supermajority, correct peers subset => invalid
  size_t block_signatures_amount;
  EXPECT_CALL(*supermajority_checker, hasSupermajority(_, _))
      .WillOnce(DoAll(SaveArg<0>(&block_signatures_amount), Return(false)));

  EXPECT_CALL(*storage, applyIf(block, _))
      .WillOnce(InvokeArgument<1>(
          block, LedgerState{peers, sync_peers, prev_height, prev_hash}));

  ASSERT_FALSE(validator->validateAndApply(block, *storage));
  ASSERT_EQ(boost::size(block->signatures()), block_signatures_amount);
}
