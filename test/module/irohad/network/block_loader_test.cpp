/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <grpc++/security/server_credentials.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <gtest/gtest.h>

#include "builders/protobuf/builder_templates/transaction_template.hpp"
#include "consensus/consensus_block_cache.hpp"
#include "cryptography/hash.hpp"
#include "datetime/time.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_client_factory.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/mock_block_query.hpp"
#include "module/irohad/ametsuchi/mock_block_query_factory.hpp"
#include "module/irohad/ametsuchi/mock_peer_query.hpp"
#include "module/irohad/ametsuchi/mock_peer_query_factory.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "network/impl/block_loader_impl.hpp"
#include "network/impl/block_loader_service.hpp"
#include "network/impl/client_factory.hpp"
#include "validators/default_validator.hpp"

using namespace std::literals;
using namespace iroha::network;
using namespace iroha::ametsuchi;
using namespace framework::expected;
using namespace shared_model::crypto;
using namespace shared_model::interface::types;
using namespace shared_model::validation;

using testing::_;
using testing::A;
using testing::ByMove;
using testing::Return;

using wPeer = std::shared_ptr<shared_model::interface::Peer>;

class BlockLoaderTest : public testing::Test {
 public:
  void SetUp() override {
    peer_query = std::make_shared<MockPeerQuery>();
    peer_query_factory = std::make_shared<MockPeerQueryFactory>();
    EXPECT_CALL(*peer_query_factory, createPeerQuery())
        .WillRepeatedly(testing::Return(boost::make_optional(
            std::shared_ptr<iroha::ametsuchi::PeerQuery>(peer_query))));
    storage = std::make_shared<MockBlockQuery>();
    block_query_factory = std::make_shared<MockBlockQueryFactory>();
    EXPECT_CALL(*block_query_factory, createBlockQuery())
        .WillRepeatedly(testing::Return(boost::make_optional(
            std::shared_ptr<iroha::ametsuchi::BlockQuery>(storage))));
    block_cache = std::make_shared<iroha::consensus::ConsensusResultCache>();
    auto validator_ptr =
        std::make_unique<MockValidator<shared_model::interface::Block>>();
    validator = validator_ptr.get();
    loader = std::make_shared<BlockLoaderImpl>(
        peer_query_factory,
        std::make_shared<shared_model::proto::ProtoBlockFactory>(
            std::move(validator_ptr),
            std::make_unique<MockValidator<iroha::protocol::Block>>()),
        getTestLogger("BlockLoader"),
        std::make_unique<ClientFactoryImpl<BlockLoaderImpl::Service>>(
            getTestInsecureClientFactory(std::nullopt)));
    service = std::make_shared<BlockLoaderService>(
        block_query_factory, block_cache, getTestLogger("BlockLoaderService"));

    grpc::ServerBuilder builder;
    int port = 0;
    builder.AddListeningPort(
        "127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(service.get());
    server = builder.BuildAndStart();

    address = "127.0.0.1:" + std::to_string(port);
    peer = makePeer(address, peer_key);

    ASSERT_TRUE(server);
    ASSERT_NE(port, 0);
  }

  void setPeerQuery() {
    EXPECT_CALL(*peer_query, getLedgerPeers(false))
        .WillRepeatedly(Return(std::vector<wPeer>{peer}));
    EXPECT_CALL(
        *peer_query,
        getLedgerPeerByPublicKey(PublicKeyHexStringView{peer->pubkey()}))
        .WillRepeatedly(
            Return(std::shared_ptr<shared_model::interface::Peer>(peer)));
  }

  auto getBaseBlockBuilder(
      const Hash &prev_hash =
          Hash(std::string(DefaultCryptoAlgorithmType::kHashLength, '0')),
      shared_model::interface::types::HeightType height = 1) const {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(TestUnsignedTransactionBuilder()
                      .creatorAccountId("account@domain")
                      .setAccountQuorum("account@domain", 1)
                      .createdTime(iroha::time::now())
                      .quorum(1)
                      .build()
                      .signAndAddSignature(key)
                      .finish());
    return shared_model::proto::TemplateBlockBuilder<
               (1 << shared_model::proto::TemplateBlockBuilder<>::total) - 1,
               shared_model::validation::AlwaysValidValidator,
               shared_model::proto::UnsignedWrapper<
                   shared_model::proto::Block>>()
        .height(height)
        .prevHash(prev_hash)
        .createdTime(iroha::time::now())
        .transactions(txs);
  }

  auto retrieveBlockAndCompare(
      const shared_model::interface::types::HeightType height) {
    return loader->retrieveBlock(peer_key, height).assumeValue();
  }

  std::shared_ptr<MockPeer> peer;
  std::string address;
  shared_model::interface::types::PublicKeyHexStringView peer_key{"peer_key"sv};
  Keypair key = DefaultCryptoAlgorithmType::generateKeypair();
  std::shared_ptr<MockPeerQuery> peer_query;
  std::shared_ptr<MockPeerQueryFactory> peer_query_factory;
  std::shared_ptr<MockBlockQuery> storage;
  std::shared_ptr<MockBlockQueryFactory> block_query_factory;
  std::shared_ptr<BlockLoaderImpl> loader;
  std::shared_ptr<BlockLoaderService> service;
  std::unique_ptr<grpc::Server> server;
  std::shared_ptr<iroha::consensus::ConsensusResultCache> block_cache;
  MockValidator<shared_model::interface::Block> *validator;
};

/**
 * Current block height 1 => Other block height 1 => no blocks received
 * @given empty storage, related block loader and base block
 * @when retrieveBlocks is called
 * @then nothing is returned
 */
TEST_F(BlockLoaderTest, ValidWhenSameTopBlock) {
  auto block = getBaseBlockBuilder().build().signAndAddSignature(key).finish();

  setPeerQuery();
  EXPECT_CALL(*storage, getTopBlockHeight()).WillOnce(Return(1));

  auto reader = loader->retrieveBlocks(1, peer_key).assumeValue();
  size_t count = 0;
  while (std::holds_alternative<
         std::shared_ptr<const shared_model::interface::Block>>(
      reader->read())) {
    ++count;
  }
  ASSERT_EQ(0, count);
}

/**
 * @given block loader and a pair of consecutive blocks
 * @when retrieveBlocks is called
 * @then the last one is returned
 */
TEST_F(BlockLoaderTest, ValidWhenOneBlock) {
  // Current block height 1 => Other block height 2 => one block received
  // time validation should work based on the block field
  // so it should pass stateless BlockLoader validation
  auto block = getBaseBlockBuilder()
                   .createdTime(228)
                   .build()
                   .signAndAddSignature(key)
                   .finish();

  auto top_block = getBaseBlockBuilder()
                       .createdTime(block.createdTime() + 1)
                       .height(block.height() + 1)
                       .build()
                       .signAndAddSignature(key)
                       .finish();

  setPeerQuery();
  EXPECT_CALL(*storage, getTopBlockHeight())
      .WillOnce(Return(top_block.height()));
  EXPECT_CALL(*storage, getBlock(top_block.height()))
      .WillOnce(Return(ByMove(iroha::expected::makeValue(
          clone<shared_model::interface::Block>(top_block)))));
  auto reader = loader->retrieveBlocks(1, peer_key).assumeValue();
  size_t count = 0;
  for (auto maybe_block = reader->read(); std::holds_alternative<
           std::shared_ptr<const shared_model::interface::Block>>(maybe_block);
       maybe_block = reader->read()) {
    ++count;
    ASSERT_EQ(*std::get<std::shared_ptr<const shared_model::interface::Block>>(
                  maybe_block),
              top_block);
  }
  ASSERT_EQ(1, count);
}

/**
 * @given block loader, a block, and additional num_blocks blocks
 * @when retrieveBlocks is called
 * @then it returns consecutive heights
 */
TEST_F(BlockLoaderTest, ValidWhenMultipleBlocks) {
  // Current block height 1 => Other block height n => n-1 blocks received
  // time validation should work based on the block field
  // so it should pass stateless BlockLoader validation
  auto block = getBaseBlockBuilder()
                   .createdTime(1337)
                   .build()
                   .signAndAddSignature(key)
                   .finish();

  auto num_blocks = 2;
  auto next_height = block.height() + 1;

  EXPECT_CALL(*storage, getTopBlockHeight())
      .WillOnce(Return(block.height() + num_blocks));
  for (auto i = next_height; i < next_height + num_blocks; ++i) {
    auto blk = getBaseBlockBuilder()
                   .height(i)
                   .build()
                   .signAndAddSignature(key)
                   .finish();

    EXPECT_CALL(*storage, getBlock(i))
        .WillOnce(Return(ByMove(iroha::expected::makeValue(
            clone<shared_model::interface::Block>(blk)))));
  }

  setPeerQuery();
  auto reader = loader->retrieveBlocks(1, peer_key).assumeValue();
  size_t count = 0;
  auto height = next_height;
  for (auto maybe_block = reader->read(); std::holds_alternative<
           std::shared_ptr<const shared_model::interface::Block>>(maybe_block);
       maybe_block = reader->read()) {
    ++count;
    ASSERT_EQ(std::get<std::shared_ptr<const shared_model::interface::Block>>(
                  maybe_block)
                  ->height(),
              height);
    ++height;
  }
  ASSERT_EQ(num_blocks, count);
}

MATCHER_P(RefAndPointerEq, arg1, "") {
  return arg == *arg1;
}
/**
 * @given block loader @and consensus cache with a block
 * @when retrieveBlock is called with the related height
 * @then it returns the same block @and block loader service does not ask
 * storage
 */
TEST_F(BlockLoaderTest, ValidWhenBlockPresent) {
  // Request existing block => success
  auto block = std::make_shared<shared_model::proto::Block>(
      getBaseBlockBuilder().build().signAndAddSignature(key).finish());
  block_cache->insert(block);

  setPeerQuery();
  EXPECT_CALL(*validator, validate(RefAndPointerEq(block)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*storage, getBlock(_)).Times(0);

  EXPECT_EQ(*block, *retrieveBlockAndCompare(block->height()));
}

/**
 * @given block loader @and consensus cache with a block @and mocked storage
 * with two blocks
 * @when retrieveBlock is called with height of previous block
 * @then consensus cache is missed @and block loader tries to fetch block from
 * the storage
 */
TEST_F(BlockLoaderTest, ValidWhenBlockMissing) {
  auto prev_block = std::make_shared<shared_model::proto::Block>(
      getBaseBlockBuilder().build().signAndAddSignature(key).finish());
  auto cur_block = std::make_shared<shared_model::proto::Block>(
      getBaseBlockBuilder(prev_block->hash(), prev_block->height() + 1)
          .build()
          .signAndAddSignature(key)
          .finish());
  block_cache->insert(cur_block);

  setPeerQuery();
  EXPECT_CALL(*storage, getBlock(prev_block->height()))
      .WillOnce(Return(ByMove(iroha::expected::makeValue(
          clone<shared_model::interface::Block>(*prev_block)))));

  EXPECT_EQ(*prev_block, *retrieveBlockAndCompare(prev_block->height()));
}

/**
 * @given block loader @and empty consensus cache @and two blocks in storage
 * @when retrieveBlock is called with first block's height
 * @then consensus cache is missed @and block loader tries to fetch block from
 * the storage
 */
TEST_F(BlockLoaderTest, ValidWithEmptyCache) {
  auto prev_block = std::make_shared<shared_model::proto::Block>(
      getBaseBlockBuilder().build().signAndAddSignature(key).finish());
  auto cur_block = std::make_shared<shared_model::proto::Block>(
      getBaseBlockBuilder(prev_block->hash(), prev_block->height() + 1)
          .build()
          .signAndAddSignature(key)
          .finish());

  setPeerQuery();
  EXPECT_CALL(*storage, getBlock(prev_block->height()))
      .WillOnce(Return(ByMove(iroha::expected::makeValue(
          clone<shared_model::interface::Block>(*prev_block)))));

  EXPECT_EQ(*prev_block, *retrieveBlockAndCompare(prev_block->height()));
}

/**
 * @given block loader @and empty consensus cache @and no blocks in storage
 * @when retrieveBlock is called with some block height
 * @then consensus cache is missed @and block storage is missed @and block
 * loader returns nothing
 */
TEST_F(BlockLoaderTest, NoBlocksInStorage) {
  setPeerQuery();
  EXPECT_CALL(*storage, getBlock(1))
      .WillOnce(
          Return(ByMove(iroha::expected::makeError(BlockQuery::GetBlockError{
              BlockQuery::GetBlockError::Code::kNoBlock, "no block"}))));

  IROHA_ASSERT_RESULT_ERROR(loader->retrieveBlock(peer_key, 1));
}
