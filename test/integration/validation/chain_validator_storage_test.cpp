/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "validation/impl/chain_validator_impl.hpp"

#include "ametsuchi/mutable_storage.hpp"
#include "builders/protobuf/transaction.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "cryptography/keypair.hpp"
#include "framework/result_fixture.hpp"
#include "framework/test_logger.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using shared_model::interface::types::PublicKeyHexStringView;

// TODO mboldyrev 14.02.2019 IR-324 Use supermajority checker mock
static const iroha::consensus::yac::ConsistencyModel kConsistencyModel =
    iroha::consensus::yac::ConsistencyModel::kBft;

namespace iroha {

  class ChainValidatorStorageTest : public ametsuchi::AmetsuchiTest {
   public:
    void SetUp() override {
      ametsuchi::AmetsuchiTest::SetUp();
      validator = std::make_shared<validation::ChainValidatorImpl>(
          supermajority_checker, getTestLogger("ChainValidator"));

      for (size_t i = 0; i < 5; ++i) {
        keys.push_back(shared_model::crypto::DefaultCryptoAlgorithmType::
                           generateKeypair());
      }
    }

    /// Create transaction builder with filled account id, created time, quorum
    auto baseTx() {
      return shared_model::proto::TransactionBuilder()
          .creatorAccountId("admin@test")
          .createdTime(iroha::time::now())
          .quorum(1);
    }

    /// Complete builder by adding a signature and return a signed transaction
    template <typename Builder>
    auto completeTx(Builder builder) {
      return builder.build().signAndAddSignature(keys.at(0)).finish();
    }

    /// Generate a dummy transaction with create role command
    auto dummyTx(std::size_t i) {
      return completeTx(baseTx().createRole("role" + std::to_string(i), {}));
    }

    /// Create block unsigned wrapper with given transactions, height, prev hash
    auto baseBlock(std::vector<shared_model::proto::Transaction> transactions,
                   shared_model::interface::types::HeightType height,
                   shared_model::interface::types::HashType prev_hash) {
      return shared_model::proto::BlockBuilder()
          .transactions(transactions)
          .height(height)
          .prevHash(prev_hash)
          .createdTime(iroha::time::now())
          .build();
    }

    /// Complete wrapper and return a signed object through pointer
    template <typename Wrapper>
    std::shared_ptr<shared_model::interface::Block> completeBlock(
        Wrapper &&wrapper) {
      return clone(std::forward<Wrapper>(wrapper).finish());
    }

    /// Create first block with 4 peers, apply it to storage and return it
    auto generateAndApplyFirstBlock() {
      using Pk = PublicKeyHexStringView;
      auto tx =
          completeTx(baseTx()
                         .addPeer("0.0.0.0:50541", Pk{keys.at(0).publicKey()})
                         .addPeer("0.0.0.0:50542", Pk{keys.at(1).publicKey()})
                         .addPeer("0.0.0.0:50543", Pk{keys.at(2).publicKey()})
                         .addPeer("0.0.0.0:50544", Pk{keys.at(3).publicKey()}));

      auto block = completeBlock(
          baseBlock({tx},
                    1,
                    shared_model::crypto::DefaultHashProvider::makeHash(
                        shared_model::crypto::Blob("")))
              .signAndAddSignature(keys.at(0)));

      auto ms = createMutableStorage();

      ms->apply(block);
      auto commit_result = storage->commit(std::move(ms));
      EXPECT_TRUE(boost::get<expected::ValueOf<decltype(commit_result)>>(
          (&commit_result)));

      return block;
    }

    /// Apply a chain of blocks and return its validation status
    auto createAndValidateChain(
        std::vector<std::shared_ptr<const shared_model::interface::Block>>
            chain) {
      auto ms = createMutableStorage();
      for (auto &block : chain) {
        if (not validator->validateAndApply(block, *ms)) {
          return false;
        }
      }
      return true;
    }

    std::shared_ptr<validation::ChainValidatorImpl> validator;
    std::vector<shared_model::crypto::Keypair> keys;
    std::shared_ptr<consensus::yac::SupermajorityChecker>
        supermajority_checker = consensus::yac::getSupermajorityChecker(
            kConsistencyModel  // TODO mboldyrev 13.12.2018 IR-
                               // Parametrize the tests with
                               // consistency models
        );
  };

  /**
   * @given initialized storage
   * block 1 - initial block with 4 peers
   * block 2 - new peer added. signed by all ledger peers
   * block 3 - signed by all ledger peers, contains signature of new peer
   * @when blocks 2 and 3 are validated
   * @then result is successful
   */
  TEST_F(ChainValidatorStorageTest, PeerAdded) {
    auto block1 = generateAndApplyFirstBlock();

    auto add_peer = completeTx(baseTx().addPeer(
        "0.0.0.0:50545", PublicKeyHexStringView{keys.at(4).publicKey()}));
    auto block2 = completeBlock(baseBlock({add_peer}, 2, block1->hash())
                                    .signAndAddSignature(keys.at(0))
                                    .signAndAddSignature(keys.at(1))
                                    .signAndAddSignature(keys.at(2)));

    auto block3 = completeBlock(baseBlock({dummyTx(3)}, 3, block2->hash())
                                    .signAndAddSignature(keys.at(0))
                                    .signAndAddSignature(keys.at(1))
                                    .signAndAddSignature(keys.at(2))
                                    .signAndAddSignature(keys.at(3))
                                    .signAndAddSignature(keys.at(4)));

    ASSERT_TRUE(createAndValidateChain({block2, block3}));
  }

  /**
   * @given initialized storage with 4 peers
   * block 1 - initial block with 4 peers
   * block 2 - signed by all ledger peers
   * block 3 - signed by all ledger peers
   * @when blocks 2 and 3 are validated
   * @then result is successful
   */
  TEST_F(ChainValidatorStorageTest, NoPeerAdded) {
    auto block1 = generateAndApplyFirstBlock();

    auto block2 = completeBlock(baseBlock({dummyTx(2)}, 2, block1->hash())
                                    .signAndAddSignature(keys.at(0))
                                    .signAndAddSignature(keys.at(1))
                                    .signAndAddSignature(keys.at(2)));

    auto block3 = completeBlock(baseBlock({dummyTx(3)}, 3, block2->hash())
                                    .signAndAddSignature(keys.at(0))
                                    .signAndAddSignature(keys.at(1))
                                    .signAndAddSignature(keys.at(2))
                                    .signAndAddSignature(keys.at(3)));

    ASSERT_TRUE(createAndValidateChain({block2, block3}));
  }

  /**
   * @given initialized storage
   * block 1 - initial block with 4 peers
   * block 2 - invalid previous hash, signed by all peers
   * @when block 2 is validated
   * @then result is not successful
   */
  TEST_F(ChainValidatorStorageTest, InvalidHash) {
    auto block1 = generateAndApplyFirstBlock();

    auto block2 = completeBlock(
        baseBlock({dummyTx(2)},
                  2,
                  shared_model::crypto::DefaultHashProvider::makeHash(
                      shared_model::crypto::Blob("bad_hash")))
            .signAndAddSignature(keys.at(0))
            .signAndAddSignature(keys.at(1))
            .signAndAddSignature(keys.at(2))
            .signAndAddSignature(keys.at(3)));

    ASSERT_FALSE(createAndValidateChain({block2}));
  }

  /**
   * @given initialized storage
   * block 1 - initial block with 4 peers
   * block 2 - signed by only 2 out of 4 peers, no supermajority
   * @when block 2 is validated
   * @then result is not successful
   */
  TEST_F(ChainValidatorStorageTest, NoSupermajority) {
    auto block1 = generateAndApplyFirstBlock();

    ASSERT_FALSE(supermajority_checker->hasSupermajority(2, 4))
        << "This test assumes that 2 out of 4 peers do not have supermajority!";
    auto block2 = completeBlock(baseBlock({dummyTx(2)}, 2, block1->hash())
                                    .signAndAddSignature(keys.at(0))
                                    .signAndAddSignature(keys.at(1)));

    ASSERT_FALSE(createAndValidateChain({block2}));
  }

}  // namespace iroha
