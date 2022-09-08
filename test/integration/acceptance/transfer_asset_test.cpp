/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <boost/variant.hpp>

#include "ametsuchi/setting_query.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "instantiate_test_suite.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "utils/query_error_response_visitor.hpp"
#include "validators/field_validator.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

struct TransferAsset : AcceptanceFixture,
                       ::testing::WithParamInterface<StorageType> {
  /**
   * Creates the transaction with the first user creation commands
   * @param perms are the permissions of the user
   * @return built tx
   */
  auto makeFirstUser(const interface::RolePermissionSet &perms = {
                         interface::permissions::Role::kTransfer}) {
    auto new_perms = perms;
    new_perms.set(interface::permissions::Role::kAddAssetQty);
    return AcceptanceFixture::makeUserWithPerms(new_perms);
  }

  /**
   * Creates the transaction with the second user creation commands
   * @param perms are the permissions of the user
   * @return built tx
   */
  auto makeSecondUser(const interface::RolePermissionSet &perms = {
                          interface::permissions::Role::kReceive}) {
    return createUserWithPerms(
               kUser2,
               PublicKeyHexStringView{kUser2Keypair.publicKey()},
               kRole2,
               perms)
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  /**
   * Creates the transaction with the third user creation commands
   * @param perms are the permissions of the user
   * @return built tx
   */
  auto makeThirdUser(const interface::RolePermissionSet &perms = {
      interface::permissions::Role::kTransfer}) {
    return createUserWithPerms(
        kUser3,
        PublicKeyHexStringView{kUser3Keypair.publicKey()},
        kRole3,
        perms)
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  proto::Transaction addAssets() {
    return addAssets(kAmount);
  }

  proto::Transaction addAssets(const std::string &amount) {
    return complete(baseTx().addAssetQuantity(kAssetId, amount));
  }

  proto::Transaction makeTransfer(const std::string &amount) {
    return complete(
        baseTx().transferAsset(kUserId, kUser2Id, kAssetId, kDesc, amount));
  }

  proto::Transaction makeTransfer2(const std::string &amount) {
    return complete(
        baseTx(kUser3Id).transferAsset(kUserId, kUser2Id, kAssetId, kDesc, amount), kUser3Keypair);
  }

  proto::Transaction makeTransfer() {
    return makeTransfer(kAmount);
  }

  proto::Transaction makeTransfer2() {
    return makeTransfer2(kAmount);
  }

  static constexpr iroha::StorageType storage_types[] = {
      iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb};

  const std::string kAmount = "1.0";
  const std::string kDesc = "description";
  const std::string kRole2 = "roletwo";
  const std::string kRole3 = "rolethree";
  const std::string kUser2 = "usertwo";
  const std::string kUser3 = "userthree";
  const std::string kUser2Id = kUser2 + "@" + kDomain;
  const std::string kUser3Id = kUser3 + "@" + kDomain;
  const crypto::Keypair kUser2Keypair =
      crypto::DefaultCryptoAlgorithmType::generateKeypair();
  const crypto::Keypair kUser3Keypair =
      crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(TransferAsset);

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 * also covered by postgres_executor_test TransferAccountAssetTest.Valid
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command
 * @then there is the tx in proposal
 */
TEST_P(TransferAsset, Basic) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeTransfer(), CHECK_TXS_QUANTITY(1));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by
 * postgres_executor_test TransferAccountAssetTest.NoPerms
 *
 * @given pair of users
 *        AND the first user without can_transfer permission
 * @when execute tx with TransferAsset command
 * @then there is an empty verified proposal
 */
TEST_P(TransferAsset, WithoutCanTransfer) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser({}), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(makeTransfer())
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

TEST_P(TransferAsset, AnotherUserTx) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeThirdUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(makeTransfer2())
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 convert to a SFV integration test
 * (not covered by postgres_executor_test)
 *
 * @given pair of users
 *        AND the second user without can_receive permission
 * @when execute tx with TransferAsset command
 * @then there is an empty verified proposal
 */
TEST_P(TransferAsset, WithoutCanReceive) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      // TODO(@l4l) 23/06/18: remove permission with IR-1367
      .sendTxAwait(makeSecondUser({interface::permissions::Role::kAddPeer}),
                   CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(makeTransfer())
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by
 * postgres_executor_test TransferAccountAssetTest.NoAccount
 *
 * @given some user with all required permissions
 * @when execute tx with TransferAsset command to nonexistent destination
 * @then there is an empty verified proposal
 */
TEST_P(TransferAsset, NonexistentDest) {
  std::string nonexistent = "inexist@test";
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().transferAsset(
          kUserId, nonexistent, kAssetId, kDesc, kAmount)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by
 * postgres_executor_test TransferAccountAssetTest.NoAsset
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command with nonexistent asset
 * @then there is an empty verified proposal
 */
TEST_P(TransferAsset, NonexistentAsset) {
  std::string nonexistent = "inexist#test";
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().transferAsset(
          kUserId, kUser2Id, nonexistent, kDesc, kAmount)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by field validator test
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command with zero amount
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_P(TransferAsset, ZeroAmount) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(makeTransfer("0.0"), CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by field validator test
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command with empty-str description
 * @then it passed to the proposal
 */
TEST_P(TransferAsset, EmptyDesc) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(complete(baseTx().transferAsset(
                       kUserId, kUser2Id, kAssetId, "", kAmount)),
                   CHECK_TXS_QUANTITY(1));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by field validator test
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command with a description longer than
 * stateless validator allows
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_P(TransferAsset, LongDescStateless) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().transferAsset(
                  kUserId,
                  kUser2Id,
                  kAssetId,
                  std::string(
                      validation::FieldValidator::kMaxDescriptionSize + 1, 'a'),
                  kAmount)),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 transform to SFV test
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command with a description longer than
 * iroha::ametsuchi::kMaxDescriptionSizeKey settings value
 * @then the tx hasn't passed stateful validation
 */
TEST_P(TransferAsset, LongDescStateful) {
  const size_t max_descr_size_setting{10};

  auto send_ast_tx = complete(baseTx(kAdminId).transferAsset(
      kAdminId,
      kUserId,
      kAssetId,
      std::string(max_descr_size_setting + 1, 'a'),
      kAmount));

  IntegrationTestFramework itf(1, GetParam());
  itf.setInitialState(
         kAdminKeypair,
         TestBlockBuilder()
             .transactions(std::vector<shared_model::proto::Transaction>{
                 shared_model::proto::TransactionBuilder()
                     .creatorAccountId(kAdminId)
                     .createdTime(iroha::time::now())
                     .addPeer(itf.getAddress(),
                              PublicKeyHexStringView{kAdminKeypair.publicKey()})
                     .createRole(kAdminRole,
                                 {interface::permissions::Role::kRoot})
                     .createDomain(kDomain, kAdminRole)
                     .createAccount(
                         kAdminName,
                         kDomain,
                         PublicKeyHexStringView{kAdminKeypair.publicKey()})
                     .createAccount(
                         kUser,
                         kDomain,
                         PublicKeyHexStringView{kUserKeypair.publicKey()})
                     .createAsset(kAssetName, kDomain, 1)
                     .addAssetQuantity(kAssetId, kAmount)
                     .setSettingValue(iroha::ametsuchi::kMaxDescriptionSizeKey,
                                      std::to_string(max_descr_size_setting))
                     .quorum(1)
                     .build()
                     .signAndAddSignature(kAdminKeypair)
                     .finish()})
             .createdTime(iroha::time::now())
             .height(1)
             .build())
      .sendTx(send_ast_tx)
      .checkStatus(send_ast_tx.hash(), CHECK_STATELESS_VALID)
      .checkStatus(send_ast_tx.hash(), CHECK_ENOUGH_SIGNATURES)
      .checkStatus(send_ast_tx.hash(), CHECK_STATEFUL_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by
 * postgres_executor_test TransferAccountAssetTest.Overdraft
 *
 * @given pair of users with all required permissions
 * @when execute tx with TransferAsset command with amount more, than user has
 * @then there is an empty verified proposal
 */
TEST_P(TransferAsset, MoreThanHas) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets("50.0"), CHECK_TXS_QUANTITY(1))
      .sendTx(makeTransfer("100.0"))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by
 * postgres_executor_test TransferAccountAssetTest.OverflowDestination
 *
 * @given pair of users with all required permissions, and tx sender's balance
 * is replenished if required
 * @when execute two txes with TransferAsset command: one with the largest and
 * another the smallest possible quantity
 * @then first transaction is commited @and there is an empty verified proposal
 * for the second
 */
TEST_P(TransferAsset, DestOverflowPrecision1) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(kAmountPrec1Max.toStringRepr()),
                   CHECK_TXS_QUANTITY(1))
      // Send the largest possible quantity
      .sendTxAwait(makeTransfer(kAmountPrec1Max.toStringRepr()),
                   CHECK_TXS_QUANTITY(1))
      // Restore sender's balance
      .sendTxAwait(addAssets("0.1"), CHECK_TXS_QUANTITY(1))
      // Send the smallest possible quantity
      .sendTx(makeTransfer("0.1"))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 convert to a TransactionValidator unit test
 *
 * @given some user with all required permissions
 * @when execute tx with TransferAsset command where the source and destination
 * accounts are the same
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_P(TransferAsset, SourceIsDest) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(addAssets(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().transferAsset(
                  kUserId, kUserId, kAssetId, kDesc, kAmount)),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 convert to a SFV integration test
 * (not covered by postgres_executor_test)
 *
 * @given some user with all required permission
 * @when execute tx with TransferAsset command where the destination user's
 * domain differ from the source user one
 * @then the tx is commited
 */
TEST_P(TransferAsset, InterDomain) {
  const std::string kNewDomain = "newdom";
  const std::string kUser2Id = kUser2 + "@" + kNewDomain;
  const std::string kNewAssetId = kAssetName + "#" + kNewDomain;

  auto make_second_user =
      baseTx()
          .creatorAccountId(kAdminId)
          .createRole(kRole2, {interface::permissions::Role::kReceive})
          .createDomain(kNewDomain, kRole2)
          .createAccount(kUser2,
                         kNewDomain,
                         PublicKeyHexStringView{kUser2Keypair.publicKey()})
          .createAsset(kAssetName, kNewDomain, 1)
          .build()
          .signAndAddSignature(kAdminKeypair)
          .finish();
  auto add_assets = complete(baseTx().addAssetQuantity(kNewAssetId, kAmount));
  auto make_transfer = complete(
      baseTx().transferAsset(kUserId, kUser2Id, kNewAssetId, kDesc, kAmount));

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(make_second_user, CHECK_TXS_QUANTITY(1))
      .sendTxAwait(add_assets, CHECK_TXS_QUANTITY(1))
      .sendTxAwait(make_transfer, CHECK_TXS_QUANTITY(1));
}

/**
 * TODO mboldyrev 18.01.2019 IR-226 remove, covered by field validator test
 *
 * @given a pair of users with all required permissions
 *        AND asset with big precision
 * @when asset is added and then TransferAsset is called
 * @then txes passed commit and the state as intented
 */
TEST_P(TransferAsset, BigPrecision) {
  const std::string kNewAsset = kAssetName + "a";
  const std::string kNewAssetId = kNewAsset + "#" + kDomain;
  const auto kPrecision = 5;
  const std::string kInitial = "500";
  const std::string kForTransfer = "1.00000";
  const std::string kLeft = "499.00000";

  auto create_asset = baseTx()
                          .creatorAccountId(kAdminId)
                          .createAsset(kNewAsset, kDomain, kPrecision)
                          .build()
                          .signAndAddSignature(kAdminKeypair)
                          .finish();
  auto add_assets = complete(baseTx().addAssetQuantity(kNewAssetId, kInitial));
  auto make_transfer = complete(baseTx().transferAsset(
      kUserId, kUser2Id, kNewAssetId, kDesc, kForTransfer));

  auto check_balance = [](std::string account_id, std::string val) {
    return [a = std::move(account_id), v = val](auto &resp) {
      auto &acc_ast =
          boost::get<const shared_model::interface::AccountAssetResponse &>(
              resp.get());
      for (auto &ast : acc_ast.accountAssets()) {
        if (ast.accountId() == a) {
          ASSERT_EQ(v, ast.balance().toStringRepr());
        }
      }
    };
  };

  auto make_query = [this](std::string account_id) {
    return baseQry()
        .creatorAccountId(kAdminId)
        .getAccountAssets(account_id, kMaxPageSize, std::nullopt)
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  };
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(create_asset, CHECK_TXS_QUANTITY(1))
      .sendTxAwait(add_assets, CHECK_TXS_QUANTITY(1))
      .sendTxAwait(make_transfer, CHECK_TXS_QUANTITY(1))
      .sendQuery(make_query(kUserId), check_balance(kUserId, kLeft))
      .sendQuery(make_query(kUser2Id), check_balance(kUser2Id, kForTransfer));
}
