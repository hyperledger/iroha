/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class CreateAccount : public AcceptanceFixture {
 public:
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kCreateAccount}) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  const std::string kNewUser = "userone";
  const crypto::Keypair kNewUserKeypair =
      crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * @given some user with can_create_account permission
 * @when execute tx with CreateAccount command
 * @then there is the tx in proposal
 */
TEST_F(CreateAccount, Basic) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().createAccount(
              kNewUser, kDomain, kNewUserKeypair.publicKey())),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-205 remove, covered by
 * postgres_executor_test CreateAccount.NoPerms
 *
 * @given some user without can_create_account permission
 * @when execute tx with CreateAccount command
 * @then verified proposal is empty
 */
TEST_F(CreateAccount, NoPermissions) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kGetMyTxs}))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAccount(
          kNewUser, kDomain, kNewUserKeypair.publicKey())))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-205 remove, covered by
 * postgres_executor_test CreateAccount.NoDomain
 *
 * @given some user with can_create_account permission
 * @when execute tx with CreateAccount command with nonexistent domain
 * @then verified proposal is empty
 */
TEST_F(CreateAccount, NoDomain) {
  const std::string nonexistent_domain = "asdf";
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAccount(
          kNewUser, nonexistent_domain, kNewUserKeypair.publicKey())))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-205 remove, covered by
 * postgres_executor_test CreateAccount.NameExists
 *
 * @given some user with can_create_account permission
 * @when execute tx with CreateAccount command with already existing username
 * @then verified proposal is empty
 */
TEST_F(CreateAccount, ExistingName) {
  std::string existing_name = kUser;
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAccount(
          existing_name, kDomain, kNewUserKeypair.publicKey())))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](const auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-205 seems can be removed (covered by field
 * validator test)
 *
 * @given some user with can_create_account permission
 * @when execute tx with CreateAccount command with maximum available length
 * @then there is the tx in proposal
 */
TEST_F(CreateAccount, MaxLenName) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().createAccount(
              std::string(32, 'a'), kDomain, kNewUserKeypair.publicKey())),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-205 seems can be removed (covered by field
 * validator test)
 *
 * @given some user with can_create_account permission
 * @when execute tx with CreateAccount command with too long account length
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(CreateAccount, TooLongName) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAccount(
                  std::string(33, 'a'), kDomain, kNewUserKeypair.publicKey())),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-205 seems can be removed (covered by field
 * validator test and the above test)
 *
 * @given some user with can_create_account permission
 * @when execute tx with CreateAccount command with empty user name
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(CreateAccount, EmptyName) {
  std::string empty_name = "";
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAccount(
                  empty_name, kDomain, kNewUserKeypair.publicKey())),
              CHECK_STATELESS_INVALID);
}

/**
 * Checks that there is no privelege elevation issue via CreateAccount
 *
 * @given two domains: the first domain has default role that contain
 * can_create_account permission, the second domain has default role that
 * contains more permissions than default role of the first domain
 * @when the user of an account from the first domain tries to create an account
 * in the second domain
 * @then transaction should fail stateful validation
 */
TEST_F(CreateAccount, PrivelegeElevation) {
  auto second_domain_tx = complete(
      baseTx(kAdminId).createDomain(kSecondDomain, kAdminRole), kAdminKeypair);
  auto create_elevated_user = complete(baseTx().createAccount(
      kNewUser, kSecondDomain, kNewUserKeypair.publicKey()));
  auto rejected_hash = create_elevated_user.hash();

  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(second_domain_tx, CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeUserWithPerms(), CHECK_TXS_QUANTITY(1))
      .sendTx(create_elevated_user)
      .skipProposal()
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock([&rejected_hash](const auto &block) {
        const auto rejected_hashes = block->rejected_transactions_hashes();
        ASSERT_THAT(rejected_hashes, ::testing::Contains(rejected_hash));
        ASSERT_EQ(boost::size(rejected_hashes), 1);
      });
}
