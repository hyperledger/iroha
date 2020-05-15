/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "builders/protobuf/transaction.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

class SetAccountDetail : public AcceptanceFixture {
 public:
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kAddPeer}) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  auto baseTx(const interface::types::AccountIdType &account_id,
              const interface::types::AccountDetailKeyType &key,
              const interface::types::AccountDetailValueType &value) {
    return AcceptanceFixture::baseTx().setAccountDetail(account_id, key, value);
  }

  auto baseTx(const interface::types::AccountIdType &account_id) {
    return baseTx(account_id, kKey, kValue);
  }

  auto makeSecondUser(const interface::RolePermissionSet &perms = {
                          interface::permissions::Role::kAddPeer}) {
    static const std::string kRole2 = "roletwo";
    return AcceptanceFixture::createUserWithPerms(
               kUser2,
               PublicKeyHexStringView{kUser2Keypair.publicKey()},
               kRole2,
               perms)
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  const interface::types::AccountDetailKeyType kKey = "key";
  const interface::types::AccountDetailValueType kValue = "value";
  const std::string kUser2 = "user2";
  const std::string kUser2Id = kUser2 + "@" + kDomain;
  const crypto::Keypair kUser2Keypair =
      crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

/**
 * TODO mboldyrev 18.01.2019 IR-223 convert to a field validator unit test
 *
 * C276
 * @given a user with required permission
 * @when execute tx with SetAccountDetail command with max key
 * @then there is the tx in block
 */
TEST_F(SetAccountDetail, BigPossibleKey) {
  const std::string kBigKey = std::string(64, 'a');
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(complete(baseTx(kUserId, kBigKey, kValue)), [](auto &block) {
        ASSERT_EQ(block->transactions().size(), 1);
      });
}

/**
 * TODO mboldyrev 18.01.2019 IR-223 remove, covered by field validator test
 *
 * C277
 * @given a user with required permission
 * @when execute tx with SetAccountDetail command with empty key
 * @then there is no tx in block
 */
TEST_F(SetAccountDetail, EmptyKey) {
  const std::string kEmptyKey = "";
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx(kUserId, kEmptyKey, kValue)),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-223 remove, covered by field validator test
 *
 * C278
 * @given a user with required permission
 * @when execute tx with SetAccountDetail command with empty value
 * @then there is no tx in block
 */
TEST_F(SetAccountDetail, EmptyValue) {
  const std::string kEmptyValue = "";
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx(kUserId, kKey, kEmptyValue)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-223 convert the part with key to a field
 * validator unit test; the part with value is covered by field validator test
 *
 * C279
 * @given a user with required permission
 * @when execute tx with SetAccountDetail command with huge both key and value
 * @then there is no tx in block
 */
TEST_F(SetAccountDetail, HugeKeyValue) {
  const std::string kHugeKey = std::string(10000, 'a');
  const std::string kHugeValue = std::string(10000, 'b');
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx(kUserId, kHugeKey, kHugeValue)),
              CHECK_STATELESS_INVALID);
}
