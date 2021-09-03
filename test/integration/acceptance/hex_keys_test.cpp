/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <boost/algorithm/string.hpp>
#include <cctype>
#include <functional>
#include <iterator>
#include <utility>

#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "cryptography/keypair.hpp"
#include "datetime/time.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace shared_model;
using namespace shared_model::crypto;
using namespace shared_model::interface::types;
using namespace integration_framework;

namespace {
  using Transformer = int (*)(int);

  static auto kUpperLowerTransformers{
      ::testing::Values<Transformer, Transformer>(&std::tolower,
                                                  &std::toupper)};

  std::string transformHexPublicKey(PublicKeyHexStringView public_key,
                                    Transformer transformer) {
    std::string_view const &original_pubkey = public_key;
    std::string transformed_pubkey;
    std::transform(original_pubkey.begin(),
                   original_pubkey.end(),
                   std::back_inserter(transformed_pubkey),
                   *transformer);
    return transformed_pubkey;
  }

  Keypair transformHexPublicKey(Keypair keypair, Transformer transformer) {
    return Keypair{
        PublicKeyHexStringView{transformHexPublicKey(
            PublicKeyHexStringView{keypair.publicKey()}, transformer)},
        crypto::PrivateKey(keypair.privateKey())};
  }
}  // namespace

struct HexKeys : public AcceptanceFixture,
                 public ::testing::WithParamInterface<
                     std::tuple<Transformer, Transformer>> {
  HexKeys() : kNow(iroha::time::now()) {}

  void SetUp() override {}

  template <typename F>
  void executeForItf(F &&f) {
    for (auto const type : {iroha::StorageType::kPostgres}) {
      IntegrationTestFramework itf(1, type);
      using Role = interface::permissions::Role;
      const interface::RolePermissionSet permissions = {Role::kAddSignatory,
                                                        Role::kRemoveSignatory,
                                                        Role::kAddPeer,
                                                        Role::kCreateAccount,
                                                        Role::kAppendRole,
                                                        Role::kGetMyAccount};

      itf.setInitialState(common_constants::kAdminKeypair)
          .sendTxAwait(AcceptanceFixture::makeUserWithPerms(permissions),
                       CHECK_TXS_QUANTITY(1));
      std::forward<F>(f)(itf);
    }
  }

  auto addSignatory(
      PublicKeyHexStringView key,
      interface::types::TimestampType time,
      interface::types::AccountIdType user_id = common_constants::kUserId) {
    return AcceptanceFixture::baseTx().createdTime(time).addSignatory(user_id,
                                                                      key);
  }

  auto removeSignatory(
      PublicKeyHexStringView key,
      interface::types::TimestampType time,
      interface::types::AccountIdType user_id = common_constants::kUserId) {
    return AcceptanceFixture::baseTx().createdTime(time).removeSignatory(
        user_id, key);
  }

  auto createAccount(PublicKeyHexStringView key,
                     interface::types::TimestampType time) {
    return AcceptanceFixture::baseTx().createdTime(time).createAccount(
        common_constants::kSecondUser, common_constants::kDomain, key);
  }

  auto addPeer(PublicKeyHexStringView key,
               interface::types::TimestampType time) {
    const auto imaginary_address = "192.168.23.149:50051";
    return AcceptanceFixture::baseTx().createdTime(time).addPeer(
        imaginary_address, key);
  }

  Keypair keypair = DefaultCryptoAlgorithmType::generateKeypair();

  Keypair keypair_v1 = transformHexPublicKey(keypair, std::get<0>(GetParam()));
  Keypair keypair_v2 = transformHexPublicKey(keypair, std::get<1>(GetParam()));

  PublicKeyHexStringView public_key_v1{keypair_v1.publicKey()};
  PublicKeyHexStringView public_key_v2{keypair_v2.publicKey()};

  Keypair another_keypair = DefaultCryptoAlgorithmType::generateKeypair();

  const interface::types::TimestampType kNow;
};

/**
 * @given an account with kAddSignatory permission
 * @when the same public key is used twice but written in different case
 * @then only first attempt to add the key succeeds
 */
TEST_P(HexKeys, AddSignatory) {
  executeForItf([&](auto &itf) {
    auto tx1 = complete(addSignatory(public_key_v1, kNow));
    auto tx2 = complete(addSignatory(public_key_v2, kNow + 1));
    auto hash1 = tx1.hash();
    auto hash2 = tx2.hash();

    itf.sendTxAwait(tx1, CHECK_TXS_QUANTITY(1))
        .sendTxAwait(tx2, CHECK_TXS_QUANTITY(0));
  });
}

/**
 * @given a user with kAddSignatory and kRemoveSignatory permissions
 * @when a user adds a signatory using uppercased key string
 * @then the signatory can be removed using lowercased key string
 */
TEST_P(HexKeys, RemoveSignatory) {
  executeForItf([&](auto &itf) {
    auto tx1 = complete(addSignatory(public_key_v1, kNow));
    auto tx2 = complete(removeSignatory(public_key_v2, kNow + 1));
    auto hash2 = tx2.hash();

    itf.sendTxAwait(tx1, CHECK_TXS_QUANTITY(1))
        .sendTxAwait(tx2, CHECK_TXS_QUANTITY(1));
  });
}

/**
 * @given a user created with uppercased public key
 * @when some additional key is added to the user
 * @then the first key can be removed even when it passed in lower case to a
 * command
 */
TEST_P(HexKeys, CreateAccount) {
  executeForItf([&](auto &itf) {
    auto user = common_constants::kSameDomainUserId;

    // kUserId creates kSameDomainUserId and appends the role with test
    // permissions
    auto tx1 = complete(createAccount(public_key_v1, kNow)
                            .appendRole(user, common_constants::kRole));

    // kSameDomainUserId adds one more key to own account
    auto tx2 = complete(
        addSignatory(
            PublicKeyHexStringView{another_keypair.publicKey()}, kNow + 1, user)
            .creatorAccountId(user),
        keypair_v2);

    // kSameDomainUserId removes the initial key specifing it in other font case
    auto tx3 = complete(
        removeSignatory(public_key_v2, kNow + 2, user).creatorAccountId(user),
        keypair_v2);

    itf.sendTxAwait(tx1, CHECK_TXS_QUANTITY(1))
        .sendTxAwait(tx2, CHECK_TXS_QUANTITY(1))
        .sendTxAwait(tx3, CHECK_TXS_QUANTITY(1));
  });
}

/**
 * @given an initialized peer
 * @when a user tries to add another peer with the same key as the first peer
 * has, but written in a different font case
 * @then the transaction is considered as stateful invalid
 */
TEST_P(HexKeys, AddPeerSameKeyDifferentCase) {
  executeForItf([&](auto &itf) {
    std::string original_key{common_constants::kAdminKeypair.publicKey()};
    std::string same_key_transformed = transformHexPublicKey(
        PublicKeyHexStringView{original_key}, std::get<0>(GetParam()));
    auto tx =
        complete(addPeer(PublicKeyHexStringView{same_key_transformed}, kNow));
    auto hash = tx.hash();

    itf.sendTxAwait(tx, CHECK_TXS_QUANTITY(0));
  });
}

/**
 * @given a user with kGetMyAccount permission
 * @when query their account with transformed signatures
 * @then query succeeds
 */
TEST_P(HexKeys, QuerySignature) {
  executeForItf([&](auto &itf) {
    using namespace shared_model::interface;
    itf.sendQuery(
        complete(baseQry().getAccount(common_constants::kUserId),
                 transformHexPublicKey(common_constants::kUserKeypair,
                                       std::get<0>(GetParam()))),
        [](auto const &general_response) {
          AccountResponse const *account_response =
              boost::get<AccountResponse const &>(&general_response.get());
          ASSERT_NE(account_response, nullptr);
          EXPECT_EQ(account_response->account().accountId(),
                    common_constants::kUserId);
        });
  });
}

INSTANTIATE_TEST_SUITE_P(LowerAndUpper,
                         HexKeys,
                         ::testing::Combine(kUpperLowerTransformers,
                                            kUpperLowerTransformers));
