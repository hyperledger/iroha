/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "builders/protobuf/builder_templates/query_template.hpp"
#include "framework/crypto_literals.hpp"
#include "instantiate_test_suite.hpp"
#include "integration/acceptance/grantable_permissions_fixture.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace integration_framework;

using namespace shared_model;
using namespace shared_model::interface;
using namespace shared_model::interface::permissions;
using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

struct RevokePermissionFx : GrantablePermissionsFixture,
                            ::testing::WithParamInterface<StorageType> {};
INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(RevokePermissionFx);

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 * also covered by postgres_executor_test RevokePermission.Valid
 *
 * C269 Revoke permission from a non-existing account
 * @given ITF instance and only one account with can_grant permission
 * @when the account tries to revoke grantable permission from non-existing
 * account
 * @then transaction would not be committed
 */
TEST_P(RevokePermissionFx, RevokeFromNonExistingAccount) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeAccountWithPerms(
          kAccount1, kAccount1Keypair, {Role::kSetMyQuorum}, kRole1))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(revokePermission(kAccount1,
                               kAccount1Keypair,
                               kAccount2,
                               permissions::Grantable::kSetMyQuorum))
      .checkProposal(
          // transaction is stateless valid
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkVerifiedProposal(
          // transaction is not stateful valid (kAccount2 does not exist)
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-222 convert to a SFV integration test
 * (no such test in postgres_executor_test)
 *
 * C271 Revoke permission more than once
 * @given ITF instance, two accounts, the first account has granted a permission
 * to the second
 * @when the first account revokes the permission twice
 * @then the second revoke does not pass stateful validation
 */
TEST_P(RevokePermissionFx, RevokeTwice) {
  IntegrationTestFramework itf(1, GetParam());
  itf.setInitialState(kAdminKeypair);
  createTwoAccounts(itf, {Role::kSetMyQuorum}, {Role::kReceive})
      .sendTx(grantPermission(kAccount1,
                              kAccount1Keypair,
                              kAccount2,
                              permissions::Grantable::kSetMyQuorum))
      .skipVerifiedProposal()
      .checkBlock(
          // permission was successfully granted
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          revokePermission(
              kAccount1,
              kAccount1Keypair,
              kAccount2,
              permissions::Grantable::kSetMyQuorum),  // permission was
                                                      // successfully revoked
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTx(revokePermission(kAccount1,
                               kAccount1Keypair,
                               kAccount2,
                               permissions::Grantable::kSetMyQuorum))
      .checkVerifiedProposal(
          // permission cannot be revoked twice
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-222 remove, covered by
 * postgres_executor_test RevokePermission.NoPerms
 *
 * Revoke without permission
 * @given ITF instance, three accounts:
 *  - first account does not have any permissions
 *  - second account has a grantable permission from the third account
 *  - third account gives a grantable permissions to the second account
 * @when first account tries to revoke permissions from the second
 * @then revoke fails
 */
TEST_P(RevokePermissionFx, RevokeWithoutPermission) {
  IntegrationTestFramework itf(1, GetParam());
  itf.setInitialState(kAdminKeypair);
  createTwoAccounts(itf, {}, {Role::kReceive})
      .sendTxAwait(
          makeUserWithPerms({interface::permissions::Role::kSetMyQuorum}),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          grantPermission(kUser,
                          kUserKeypair,
                          kAccount2,
                          permissions::Grantable::kSetMyQuorum),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          revokePermission(kAccount1,
                           kAccount1Keypair,
                           kAccount2,
                           permissions::Grantable::kSetMyQuorum),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); })
      .done();
}

/**
 * Revoke permission, which was granted, though the granter does not have a
 * corresponding permission already
 * @given ITF instance, two accounts, at the beginning first account have
 * can_grant permission and grants a permission to second account, then the
 * first account lost can_grant permission
 * @when the first account tries to revoke permission from the second
 * @then revoke is successful
 */
TEST_P(RevokePermissionFx, RevokeTheGrantedPermissionWithoutPermission) {
  auto detach_role_tx = GrantablePermissionsFixture::TxBuilder()
                            .createdTime(getUniqueTime())
                            .creatorAccountId(kAdminId)
                            .quorum(1)
                            .detachRole(kAccount1 + "@" + kDomain, kRole1)
                            .build()
                            .signAndAddSignature(kAdminKeypair)
                            .finish();

  IntegrationTestFramework itf(1, GetParam());
  itf.setInitialState(kAdminKeypair);
  createTwoAccounts(itf, {Role::kSetMyQuorum}, {Role::kReceive})
      .sendTxAwait(
          grantPermission(kAccount1,
                          kAccount1Keypair,
                          kAccount2,
                          permissions::Grantable::kSetMyQuorum),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          detach_role_tx,
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTx(revokePermission(kAccount1,
                               kAccount1Keypair,
                               kAccount2,
                               permissions::Grantable::kSetMyQuorum))
      .checkProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .done();
}

namespace grantables {

  using gpf = GrantablePermissionsFixture;

  template <typename GrantableType>
  struct GrantRevokeFixture : GrantablePermissionsFixture,
                              ::testing::WithParamInterface<StorageType> {
    GrantableType grantable_type_;
  };

  struct GrantableType {
    const Role can_grant_permission_;
    const Grantable grantable_permission_;
    interface::types::HashType tx_hash_;

    virtual IntegrationTestFramework &prepare(
        GrantablePermissionsFixture &fixture, IntegrationTestFramework &itf) {
      (void)fixture;  // prevent warning about unused param, fixture is needed
                      // in some derivatives
      return itf;
    }

    virtual proto::Transaction testTransaction(
        GrantablePermissionsFixture &fixture) = 0;

   protected:
    GrantableType(const Role &can_grant_permission,
                  const Grantable &grantable_permission)
        : can_grant_permission_(can_grant_permission),
          grantable_permission_(grantable_permission) {}
  };

  struct AddMySignatory : public GrantableType {
    AddMySignatory()
        : GrantableType(Role::kAddMySignatory, Grantable::kAddMySignatory) {}

    proto::Transaction testTransaction(
        GrantablePermissionsFixture &f) override {
      return f.permitteeAddSignatory(
          f.kAccount2, f.kAccount2Keypair, f.kAccount1);
    }
  };

  struct RemoveMySignatory : public GrantableType {
    RemoveMySignatory()
        : GrantableType(Role::kRemoveMySignatory,
                        Grantable::kRemoveMySignatory) {}

    IntegrationTestFramework &prepare(GrantablePermissionsFixture &f,
                                      IntegrationTestFramework &itf) override {
      auto account_id = f.kAccount1 + "@" + kDomain;
      auto add_signatory_tx =
          GrantablePermissionsFixture::TxBuilder()
              .createdTime(f.getUniqueTime())
              .creatorAccountId(account_id)
              .quorum(1)
              .addSignatory(
                  account_id,
                  PublicKeyHexStringView{f.kAccount2Keypair.publicKey()})
              .addSignatory(account_id, "516A"_hex_pubkey)
              .build()
              .signAndAddSignature(f.kAccount1Keypair)
              .finish();
      itf.sendTx(add_signatory_tx)
          .checkProposal(
              [](auto &prop) { ASSERT_EQ(prop->transactions().size(), 1); })
          .checkBlock(
              [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
      return itf;
    }

    proto::Transaction testTransaction(
        GrantablePermissionsFixture &f) override {
      return f.permitteeRemoveSignatory(
          f.kAccount2, f.kAccount2Keypair, f.kAccount1);
    }
  };

  struct SetMyAccountDetail : public GrantableType {
    SetMyAccountDetail()
        : GrantableType(Role::kSetMyAccountDetail,
                        Grantable::kSetMyAccountDetail) {}

    proto::Transaction testTransaction(
        GrantablePermissionsFixture &f) override {
      return f.setAccountDetail(f.kAccount2,
                                f.kAccount2Keypair,
                                f.kAccount1,
                                f.kAccountDetailKey,
                                f.kAccountDetailValue);
    }
  };

  struct SetMyQuorum : public GrantableType {
    SetMyQuorum()
        : GrantableType(Role::kSetMyQuorum, Grantable::kSetMyQuorum) {}

    proto::Transaction testTransaction(
        GrantablePermissionsFixture &f) override {
      return f.setQuorum(f.kAccount2, f.kAccount2Keypair, f.kAccount1, 1);
    }
  };

  struct TransferMyAssets : public GrantableType {
    TransferMyAssets()
        : GrantableType(Role::kTransferMyAssets, Grantable::kTransferMyAssets) {
    }

    IntegrationTestFramework &prepare(GrantablePermissionsFixture &f,
                                      IntegrationTestFramework &itf) override {
      auto create_and_transfer_coins =
          GrantablePermissionsFixture::TxBuilder()
              .createdTime(f.getUniqueTime())
              .creatorAccountId(kAdminId)
              .quorum(1)
              .addAssetQuantity(kAssetId, "9000.0")
              .transferAsset(kAdminId,
                             f.kAccount1 + "@" + kDomain,
                             kAssetId,
                             "init top up",
                             "8000.0")
              .build()
              .signAndAddSignature(kAdminKeypair)
              .finish();
      itf.sendTx(create_and_transfer_coins)
          .checkProposal(
              [](auto &prop) { ASSERT_EQ(prop->transactions().size(), 1); })
          .checkBlock(
              [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
      return itf;
    }

    proto::Transaction testTransaction(
        GrantablePermissionsFixture &f) override {
      return f.transferAssetFromSource(
          f.kAccount2, f.kAccount2Keypair, f.kAccount1, "1000.0", f.kAccount2);
    }
  };

  TYPED_TEST_SUITE_P(GrantRevokeFixture);

  /**
   * TODO mboldyrev 18.01.2019 IR-222 convert to a SFV integration test
   *
   * The test iterates over helper types (GrantablePermissionsTypes).
   * That helper types contain information about required Grantable and Role
   * permissions for the test.
   *
   * The test does the following:
   * - creates two accounts
   * - first account grants permission to the second account
   * - does preparation of the first account (for example gives assets for
   * future transfer during the main part of the test)
   * - does the test transaction (each GrantablePermissionType has own test
   * transaction)
   * - first account revokes the permission from the second account
   * - does the test transaction again
   * - checks that the last transaction was failed due to a missing permission
   */
  TYPED_TEST_P(GrantRevokeFixture, GrantAndRevokePermission) {
    IntegrationTestFramework itf(1, StorageType::kRocksDb); //GetParam());
    itf.setInitialState(kAdminKeypair);

    gpf::createTwoAccounts(itf,
                           {this->grantable_type_.can_grant_permission_,
                            Role::kAddSignatory,
                            Role::kReceive},
                           {Role::kReceive})
        .sendTxAwait(
            gpf::grantPermission(gpf::kAccount1,
                                 gpf::kAccount1Keypair,
                                 gpf::kAccount2,
                                 this->grantable_type_.grantable_permission_),
            // permission was successfully granted
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
    this->grantable_type_.prepare(*this, itf)
        .sendTx(this->grantable_type_.testTransaction(*this))
        .checkProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .skipVerifiedProposal()
        .checkBlock(
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
        .sendTxAwait(
            gpf::revokePermission(gpf::kAccount1,
                                  gpf::kAccount1Keypair,
                                  gpf::kAccount2,
                                  this->grantable_type_.grantable_permission_),
            // permission was successfully revoked
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
    auto last_check_tx = this->grantable_type_.testTransaction(*this);
    std::vector<interface::types::HashType> hashes{last_check_tx.hash()};
    auto last_tx_status_query = TestUnsignedQueryBuilder()
                                    .creatorAccountId(kAdminId)
                                    .createdTime(this->getUniqueTime())
                                    .queryCounter(1)
                                    .getTransactions(hashes)
                                    .build()
                                    .signAndAddSignature(kAdminKeypair)
                                    .finish();
    itf.sendTx(last_check_tx)
        .checkProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .skipVerifiedProposal()
        .checkBlock(
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); })
        .done();
  }

  REGISTER_TYPED_TEST_SUITE_P(GrantRevokeFixture, GrantAndRevokePermission);

  using GrantablePermissionsTypes = ::testing::Types<AddMySignatory,
                                                     RemoveMySignatory,
                                                     SetMyAccountDetail,
                                                     SetMyQuorum,
                                                     TransferMyAssets>;
  INSTANTIATE_TYPED_TEST_SUITE_P(DifferentGrantablePermissionsTypes,
                                 GrantRevokeFixture,
                                 GrantablePermissionsTypes);

}  // namespace grantables
