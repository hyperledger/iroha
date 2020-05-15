/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRANTABLE_PERMISSIONS_FIXTURE_HPP
#define IROHA_GRANTABLE_PERMISSIONS_FIXTURE_HPP

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

class GrantablePermissionsFixture : public AcceptanceFixture {
 public:
  using TxBuilder = TestUnsignedTransactionBuilder;

  /**
   * Create a transaction that creates a user and a role with specified name and
   * a set of permissions. The default domain role will be detached from the
   * user and the new role will be attached to the user.
   * @param user - user name without domain
   * @param key - keypair used to sign user creation tx
   * @param perms - permissions to be contained in role
   * @param role - role name to be attached to the user
   * @return proto::Transaction
   */
  shared_model::proto::Transaction makeAccountWithPerms(
      const shared_model::interface::types::AccountNameType &user,
      const shared_model::crypto::Keypair &key,
      const shared_model::interface::RolePermissionSet &perms,
      const shared_model::interface::types::RoleIdType &role);

  /**
   * Creates two accounts with corresponding permission sets.
   * Accounts are created in integration_framework::kDomain,
   * their names will be kAccount1 and kAccount2 and
   * the names of their roles will be kRole1 and kRole2.
   * @param itf - initialized instance of test framework
   * @param perm1 set of permissions for account #1
   * @param perm2 set of permissions for account #2
   * @return reference to ITF object with two transactions
   */
  integration_framework::IntegrationTestFramework &createTwoAccounts(
      integration_framework::IntegrationTestFramework &itf,
      const shared_model::interface::RolePermissionSet &perm1,
      const shared_model::interface::RolePermissionSet &perm2);

  /**
   * Create a transaction such that the creator grants permittee a permission
   * @param creator_account_name - first's account name without domain
   * @param creator_key - the keypair to sign the transaction
   * @param permittee_account_name - a name of permittee account (receives the
   * grantable permission)
   * @param grant_permission - grantable permisssion to be granted
   * @return proto::Transaction
   */
  shared_model::proto::Transaction grantPermission(
      const shared_model::interface::types::AccountNameType
          &creator_account_name,
      const shared_model::crypto::Keypair &creator_key,
      const shared_model::interface::types::AccountNameType
          &permittee_account_name,
      const shared_model::interface::permissions::Grantable &grant_permission);

  /**
   * Forms a transaction such that creator of transaction revokes a permission
   * from permittee
   * @param creator_account_name - first's account name without domain
   * @param creator_key - the keypair to sign the transaction
   * @param permittee_account_name - a name of permittee account (lost the
   * grantable permission)
   * @param revoke_permission - grantable permission to be revoked
   * @return proto::Transaction
   */
  shared_model::proto::Transaction revokePermission(
      const shared_model::interface::types::AccountNameType
          &creator_account_name,
      const shared_model::crypto::Keypair &creator_key,
      const shared_model::interface::types::AccountNameType
          &permittee_account_name,
      const shared_model::interface::permissions::Grantable &revoke_permission);

  /**
   * Forms a transaction that adds signatory to an account
   * @param permittee_account_name name of account which is granted permission
   * @param permittee_key key of account which is granted permission
   * @param account_name account name which has granted permission to permittee
   * @return a transaction
   */
  shared_model::proto::Transaction permitteeAddSignatory(
      const shared_model::interface::types::AccountNameType
          &permittee_account_name,
      const shared_model::crypto::Keypair &permittee_key,
      const shared_model::interface::types::AccountNameType &account_name);

  /**
   * Forms a transaction that removes signatory of an account
   * @param permittee_account_name name of account which is granted permission
   * @param permittee_key key of account which is granted permission
   * @param account_name account name which has granted permission to permittee
   * @return a transaction
   */
  shared_model::proto::Transaction permitteeRemoveSignatory(
      const shared_model::interface::types::AccountNameType
          &permittee_account_name,
      const shared_model::crypto::Keypair &permittee_key,
      const shared_model::interface::types::AccountNameType &account_name);

  /**
   * Forms a transaction that allows permitted user to modify quorum field
   * @param permittee_account_name name of account which is granted permission
   * @param permittee_key key of account which is granted permission
   * @param account_name account name which has granted permission to permittee
   * @param quorum quorum field
   * @return a transaction
   */
  shared_model::proto::Transaction setQuorum(
      const shared_model::interface::types::AccountNameType
          &permittee_account_name,
      const shared_model::crypto::Keypair &permittee_key,
      const shared_model::interface::types::AccountNameType &account_name,
      shared_model::interface::types::QuorumType quorum);

  /**
   * Forms a transaction that allows permitted user to set details of the
   * account
   * @param permittee_account_name name of account which is granted permission
   * @param permittee_key key of account which is granted permission
   * @param account_name account name which has granted permission to permittee
   * @param key of the data to set
   * @param detail is the data value
   * @return a transaction
   */
  shared_model::proto::Transaction setAccountDetail(
      const shared_model::interface::types::AccountNameType
          &permittee_account_name,
      const shared_model::crypto::Keypair &permittee_key,
      const shared_model::interface::types::AccountNameType &account_name,
      const shared_model::interface::types::AccountDetailKeyType &key,
      const shared_model::interface::types::AccountDetailValueType &detail);

  /**
   * Adds specified amount of an asset and transfers it
   * @param creator_name account name which is creating transfer transaction
   * @param creator_key account key which is creating transfer transaction
   * @param amount created amount of a default asset in AcceptanceFixture
   * @param receiver_name name of an account which receives transfer
   * @return a transaction
   */
  shared_model::proto::Transaction addAssetAndTransfer(
      const shared_model::interface::types::AccountNameType &creator_name,
      const shared_model::crypto::Keypair &creator_key,
      const shared_model::interface::types::AccountNameType &amount,
      const shared_model::interface::types::AccountNameType &receiver_name);

  /**
   * Transaction, that transfers default asset (from default ITF genesis block)
   * from source account to receiver
   * @param creator_name account name which is creating transfer transaction
   * @param creator_key account key which is creating transfer transaction
   * @param source_account_name account which has assets to transfer
   * @param amount amount of transferred asset
   * @param receiver_name name of an account which receives transfer
   * @return a transaction
   */
  shared_model::proto::Transaction transferAssetFromSource(
      const shared_model::interface::types::AccountNameType &creator_name,
      const shared_model::crypto::Keypair &creator_key,
      const shared_model::interface::types::AccountNameType
          &source_account_name,
      const std::string &amount,
      const shared_model::interface::types::AccountNameType &receiver_name);

  /**
   * Get signatories of an account (same as transaction creator)
   * @param account_name account name which has signatories
   * @param account_key account key which has signatories
   * @return a query
   */
  shared_model::proto::Query querySignatories(
      const shared_model::interface::types::AccountNameType &account_name,
      const shared_model::crypto::Keypair &account_key);

  /**
   * Get account metadata in order to check quorum field
   * @param account_name account name
   * @param account_key account key
   * @return a query
   */
  shared_model::proto::Query queryAccount(
      const shared_model::interface::types::AccountNameType &account_name,
      const shared_model::crypto::Keypair &account_key);

  /**
   * Get account details
   * @param account_name account name which has AccountDetails in JSON
   * @param account_key account key which has AccountDetails in JSON
   * @return a query
   */
  shared_model::proto::Query queryAccountDetail(
      const shared_model::interface::types::AccountNameType &account_name,
      const shared_model::crypto::Keypair &account_key);

  /**
   * Creates a lambda that checks query response for signatures
   * @param signatory a keypair that has a public key to compare
   * @param quantity required quantity of signatories
   * @param is_contained true if the signatory is in the set
   * @return function
   */
  static auto checkSignatorySet(const shared_model::crypto::Keypair &signatory,
                                int quantity,
                                bool is_contained) {
    return [&signatory, quantity, is_contained](
               const shared_model::proto::QueryResponse &query_response) {
      ASSERT_NO_THROW({
        const auto &resp =
            boost::get<const shared_model::interface::SignatoriesResponse &>(
                query_response.get());

        ASSERT_EQ(resp.keys().size(), quantity);
        auto &keys = resp.keys();

        ASSERT_EQ((std::find(keys.begin(), keys.end(), signatory.publicKey())
                   != keys.end()),
                  is_contained);
      });
    };
  }

  /**
   * Lambda method that checks quorum to be equal to passed quantity value
   * @param quorum_quantity value of quorum that has to be equal in query
   * response
   * @return function
   */
  static auto checkQuorum(int quorum_quantity) {
    return [quorum_quantity](
               const shared_model::proto::QueryResponse &query_response) {
      ASSERT_NO_THROW({
        const auto &resp =
            boost::get<const shared_model::interface::AccountResponse &>(
                query_response.get());

        ASSERT_EQ(resp.account().quorum(), quorum_quantity);
      });
    };
  }

  /**
   * Lambda method that checks account details to contain key and value (detail)
   * @param key key which has to be equal in account details
   * @param detail value which has to be equal in account details
   * @return function
   */
  static auto checkAccountDetail(const std::string &key,
                                 const std::string &detail) {
    return [&key,
            &detail](const shared_model::proto::QueryResponse &query_response) {
      ASSERT_NO_THROW({
        const auto &resp =
            boost::get<const shared_model::interface::AccountDetailResponse &>(
                query_response.get());
        ASSERT_TRUE(resp.detail().find(key) != std::string::npos);
        ASSERT_TRUE(resp.detail().find(detail) != std::string::npos);
      });
    };
  }

  const std::string kAccount1 = "accountone";
  const std::string kAccount2 = "accounttwo";

  const std::string kRole1 = "roleone";
  const std::string kRole2 = "roletwo";

  const shared_model::crypto::Keypair kAccount1Keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  const shared_model::crypto::Keypair kAccount2Keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

  const std::string kAccountDetailKey = "some_key";
  const std::string kAccountDetailValue = "some_value";

  const shared_model::interface::RolePermissionSet kCanGrantAll{
      shared_model::interface::permissions::Role::kAddMySignatory,
      shared_model::interface::permissions::Role::kRemoveMySignatory,
      shared_model::interface::permissions::Role::kSetMyQuorum,
      shared_model::interface::permissions::Role::kSetMyAccountDetail,
      shared_model::interface::permissions::Role::kTransferMyAssets};

  const std::vector<shared_model::interface::permissions::Grantable>
      kAllGrantable{
          shared_model::interface::permissions::Grantable::kAddMySignatory,
          shared_model::interface::permissions::Grantable::kRemoveMySignatory,
          shared_model::interface::permissions::Grantable::kSetMyQuorum,
          shared_model::interface::permissions::Grantable::kSetMyAccountDetail,
          shared_model::interface::permissions::Grantable::kTransferMyAssets};
};

#endif  // IROHA_GRANTABLE_PERMISSIONS_FIXTURE_HPP
