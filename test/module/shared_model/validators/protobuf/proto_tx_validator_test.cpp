/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_transaction_validator.hpp"

#include <gtest/gtest.h>
#include <optional>
#include "module/shared_model/validators/validators_fixture.hpp"
#include "validators/validation_error_output.hpp"

const static std::string rolename = "rolename";
const static std::string account_id = "account@domain";
const static std::string account_name = "account";
const static std::string domain_id = "domain";
const static std::string address_ipv4 = "127.0.0.1";

const static std::string valid_pubkey(32, '1');
const static std::string invalid_pubkey("not_hex");

const static iroha::protocol::RolePermission valid_role_permission =
    iroha::protocol::RolePermission::can_read_assets;
const static iroha::protocol::RolePermission invalid_role_permission =
    static_cast<iroha::protocol::RolePermission>(-1);

const static iroha::protocol::GrantablePermission valid_grantable_permission =
    iroha::protocol::GrantablePermission::can_add_my_signatory;
const static iroha::protocol::GrantablePermission invalid_grantable_permission =
    static_cast<iroha::protocol::GrantablePermission>(-1);

iroha::protocol::Transaction generateCreateRoleTransaction(
    iroha::protocol::RolePermission permission) {
  auto tx = iroha::protocol::Transaction();

  auto cr = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_create_role();
  cr->set_role_name(rolename);
  cr->add_permissions(permission);
  return tx;
}

iroha::protocol::Transaction generateGrantPermissionTransaction(
    iroha::protocol::GrantablePermission permission) {
  auto tx = iroha::protocol::Transaction();

  auto gp = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_grant_permission();
  gp->set_account_id(account_id);
  gp->set_permission(permission);
  return tx;
}

iroha::protocol::Transaction generateRevokePermissionTransaction(
    iroha::protocol::GrantablePermission permission) {
  auto tx = iroha::protocol::Transaction();

  auto gp = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_revoke_permission();
  gp->set_account_id(account_id);
  gp->set_permission(permission);
  return tx;
}

iroha::protocol::Transaction generateAddSignatoryTransaction(
    const std::string &signatory) {
  auto tx = iroha::protocol::Transaction();
  auto as = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_add_signatory();
  as->set_account_id(account_id);
  as->set_public_key(signatory);
  return tx;
}

iroha::protocol::Transaction generateCreateAccountTransaction(
    const std::string &pubkey) {
  auto tx = iroha::protocol::Transaction();
  auto ca = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_create_account();
  ca->set_account_name(account_name);
  ca->set_domain_id(domain_id);
  ca->set_public_key(pubkey);
  return tx;
}

iroha::protocol::Transaction generateRemoveSignatoryTransaction(
    const std::string &signatory) {
  auto tx = iroha::protocol::Transaction();
  auto rs = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_remove_signatory();
  rs->set_account_id(account_id);
  rs->set_public_key(signatory);
  return tx;
}

iroha::protocol::Transaction generateAddPeerTransaction(
    const std::string &pubkey) {
  auto tx = iroha::protocol::Transaction();
  auto as = tx.mutable_payload()
                ->mutable_reduced_payload()
                ->add_commands()
                ->mutable_add_peer();
  as->mutable_peer()->set_address(address_ipv4);
  as->mutable_peer()->set_peer_key(pubkey);
  return tx;
}

class ProtoTxValidatorTest : public ValidatorsTest {
 protected:
  shared_model::validation::ProtoTransactionValidator validator;
};

// valid transaction tests

class ValidProtoTxValidatorTest
    : public ProtoTxValidatorTest,
      public ::testing::WithParamInterface<iroha::protocol::Transaction> {};

/**
 * @given valid protocol transaction
 * @when proto tx validator validates it
 * @then answer does not contain errors
 */
TEST_P(ValidProtoTxValidatorTest, ValidTxsTest) {
  auto tx = GetParam();
  ASSERT_EQ(validator.validate(tx), std::nullopt) << tx.DebugString();
}

INSTANTIATE_TEST_SUITE_P(
    ValidProtoTxs,
    ValidProtoTxValidatorTest,
    ::testing::Values(
        generateAddSignatoryTransaction(valid_pubkey),
        generateCreateAccountTransaction(valid_pubkey),
        generateRemoveSignatoryTransaction(valid_pubkey),
        generateCreateAccountTransaction(valid_pubkey),
        generateAddPeerTransaction(valid_pubkey),
        generateCreateRoleTransaction(valid_role_permission),
        generateGrantPermissionTransaction(valid_grantable_permission),
        generateRevokePermissionTransaction(valid_grantable_permission)));

// invalid transaction tests

class InvalidProtoTxValidatorTest
    : public ProtoTxValidatorTest,
      public ::testing::WithParamInterface<iroha::protocol::Transaction> {};

/**
 * @given invalid protocol transaction
 * @when proto tx validator validates it
 * @then answer contains errors
 */
TEST_P(InvalidProtoTxValidatorTest, InvalidTxssTest) {
  auto tx = GetParam();
  ASSERT_TRUE(validator.validate(tx)) << tx.DebugString();
}

INSTANTIATE_TEST_SUITE_P(
    InvalidProtoTxs,
    InvalidProtoTxValidatorTest,
    ::testing::Values(
        generateAddSignatoryTransaction(invalid_pubkey),
        generateCreateAccountTransaction(invalid_pubkey),
        generateRemoveSignatoryTransaction(invalid_pubkey),
        generateCreateAccountTransaction(invalid_pubkey),
        generateAddPeerTransaction(invalid_pubkey),
        generateCreateRoleTransaction(invalid_role_permission),
        generateGrantPermissionTransaction(invalid_grantable_permission),
        generateRevokePermissionTransaction(invalid_grantable_permission)));
