/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/grantable_permissions_fixture.hpp"

#include "framework/common_constants.hpp"

using namespace shared_model::interface::permissions;
using namespace common_constants;

shared_model::proto::Transaction
GrantablePermissionsFixture::makeAccountWithPerms(
    const shared_model::interface::types::AccountNameType &user,
    shared_model::interface::types::PublicKeyHexStringView key,
    const shared_model::interface::RolePermissionSet &perms,
    const shared_model::interface::types::RoleIdType &role) {
  return createUserWithPerms(user, key, role, perms)
      .build()
      .signAndAddSignature(*kAdminSigner)
      .finish();
}

integration_framework::IntegrationTestFramework &
GrantablePermissionsFixture::createTwoAccounts(
    integration_framework::IntegrationTestFramework &itf,
    const shared_model::interface::RolePermissionSet &perm1,
    const shared_model::interface::RolePermissionSet &perm2) {
  itf.sendTx(makeAccountWithPerms(
                 kAccount1, kAccount1Signer->publicKey(), perm1, kRole1))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(makeAccountWithPerms(
          kAccount2, kAccount2Signer->publicKey(), perm2, kRole2))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock();
  return itf;
}

shared_model::proto::Transaction GrantablePermissionsFixture::grantPermission(
    const shared_model::interface::types::AccountNameType &creator_account_name,
    const shared_model::crypto::CryptoSigner &signer,
    const shared_model::interface::types::AccountNameType
        &permittee_account_name,
    const shared_model::interface::permissions::Grantable &grant_permission) {
  const auto creator_account_id = creator_account_name + "@" + kDomain;
  const auto permittee_account_id = permittee_account_name + "@" + kDomain;
  return complete(baseTx(creator_account_id)
                      .grantPermission(permittee_account_id, grant_permission),
                  signer);
}

shared_model::proto::Transaction GrantablePermissionsFixture::revokePermission(
    const shared_model::interface::types::AccountNameType &creator_account_name,
    const shared_model::crypto::CryptoSigner &signer,
    const shared_model::interface::types::AccountNameType
        &permittee_account_name,
    const shared_model::interface::permissions::Grantable &revoke_permission) {
  const auto creator_account_id = creator_account_name + "@" + kDomain;
  const auto permittee_account_id = permittee_account_name + "@" + kDomain;
  return complete(
      baseTx(creator_account_id)
          .revokePermission(permittee_account_id, revoke_permission),
      signer);
}

shared_model::proto::Transaction
GrantablePermissionsFixture::permitteeAddSignatory(
    const shared_model::interface::types::AccountNameType
        &permittee_account_name,
    const shared_model::crypto::CryptoSigner &permittee_signer,
    const shared_model::interface::types::AccountNameType &account_name) {
  const auto permittee_account_id = permittee_account_name + "@" + kDomain;
  const auto account_id = account_name + "@" + kDomain;
  return baseTx(permittee_account_id)
      .addSignatory(account_id, permittee_signer.publicKey())
      .build()
      .signAndAddSignature(permittee_signer)
      .finish();
}

shared_model::proto::Transaction
GrantablePermissionsFixture::permitteeRemoveSignatory(
    const shared_model::interface::types::AccountNameType
        &permittee_account_name,
    const shared_model::crypto::CryptoSigner &permittee_signer,
    const shared_model::interface::types::AccountNameType &account_name) {
  const auto permittee_account_id = permittee_account_name + "@" + kDomain;
  const auto account_id = account_name + "@" + kDomain;
  return baseTx(permittee_account_id)
      .removeSignatory(account_id, permittee_signer.publicKey())
      .build()
      .signAndAddSignature(permittee_signer)
      .finish();
}

shared_model::proto::Transaction GrantablePermissionsFixture::setQuorum(
    const shared_model::interface::types::AccountNameType
        &permittee_account_name,
    const shared_model::crypto::CryptoSigner &signer,
    const shared_model::interface::types::AccountNameType &account_name,
    shared_model::interface::types::QuorumType quorum) {
  const auto permittee_account_id = permittee_account_name + "@" + kDomain;
  const auto account_id = account_name + "@" + kDomain;
  return complete(
      baseTx(permittee_account_id).setAccountQuorum(account_id, quorum),
      signer);
}

shared_model::proto::Transaction GrantablePermissionsFixture::setAccountDetail(
    const shared_model::interface::types::AccountNameType
        &permittee_account_name,
    const shared_model::crypto::CryptoSigner &signer,
    const shared_model::interface::types::AccountNameType &account_name,
    const shared_model::interface::types::AccountDetailKeyType &key,
    const shared_model::interface::types::AccountDetailValueType &detail) {
  const auto permittee_account_id = permittee_account_name + "@" + kDomain;
  const auto account_id = account_name + "@" + kDomain;
  return complete(
      baseTx(permittee_account_id).setAccountDetail(account_id, key, detail),
      signer);
}

shared_model::proto::Transaction
GrantablePermissionsFixture::addAssetAndTransfer(
    const shared_model::interface::types::AccountNameType &creator_name,
    const shared_model::crypto::CryptoSigner &signer,
    const shared_model::interface::types::AccountNameType &amount,
    const shared_model::interface::types::AccountNameType &receiver_name) {
  const auto creator_account_id = creator_name + "@" + kDomain;
  const auto receiver_account_id = receiver_name + "@" + kDomain;
  const auto asset_id = kAssetName + "#" + kDomain;
  return complete(
      baseTx(creator_account_id)
          .addAssetQuantity(asset_id, amount)
          .transferAsset(
              creator_account_id, receiver_account_id, asset_id, "", amount),
      signer);
}

shared_model::proto::Transaction
GrantablePermissionsFixture::transferAssetFromSource(
    const shared_model::interface::types::AccountNameType &creator_name,
    const shared_model::crypto::CryptoSigner &signer,
    const shared_model::interface::types::AccountNameType &source_account_name,
    const std::string &amount,
    const shared_model::interface::types::AccountNameType &receiver_name) {
  const auto creator_account_id = creator_name + "@" + kDomain;
  const auto source_account_id = source_account_name + "@" + kDomain;
  const auto receiver_account_id = receiver_name + "@" + kDomain;
  const auto asset_id = kAssetName + "#" + kDomain;
  return complete(
      baseTx(creator_account_id)
          .transferAsset(
              source_account_id, receiver_account_id, asset_id, "", amount),
      signer);
}

shared_model::proto::Query GrantablePermissionsFixture::querySignatories(
    const shared_model::interface::types::AccountNameType &account_name,
    const shared_model::crypto::CryptoSigner &signer) {
  const std::string account_id = account_name + "@" + kDomain;
  return complete(baseQry(account_id).getSignatories(account_id), signer);
}

shared_model::proto::Query GrantablePermissionsFixture::queryAccount(
    const shared_model::interface::types::AccountNameType &account_name,
    const shared_model::crypto::CryptoSigner &signer) {
  const auto account_id = account_name + "@" + kDomain;
  return complete(baseQry(account_id).getAccount(account_id), signer);
}

shared_model::proto::Query GrantablePermissionsFixture::queryAccountDetail(
    const shared_model::interface::types::AccountNameType &account_name,
    const shared_model::crypto::CryptoSigner &signer) {
  const auto account_id = account_name + "@" + kDomain;
  return complete(
      baseQry(account_id).getAccountDetail(kMaxPageSize, account_id), signer);
}
