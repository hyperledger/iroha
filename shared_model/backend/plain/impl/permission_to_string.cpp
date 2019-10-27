/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/permission_to_string.hpp"

#include <unordered_map>

#include "interfaces/permissions.hpp"

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;
using shared_model::plain::PermissionToString;

namespace {

  const std::unordered_map<Role, std::string> kRoleToString{
      {Role::kAppendRole, "AppendRole"},
      {Role::kCreateRole, "CreateRole"},
      {Role::kDetachRole, "DetachRole"},
      {Role::kAddAssetQty, "AddAssetQty"},
      {Role::kSubtractAssetQty, "SubtractAssetQty"},
      {Role::kAddPeer, "AddPeer"},
      {Role::kAddSignatory, "AddSignatory"},
      {Role::kRemoveSignatory, "RemoveSignatory"},
      {Role::kSetQuorum, "SetQuorum"},
      {Role::kCreateAccount, "CreateAccount"},
      {Role::kSetDetail, "SetDetail"},
      {Role::kCreateAsset, "CreateAsset"},
      {Role::kTransfer, "Transfer"},
      {Role::kReceive, "Receive"},
      {Role::kCreateDomain, "CreateDomain"},
      {Role::kReadAssets, "ReadAssets"},
      {Role::kGetRoles, "GetRoles"},
      {Role::kGetMyAccount, "GetMyAccount"},
      {Role::kGetAllAccounts, "GetAllAccounts"},
      {Role::kGetDomainAccounts, "GetDomainAccounts"},
      {Role::kGetMySignatories, "GetMySignatories"},
      {Role::kGetAllSignatories, "GetAllSignatories"},
      {Role::kGetDomainSignatories, "GetDomainSignatories"},
      {Role::kGetMyAccAst, "GetMyAccAst"},
      {Role::kGetAllAccAst, "GetAllAccAst"},
      {Role::kGetDomainAccAst, "GetDomainAccAst"},
      {Role::kGetMyAccDetail, "GetMyAccDetail"},
      {Role::kGetAllAccDetail, "GetAllAccDetail"},
      {Role::kGetDomainAccDetail, "GetDomainAccDetail"},
      {Role::kGetMyAccTxs, "GetMyAccTxs"},
      {Role::kGetAllAccTxs, "GetAllAccTxs"},
      {Role::kGetDomainAccTxs, "GetDomainAccTxs"},
      {Role::kGetMyAccAstTxs, "GetMyAccAstTxs"},
      {Role::kGetAllAccAstTxs, "GetAllAccAstTxs"},
      {Role::kGetDomainAccAstTxs, "GetDomainAccAstTxs"},
      {Role::kGetMyTxs, "GetMyTxs"},
      {Role::kGetAllTxs, "GetAllTxs"},
      {Role::kSetMyQuorum, "SetMyQuorum"},
      {Role::kAddMySignatory, "AddMySignatory"},
      {Role::kRemoveMySignatory, "RemoveMySignatory"},
      {Role::kTransferMyAssets, "TransferMyAssets"},
      {Role::kSetMyAccountDetail, "SetMyAccountDetail"},
      {Role::kGetBlocks, "GetBlocks"},
      {Role::kAddDomainAssetQty, "AddDomainAssetQty"},
      {Role::kSubtractDomainAssetQty, "SubtractDomainAssetQty"},
      {Role::kGetPeers, "GetPeers"},
      {Role::kRemovePeer, "RemovePeer"},
      {Role::kRoot, "Root"}};

  const std::unordered_map<Grantable, std::string> kGrantableToString{
      {Grantable::kAddMySignatory, "AddMySignatory"},
      {Grantable::kRemoveMySignatory, "RemoveMySignatory"},
      {Grantable::kSetMyQuorum, "SetMyQuorum"},
      {Grantable::kSetMyAccountDetail, "SetMyAccountDetail"},
      {Grantable::kTransferMyAssets, "TransferMyAssets"}};
}  // namespace

std::string PermissionToString::toString(interface::permissions::Role p) const {
  return kRoleToString.at(p);
}

std::string PermissionToString::toString(
    interface::permissions::Grantable p) const {
  return kGrantableToString.at(p);
}
