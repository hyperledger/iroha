/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PERMISSIONS_HPP
#define IROHA_SHARED_MODEL_PERMISSIONS_HPP

#include <bitset>
#include <functional>
#include <initializer_list>
#include <string>

namespace shared_model {
  namespace interface {
    namespace permissions {
      enum class Role {
        kAppendRole,
        kCreateRole,
        kDetachRole,
        kAddAssetQty,
        kSubtractAssetQty,
        kAddPeer,
        kAddSignatory,
        kRemoveSignatory,
        kSetQuorum,
        kCreateAccount,
        kSetDetail,
        kCreateAsset,
        kTransfer,
        kReceive,
        kCreateDomain,
        kReadAssets,
        kGetRoles,
        kGetMyAccount,
        kGetAllAccounts,
        kGetDomainAccounts,
        kGetMySignatories,
        kGetAllSignatories,
        kGetDomainSignatories,
        kGetMyAccAst,
        kGetAllAccAst,
        kGetDomainAccAst,
        kGetMyAccDetail,
        kGetAllAccDetail,
        kGetDomainAccDetail,
        kGetMyAccTxs,
        kGetAllAccTxs,
        kGetDomainAccTxs,
        kGetMyAccAstTxs,
        kGetAllAccAstTxs,
        kGetDomainAccAstTxs,
        kGetMyTxs,
        kGetAllTxs,
        kSetMyQuorum,
        kAddMySignatory,
        kRemoveMySignatory,
        kTransferMyAssets,
        kSetMyAccountDetail,
        kGetBlocks,
        kAddDomainAssetQty,
        kSubtractDomainAssetQty,
        COUNT
      };

      enum class Grantable {
        kAddMySignatory,
        kRemoveMySignatory,
        kSetMyQuorum,
        kSetMyAccountDetail,
        kTransferMyAssets,

        COUNT
      };

      Role permissionFor(Grantable);

      /**
       * @param perm protocol object for checking
       * @return true if valid, false otherwise
       */
      bool isValid(interface::permissions::Role perm) noexcept;

      /**
       * @param perm protocol object for checking
       * @return true if valid, false otherwise
       */
      bool isValid(interface::permissions::Grantable perm) noexcept;
    }  // namespace permissions

    template <typename Perm>
    class PermissionSet
        : private std::bitset<static_cast<size_t>(Perm::COUNT)> {
     private:
      using Parent = std::bitset<static_cast<size_t>(Perm::COUNT)>;

     public:
      PermissionSet();
      PermissionSet(std::initializer_list<Perm> list);
      explicit PermissionSet(const std::string &bitstring);

      // TODO [IR-1889] Akvinikym 21.11.18: introduce toString() method
      std::string toBitstring() const;

      static size_t size();
      PermissionSet &reset();
      PermissionSet &set();
      PermissionSet &set(Perm p);
      PermissionSet &unset(Perm p);

      bool test(Perm p) const;
      bool none() const;

      bool isSubsetOf(const PermissionSet<Perm> &r) const;

      bool operator==(const PermissionSet<Perm> &r) const;
      bool operator!=(const PermissionSet<Perm> &r) const;
      PermissionSet<Perm> &operator&=(const PermissionSet<Perm> &r);
      PermissionSet<Perm> &operator|=(const PermissionSet<Perm> &r);
      PermissionSet<Perm> &operator^=(const PermissionSet<Perm> &r);

      void iterate(std::function<void(Perm)> f) const;
    };

    using RolePermissionSet = PermissionSet<permissions::Role>;
    using GrantablePermissionSet = PermissionSet<permissions::Grantable>;
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_TRANSACTION_HPP
