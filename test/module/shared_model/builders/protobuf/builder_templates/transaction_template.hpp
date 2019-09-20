/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSACTION_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_TRANSACTION_BUILDER_TEMPLATE_HPP

#include <memory>

#include "backend/protobuf/transaction.hpp"

#include "backend/protobuf/permissions.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"
#include "module/shared_model/builders/protobuf/unsigned_proto.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template tx builder for creating new types of transaction builders by
     * means of replacing template parameters
     * @tparam BT -- build type of built object returned by build method
     */
    template <typename BT = UnsignedWrapper<Transaction>>
    class [[deprecated]] TemplateTransactionBuilder {
     private:
      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param f - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      TemplateTransactionBuilder<BT> transform(Transformation t) const;

      /**
       * Make add command transformation on copied object
       * @tparam Transformation - callable type for changing command
       * @param f - transform function for proto command
       * @return new builder with added command
       */
      template <typename Transformation>
      TemplateTransactionBuilder<BT> addCommand(Transformation t) const;

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateTransactionBuilder();

      TemplateTransactionBuilder(const TemplateTransactionBuilder<BT> &o);

      TemplateTransactionBuilder<BT> &operator=(
          const TemplateTransactionBuilder<BT> &o);

      TemplateTransactionBuilder<BT> creatorAccountId(
          const interface::types::AccountIdType &account_id) const;

      TemplateTransactionBuilder<BT> batchMeta(
          interface::types::BatchType type,
          std::vector<interface::types::HashType> hashes) const;

      TemplateTransactionBuilder<BT> createdTime(
          interface::types::TimestampType created_time) const;

      TemplateTransactionBuilder<BT> quorum(interface::types::QuorumType quorum)
          const;

      TemplateTransactionBuilder<BT> addAssetQuantity(
          const interface::types::AssetIdType &asset_id,
          const std::string &amount) const;

      TemplateTransactionBuilder<BT> addPeerRaw(
          const interface::types::AddressType &address,
          const std::string &peer_key) const;

      TemplateTransactionBuilder<BT> addPeer(
          const interface::types::AddressType &address,
          const interface::types::PubkeyType &peer_key) const;

      TemplateTransactionBuilder<BT> removePeer(
          const interface::types::PubkeyType &public_key) const;

      TemplateTransactionBuilder<BT> addSignatoryRaw(
          const interface::types::AccountIdType &account_id,
          const std::string &public_key) const;

      TemplateTransactionBuilder<BT> addSignatory(
          const interface::types::AccountIdType &account_id,
          const interface::types::PubkeyType &public_key) const;

      TemplateTransactionBuilder<BT> removeSignatoryRaw(
          const interface::types::AccountIdType &account_id,
          const std::string &public_key) const;

      TemplateTransactionBuilder<BT> removeSignatory(
          const interface::types::AccountIdType &account_id,
          const interface::types::PubkeyType &public_key) const;

      TemplateTransactionBuilder<BT> appendRole(
          const interface::types::AccountIdType &account_id,
          const interface::types::RoleIdType &role_name) const;

      TemplateTransactionBuilder<BT> createAsset(
          const interface::types::AssetNameType &asset_name,
          const interface::types::DomainIdType &domain_id,
          interface::types::PrecisionType precision) const;

      TemplateTransactionBuilder<BT> createAccountRaw(
          const interface::types::AccountNameType &account_name,
          const interface::types::DomainIdType &domain_id,
          const std::string &main_pubkey) const;

      TemplateTransactionBuilder<BT> createAccount(
          const interface::types::AccountNameType &account_name,
          const interface::types::DomainIdType &domain_id,
          const interface::types::PubkeyType &main_pubkey) const;

      TemplateTransactionBuilder<BT> createDomain(
          const interface::types::DomainIdType &domain_id,
          const interface::types::RoleIdType &default_role) const;

      TemplateTransactionBuilder<BT> createRole(
          const interface::types::RoleIdType &role_name,
          const interface::RolePermissionSet &permissions) const;

      TemplateTransactionBuilder<BT> detachRole(
          const interface::types::AccountIdType &account_id,
          const interface::types::RoleIdType &role_name) const;

      TemplateTransactionBuilder<BT> grantPermission(
          const interface::types::AccountIdType &account_id,
          interface::permissions::Grantable permission) const;

      TemplateTransactionBuilder<BT> revokePermission(
          const interface::types::AccountIdType &account_id,
          interface::permissions::Grantable permission) const;

      TemplateTransactionBuilder<BT> setAccountDetail(
          const interface::types::AccountIdType &account_id,
          const interface::types::AccountDetailKeyType &key,
          const interface::types::AccountDetailValueType &value) const;

      TemplateTransactionBuilder<BT> setAccountQuorum(
          const interface::types::AddressType &account_id,
          interface::types::QuorumType quorum) const;

      TemplateTransactionBuilder<BT> subtractAssetQuantity(
          const interface::types::AssetIdType &asset_id,
          const std::string &amount) const;

      TemplateTransactionBuilder<BT> transferAsset(
          const interface::types::AccountIdType &src_account_id,
          const interface::types::AccountIdType &dest_account_id,
          const interface::types::AssetIdType &asset_id,
          const interface::types::DescriptionType &description,
          const std::string &amount) const;

      BT build() const;

      ~TemplateTransactionBuilder();

     private:
      std::unique_ptr<iroha::protocol::Transaction> transaction_;
    };

    extern template class TemplateTransactionBuilder<Transaction>;
    extern template class TemplateTransactionBuilder<
        UnsignedWrapper<Transaction>>;
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSACTION_BUILDER_TEMPLATE_HPP
