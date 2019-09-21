/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/builders/protobuf/builder_templates/transaction_template.hpp"

#include "transaction.pb.h"

using namespace shared_model;
using namespace shared_model::proto;

template <typename BT>
template <typename Transformation>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::transform(
    Transformation t) const {
  TemplateTransactionBuilder<BT> copy = *this;
  t(*copy.transaction_);
  return copy;
}

template <typename BT>
template <typename Transformation>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::addCommand(
    Transformation t) const {
  TemplateTransactionBuilder<BT> copy = *this;
  t(copy.transaction_->mutable_payload()
        ->mutable_reduced_payload()
        ->add_commands());
  return copy;
}

template <typename BT>
TemplateTransactionBuilder<BT>::TemplateTransactionBuilder()
    : transaction_{std::make_unique<iroha::protocol::Transaction>()} {}

template <typename BT>
TemplateTransactionBuilder<BT>::TemplateTransactionBuilder(
    const TemplateTransactionBuilder<BT> &o)
    : transaction_{
          std::make_unique<iroha::protocol::Transaction>(*o.transaction_)} {}

template <typename BT>
TemplateTransactionBuilder<BT> &TemplateTransactionBuilder<BT>::operator=(
    const TemplateTransactionBuilder<BT> &o) {
  if (this != &o) {
    transaction_ =
        std::make_unique<iroha::protocol::Transaction>(*o.transaction_);
  }
  return *this;
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::creatorAccountId(
    const interface::types::AccountIdType &account_id) const {
  return transform([&](auto &tx) {
    tx.mutable_payload()->mutable_reduced_payload()->set_creator_account_id(
        account_id);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::batchMeta(
    interface::types::BatchType type,
    std::vector<interface::types::HashType> hashes) const {
  return transform([&](auto &tx) {
    tx.mutable_payload()->mutable_batch()->set_type(
        static_cast<
            iroha::protocol::Transaction::Payload::BatchMeta::BatchType>(type));
    for (const auto &hash : hashes) {
      tx.mutable_payload()->mutable_batch()->add_reduced_hashes(hash.hex());
    }
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::createdTime(
    interface::types::TimestampType created_time) const {
  return transform([&](auto &tx) {
    tx.mutable_payload()->mutable_reduced_payload()->set_created_time(
        created_time);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::quorum(
    interface::types::QuorumType quorum) const {
  return transform([&](auto &tx) {
    tx.mutable_payload()->mutable_reduced_payload()->set_quorum(quorum);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::addAssetQuantity(
    const interface::types::AssetIdType &asset_id,
    const std::string &amount) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_add_asset_quantity();
    command->set_asset_id(asset_id);
    command->set_amount(amount);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::addPeerRaw(
    const interface::types::AddressType &address,
    const std::string &peer_key) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_add_peer();
    auto peer = command->mutable_peer();
    peer->set_address(address);
    peer->set_peer_key(peer_key);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::addPeer(
    const interface::types::AddressType &address,
    const interface::types::PubkeyType &peer_key) const {
  return addPeerRaw(address, peer_key.hex());
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::removePeer(
    const interface::types::PubkeyType &public_key) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_remove_peer();
    command->set_public_key(public_key.hex());
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::addSignatoryRaw(
    const interface::types::AccountIdType &account_id,
    const std::string &public_key) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_add_signatory();
    command->set_account_id(account_id);
    command->set_public_key(public_key);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::addSignatory(
    const interface::types::AccountIdType &account_id,
    const interface::types::PubkeyType &public_key) const {
  return addSignatoryRaw(account_id, public_key.hex());
}

template <typename BT>
TemplateTransactionBuilder<BT>
TemplateTransactionBuilder<BT>::removeSignatoryRaw(
    const interface::types::AccountIdType &account_id,
    const std::string &public_key) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_remove_signatory();
    command->set_account_id(account_id);
    command->set_public_key(public_key);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::removeSignatory(
    const interface::types::AccountIdType &account_id,
    const interface::types::PubkeyType &public_key) const {
  return removeSignatoryRaw(account_id, public_key.hex());
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::appendRole(
    const interface::types::AccountIdType &account_id,
    const interface::types::RoleIdType &role_name) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_append_role();
    command->set_account_id(account_id);
    command->set_role_name(role_name);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::createAsset(
    const interface::types::AssetNameType &asset_name,
    const interface::types::DomainIdType &domain_id,
    interface::types::PrecisionType precision) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_create_asset();
    command->set_asset_name(asset_name);
    command->set_domain_id(domain_id);
    command->set_precision(precision);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::createAccountRaw(
    const interface::types::AccountNameType &account_name,
    const interface::types::DomainIdType &domain_id,
    const std::string &main_pubkey) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_create_account();
    command->set_account_name(account_name);
    command->set_domain_id(domain_id);
    command->set_public_key(main_pubkey);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::createAccount(
    const interface::types::AccountNameType &account_name,
    const interface::types::DomainIdType &domain_id,
    const interface::types::PubkeyType &main_pubkey) const {
  return createAccountRaw(account_name, domain_id, main_pubkey.hex());
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::createDomain(
    const interface::types::DomainIdType &domain_id,
    const interface::types::RoleIdType &default_role) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_create_domain();
    command->set_domain_id(domain_id);
    command->set_default_role(default_role);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::createRole(
    const interface::types::RoleIdType &role_name,
    const interface::RolePermissionSet &permissions) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_create_role();
    command->set_role_name(role_name);
    for (size_t i = 0; i < permissions.size(); ++i) {
      auto perm = static_cast<interface::permissions::Role>(i);
      if (permissions.isSet(perm)) {
        command->add_permissions(permissions::toTransport(perm));
      }
    }
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::detachRole(
    const interface::types::AccountIdType &account_id,
    const interface::types::RoleIdType &role_name) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_detach_role();
    command->set_account_id(account_id);
    command->set_role_name(role_name);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::grantPermission(
    const interface::types::AccountIdType &account_id,
    interface::permissions::Grantable permission) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_grant_permission();
    command->set_account_id(account_id);
    command->set_permission(permissions::toTransport(permission));
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::revokePermission(
    const interface::types::AccountIdType &account_id,
    interface::permissions::Grantable permission) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_revoke_permission();
    command->set_account_id(account_id);
    command->set_permission(permissions::toTransport(permission));
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::setAccountDetail(
    const interface::types::AccountIdType &account_id,
    const interface::types::AccountDetailKeyType &key,
    const interface::types::AccountDetailValueType &value) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_set_account_detail();
    command->set_account_id(account_id);
    command->set_key(key);
    command->set_value(value);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::setAccountQuorum(
    const interface::types::AddressType &account_id,
    interface::types::QuorumType quorum) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_set_account_quorum();
    command->set_account_id(account_id);
    command->set_quorum(quorum);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT>
TemplateTransactionBuilder<BT>::subtractAssetQuantity(
    const interface::types::AssetIdType &asset_id,
    const std::string &amount) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_subtract_asset_quantity();
    command->set_asset_id(asset_id);
    command->set_amount(amount);
  });
}

template <typename BT>
TemplateTransactionBuilder<BT> TemplateTransactionBuilder<BT>::transferAsset(
    const interface::types::AccountIdType &src_account_id,
    const interface::types::AccountIdType &dest_account_id,
    const interface::types::AssetIdType &asset_id,
    const interface::types::DescriptionType &description,
    const std::string &amount) const {
  return addCommand([&](auto proto_command) {
    auto command = proto_command->mutable_transfer_asset();
    command->set_src_account_id(src_account_id);
    command->set_dest_account_id(dest_account_id);
    command->set_asset_id(asset_id);
    command->set_description(description);
    command->set_amount(amount);
  });
}

template <typename BT>
BT TemplateTransactionBuilder<BT>::build() const {
  auto result = Transaction(iroha::protocol::Transaction(*transaction_));

  return BT(std::move(result));
}

template <typename BT>
TemplateTransactionBuilder<BT>::~TemplateTransactionBuilder() = default;

template class shared_model::proto::TemplateTransactionBuilder<Transaction>;
template class shared_model::proto::TemplateTransactionBuilder<
    UnsignedWrapper<Transaction>>;
