/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_command_factory.hpp"

#include <regex>

#include "model/commands/add_asset_quantity.hpp"
#include "model/commands/add_peer.hpp"
#include "model/commands/add_signatory.hpp"
#include "model/commands/append_role.hpp"
#include "model/commands/create_account.hpp"
#include "model/commands/create_asset.hpp"
#include "model/commands/create_domain.hpp"
#include "model/commands/create_role.hpp"
#include "model/commands/detach_role.hpp"
#include "model/commands/grant_permission.hpp"
#include "model/commands/remove_signatory.hpp"
#include "model/commands/revoke_permission.hpp"
#include "model/commands/set_account_detail.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/subtract_asset_quantity.hpp"
#include "model/commands/transfer_asset.hpp"

using namespace rapidjson;

namespace iroha {
  namespace model {
    namespace converters {
      template <>
      struct Convert<Peer> {
        template <typename T>
        boost::optional<Peer> operator()(T &&x) const {
          auto des = makeFieldDeserializer(std::forward<T>(x));
          auto address = des.String("address");
          auto pubkey = des.String("peer_key");

          if (not address or not pubkey) {
            return boost::none;
          }

          return boost::make_optional(Peer(
              address.value(),
              iroha::hexstringToArray<iroha::pubkey_t::size()>(pubkey.value())
                  .value()));
        }
      };

      JsonCommandFactory::JsonCommandFactory() {
        serializers_ = {
            {typeid(AddAssetQuantity),
             &JsonCommandFactory::serializeAddAssetQuantity},
            {typeid(SubtractAssetQuantity),
             &JsonCommandFactory::serializeSubtractAssetQuantity},
            {typeid(AddPeer), &JsonCommandFactory::serializeAddPeer},
            {typeid(AddSignatory), &JsonCommandFactory::serializeAddSignatory},
            {typeid(CreateAccount),
             &JsonCommandFactory::serializeCreateAccount},
            {typeid(CreateAsset), &JsonCommandFactory::serializeCreateAsset},
            {typeid(CreateDomain), &JsonCommandFactory::serializeCreateDomain},
            {typeid(SetAccountDetail),
             &JsonCommandFactory::serializeSetAccountDetail},
            {typeid(RemoveSignatory),
             &JsonCommandFactory::serializeRemoveSignatory},
            {typeid(SetQuorum), &JsonCommandFactory::serializeSetQuorum},
            {typeid(TransferAsset),
             &JsonCommandFactory::serializeTransferAsset},
            {typeid(AppendRole), &JsonCommandFactory::serializeAppendRole},
            {typeid(CreateRole), &JsonCommandFactory::serializeCreateRole},
            {typeid(DetachRole), &JsonCommandFactory::serializeDetachRole},
            {typeid(GrantPermission),
             &JsonCommandFactory::serializeGrantPermission},
            {typeid(RevokePermission),
             &JsonCommandFactory::serializeRevokePermission}};

        deserializers_ = {
            {"AddAssetQuantity",
             &JsonCommandFactory::deserializeAddAssetQuantity},
            {"SubtractAssetQuantity",
             &JsonCommandFactory::deserializeSubtractAssetQuantity},
            {"AddPeer", &JsonCommandFactory::deserializeAddPeer},
            {"AddSignatory", &JsonCommandFactory::deserializeAddSignatory},
            {"CreateAccount", &JsonCommandFactory::deserializeCreateAccount},
            {"CreateAsset", &JsonCommandFactory::deserializeCreateAsset},
            {"CreateDomain", &JsonCommandFactory::deserializeCreateDomain},
            {"SetAccountDetail",
             &JsonCommandFactory::deserializeSetAccountDetail},
            {"RemoveSignatory",
             &JsonCommandFactory::deserializeRemoveSignatory},
            {"SetQuorum", &JsonCommandFactory::deserializeSetQuorum},
            {"TransferAsset", &JsonCommandFactory::deserializeTransferAsset},
            {"AppendRole", &JsonCommandFactory::deserializeAppendRole},
            {"DetachRole", &JsonCommandFactory::deserializeDetachRole},
            {"CreateRole", &JsonCommandFactory::deserializeCreateRole},
            {"GrantPermission",
             &JsonCommandFactory::deserializeGrantPermission},
            {"RevokePermission",
             &JsonCommandFactory::deserializeRevokePermission}};
      }

      // AddAssetQuantity
      Document JsonCommandFactory::serializeAddAssetQuantity(
          std::shared_ptr<Command> command) {
        auto add_asset_quantity =
            static_cast<AddAssetQuantity *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "AddAssetQuantity", allocator);
        document.AddMember("asset_id", add_asset_quantity->asset_id, allocator);
        document.AddMember("amount", add_asset_quantity->amount, allocator);
        document.AddMember("description", add_asset_quantity->description, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeAddAssetQuantity(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<AddAssetQuantity>()
            | des.String(&AddAssetQuantity::asset_id, "asset_id")
            | des.String(&AddAssetQuantity::amount, "amount")
            | des.String(&AddAssetQuantity::description, "description") | toCommand;
      }

      // AddPeer
      Document JsonCommandFactory::serializeAddPeer(
          std::shared_ptr<Command> command) {
        auto add_peer = static_cast<AddPeer *>(command.get());
        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "AddPeer", allocator);

        Value peer;
        peer.SetObject();
        peer.AddMember("address", add_peer->peer.address, allocator);
        peer.AddMember(
            "peer_key", add_peer->peer.pubkey.to_hexstring(), allocator);

        document.AddMember("peer", peer, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeAddPeer(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<AddPeer>() | des.Object(&AddPeer::peer, "peer")
            | toCommand;
      }

      // AddSignatory
      Document JsonCommandFactory::serializeAddSignatory(
          std::shared_ptr<Command> command) {
        auto add_signatory = static_cast<AddSignatory *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "AddSignatory", allocator);
        document.AddMember("account_id", add_signatory->account_id, allocator);
        document.AddMember(
            "pubkey", add_signatory->pubkey.to_hexstring(), allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeAddSignatory(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<AddSignatory>()
            | des.String(&AddSignatory::account_id, "account_id")
            | des.String(&AddSignatory::pubkey, "pubkey") | toCommand;
      }

      // CreateAccount
      Document JsonCommandFactory::serializeCreateAccount(
          std::shared_ptr<Command> command) {
        auto create_account = static_cast<CreateAccount *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "CreateAccount", allocator);
        document.AddMember(
            "account_name", create_account->account_name, allocator);
        document.AddMember("domain_id", create_account->domain_id, allocator);
        document.AddMember(
            "pubkey", create_account->pubkey.to_hexstring(), allocator);
        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeCreateAccount(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<CreateAccount>()
            | des.String(&CreateAccount::account_name, "account_name")
            | des.String(&CreateAccount::domain_id, "domain_id")
            | des.String(&CreateAccount::pubkey, "pubkey") | toCommand;
      }

      // Set Account Detail
      rapidjson::Document JsonCommandFactory::serializeSetAccountDetail(
          std::shared_ptr<Command> command) {
        auto set_account_detail =
            static_cast<SetAccountDetail *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "SetAccountDetail", allocator);
        document.AddMember(
            "account_id", set_account_detail->account_id, allocator);
        document.AddMember("key", set_account_detail->key, allocator);
        document.AddMember("value", set_account_detail->value, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeSetAccountDetail(
          const rapidjson::Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<SetAccountDetail>()
            | des.String(&SetAccountDetail::account_id, "account_id")
            | des.String(&SetAccountDetail::key, "key")
            | des.String(&SetAccountDetail::value, "value") | toCommand;
      }

      // CreateAsset
      Document JsonCommandFactory::serializeCreateAsset(
          std::shared_ptr<Command> command) {
        auto create_asset = static_cast<CreateAsset *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "CreateAsset", allocator);
        document.AddMember("asset_name", create_asset->asset_name, allocator);
        document.AddMember("domain_id", create_asset->domain_id, allocator);
        document.AddMember("precision", create_asset->precision, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeCreateAsset(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<CreateAsset>()
            | des.String(&CreateAsset::asset_name, "asset_name")
            | des.String(&CreateAsset::domain_id, "domain_id")
            | des.Uint(&CreateAsset::precision, "precision") | toCommand;
      }

      // CreateDomain
      Document JsonCommandFactory::serializeCreateDomain(
          std::shared_ptr<Command> command) {
        auto create_domain = static_cast<CreateDomain *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "CreateDomain", allocator);
        document.AddMember("domain_id", create_domain->domain_id, allocator);
        document.AddMember(
            "user_default_role", create_domain->user_default_role, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeCreateDomain(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<CreateDomain>()
            | des.String(&CreateDomain::domain_id, "domain_id")
            | des.String(&CreateDomain::user_default_role, "user_default_role")
            | toCommand;
      }

      // RemoveSignatory
      Document JsonCommandFactory::serializeRemoveSignatory(
          std::shared_ptr<Command> command) {
        auto remove_signatory = static_cast<RemoveSignatory *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "RemoveSignatory", allocator);
        document.AddMember(
            "account_id", remove_signatory->account_id, allocator);
        document.AddMember(
            "pubkey", remove_signatory->pubkey.to_hexstring(), allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeRemoveSignatory(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<RemoveSignatory>()
            | des.String(&RemoveSignatory::account_id, "account_id")
            | des.String(&RemoveSignatory::pubkey, "pubkey") | toCommand;
      }

      // SetAccountQuorum
      Document JsonCommandFactory::serializeSetQuorum(
          std::shared_ptr<Command> command) {
        auto set_quorum = static_cast<SetQuorum *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "SetQuorum", allocator);
        document.AddMember("account_id", set_quorum->account_id, allocator);
        document.AddMember("new_quorum", set_quorum->new_quorum, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeSetQuorum(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<SetQuorum>()
            | des.String(&SetQuorum::account_id, "account_id")
            | des.Uint(&SetQuorum::new_quorum, "new_quorum") | toCommand;
      }

      // TransferAsset
      Document JsonCommandFactory::serializeTransferAsset(
          std::shared_ptr<Command> command) {
        auto transfer_asset = static_cast<TransferAsset *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "TransferAsset", allocator);
        document.AddMember(
            "src_account_id", transfer_asset->src_account_id, allocator);
        document.AddMember(
            "dest_account_id", transfer_asset->dest_account_id, allocator);
        document.AddMember("asset_id", transfer_asset->asset_id, allocator);
        document.AddMember(
            "description", transfer_asset->description, allocator);
        document.AddMember("amount", transfer_asset->amount, allocator);

        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeTransferAsset(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<TransferAsset>()
            | des.String(&TransferAsset::src_account_id, "src_account_id")
            | des.String(&TransferAsset::dest_account_id, "dest_account_id")
            | des.String(&TransferAsset::asset_id, "asset_id")
            | des.String(&TransferAsset::description, "description")
            | des.String(&TransferAsset::amount, "amount") | toCommand;
      }

      rapidjson::Document JsonCommandFactory::serializeAppendRole(
          std::shared_ptr<Command> command) {
        auto cmd = static_cast<AppendRole *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "AppendRole", allocator);
        document.AddMember("account_id", cmd->account_id, allocator);
        document.AddMember("role_name", cmd->role_name, allocator);
        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeAppendRole(
          const rapidjson::Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<AppendRole>()
            | des.String(&AppendRole::account_id, "account_id")
            | des.String(&AppendRole::role_name, "role_name") | toCommand;
      }

      rapidjson::Document JsonCommandFactory::serializeDetachRole(
          std::shared_ptr<Command> command) {
        auto cmd = static_cast<DetachRole *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "DetachRole", allocator);
        document.AddMember("account_id", cmd->account_id, allocator);
        document.AddMember("role_name", cmd->role_name, allocator);
        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeDetachRole(
          const rapidjson::Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<DetachRole>()
            | des.String(&DetachRole::account_id, "account_id")
            | des.String(&DetachRole::role_name, "role_name") | toCommand;
      }

      rapidjson::Document JsonCommandFactory::serializeCreateRole(
          std::shared_ptr<Command> command) {
        auto cmd = static_cast<CreateRole *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "CreateRole", allocator);
        document.AddMember("role_name", cmd->role_name, allocator);
        Value perms;
        perms.SetArray();
        for (auto perm : cmd->permissions) {
          Value perm_value;
          perm_value.Set(perm, allocator);
          perms.PushBack(perm_value, allocator);
        }
        document.AddMember("permissions", perms, allocator);
        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeCreateRole(
          const rapidjson::Value &document) {
        if (document.HasMember("role_name") and document["role_name"].IsString()
            and document.HasMember("permissions")
            and document["permissions"].IsArray()) {
          std::set<std::string> perms;
          for (auto &v : document["permissions"].GetArray()) {
            if (not v.IsString()) {
              return boost::none;
            }
            perms.insert(v.GetString());
          }
          auto role_name = document["role_name"].GetString();
          return make_optional_ptr<CreateRole>(role_name, perms) | toCommand;
        }
        return boost::none;
      }

      rapidjson::Document JsonCommandFactory::serializeGrantPermission(
          std::shared_ptr<Command> command) {
        auto cmd = static_cast<GrantPermission *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();
        document.SetObject();
        document.AddMember("command_type", "GrantPermission", allocator);
        document.AddMember("account_id", cmd->account_id, allocator);
        document.AddMember("permission_name", cmd->permission_name, allocator);
        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeGrantPermission(
          const rapidjson::Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<GrantPermission>()
            | des.String(&GrantPermission::account_id, "account_id")
            | des.String(&GrantPermission::permission_name, "permission_name")
            | toCommand;
      }

      rapidjson::Document JsonCommandFactory::serializeRevokePermission(
          std::shared_ptr<Command> command) {
        auto cmd = static_cast<RevokePermission *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();
        document.SetObject();
        document.AddMember("command_type", "RevokePermission", allocator);
        document.AddMember("account_id", cmd->account_id, allocator);
        document.AddMember("permission_name", cmd->permission_name, allocator);
        return document;
      }

      optional_ptr<Command> JsonCommandFactory::deserializeRevokePermission(
          const rapidjson::Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<RevokePermission>()
            | des.String(&RevokePermission::account_id, "account_id")
            | des.String(&RevokePermission::permission_name, "permission_name")
            | toCommand;
      }

      // SubtractAssetQuantity
      Document JsonCommandFactory::serializeSubtractAssetQuantity(
          std::shared_ptr<Command> command) {
        auto subtract_asset_quantity =
            static_cast<SubtractAssetQuantity *>(command.get());

        Document document;
        auto &allocator = document.GetAllocator();

        document.SetObject();
        document.AddMember("command_type", "SubtractAssetQuantity", allocator);
        document.AddMember(
            "asset_id", subtract_asset_quantity->asset_id, allocator);
        document.AddMember(
            "amount", subtract_asset_quantity->amount, allocator);
        document.AddMember(
            "description", subtract_asset_quantity->description, allocator);

        return document;
      }

      optional_ptr<Command>
      JsonCommandFactory::deserializeSubtractAssetQuantity(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        return make_optional_ptr<SubtractAssetQuantity>()
            | des.String(&SubtractAssetQuantity::asset_id, "asset_id")
            | des.String(&SubtractAssetQuantity::amount, "amount")
            | des.String(&SubtractAssetQuantity::description, "description") | toCommand;
      }

      // Abstract
      Document JsonCommandFactory::serializeAbstractCommand(
          std::shared_ptr<Command> command) {
        auto cmd = command.get();
        return makeMethodInvoke(*this, command)(serializers_.at(typeid(*cmd)));
      }

      optional_ptr<model::Command>
      JsonCommandFactory::deserializeAbstractCommand(const Value &document) {
        return makeFieldDeserializer(document).String("command_type")
            | makeOptionalGet(deserializers_)
            | makeMethodInvoke(*this, document);
      }
    }  // namespace converters
  }    // namespace model
}  // namespace iroha
