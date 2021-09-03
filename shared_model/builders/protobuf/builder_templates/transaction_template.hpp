/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSACTION_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_TRANSACTION_BUILDER_TEMPLATE_HPP

#include "backend/protobuf/transaction.hpp"

#include <boost/range/algorithm/for_each.hpp>

#include "commands.pb.h"
#include "primitive.pb.h"
#include "transaction.pb.h"

#include "backend/protobuf/permissions.hpp"
#include "builders/protobuf/unsigned_proto.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/engine_type.hpp"
#include "interfaces/permissions.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/default_validator.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template tx builder for creating new types of transaction builders by
     * means of replacing template parameters
     * @tparam S -- field counter for checking that all required fields are set
     * @tparam SV -- stateless validator called when build method is invoked
     * @tparam BT -- build type of built object returned by build method
     */
    template <int S = 0,
              typename SV = validation::DefaultUnsignedTransactionValidator,
              typename BT = UnsignedWrapper<Transaction>>
    class /*[[deprecated]]*/ TemplateTransactionBuilder {
     private:
      template <int, typename, typename>
      friend class TemplateTransactionBuilder;

      enum RequiredFields {
        Command,
        CreatorAccountId,
        CreatedTime,
        Quorum,
        TOTAL
      };

      template <int s>
      using NextBuilder = TemplateTransactionBuilder<S | (1 << s), SV, BT>;

      using ProtoTx = iroha::protocol::Transaction;
      using ProtoCommand = iroha::protocol::Command;

      template <int Sp>
      TemplateTransactionBuilder(
          const TemplateTransactionBuilder<Sp, SV, BT> &o)
          : transaction_(o.transaction_),
            stateless_validator_(o.stateless_validator_) {}

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param f - transform function for proto object
       * @return new builder with updated state
       */
      template <int Fields, typename Transformation>
      auto transform(Transformation t) const {
        NextBuilder<Fields> copy = *this;
        t(copy.transaction_);
        return copy;
      }

      /**
       * Make add command transformation on copied object
       * @tparam Transformation - callable type for changing command
       * @param f - transform function for proto command
       * @return new builder with added command
       */
      template <typename Transformation>
      auto addCommand(Transformation t) const {
        NextBuilder<Command> copy = *this;
        t(copy.transaction_.mutable_payload()
              ->mutable_reduced_payload()
              ->add_commands());
        return copy;
      }

      TemplateTransactionBuilder(const SV &validator)
          : stateless_validator_(validator) {}

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateTransactionBuilder()
          : TemplateTransactionBuilder(
                SV(iroha::test::kTestsValidatorsConfig)) {}

      auto creatorAccountId(const interface::types::AccountIdType &account_id)
          const {
        return transform<CreatorAccountId>([&](auto &tx) {
          tx.mutable_payload()
              ->mutable_reduced_payload()
              ->set_creator_account_id(account_id);
        });
      }

      auto batchMeta(interface::types::BatchType type,
                     std::vector<interface::types::HashType> hashes) const {
        return transform<0>([&](auto &tx) {
          tx.mutable_payload()->mutable_batch()->set_type(
              static_cast<
                  iroha::protocol::Transaction::Payload::BatchMeta::BatchType>(
                  type));
          for (const auto &hash : hashes) {
            tx.mutable_payload()->mutable_batch()->add_reduced_hashes(
                hash.hex());
          }
        });
      }

      auto createdTime(interface::types::TimestampType created_time) const {
        return transform<CreatedTime>([&](auto &tx) {
          tx.mutable_payload()->mutable_reduced_payload()->set_created_time(
              created_time);
        });
      }

      auto quorum(interface::types::QuorumType quorum) const {
        return transform<Quorum>([&](auto &tx) {
          tx.mutable_payload()->mutable_reduced_payload()->set_quorum(quorum);
        });
      }

      auto addAssetQuantity(const interface::types::AssetIdType &asset_id,
                            const std::string &amount) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_add_asset_quantity();
          command->set_asset_id(asset_id);
          command->set_amount(amount);
        });
      }

      auto addPeer(const interface::types::AddressType &address,
                   interface::types::PublicKeyHexStringView peer_key,
                   const std::optional<interface::types::TLSCertificateType>
                       &tls_certificate = std::nullopt) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_add_peer();
          auto peer = command->mutable_peer();
          peer->set_address(address);
          const std::string_view peer_key_sv{peer_key};
          peer->set_peer_key(peer_key_sv.data(), peer_key_sv.size());
          if (tls_certificate) {
            peer->set_tls_certificate(*tls_certificate);
          }
        });
      }

      auto removePeer(interface::types::PublicKeyHexStringView public_key)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_remove_peer();
          std::string_view const &public_key_string{public_key};
          command->set_public_key(public_key_string.data(),
                                  public_key_string.size());
        });
      }

      auto addSignatory(const interface::types::AccountIdType &account_id,
                        interface::types::PublicKeyHexStringView public_key)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_add_signatory();
          command->set_account_id(account_id);
          const std::string_view &public_key_sv = public_key;
          command->set_public_key(public_key_sv.data(), public_key_sv.size());
        });
      }

      auto removeSignatory(const interface::types::AccountIdType &account_id,
                           interface::types::PublicKeyHexStringView public_key)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_remove_signatory();
          command->set_account_id(account_id);
          const std::string_view public_key_sv = public_key;
          command->set_public_key(public_key_sv.data(), public_key_sv.size());
        });
      }

      auto callEngine(
          const interface::types::AccountIdType &caller,
          std::optional<interface::types::EvmCalleeHexStringView> callee,
          interface::types::EvmCodeHexStringView input) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_call_engine();
          command->set_type(iroha::protocol::CallEngine::EngineType::
                                CallEngine_EngineType_kSolidity);
          command->set_caller(caller);
          if (callee) {
            const auto callee_sv =
                static_cast<std::string_view const &>(callee.value());
            command->set_callee(callee_sv.data(), callee_sv.size());
          }
          const auto input_sv = static_cast<std::string_view const &>(input);
          command->set_input(input_sv.data(), input_sv.size());
        });
      }

      auto appendRole(const interface::types::AccountIdType &account_id,
                      const interface::types::RoleIdType &role_name) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_append_role();
          command->set_account_id(account_id);
          command->set_role_name(role_name);
        });
      }

      auto createAsset(const interface::types::AssetNameType &asset_name,
                       const interface::types::DomainIdType &domain_id,
                       interface::types::PrecisionType precision) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_create_asset();
          command->set_asset_name(asset_name);
          command->set_domain_id(domain_id);
          command->set_precision(precision);
        });
      }

      auto createAccount(const interface::types::AccountNameType &account_name,
                         const interface::types::DomainIdType &domain_id,
                         interface::types::PublicKeyHexStringView main_pubkey)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_create_account();
          command->set_account_name(account_name);
          command->set_domain_id(domain_id);
          std::string_view main_pubkey_sv{main_pubkey};
          command->set_public_key(main_pubkey_sv.data(), main_pubkey_sv.size());
        });
      }

      auto createDomain(const interface::types::DomainIdType &domain_id,
                        const interface::types::RoleIdType &default_role)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_create_domain();
          command->set_domain_id(domain_id);
          command->set_default_role(default_role);
        });
      }

      auto createRole(const interface::types::RoleIdType &role_name,
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

      auto detachRole(const interface::types::AccountIdType &account_id,
                      const interface::types::RoleIdType &role_name) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_detach_role();
          command->set_account_id(account_id);
          command->set_role_name(role_name);
        });
      }

      auto grantPermission(const interface::types::AccountIdType &account_id,
                           interface::permissions::Grantable permission) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_grant_permission();
          command->set_account_id(account_id);
          command->set_permission(permissions::toTransport(permission));
        });
      }

      auto revokePermission(const interface::types::AccountIdType &account_id,
                            interface::permissions::Grantable permission)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_revoke_permission();
          command->set_account_id(account_id);
          command->set_permission(permissions::toTransport(permission));
        });
      }

      auto setAccountDetail(
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

      auto setAccountQuorum(const interface::types::AddressType &account_id,
                            interface::types::QuorumType quorum) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_set_account_quorum();
          command->set_account_id(account_id);
          command->set_quorum(quorum);
        });
      }

      auto subtractAssetQuantity(const interface::types::AssetIdType &asset_id,
                                 const std::string &amount) const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_subtract_asset_quantity();
          command->set_asset_id(asset_id);
          command->set_amount(amount);
        });
      }

      auto transferAsset(const interface::types::AccountIdType &src_account_id,
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

      auto setSettingValue(const interface::types::SettingKeyType &key,
                           const interface::types::SettingValueType &value)
          const {
        return addCommand([&](auto proto_command) {
          auto command = proto_command->mutable_set_setting_value();
          command->set_key(key);
          command->set_value(value);
        });
      }

      auto build() const {
        static_assert(S == (1 << TOTAL) - 1, "Required fields are not set");
        auto result = Transaction(iroha::protocol::Transaction(transaction_));
        if (auto error = stateless_validator_.validate(result)) {
          throw std::invalid_argument(error->toString());
        }
        return BT(std::move(result));
      }

      static const int total = RequiredFields::TOTAL;

     private:
      ProtoTx transaction_;
      SV stateless_validator_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSACTION_BUILDER_TEMPLATE_HPP
