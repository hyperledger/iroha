/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_COMMON_OBJECTS_FACTORY_HPP
#define IROHA_PROTO_COMMON_OBJECTS_FACTORY_HPP

#include <regex>

#include "backend/protobuf/common_objects/account.hpp"
#include "backend/protobuf/common_objects/account_asset.hpp"
#include "backend/protobuf/common_objects/asset.hpp"
#include "backend/protobuf/common_objects/domain.hpp"
#include "backend/protobuf/common_objects/peer.hpp"
#include "backend/protobuf/common_objects/signature.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "primitive.pb.h"
#include "validators/validation_error.hpp"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace proto {
    /**
     * ProtoCommonObjectsFactory constructs protobuf-based objects.
     * It performs stateless validation with provided validator
     * @tparam Validator
     */
    template <typename Validator>
    class ProtoCommonObjectsFactory : public interface::CommonObjectsFactory {
     public:
      ProtoCommonObjectsFactory(
          std::shared_ptr<validation::ValidatorsConfig> config)
          : validator_(config) {}

      FactoryResult<std::unique_ptr<interface::Peer>> createPeer(
          const interface::types::AddressType &address,
          interface::types::PublicKeyHexStringView public_key,
          const std::optional<interface::types::TLSCertificateType>
              &tls_certificate = std::nullopt) override {
        iroha::protocol::Peer peer;
        peer.set_address(address);
        std::string_view const &public_key_string{public_key};
        peer.set_peer_key(public_key_string.data(), public_key_string.size());
        if (tls_certificate) {
          peer.set_tls_certificate(*tls_certificate);
        }
        auto proto_peer = std::make_unique<Peer>(std::move(peer));

        auto error = validator_.validatePeer(*proto_peer);

        return validated<std::unique_ptr<interface::Peer>>(
            std::move(proto_peer), error);
      }

      FactoryResult<std::unique_ptr<interface::Account>> createAccount(
          const interface::types::AccountIdType &account_id,
          const interface::types::DomainIdType &domain_id,
          interface::types::QuorumType quorum,
          const interface::types::JsonType &jsonData) override {
        iroha::protocol::Account account;
        account.set_account_id(account_id);
        account.set_domain_id(domain_id);
        account.set_quorum(quorum);
        account.set_json_data(jsonData);

        auto proto_account = std::make_unique<Account>(std::move(account));

        auto error = validator_.validateAccount(*proto_account);

        return validated<std::unique_ptr<interface::Account>>(
            std::move(proto_account), error);
      }

      FactoryResult<std::unique_ptr<interface::AccountAsset>>
      createAccountAsset(const interface::types::AccountIdType &account_id,
                         const interface::types::AssetIdType &asset_id,
                         const interface::Amount &balance) override {
        iroha::protocol::AccountAsset account_asset;
        account_asset.set_account_id(account_id);
        account_asset.set_asset_id(asset_id);
        account_asset.set_balance(balance.toStringRepr());

        auto proto_account_asset =
            std::make_unique<AccountAsset>(std::move(account_asset));

        auto error = validator_.validateAccountAsset(*proto_account_asset);

        return validated<std::unique_ptr<interface::AccountAsset>>(
            std::move(proto_account_asset), error);
      }

      FactoryResult<std::unique_ptr<interface::Asset>> createAsset(
          const interface::types::AssetIdType &asset_id,
          const interface::types::DomainIdType &domain_id,
          interface::types::PrecisionType precision) override {
        iroha::protocol::Asset asset;
        asset.set_asset_id(asset_id);
        asset.set_domain_id(domain_id);
        asset.set_precision(precision);

        auto proto_asset = std::make_unique<Asset>(std::move(asset));

        auto error = validator_.validateAsset(*proto_asset);

        return validated<std::unique_ptr<interface::Asset>>(
            std::move(proto_asset), error);
      }

      FactoryResult<std::unique_ptr<interface::Domain>> createDomain(
          const interface::types::DomainIdType &domain_id,
          const interface::types::RoleIdType &default_role) override {
        iroha::protocol::Domain domain;
        domain.set_domain_id(domain_id);
        domain.set_default_role(default_role);

        auto proto_domain = std::make_unique<Domain>(std::move(domain));

        auto error = validator_.validateDomain(*proto_domain);

        return validated<std::unique_ptr<interface::Domain>>(
            std::move(proto_domain), error);
      }

      FactoryResult<std::unique_ptr<interface::Signature>> createSignature(
          interface::types::PublicKeyHexStringView key,
          interface::types::SignedHexStringView signed_data) override {
        iroha::protocol::Signature signature;
        std::string_view const &public_key_string{key};
        signature.set_public_key(public_key_string.data(),
                                 public_key_string.size());
        std::string_view const &signed_string{signed_data};
        signature.set_signature(signed_string.data(), signed_string.size());

        auto proto_singature =
            std::make_unique<Signature>(std::move(signature));

        auto error = validator_.validateSignatureForm(*proto_singature);

        return validated<std::unique_ptr<interface::Signature>>(
            std::move(proto_singature), error);
      }

     private:
      /**
       * Make result object.
       * @param object - validated object
       * @param error - optional error of validation result
       */
      template <typename ReturnValueType>
      FactoryResult<ReturnValueType> validated(
          ReturnValueType object,
          const std::optional<validation::ValidationError> &error) {
        if (error) {
          return error.value().toString();
        }
        return iroha::expected::makeValue(std::move(object));
      }

      Validator validator_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_COMMON_OBJECTS_FACTORY_HPP
