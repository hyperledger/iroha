/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_OBJECTS_FACTORY_HPP
#define IROHA_COMMON_OBJECTS_FACTORY_HPP

#include <memory>

#include "common/result.hpp"
#include "interfaces/common_objects/account.hpp"
#include "interfaces/common_objects/account_asset.hpp"
#include "interfaces/common_objects/asset.hpp"
#include "interfaces/common_objects/domain.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/signature.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * CommonObjectsFactory provides methods to construct common objects
     * such as peer, account etc.
     */
    class CommonObjectsFactory {
     public:
      template <typename T>
      using FactoryResult = iroha::expected::Result<T, std::string>;

      /**
       * Create peer instance
       */
      virtual FactoryResult<std::unique_ptr<Peer>> createPeer(
          const types::AddressType &address,
          types::PublicKeyHexStringView public_key,
          const std::optional<types::TLSCertificateType> &tls_certificate =
              std::nullopt) = 0;

      /**
       * Create account instance
       */
      virtual FactoryResult<std::unique_ptr<Account>> createAccount(
          const types::AccountIdType &account_id,
          const types::DomainIdType &domain_id,
          types::QuorumType quorum,
          const types::JsonType &jsonData) = 0;

      /**
       * Create account asset instance
       */
      virtual FactoryResult<std::unique_ptr<AccountAsset>> createAccountAsset(
          const types::AccountIdType &account_id,
          const types::AssetIdType &asset_id,
          const Amount &balance) = 0;

      /**
       * Create asset instance
       */
      virtual FactoryResult<std::unique_ptr<Asset>> createAsset(
          const types::AssetIdType &asset_id,
          const types::DomainIdType &domain_id,
          types::PrecisionType precision) = 0;

      /**
       * Create domain instance
       */
      virtual FactoryResult<std::unique_ptr<Domain>> createDomain(
          const types::DomainIdType &domain_id,
          const types::RoleIdType &default_role) = 0;

      /**
       * Create signature instance
       */
      virtual FactoryResult<std::unique_ptr<Signature>> createSignature(
          types::PublicKeyHexStringView key,
          types::SignedHexStringView signed_data) = 0;

      virtual ~CommonObjectsFactory() = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_COMMONOBJECTSFACTORY_HPP
