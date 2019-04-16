/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PB_QUERY_RESPONSE_FACTORY_HPP
#define IROHA_PB_QUERY_RESPONSE_FACTORY_HPP

#include "model/account_asset.hpp"
#include "model/common.hpp"
#include "model/queries/responses/account_assets_response.hpp"
#include "model/queries/responses/account_detail_response.hpp"
#include "model/queries/responses/account_response.hpp"
#include "model/queries/responses/asset_response.hpp"
#include "model/queries/responses/error_response.hpp"
#include "model/queries/responses/roles_response.hpp"
#include "model/queries/responses/signatories_response.hpp"
#include "model/queries/responses/transactions_response.hpp"
#include "qry_responses.pb.h"

namespace iroha {
  namespace model {
    namespace converters {

      /**
       * Converting business objects to protobuf and vice versa
       */
      class PbQueryResponseFactory {
       public:
        boost::optional<protocol::QueryResponse> serialize(
            const std::shared_ptr<QueryResponse> query_response) const;
        optional_ptr<QueryResponse> deserialize(
            const protocol::QueryResponse &query_response) const;

        protocol::Account serializeAccount(const model::Account &account) const;
        model::Account deserializeAccount(
            const protocol::Account &pb_account) const;

        protocol::AccountResponse serializeAccountResponse(
            const model::AccountResponse &accountResponse) const;
        model::AccountResponse deserializeAccountResponse(
            const protocol::AccountResponse pb_response) const;

        protocol::AccountAsset serializeAccountAsset(
            const model::AccountAsset &account_asset) const;
        model::AccountAsset deserializeAccountAsset(
            const protocol::AccountAsset &account_asset) const;

        protocol::AccountAssetResponse serializeAccountAssetResponse(
            const model::AccountAssetResponse &accountAssetResponse) const;
        model::AccountAssetResponse deserializeAccountAssetResponse(
            const protocol::AccountAssetResponse &account_asset_response) const;

        protocol::AccountDetailResponse serializeAccountDetailResponse(
            const model::AccountDetailResponse &accountDetailResponse) const;
        model::AccountDetailResponse deserializeAccountDetailResponse(
            const protocol::AccountDetailResponse &account_detail_response)
            const;

        protocol::SignatoriesResponse serializeSignatoriesResponse(
            const model::SignatoriesResponse &signatoriesResponse) const;
        model::SignatoriesResponse deserializeSignatoriesResponse(
            const protocol::SignatoriesResponse &signatoriesResponse) const;

        protocol::TransactionsResponse serializeTransactionsResponse(
            const model::TransactionsResponse &transactionsResponse) const;
        model::TransactionsResponse deserializeTransactionsResponse(
            const protocol::TransactionsResponse &tx_response) const;

        protocol::AssetResponse serializeAssetResponse(
            const model::AssetResponse &response) const;
        model::AssetResponse deserializeAssetResponse(
            const protocol::AssetResponse &response) const;

        protocol::RolesResponse serializeRolesResponse(
            const model::RolesResponse &response) const;
        model::RolesResponse deserializeRolesResponse(
            const protocol::RolesResponse &response) const;

        protocol::RolePermissionsResponse serializeRolePermissionsResponse(
            const model::RolePermissionsResponse &response) const;
        model::RolePermissionsResponse deserializeRolePermissionsResponse(
            const protocol::RolePermissionsResponse &response) const;

        protocol::ErrorResponse serializeErrorResponse(
            const model::ErrorResponse &errorResponse) const;
        model::ErrorResponse deserializeErrorResponse(
            const protocol::ErrorResponse &response) const;
      };
    }  // namespace converters
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_PB_QUERY_RESPONSE_FACTORY_HPP
