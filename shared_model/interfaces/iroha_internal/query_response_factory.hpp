/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_RESPONSE_FACTORY_HPP
#define IROHA_QUERY_RESPONSE_FACTORY_HPP

#include <memory>

#include <boost/optional.hpp>
#include "interfaces/common_objects/account.hpp"
#include "interfaces/common_objects/asset.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/query_response.hpp"

namespace shared_model {
  namespace crypto {
    class Hash;
  }
  namespace interface {
    class Block;
    class Amount;
  }  // namespace interface
}  // namespace shared_model

namespace shared_model {
  namespace interface {

    /**
     * Factory for building query responses
     */
    class QueryResponseFactory {
     public:
      virtual ~QueryResponseFactory() = default;

      /**
       * Create response for account asset query
       * @param assets to be inserted into the response
       * @param total_assets_number the number of all assets as opposed to the
       * page size
       * @param next_asset_id if there are more assets ofter the provided ones,
       * this specifies the id of the first following asset; otherwise none
       * @param query_hash - hash of the query, for which response is created
       * @return account asset response
       */
      virtual std::unique_ptr<QueryResponse> createAccountAssetResponse(
          std::vector<std::tuple<types::AccountIdType,
                                 types::AssetIdType,
                                 shared_model::interface::Amount>> assets,
          size_t total_assets_number,
          boost::optional<shared_model::interface::types::AssetIdType>
              next_asset_id,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for account detail query
       * @param account_detail to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return account detail response
       */
      virtual std::unique_ptr<QueryResponse> createAccountDetailResponse(
          types::DetailType account_detail,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for account query
       * @param account_id of account to be inserted into the response
       * @param domain_id of account to be inserted into the response
       * @param quorum of account to be inserted into the response
       * @param jsonData of account to be inserted into the response
       * @param roles to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return account response
       */
      virtual std::unique_ptr<QueryResponse> createAccountResponse(
          interface::types::AccountIdType account_id,
          interface::types::DomainIdType domain_id,
          interface::types::QuorumType quorum,
          interface::types::JsonType jsonData,
          std::vector<std::string> roles,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for get block query
       * @param block to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return block response
       */
      virtual std::unique_ptr<QueryResponse> createBlockResponse(
          std::unique_ptr<Block> block,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Describes type of error to be placed inside the error query response
       */
      enum class ErrorQueryType {
        kStatelessFailed,
        kStatefulFailed,
        kNoAccount,
        kNoAccountAssets,
        kNoAccountDetail,
        kNoSignatories,
        kNotSupported,
        kNoAsset,
        kNoRoles
      };
      /**
       * Create response for failed query
       * @param error_type - type of error to be inserted into the response
       * @param error_msg - message, which is to be set in the response
       * @param error_code - stateful error code to be set in the response
       * @param query_hash - hash of the query, for which response is created
       * @return error response
       */
      virtual std::unique_ptr<QueryResponse> createErrorQueryResponse(
          ErrorQueryType error_type,
          ErrorQueryResponse::ErrorMessageType error_msg,
          ErrorQueryResponse::ErrorCodeType error_code,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for signatories query
       * @param signatories to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return signatories response
       */
      virtual std::unique_ptr<QueryResponse> createSignatoriesResponse(
          std::vector<types::PubkeyType> signatories,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for transactions query
       * @param transactions to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return transactions response
       */
      virtual std::unique_ptr<QueryResponse> createTransactionsResponse(
          std::vector<std::unique_ptr<shared_model::interface::Transaction>>
              transactions,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for transactions pagination query
       * @param transactions - list of transactions in this page
       * @param next_tx_hash - hash of the transaction after
       * the last in the page
       * @param all_transactions_size - total number of transactions
       * for this query
       * @param query_hash - hash of the query, for which response is created
       * @return transactions response
       */
      virtual std::unique_ptr<QueryResponse> createTransactionsPageResponse(
          std::vector<std::unique_ptr<shared_model::interface::Transaction>>
              transactions,
          const crypto::Hash &next_tx_hash,
          interface::types::TransactionsNumberType all_transactions_size,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for transactions pagination query without next hash
       * @param transactions - list of transactions in this page
       * @param all_transactions_size - total number of transactions
       * for this query
       * @param query_hash - hash of the query, for which response is created
       * @return transactions response
       */
      virtual std::unique_ptr<QueryResponse> createTransactionsPageResponse(
          std::vector<std::unique_ptr<shared_model::interface::Transaction>>
              transactions,
          interface::types::TransactionsNumberType all_transactions_size,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for asset query
       * @param asset_id of asset to be inserted into the response
       * @param domain_id of asset to be inserted into the response
       * @param precision of asset to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return asset response
       */
      virtual std::unique_ptr<QueryResponse> createAssetResponse(
          types::AssetIdType asset_id,
          types::DomainIdType domain_id,
          types::PrecisionType precision,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for roles query
       * @param roles to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return roles response
       */
      virtual std::unique_ptr<QueryResponse> createRolesResponse(
          std::vector<types::RoleIdType> roles,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for role permissions query
       * @param role_permissions to be inserted into the response
       * @param query_hash - hash of the query, for which response is created
       * @return role permissions response
       */
      virtual std::unique_ptr<QueryResponse> createRolePermissionsResponse(
          RolePermissionSet role_permissions,
          const crypto::Hash &query_hash) const = 0;

      /**
       * Create response for block query with block
       * @param block to be inserted into the response
       * @return block query response with block
       */
      virtual std::unique_ptr<BlockQueryResponse> createBlockQueryResponse(
          std::shared_ptr<const Block> block) const = 0;

      /**
       * Create response for block query with error
       * @param error_message to be inserted into the response
       * @return block query response with error
       */
      virtual std::unique_ptr<BlockQueryResponse> createBlockQueryResponse(
          std::string error_message) const = 0;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_QUERY_RESPONSE_FACTORY_HPP
