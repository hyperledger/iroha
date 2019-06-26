/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_QUERY_FACTORY_HPP
#define IROHA_MOCK_QUERY_FACTORY_HPP

#include "module/shared_model/query_mocks.hpp"

namespace shared_model {
  namespace interface {
    class MockQueryFactory {
      template <typename T>
      using FactoryResult = std::unique_ptr<T>;

     public:
      FactoryResult<MockAssetPaginationMeta> constructAssetPaginationMeta(
          types::TransactionsNumberType page_size,
          boost::optional<types::AssetIdType> first_asset_id) const;

      FactoryResult<MockGetAccountAssets> constructGetAccountAssets(
          const types::AccountIdType &account_id,
          boost::optional<const interface::AssetPaginationMeta &>
              pagination_meta) const;

      FactoryResult<MockGetAccountAssetTransactions>
      constructGetAccountAssetTransactions(
          const types::AccountIdType &account_id,
          const types::AccountIdType &asset_id,
          const TxPaginationMeta &pagination_meta) const;

      FactoryResult<MockGetAccountDetail> constructGetAccountDetail(
          const types::AccountIdType &account_id,
          boost::optional<types::AccountDetailKeyType> key,
          boost::optional<types::AccountIdType> writer,
          boost::optional<const AccountDetailPaginationMeta &> pagination_meta)
          const;

      FactoryResult<MockGetAccount> constructGetAccount(
          const types::AccountIdType &account_id) const;

      FactoryResult<MockGetAccountTransactions> constructGetAccountTransactions(
          const types::AccountIdType &account_id,
          const TxPaginationMeta &pagination_meta) const;

      FactoryResult<MockGetAssetInfo> constructGetAssetInfo(
          const types::AssetIdType &asset_id) const;

      FactoryResult<MockGetBlock> constructGetBlock(
          types::HeightType height) const;

      FactoryResult<MockGetRolePermissions> constructGetRolePermissions(
          const types::RoleIdType &role_id) const;

      FactoryResult<MockGetSignatories> constructGetSignatories(
          const types::AccountIdType &account_id) const;

      FactoryResult<MockGetTransactions> constructGetTransactions(
          const GetTransactions::TransactionHashesType &transaction_hashes)
          const;

      FactoryResult<MockTxPaginationMeta> constructTxPaginationMeta(
          types::TransactionsNumberType page_size,
          boost::optional<types::HashType> first_tx_hash) const;

     private:
      /**
       * Create the mock object and apply expectations setter on it
       * @tparam QueryMock - mock object type to instantiate
       * @tparam ExpectationsSetter - type of callable that sets expectations
       * for the mock object
       * @param expectations_setter - the callable that sets expectations
       * @return factory result for the requested mock type
       */
      template <typename QueryMock, typename ExpectationsSetter>
      FactoryResult<QueryMock> createFactoryResult(
          const ExpectationsSetter &expectations_setter) const;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_MOCK_QUERY_FACTORY_HPP
