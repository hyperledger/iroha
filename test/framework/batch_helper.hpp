/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BATCH_HELPER_HPP
#define IROHA_BATCH_HELPER_HPP

#include <memory>

#include "datetime/time.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

namespace framework {
  namespace batch {

    /**
     * Creates transaction builder with set creator
     * @tparam TransactionBuilderType type of tranasction builder
     * @return prepared transaction builder
     */
    template <typename TransactionBuilderType = TestTransactionBuilder>
    TransactionBuilderType prepareTransactionBuilder(
        const std::string &creator,
        const size_t &created_time = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1);

    /**
     * Creates unsigned transaction builder with set creator
     * @return prepared transaction builder
     */
    TestUnsignedTransactionBuilder prepareUnsignedTransactionBuilder(
        const std::string &creator,
        const size_t &created_time = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1);

    /**
     * Create unsigned batch with given fields of transactions: batch type and
     * creator account.
     * @param btype_creator_pairs vector of pairs. First element in every pair
     * is batch type and second is creator account
     * @param now created time for every transaction
     * @return batch with the same size as size of range of pairs
     */
    shared_model::interface::types::SharedTxsCollectionType
    createUnsignedBatchTransactions(
        std::vector<std::pair<shared_model::interface::types::BatchType,
                              std::string>> btype_creator_pairs,
        size_t now = iroha::time::now());

    /**
     * Creates batch transactions, where every transaction has single signature
     * @param btype_creator_pairs vector of pairs of batch type and creator
     * account id
     * @param now created time for every transaction
     * @param quorum quorum for every transaction
     * @return batch with the same size as size of range of pairs
     */
    shared_model::interface::types::SharedTxsCollectionType
    createBatchOneSignTransactions(
        std::vector<std::pair<shared_model::interface::types::BatchType,
                              std::string>> btype_creator_pairs,
        size_t now = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1);

    /**
     * Creates batch transactions, where every transaction has single signature
     * @param batch_type - the type of batch to set to all transactions batch
     * meta
     * @param transactions_creators - vector of creator account ids for batch
     * transactions
     * @param now created time for every transaction
     * @param quorum quorum for every transaction
     * @return batch with the same size as size of range of pairs
     */
    shared_model::interface::types::SharedTxsCollectionType
    createBatchOneSignTransactions(
        const shared_model::interface::types::BatchType batch_type,
        std::vector<shared_model::interface::types::AccountIdType>
            transactions_creators,
        size_t now = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1);

    /**
     * Creates atomic batch from provided creator accounts
     * @param creators vector of creator account ids
     * @return unsigned batch of the same size as the size of creator account
     * ids
     */
    shared_model::interface::types::SharedTxsCollectionType
    createUnsignedBatchTransactions(
        shared_model::interface::types::BatchType batch_type,
        const std::vector<std::string> &creators,
        size_t now = iroha::time::now());

    /**
     * Creates transaction collection for the batch of given type and size
     * @param batch_type type of the creted transactions
     * @param batch_size size of the created collection of transactions
     * @param now created time for every transactions
     * @return unsigned batch
     */
    shared_model::interface::types::SharedTxsCollectionType
    createUnsignedBatchTransactions(
        shared_model::interface::types::BatchType batch_type,
        uint32_t batch_size,
        size_t now = iroha::time::now());

    /**
     * Creates a batch of expected size
     * @param size - number of transactions in the batch
     * @param created_time - time of batch creation
     * @return valid batch
     */
    std::unique_ptr<shared_model::interface::TransactionBatch> createValidBatch(
        const size_t &size, const size_t &created_time = iroha::time::now());

    /**
     * Wrap a transaction with batch
     * @param tx - interested transaction
     * @return created batch or throw std::runtime_error
     */
    std::shared_ptr<shared_model::interface::TransactionBatch>
    createBatchFromSingleTransaction(
        std::shared_ptr<shared_model::interface::Transaction> tx);

    /**
     * Namespace provides useful functions which are related to implementation
     * but they are internal API
     */
    namespace internal {

      /**
       * Creates a vector containing single signed transaction
       * @param reduced_hashes are the reduced hashes of the batch containing
       * that transaction
       * @param builder is builder with set information about the transaction
       * @return vector containing single signed transaction
       */
      std::shared_ptr<shared_model::proto::Transaction> completeTxBuilder(
          shared_model::proto::TemplateTransactionBuilder<
              shared_model::proto::UnsignedWrapper<
                  shared_model::proto::Transaction>> builder);

      /**
       * Creates a vector containing single unsigned transaction
       * @param reduced_hashes are the reduced hashes of the batch containing
       * that transaction
       * @param builder is builder with set information about the transaction
       * @return vector containing single unsigned transaction
       */
      std::shared_ptr<shared_model::proto::Transaction> completeTxBuilder(
          shared_model::proto::TemplateTransactionBuilder<
              shared_model::proto::Transaction> builder);

    }  // namespace internal

    /**
     * Create test batch transactions from passed transaction builders with
     * provided batch meta
     * @tparam TxBuilders variadic types of tx builders
     * @param batch_type type of the batch
     * @param builders transaction builders
     * @return vector of transactions
     */
    template <typename... TxBuilders>
    auto makeTestBatchTransactions(
        shared_model::interface::types::BatchType batch_type,
        TxBuilders... builders) {
      std::vector<shared_model::interface::types::HashType> reduced_hashes;
      reduced_hashes.insert(reduced_hashes.end(),
                            {builders.build().reducedHash()...});

      shared_model::interface::types::SharedTxsCollectionType result;
      result.insert(result.end(),
                    {internal::completeTxBuilder(
                        builders.batchMeta(batch_type, reduced_hashes))...});
      return result;
    }

    /**
     * Create test batch transactions from passed transaction builders
     * @tparam TxBuilders - variadic types of tx builders
     * @return vector of transactions
     */
    template <typename... TxBuilders>
    auto makeTestBatchTransactions(TxBuilders... builders) {
      return makeTestBatchTransactions(
          shared_model::interface::types::BatchType::ATOMIC, builders...);
    }

    /**
     * Create test batch from passed transaction builders
     * @tparam TxBuilders - variadic types of tx builders
     * @return shared_ptr for batch
     */
    template <typename... TxBuilders>
    auto makeTestBatch(TxBuilders... builders) {
      auto transactions = makeTestBatchTransactions(builders...);

      return std::make_shared<shared_model::interface::TransactionBatchImpl>(
          transactions);
    }

  }  // namespace batch
}  // namespace framework

#endif  // IROHA_BATCH_HELPER_HPP
