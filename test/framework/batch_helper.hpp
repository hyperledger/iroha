/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BATCH_HELPER_HPP
#define IROHA_BATCH_HELPER_HPP

#include <boost/move/iterator.hpp>
#include <boost/range/irange.hpp>

#include "framework/result_fixture.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "validators/default_validator.hpp"

namespace framework {
  namespace batch {

    /**
     * Creates transaction builder with set creator
     * @tparam TransactionBuilderType type of tranasction builder
     * @return prepared transaction builder
     */
    template <typename TransactionBuilderType = TestTransactionBuilder>
    auto prepareTransactionBuilder(
        const std::string &creator,
        const size_t &created_time = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1) {
      return TransactionBuilderType()
          .setAccountQuorum(creator, 1)
          .creatorAccountId(creator)
          .createdTime(created_time)
          .quorum(quorum);
    }

    /**
     * Creates unsigned transaction builder with set creator
     * @return prepared transaction builder
     */
    auto prepareUnsignedTransactionBuilder(
        const std::string &creator,
        const size_t &created_time = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1) {
      return prepareTransactionBuilder<TestUnsignedTransactionBuilder>(
          creator, created_time, quorum);
    }

    /**
     * Create unsigned batch with given fields of transactions: batch type and
     * creator account.
     * @param btype_creator_pairs vector of pairs. First element in every pair
     * is batch type and second is creator account
     * @param now created time for every transaction
     * @return batch with the same size as size of range of pairs
     */
    auto createUnsignedBatchTransactions(
        std::vector<std::pair<shared_model::interface::types::BatchType,
                              std::string>> btype_creator_pairs,
        size_t now = iroha::time::now()) {
      std::vector<shared_model::interface::types::HashType> reduced_hashes;
      for (const auto &btype_creator : btype_creator_pairs) {
        auto tx = prepareTransactionBuilder(btype_creator.second, now).build();
        reduced_hashes.push_back(tx.reducedHash());
      }

      shared_model::interface::types::SharedTxsCollectionType txs;

      std::transform(
          btype_creator_pairs.begin(),
          btype_creator_pairs.end(),
          std::back_inserter(txs),
          [&now, &reduced_hashes](const auto &btype_creator)
              -> shared_model::interface::types::SharedTxsCollectionType::
                  value_type {
                    return clone(
                        prepareTransactionBuilder(btype_creator.second, now)
                            .batchMeta(btype_creator.first, reduced_hashes)
                            .build());
                  });
      return txs;
    }

    /**
     * Creates batch transactions, where every transaction has single signature
     * @param btype_creator_pairs vector of pairs of batch type and creator
     * account id
     * @param now created time for every transaction
     * @param quorum quorum for every transaction
     * @return batch with the same size as size of range of pairs
     */
    auto createBatchOneSignTransactions(
        std::vector<std::pair<shared_model::interface::types::BatchType,
                              std::string>> btype_creator_pairs,
        size_t now = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1) {
      std::vector<shared_model::interface::types::HashType> reduced_hashes;
      for (const auto &btype_creator : btype_creator_pairs) {
        auto tx =
            prepareUnsignedTransactionBuilder(btype_creator.second, now, quorum)
                .build();
        reduced_hashes.push_back(tx.reducedHash());
      }

      shared_model::interface::types::SharedTxsCollectionType txs;

      std::transform(
          btype_creator_pairs.begin(),
          btype_creator_pairs.end(),
          std::back_inserter(txs),
          [&now, &reduced_hashes, &quorum](const auto &btype_creator)
              -> shared_model::interface::types::SharedTxsCollectionType::
                  value_type {
                    return clone(
                        prepareUnsignedTransactionBuilder(
                            btype_creator.second, now, quorum)
                            .batchMeta(btype_creator.first, reduced_hashes)
                            .build()
                            .signAndAddSignature(
                                shared_model::crypto::
                                    DefaultCryptoAlgorithmType::
                                        generateKeypair())
                            .finish());
                  });
      return txs;
    }

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
    auto createBatchOneSignTransactions(
        const shared_model::interface::types::BatchType batch_type,
        const std::vector<shared_model::interface::types::AccountIdType>
            &transactions_creators,
        size_t now = iroha::time::now(),
        const shared_model::interface::types::QuorumType &quorum = 1) {
      std::vector<std::pair<shared_model::interface::types::BatchType,
                            shared_model::interface::types::AccountIdType>>
          batch_types_and_creators;
      batch_types_and_creators.reserve(transactions_creators.size());
      for (const auto &creator : transactions_creators) {
        batch_types_and_creators.emplace_back(batch_type, creator);
      }
      return createBatchOneSignTransactions(
          batch_types_and_creators, now, quorum);
    }

    /**
     * Creates atomic batch from provided creator accounts
     * @param creators vector of creator account ids
     * @return unsigned batch of the same size as the size of creator account
     * ids
     */
    auto createUnsignedBatchTransactions(
        shared_model::interface::types::BatchType batch_type,
        const std::vector<std::string> &creators,
        size_t now = iroha::time::now()) {
      std::vector<std::pair<decltype(batch_type), std::string>> fields;
      std::transform(creators.begin(),
                     creators.end(),
                     std::back_inserter(fields),
                     [&batch_type](const auto creator) {
                       return std::make_pair(batch_type, creator);
                     });
      return createUnsignedBatchTransactions(fields, now);
    }

    /**
     * Creates transaction collection for the batch of given type and size
     * @param batch_type type of the creted transactions
     * @param batch_size size of the created collection of transactions
     * @param now created time for every transactions
     * @return unsigned batch
     */
    auto createUnsignedBatchTransactions(
        shared_model::interface::types::BatchType batch_type,
        uint32_t batch_size,
        size_t now = iroha::time::now()) {
      auto range = boost::irange(0, (int)batch_size);
      std::vector<std::string> creators;

      std::transform(range.begin(),
                     range.end(),
                     std::back_inserter(creators),
                     [](const auto &id) {
                       return std::string("account") + std::to_string(id)
                           + "@domain";
                     });

      return createUnsignedBatchTransactions(batch_type, creators, now);
    }

    /**
     * Creates a batch of expected size
     * @param size - number of transactions in the batch
     * @param created_time - time of batch creation
     * @return valid batch
     */
    auto createValidBatch(const size_t &size,
                          const size_t &created_time = iroha::time::now()) {
      using namespace shared_model::validation;

      auto batch_type = shared_model::interface::types::BatchType::ATOMIC;
      std::vector<std::pair<decltype(batch_type), std::string>>
          transaction_fields;
      transaction_fields.reserve(size);
      for (size_t i = 0; i < size; ++i) {
        transaction_fields.emplace_back(std::make_pair(
            batch_type, "account" + std::to_string(i) + "@domain"));
      }

      auto batch_validator =
          std::make_shared<shared_model::validation::DefaultBatchValidator>(
              iroha::test::kTestsValidatorsConfig);
      std::shared_ptr<shared_model::interface::TransactionBatchFactory>
          batch_factory = std::make_shared<
              shared_model::interface::TransactionBatchFactoryImpl>(
              batch_validator);
      auto txs =
          createBatchOneSignTransactions(transaction_fields, created_time);
      auto result_batch = batch_factory->createTransactionBatch(txs);

      return framework::expected::val(result_batch).value().value;
    }

    /**
     * Wrap a transaction with batch
     * @param tx - interested transaction
     * @return created batch or throw std::runtime_error
     */
    inline auto createBatchFromSingleTransaction(
        std::shared_ptr<shared_model::interface::Transaction> tx) {
      auto batch_validator =
          std::make_shared<shared_model::validation::DefaultBatchValidator>(
              iroha::test::kTestsValidatorsConfig);
      auto batch_factory = std::make_shared<
          shared_model::interface::TransactionBatchFactoryImpl>(
          batch_validator);
      return batch_factory->createTransactionBatch(std::move(tx))
          .match(
              [](auto &&value) -> std::shared_ptr<
                                   shared_model::interface::TransactionBatch> {
                return std::move(value.value);
              },
              [](const auto &err)
                  -> std::shared_ptr<
                      shared_model::interface::TransactionBatch> {
                throw std::runtime_error(
                    err.error
                    + "Error transformation from transaction to batch");
              });
    }

    /**
     * Namespace provides useful functions which are related to implementation
     * but they are internal API
     */
    namespace internal {

      using HashesType = std::vector<shared_model::interface::types::HashType>;

      /**
       * Struct containing batch meta information: Type of the batch and reduced
       * hash
       */
      struct BatchMeta {
        HashesType reduced_hashes;
        shared_model::interface::types::BatchType batch_type;
      };

      template <typename TxBuilder>
      auto fetchReducedHashes(const TxBuilder &builder) {
        return HashesType{builder.build().reducedHash()};
      }

      auto fetchReducedHashes() {
        return HashesType{};
      }

      template <typename FirstTxBuilder, typename... RestTxBuilders>
      auto fetchReducedHashes(const FirstTxBuilder &first,
                              const RestTxBuilders &... rest) {
        auto first_vector = fetchReducedHashes(first);
        auto rest_vector = fetchReducedHashes(rest...);
        std::copy(rest_vector.begin(),
                  rest_vector.end(),
                  boost::back_move_inserter(first_vector));
        return first_vector;
      }

      auto makeTxBatchCollection(const BatchMeta &) {
        return shared_model::interface::types::SharedTxsCollectionType();
      }

      /**
       * Creates a vector containing single signed transaction
       * @tparam TxBuilder is any builder which creates
       * UnsignedWrapper<Transaction>
       * @param reduced_hashes are the reduced hashes of the batch containing
       * that transaction
       * @param builder is builder with set information about the transaction
       * @return vector containing single signed transaction
       *
       * NOTE: SFINAE was added to check that provided builder returns
       * UnsignedWrapper<Transaction>
       */
      template <typename TxBuilder>
      auto makeTxBatchCollection(const BatchMeta &batch_meta,
                                 TxBuilder &&builder) ->
          typename std::enable_if_t<
              std::is_same<
                  decltype(builder.build()),
                  shared_model::proto::UnsignedWrapper<ProtoTxType>>::value,
              shared_model::interface::types::SharedTxsCollectionType> {
        return shared_model::interface::types::SharedTxsCollectionType{
            completeUnsignedTxBuilder(builder.batchMeta(
                batch_meta.batch_type, batch_meta.reduced_hashes))};
      }

      /**
       * Creates a vector containing single unsigned transaction
       * @tparam TxBuilder is any builder which creates Transaction
       * @param reduced_hashes are the reduced hashes of the batch containing
       * that transaction
       * @param builder is builder with set information about the transaction
       * @return vector containing single unsigned transaction
       *
       * NOTE: SFINAE was added to check that builder returns Transaction object
       */
      template <typename TxBuilder>
      auto makeTxBatchCollection(const BatchMeta &batch_meta,
                                 TxBuilder &&builder) ->
          typename std::enable_if<
              std::is_same<decltype(builder.build()), ProtoTxType>::value,
              shared_model::interface::types::SharedTxsCollectionType>::type {
        return shared_model::interface::types::SharedTxsCollectionType{
            makePolyTxFromBuilder(builder.batchMeta(
                batch_meta.batch_type, batch_meta.reduced_hashes))};
      }

      template <typename FirstTxBuilder, typename... RestTxBuilders>
      auto makeTxBatchCollection(const BatchMeta &batch_meta,
                                 FirstTxBuilder &&first,
                                 RestTxBuilders &&... rest) {
        auto first_vector = makeTxBatchCollection(batch_meta, first);
        auto rest_vector = makeTxBatchCollection(batch_meta, rest...);
        std::copy(rest_vector.begin(),
                  rest_vector.end(),
                  boost::back_move_inserter(first_vector));
        return first_vector;
      }
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
        TxBuilders &&... builders) {
      internal::BatchMeta batch_meta;
      batch_meta.batch_type = batch_type;
      batch_meta.reduced_hashes = internal::fetchReducedHashes(builders...);

      // makes clang avoid sending warning with unused function
      // (makeTxBatchCollection)
      //      internal::makeTxBatchCollection(batch_meta);

      return internal::makeTxBatchCollection(
          batch_meta, std::forward<TxBuilders>(builders)...);
    }

    /**
     * Create test batch transactions from passed transaction builders
     * @tparam TxBuilders - variadic types of tx builders
     * @return vector of transactions
     */
    template <typename... TxBuilders>
    auto makeTestBatchTransactions(TxBuilders &&... builders) {
      return makeTestBatchTransactions(
          shared_model::interface::types::BatchType::ATOMIC,
          std::forward<TxBuilders>(builders)...);
    }

    /**
     * Create test batch from passed transaction builders
     * @tparam TxBuilders - variadic types of tx builders
     * @return shared_ptr for batch
     */
    template <typename... TxBuilders>
    auto makeTestBatch(TxBuilders &&... builders) {
      auto transactions =
          makeTestBatchTransactions(std::forward<TxBuilders>(builders)...);

      return std::make_shared<shared_model::interface::TransactionBatchImpl>(
          transactions);
    }

  }  // namespace batch
}  // namespace framework

#endif  // IROHA_BATCH_HELPER_HPP
