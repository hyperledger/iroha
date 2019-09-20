/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/batch_helper.hpp"

using namespace framework;
using namespace framework::batch;
using namespace framework::batch::internal;

template <typename TransactionBuilderType = TestTransactionBuilder>
TransactionBuilderType framework::batch::prepareTransactionBuilder(
    const std::string &creator,
    const size_t &created_time,
    const shared_model::interface::types::QuorumType &quorum) {
  return TransactionBuilderType()
      .setAccountQuorum(creator, 1)
      .creatorAccountId(creator)
      .createdTime(created_time)
      .quorum(quorum);
}

TestUnsignedTransactionBuilder
framework::batch::prepareUnsignedTransactionBuilder(
    const std::string &creator,
    const size_t &created_time,
    const shared_model::interface::types::QuorumType &quorum) {
  return prepareTransactionBuilder<TestUnsignedTransactionBuilder>(
      creator, created_time, quorum);
}

shared_model::interface::types::SharedTxsCollectionType
framework::batch::createUnsignedBatchTransactions(
    std::vector<std::pair<shared_model::interface::types::BatchType,
                          std::string>> btype_creator_pairs,
    size_t now) {
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

shared_model::interface::types::SharedTxsCollectionType
framework::batch::createBatchOneSignTransactions(
    std::vector<std::pair<shared_model::interface::types::BatchType,
                          std::string>> btype_creator_pairs,
    size_t now,
    const shared_model::interface::types::QuorumType &quorum) {
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
                            shared_model::crypto::DefaultCryptoAlgorithmType::
                                generateKeypair())
                        .finish());
              });
  return txs;
}

shared_model::interface::types::SharedTxsCollectionType
framework::batch::createBatchOneSignTransactions(
    const shared_model::interface::types::BatchType batch_type,
    std::vector<shared_model::interface::types::AccountIdType>
        transactions_creators,
    size_t now,
    const shared_model::interface::types::QuorumType &quorum) {
  std::vector<std::pair<shared_model::interface::types::BatchType,
                        shared_model::interface::types::AccountIdType>>
      batch_types_and_creators;
  for (const auto &creator : transactions_creators) {
    batch_types_and_creators.emplace_back(batch_type, creator);
  }
  return createBatchOneSignTransactions(batch_types_and_creators, now, quorum);
}

shared_model::interface::types::SharedTxsCollectionType
framework::batch::createUnsignedBatchTransactions(
    shared_model::interface::types::BatchType batch_type,
    const std::vector<std::string> &creators,
    size_t now) {
  std::vector<std::pair<decltype(batch_type), std::string>> fields;
  std::transform(creators.begin(),
                 creators.end(),
                 std::back_inserter(fields),
                 [&batch_type](const auto creator) {
                   return std::make_pair(batch_type, creator);
                 });
  return createUnsignedBatchTransactions(fields, now);
}

shared_model::interface::types::SharedTxsCollectionType
framework::batch::createUnsignedBatchTransactions(
    shared_model::interface::types::BatchType batch_type,
    uint32_t batch_size,
    size_t now) {
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

std::unique_ptr<shared_model::interface::TransactionBatch>
framework::batch::createValidBatch(const size_t &size,
                                   const size_t &created_time) {
  using namespace shared_model::validation;

  auto batch_type = shared_model::interface::types::BatchType::ATOMIC;
  std::vector<std::pair<decltype(batch_type), std::string>> transaction_fields;
  for (size_t i = 0; i < size; ++i) {
    transaction_fields.push_back(
        std::make_pair(batch_type, "account" + std::to_string(i) + "@domain"));
  }

  auto batch_validator =
      std::make_shared<shared_model::validation::BatchValidator>(
          iroha::test::kTestsValidatorsConfig);
  std::shared_ptr<shared_model::interface::TransactionBatchFactory>
      batch_factory = std::make_shared<
          shared_model::interface::TransactionBatchFactoryImpl>(
          batch_validator);
  auto txs = createBatchOneSignTransactions(transaction_fields, created_time);
  auto result_batch = batch_factory->createTransactionBatch(txs);

  return framework::expected::val(result_batch).value().value;
}

std::shared_ptr<shared_model::interface::TransactionBatch>
framework::batch::createBatchFromSingleTransaction(
    std::shared_ptr<shared_model::interface::Transaction> tx) {
  auto batch_validator =
      std::make_shared<shared_model::validation::BatchValidator>(
          iroha::test::kTestsValidatorsConfig);
  auto batch_factory =
      std::make_shared<shared_model::interface::TransactionBatchFactoryImpl>(
          batch_validator);
  return batch_factory->createTransactionBatch(std::move(tx))
      .match(
          [](auto &&value)
              -> std::shared_ptr<shared_model::interface::TransactionBatch> {
            return std::move(value.value);
          },
          [](const auto &err)
              -> std::shared_ptr<shared_model::interface::TransactionBatch> {
            throw std::runtime_error(
                err.error + "Error transformation from transaction to batch");
          });
}

HashesType framework::batch::internal::fetchReducedHashes() {
  return HashesType{};
}

shared_model::interface::types::SharedTxsCollectionType
framework::batch::internal::makeTxBatchCollection(const BatchMeta &) {
  return shared_model::interface::types::SharedTxsCollectionType();
}
