/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validation/impl/stateful_validator_impl.hpp"

#include <string>

#include <boost/algorithm/cxx11/all_of.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "common/result.hpp"
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace validation {

    /**
     * Complements initial transaction check with command-by-command check
     * @param temporary_wsv to apply commands on
     * @param transactions_errors_log to write errors to
     * @param tx to be checked
     * @return empty result, if check is successful, command error otherwise
     */
    static bool checkTransactions(
        ametsuchi::TemporaryWsv &temporary_wsv,
        validation::TransactionsErrors &transactions_errors_log,
        const shared_model::interface::Transaction &tx) {
      return temporary_wsv.apply(tx).match(
          [](const auto &) { return true; },
          [&tx, &transactions_errors_log](auto &&error) {
            transactions_errors_log.emplace_back(validation::TransactionError{
                tx.hash(), std::move(error.error)});
            return false;
          });
    };

    /**
     * Validate all transactions supplied; includes special rules, such as batch
     * validation etc
     * @param txs to be validated
     * @param temporary_wsv to apply transactions on
     * @param transactions_errors_log to write errors to
     * @param batch_parser to parse batches from transaction range
     * @return range of transactions, which passed stateful validation
     */
    static auto validateTransactions(
        const shared_model::interface::types::TransactionsCollectionType &txs,
        ametsuchi::TemporaryWsv &temporary_wsv,
        validation::TransactionsErrors &transactions_errors_log,
        const shared_model::interface::TransactionBatchParser &batch_parser) {
      std::vector<bool> validation_results;
      validation_results.reserve(boost::size(txs));

      for (auto batch : batch_parser.parseBatches(txs)) {
        auto validation = [&](auto &tx) {
          return checkTransactions(temporary_wsv, transactions_errors_log, tx);
        };
        if (batch.front().batchMeta()
            and batch.front().batchMeta()->get()->type()
                == shared_model::interface::types::BatchType::ATOMIC) {
          // check all batch's transactions for validness
          auto savepoint = temporary_wsv.createSavepoint(
              "batch_" + batch.front().hash().hex());
          bool validation_result = false;

          if (boost::algorithm::all_of(batch, validation)) {
            // batch is successful; release savepoint
            validation_result = true;
            savepoint->release();
          } else {
            auto failed_tx_hash = transactions_errors_log.back().tx_hash;
            for (const auto &tx : batch) {
              if (tx.hash() != failed_tx_hash) {
                transactions_errors_log.emplace_back(
                    validation::TransactionError{
                        tx.hash(),
                        // TODO igor-egorov 22.01.2019 IR-245 add a separate
                        // error code for failed batch case
                        validation::CommandError{
                            "",
                            1,  // internal error code
                            "Another transaction failed the batch",
                            true,
                            std::numeric_limits<size_t>::max()}});
              }
            }
          }

          validation_results.insert(
              validation_results.end(), boost::size(batch), validation_result);
        } else {
          for (const auto &tx : batch) {
            validation_results.push_back(validation(tx));
          }
        }
      }

      return txs | boost::adaptors::indexed()
          | boost::adaptors::filtered(
                 [validation_results =
                      std::move(validation_results)](const auto &el) {
                   return validation_results.at(el.index());
                 })
          | boost::adaptors::transformed(
                 [](const auto &el) -> decltype(auto) { return el.value(); });
    }

    StatefulValidatorImpl::StatefulValidatorImpl(
        std::unique_ptr<shared_model::interface::UnsafeProposalFactory> factory,
        std::shared_ptr<shared_model::interface::TransactionBatchParser>
            batch_parser,
        logger::LoggerPtr log)
        : factory_(std::move(factory)),
          batch_parser_(std::move(batch_parser)),
          log_(std::move(log)) {}

    std::unique_ptr<validation::VerifiedProposalAndErrors>
    StatefulValidatorImpl::validate(
        const shared_model::interface::Proposal &proposal,
        ametsuchi::TemporaryWsv &temporaryWsv) {
      log_->info("transactions in proposal: {}",
                 proposal.transactions().size());

      auto validation_result = std::make_unique<VerifiedProposalAndErrors>();
      auto valid_txs =
          validateTransactions(proposal.transactions(),
                               temporaryWsv,
                               validation_result->rejected_transactions,
                               *batch_parser_);

      // Since proposal came from ordering gate it was already validated.
      // All transactions are validated as well
      // This allows for unsafe construction of proposal
      validation_result->verified_proposal =
          std::const_pointer_cast<const shared_model::interface::Proposal>(
              std::shared_ptr<shared_model::interface::Proposal>(
                  factory_->unsafeCreateProposal(
                      proposal.height(), proposal.createdTime(), valid_txs)));

      log_->info("transactions in verified proposal: {}",
                 validation_result->verified_proposal->transactions().size());
      return validation_result;
    }
  }  // namespace validation
}  // namespace iroha
