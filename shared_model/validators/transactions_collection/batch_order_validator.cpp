/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transactions_collection/batch_order_validator.hpp"

#include <boost/format.hpp>
#include <boost/range/algorithm/find.hpp>
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace validation {
    std::string BatchOrderValidator::canFollow(
        boost::optional<std::shared_ptr<interface::Transaction>> tr1,
        boost::optional<std::shared_ptr<interface::Transaction>> tr2) const {
      boost::optional<std::shared_ptr<interface::BatchMeta>> batch1 =
          tr1 ? tr1.value()->batchMeta() : boost::none;
      boost::optional<std::shared_ptr<interface::BatchMeta>> batch2 =
          tr2 ? tr2.value()->batchMeta() : boost::none;
      // both transactions are not a part of any batch
      if (not batch1 and not batch2) {
        return "";
      }
      // beginning of a batch
      if (not batch1) {
        if (batch2.get()->reducedHashes().size() == 0) {
          return (boost::format("Tx %s has a batch of 0 transactions")
                  % tr2.value()->hash().hex())
              .str();
        }
        if (batch2.get()->reducedHashes().front()
            != tr2.value()->reducedHash()) {
          return (boost::format("Tx %s is a first transaction of a batch, but "
                                "it's reduced hash %s doesn't match the first "
                                "reduced hash in batch %s")
                  % tr2.value()->hash().hex()
                  % batch2.get()->reducedHashes().front().hex()
                  % tr2.value()->reducedHash().hex())
              .str();
        }
        return "";
      }
      // end of a batch
      if (not batch2) {
        if (batch1.get()->reducedHashes().back()
            != tr1.value()->reducedHash()) {
          return (boost::format("Tx %s is a last transaction of a batch, but "
                                "it's reduced hash %s doesn't match the last "
                                "reduced hash in batch %s")
                  % tr1.value()->hash().hex()
                  % batch1.get()->reducedHashes().back().hex()
                  % tr1.value()->reducedHash().hex())
              .str();
        }
        return "";
      }
      // inside of a batch
      auto it1 = boost::find(batch1.get()->reducedHashes(),
                             tr1.value()->reducedHash());
      auto it2 = boost::find(batch2.get()->reducedHashes(),
                             tr2.value()->reducedHash());
      if (it1 == end(batch1.get()->reducedHashes())
          or it2 == end(batch2.get()->reducedHashes())
          or next(it1) == end(batch1.get()->reducedHashes())
          or *next(it1) != *it2) {
        // end of the bach and beginning of the next
        if (canFollow(tr1, boost::none) == ""
            and canFollow(boost::none, tr2) == "") {
          return "";
        }
        return (boost::format("Tx %s is followed by %s, but their reduced"
                              "hashed doesn't follow each other in their batch"
                              "meta")
                % tr1.value()->hash().hex() % tr2.value()->hash().hex())
            .str();
      }
      if (**batch1 != **batch2) {
        return (boost::format("Tx %s and %s are part of the same batch, but "
                              "their batch metas doesn't match")
                % tr1.value()->hash().hex() % tr2.value()->hash().hex())
            .str();
      }
      return "";
    }

    Answer BatchOrderValidator::validate(
        const interface::types::SharedTxsCollectionType &transactions) const {
      Answer res;
      ReasonsGroupType reason;
      reason.first = "Transaction order";
      boost::optional<interface::types::SharedTxsCollectionType::value_type>
          prev_transaction = boost::none;

      for (auto &transaction : transactions) {
        auto message = canFollow(prev_transaction, transaction);
        if (message != "") {
          reason.second.push_back(message);
        }
        prev_transaction = transaction;
      }
      auto message = canFollow(prev_transaction, boost::none);
      if (message != "") {
        reason.second.push_back(message);
      }
      if (not reason.second.empty()) {
        res.addReason(std::move(reason));
      }
      return res;
    }
  }  // namespace validation
}  // namespace shared_model
