/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROPOSAL_HPP
#define IROHA_SHARED_MODEL_PROPOSAL_HPP

#include "boost/range/adaptor/transformed.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/transaction_batch_helpers.hpp"
#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {

    class Proposal : public ModelPrimitive<Proposal> {
     public:
      /**
       * @return transactions
       */
      virtual types::TransactionsCollectionType transactions() const = 0;

      /**
       * @return the height
       */
      virtual types::HeightType height() const = 0;

      /**
       * @return created time
       */
      virtual types::TimestampType createdTime() const = 0;

      bool operator==(const Proposal &rhs) const override {
        return transactions() == rhs.transactions() and height() == rhs.height()
            and createdTime() == rhs.createdTime();
      }

      virtual const types::BlobType &blob() const = 0;

      virtual const types::HashType &hash() const = 0;

      std::string toString() const override {
        return detail::PrettyStringBuilder()
            .init("Proposal")
            .appendNamed("height", height())
            .appendNamed("transactions", transactions())
            .finalize();
      }

      static shared_model::crypto::Hash calculateHash(
          std::shared_ptr<const shared_model::interface::Proposal> prop) {
        return shared_model::interface::TransactionBatchHelpers::
            calculateReducedBatchHash(
                prop->transactions()
                | boost::adaptors::transformed(
                    [](const auto &tx) { return tx.reducedHash(); }));
      }
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROPOSAL_HPP
