/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_BATCH_IMPL_HPP
#define IROHA_TRANSACTION_BATCH_IMPL_HPP

#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace shared_model {
  namespace interface {

    class TransactionBatchImpl : public TransactionBatch {
     public:
      explicit TransactionBatchImpl(
          types::SharedTxsCollectionType transactions);

      TransactionBatchImpl(TransactionBatchImpl &&) = default;
      TransactionBatchImpl &operator=(TransactionBatchImpl &&) = default;

      const types::SharedTxsCollectionType &transactions() const override;

      const types::HashType &reducedHash() const override;

      bool hasAllSignatures() const override;

      bool operator==(const TransactionBatch &rhs) const override;

      std::string toString() const override;

      bool addSignature(
          size_t number_of_tx,
          const shared_model::crypto::Signed &signed_blob,
          const shared_model::crypto::PublicKey &public_key) override;

     protected:
      TransactionBatch *clone() const override;

     private:
      types::SharedTxsCollectionType transactions_;

      types::HashType reduced_hash_;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_IMPL_HPP
