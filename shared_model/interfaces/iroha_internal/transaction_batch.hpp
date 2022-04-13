/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_BATCH_HPP
#define IROHA_TRANSACTION_BATCH_HPP

#include <optional>

#include "cryptography/hash.hpp"
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Represents collection of transactions, which are to be processed together
     */
    class TransactionBatch : public ModelPrimitive<TransactionBatch> {
     public:
      /**
       * Get transactions list
       * @return list of transactions from the batch
       */
      virtual const types::SharedTxsCollectionType &transactions() const = 0;

      // TODO [IR-1874] Akvinikym 16.11.18: rename the field
      /**
       * Get the concatenation of reduced hashes as a single hash
       * @param reduced_hashes collection of reduced hashes
       * @return concatenated reduced hashes
       */
      virtual const types::HashType &reducedHash() const = 0;

      /**
       * Checks if every transaction has quorum signatures
       * @return true if every transaction has quorum signatures, false
       * otherwise
       */
      virtual bool hasAllSignatures() const = 0;

      /**
       * Add signature to concrete transaction in the batch
       * @param number_of_tx - number of transaction for inserting signature
       * @param signed_blob - signed blob of transaction
       * @param public_key - public key of inserter
       * @return true if signature has been inserted
       */
      virtual bool addSignature(size_t number_of_tx,
                                types::SignedHexStringView signed_blob,
                                types::PublicKeyHexStringView public_key) = 0;

      /// Pretty print the batch contents.
      std::string toString() const;
    };

    /**
     * This is a helper structure which serves as a predicate
     * for hash comparison.
     */
    struct BatchHashEquality {
      /**
       * The function used to compare batches for equality:
       * check only hashes of batches, without signatures
       */
      bool operator()(const std::shared_ptr<TransactionBatch> &left_tx,
                      const std::shared_ptr<TransactionBatch> &right_tx) const;
    };

    struct BatchPointerHasher {
      shared_model::crypto::Hash::Hasher hasher_;
      size_t operator()(
          const std::shared_ptr<shared_model::interface::TransactionBatch> &a)
          const;
    };

    /**
     * This is a helper structure which serves as a predicate
     * for hash comparison.
     */
    struct BatchHashLess {
      /**
       * The function used to compare batches for equality:
       * check only hashes of batches, without signatures
       */
      bool operator()(const std::shared_ptr<TransactionBatch> &left_tx,
                      const std::shared_ptr<TransactionBatch> &right_tx) const;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_HPP
