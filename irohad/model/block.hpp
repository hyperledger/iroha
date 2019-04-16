/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_HPP
#define IROHA_BLOCK_HPP

#include <vector>

#include "crypto/hash_types.hpp"
#include "model/proposal.hpp"
#include "model/signature.hpp"
#include "model/transaction.hpp"

namespace iroha {
  namespace model {

    /**
     * Block is Model-structure, that provides all block-related information
     * Block can be divided into payload which contains all the data
     * and signatures of this data.
     */
    struct Block {
      /**
       * Calculated as hash(PAYLOAD field)
       * NOT a part of payload
       */
      hash256_t hash{};

      using HashType = decltype(hash);

      /**
       * List of signatures for signing the block
       * NOT a part of PAYLOAD
       */
      std::vector<Signature> sigs;

      using SignaturesType = decltype(sigs);

      /**
       * Timestamp of block creation(signing)
       * part of PAYLOAD
       */
      ts64_t created_ts{};

      /**
       * Block number in the ledger
       * Height can be used as block_id
       * part of PAYLOAD
       */
      uint64_t height{};

      using BlockHeightType = decltype(height);

      /**
       * Hash of a previous block in the ledger
       * part of PAYLOAD
       */
      hash256_t prev_hash{};

      /**
       * Number of transactions in block body
       * part of PAYLOAD
       */
      uint16_t txs_number{};

      /**
       * Attached transactions
       * part of PAYLOAD
       */
      std::vector<Transaction> transactions;

      using TransactionsType = decltype(transactions);

      /**
       * Attached rejected transactions' hashes
       * part of PAYLOAD
       */
      std::vector<HashType> rejected_transactions_hashes;

      using RejectedTransactionsType = decltype(rejected_transactions_hashes);

      bool operator==(const Block &rhs) const;
      bool operator!=(const Block &rhs) const;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_BLOCK_HPP
