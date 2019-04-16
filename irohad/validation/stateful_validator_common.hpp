/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STATEFUL_VALIDATOR_COMMON_HPP
#define IROHA_STATEFUL_VALIDATOR_COMMON_HPP

#include <memory>
#include <utility>
#include <vector>

#include <unordered_map>

#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;
  }
}  // namespace shared_model

namespace iroha {
  namespace validation {

    /// Type of command error report which appeared during validation
    /// process; contains name of command, command error itself and
    /// the command index in the transaction.
    struct CommandError {
      /// Name of the failed command
      std::string name;

      /// Error code, with which the command failed
      uint32_t error_code;

      /// Extra information about error for developers to be placed into the log
      std::string error_extra;

      /// Shows, if transaction has passed initial validation
      bool tx_passed_initial_validation;

      /// Position of the failed command in transaction
      size_t index = 0;
    };

    /// Hash of transaction with error, which appeared during validation of this
    /// transaction
    struct TransactionError {
      shared_model::crypto::Hash tx_hash;
      CommandError error;
    };

    /// Collection of transactions errors
    using TransactionsErrors = std::vector<TransactionError>;

    /// Type of verified proposal and errors appeared in the process
    // TODO [IR-1849] mboldyrev 27.10.2018: create a special class
    // for VerifiedProposal which will include the rejected tx hashes
    struct VerifiedProposalAndErrors {
      std::shared_ptr<const shared_model::interface::Proposal>
          verified_proposal;
      TransactionsErrors rejected_transactions;
    };

  }  // namespace validation
}  // namespace iroha

#endif  // IROHA_STATEFUL_VALIDATOR_COMMON_HPP
