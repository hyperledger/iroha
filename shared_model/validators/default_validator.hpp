/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_DEFAULT_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_DEFAULT_VALIDATOR_HPP

#include "validators/block_validator.hpp"
#include "validators/blocks_query_validator.hpp"
#include "validators/field_validator.hpp"
#include "validators/proposal_validator.hpp"
#include "validators/query_validator.hpp"
#include "validators/signable_validator.hpp"
#include "validators/transaction_validator.hpp"
#include "validators/transactions_collection/batch_order_validator.hpp"
#include "validators/transactions_collection/transactions_collection_validator.hpp"

namespace shared_model {
  namespace validation {

    // -----------------------| Transaction validation |------------------------

    /**
     * Transaction validator which checks stateless validation WITHOUT
     * signatures
     */
    using DefaultUnsignedTransactionValidator =
        TransactionValidator<FieldValidator,
                             CommandValidatorVisitor<FieldValidator>>;

    /**
     * Transaction validator which checks stateless validation and signature of
     * transaction
     */
    using DefaultSignedTransactionValidator =
        SignableModelValidator<DefaultUnsignedTransactionValidator,
                               const interface::Transaction &,
                               FieldValidator>;

    /**
     * Same as DefaultSignedTransactionValidator, but checks signatures only if
     * they are present
     */
    using DefaultOptionalSignedTransactionValidator =
        SignableModelValidator<DefaultUnsignedTransactionValidator,
                               const interface::Transaction &,
                               FieldValidator,
                               false>;

    // --------------------------| Query validation |---------------------------

    /**
     * Query validator which checks stateless validation WITHOUT signatures
     */
    using DefaultUnsignedQueryValidator =
        QueryValidator<FieldValidator, QueryValidatorVisitor<FieldValidator>>;

    /**
     * Query validator which checks stateless validation including signatures
     */
    using DefaultSignedQueryValidator =
        SignableModelValidator<DefaultUnsignedQueryValidator,
                               const interface::Query &,
                               FieldValidator>;

    /**
     * Block query validator checks stateless validation WITHOUT signatures
     */
    using DefaultUnsignedBlocksQueryValidator =
        BlocksQueryValidator<FieldValidator>;

    /**
     * Block query validator which checks stateless validation including
     * signatures
     */
    using DefaultSignedBlocksQueryValidator =
        SignableModelValidator<DefaultUnsignedBlocksQueryValidator,
                               const interface::BlocksQuery &,
                               FieldValidator>;

    // ------------| Transactions collection validation |--------------

    /**
     * Transactions collection validator that checks stateless validness of
     * transactions WITHOUT signatures
     */
    using DefaultUnsignedTransactionsValidator =
        TransactionsCollectionValidator<DefaultUnsignedTransactionValidator,
                                        BatchOrderValidator,
                                        false>;

    /**
     * Transactions collection validator that checks stateless validness of
     * transactions WITHOUT signatures and allows transaction collection to be
     * empty
     */
    using DefaultUnsignedOptionalTransactionsValidator =
        TransactionsCollectionValidator<DefaultUnsignedTransactionValidator,
                                        BatchOrderValidator,
                                        true>;

    /**
     * Transactions collection validator that checks signatures and stateless
     * validness of transactions
     */
    using DefaultSignedTransactionsValidator =
        TransactionsCollectionValidator<DefaultSignedTransactionValidator,
                                        BatchOrderValidator,
                                        false>;

    using DefaultSignedTransactionsValidatorWithAllowedEmptyList =
        TransactionsCollectionValidator<DefaultSignedTransactionValidator,
                                        BatchOrderValidator,
                                        true>;

    /**
     * Proposal validator which checks stateless validation of proposal
     */
    using DefaultProposalValidator = ProposalValidator<
        FieldValidator,
        DefaultSignedTransactionsValidatorWithAllowedEmptyList>;

    /**
     * Block validator which checks blocks WITHOUT signatures. Note that it does
     * not check transactions' signatures as well
     */
    using DefaultUnsignedBlockValidator =
        BlockValidator<FieldValidator,
                       DefaultUnsignedOptionalTransactionsValidator>;

    /**
     * Block validator which checks blocks including signatures
     */
    using DefaultSignedBlockValidator =
        SignableModelValidator<DefaultUnsignedBlockValidator,
                               const interface::Block &,
                               FieldValidator>;

    using DefaultBatchValidator = BatchValidator<BatchOrderValidator>;

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_DEFAULT_VALIDATOR_HPP
