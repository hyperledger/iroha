/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRANSACTION_HPP
#define IROHA_SHARED_MODEL_TRANSACTION_HPP

#include "common/cloneable.hpp"
#include "interfaces/base/signable.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class BatchMeta;
    class Command;

    /**
     * Transaction class represent well-formed intent from client to change
     * state of ledger.
     */
    class Transaction : public Signable<Transaction>,
                        public Cloneable<Transaction> {
     public:
      /**
       * @return creator of transaction
       */
      virtual const types::AccountIdType &creatorAccountId() const = 0;

      /**
       * @return quorum of transaction
       */
      virtual types::QuorumType quorum() const = 0;

      /// Type of ordered collection of commands
      using CommandsType = boost::any_range<Command,
                                            boost::random_access_traversal_tag,
                                            const Command &>;

      /**
       * @return attached commands
       */
      virtual CommandsType commands() const = 0;

      /**
       * @return object payload (everything except signatures)
       */
      virtual const types::BlobType &reducedPayload() const = 0;

      // TODO [IR-1874] Akvinikym 16.11.18: rename the field
      /**
       * @return hash of reduced payload
       */
      virtual const types::HashType &reducedHash() const = 0;

      virtual void storeBatchHash(types::HashType const &hash) = 0;
      virtual std::optional<types::HashType> const &getBatchHash() const = 0;

      /**
       * @return new Transaction obeject with moved data
       */
      virtual std::unique_ptr<Transaction> moveTo() = 0;

      /*
       * @return Batch Meta if exists
       */
      virtual std::optional<std::shared_ptr<BatchMeta>> batchMeta() const = 0;

      std::string toString() const override;
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_TRANSACTION_HPP
