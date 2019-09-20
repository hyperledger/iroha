/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP

#include "interfaces/transaction.hpp"

namespace iroha {
  namespace protocol {
    class Transaction;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class Transaction final : public interface::Transaction {
     public:
      using TransportType = iroha::protocol::Transaction;

      explicit Transaction(const TransportType &transaction);

      explicit Transaction(TransportType &&transaction);

      explicit Transaction(TransportType &transaction);

      Transaction(const Transaction &transaction);

      Transaction(Transaction &&o) noexcept;

      ~Transaction() override;

      const interface::types::AccountIdType &creatorAccountId() const override;

      Transaction::CommandsType commands() const override;

      const interface::types::BlobType &blob() const override;

      const interface::types::BlobType &payload() const override;

      const interface::types::BlobType &reducedPayload() const override;

      interface::types::SignatureRangeType signatures() const override;

      const interface::types::HashType &reducedHash() const override;

      bool addSignature(const crypto::Signed &signed_blob,
                        const crypto::PublicKey &public_key) override;

      const interface::types::HashType &hash() const override;

      const TransportType &getTransport() const;

      interface::types::TimestampType createdTime() const override;

      interface::types::QuorumType quorum() const override;

      boost::optional<std::shared_ptr<interface::BatchMeta>> batchMeta()
          const override;

     protected:
      Transaction::ModelType *clone() const override;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP
