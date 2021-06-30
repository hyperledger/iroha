/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_INDEX_HPP
#define IROHA_POSTGRES_BLOCK_INDEX_HPP

#include "ametsuchi/impl/block_index.hpp"
//#include "ametsuchi/indexer.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger_fwd.hpp"

namespace soci {
  class session;
}

namespace iroha::ametsuchi {
  /**
   * Creates several indices for passed blocks. Namely:
   * transaction hash -> block, where this transaction is stored
   * transaction creator -> block where his transaction is located
   *
   * Additionally, for each Transfer Asset command:
   *   1. (account, asset) -> block for each:
   *     a. creator of the transaction
   *     b. source account
   *     c. destination account
   *   2. account -> block for source and destination accounts
   *   3. (account, height) -> list of txes
   */
  class PostgresBlockIndex : public BlockIndex {
   public:
    PostgresBlockIndex(//std::unique_ptr<Indexer> indexer,
    soci::session &sql,
                       logger::LoggerPtr log);

    /// Index a block.
    void index(const shared_model::interface::Block &block,
               bool do_flush = true) override;

    iroha::expected::Result<void, std::string> flush() override;

   private:
    /// Position of a transaction in the ledger.
    struct TxPosition {
      shared_model::interface::types::HeightType
          height;    ///< the height of block containing this transaction
      size_t index;  ///< the number of this transaction in the block
    };
    
    /// Index a transaction.
    void makeAccountAssetIndex(
        const shared_model::interface::types::AccountIdType &account_id,
        shared_model::interface::types::HashType const &hash,
        shared_model::interface::types::TimestampType const ts,
        TxPosition position,
        const shared_model::interface::Transaction::CommandsType &commands);

    soci::session &sql_;
    logger::LoggerPtr log_;

    void committedTxHash(const shared_model::interface::types::HashType
                             &committed_tx_hash);

    void rejectedTxHash(const shared_model::interface::types::HashType
                            &rejected_tx_hash);

    void txPositions(
        shared_model::interface::types::AccountIdType const &account,
        shared_model::interface::types::HashType const &hash,
        boost::optional<shared_model::interface::types::AssetIdType>
            &&asset_id,
        shared_model::interface::types::TimestampType const ts,
        TxPosition const &position);

    struct {
      std::vector<std::string> hash;
      std::vector<std::string> status;
    } tx_hash_status_;

    struct {
      std::vector<shared_model::interface::types::AccountIdType> account;
      std::vector<std::string> hash;
      std::vector<
          boost::optional<shared_model::interface::types::AssetIdType>>
          asset_id;
      std::vector<shared_model::interface::types::TimestampType> ts;
      std::vector<size_t> height;
      std::vector<size_t> index;
    } tx_positions_;

    /// Index tx status by its hash.
    void txHashStatus(const shared_model::interface::types::HashType &tx_hash,
                      bool is_committed);

  };
}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_BLOCK_INDEX_HPP
