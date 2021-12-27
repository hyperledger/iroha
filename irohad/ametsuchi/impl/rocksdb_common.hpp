/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_COMMON_HPP
#define IROHA_ROCKSDB_COMMON_HPP

#include <charconv>
#include <mutex>
#include <string>
#include <string_view>

#include <fmt/compile.h>
#include <fmt/format.h>
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/utilities/optimistic_transaction_db.h>
#include <rocksdb/utilities/transaction.h>
#include "ametsuchi/impl/database_cache/cache.hpp"
#include "ametsuchi/impl/executor_common.hpp"
#include "common/disable_warnings.h"
#include "common/irohad_version.hpp"
#include "common/result.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"

// clang-format off
/**
 * RocksDB data structure.
 *
 * |ROOT|-+-|STORE|-+-<height_1, value:block>
 *        |         +-<height_2, value:block>
 *        |         +-<height_3, value:block>
 *        |         +-<version>
 *        |         +-<blocks_total_count, value>
 *        |
 *        +-|WSV|-+-|NETWORK|-+-|PEERS|---+-|ADDRESS|-+-<peer_1_pubkey, value:address>
 *                |           |           |           +-<peer_2_pubkey, value:address>
 *                |           |           |
 *                |           |           +-|TLS|-+-<peer_1_pubkey, value:tls>
 *                |           |           |       +-<peer_2_pubkey, value:tls>
 *                |           |           |
 *                |           |           +-<count, value>
 *                |           |
 *                |           +-|S_PEERS|-+-|ADDRESS|-+-<peer_1_pubkey, value:address>
 *                |           |           |           +-<peer_2_pubkey, value:address>
 *                |           |           |
 *                |           |           +-|TLS|-+-<peer_1_pubkey, value:tls>
 *                |           |           |       +-<peer_2_pubkey, value:tls>
 *                |           |           |
 *                |           |           +-<count, value>
 *                |           |
 *                |           +-|STORE|-+-<top_block, value: store height#top block hash>
 *                |
 *                +-|SETTINGS|-+-<key_1, value_1>
 *                |            +-<key_2, value_2>
 *                |            +-<key_3, value_3>
 *                |
 *                +-|ROLES|-+-<role_1, value:permissions bitfield>
 *                |         +-<role_2, value:permissions bitfield>
 *                |         +-<role_3, value:permissions bitfield>
 *                |
 *                +-|TRANSACTIONS|-+-|ACCOUNTS|-+-<account_1>-+-|POSITION|-+-<height_index, value:tx_hash_1>
 *                |                |            |             |            +-<height_index, value:tx_hash_2>
 *                |                |            |             |            +-<height_index, value:tx_hash_3>
 *                |                |            |             |
 *                |                |            |             +-|TIMESTAMP|-+-<ts_1, value:tx_hash_1>
 *                |                |            |             |             +-<ts_2, value:tx_hash_2>
 *                |                |            |             |             +-<ts_3, value:tx_hash_3>
 *                |                |            |             |
 *                |                |            |             +-<tx_total_count>
 *                |                |            |
 *                |                |            +-<account_2>-+-|POSITION|-+-<height_index, value:tx_hash_4>
 *                |                |                          |            +-<height_index, value:tx_hash_5>
 *                |                |                          |            +-<height_index, value:tx_hash_6>
 *                |                |                          |
 *                |                |                          +-|TIMESTAMP|-+-<ts_1, value:tx_hash_4>
 *                |                |                          |             +-<ts_2, value:tx_hash_5>
 *                |                |                          |             +-<ts_3, value:tx_hash_6>
 *                |                |                          |
 *                |                |                          +-<tx_total_count>
 *                |                |
 *                |                +-|STATUSES|-+-<tx_hash_1, value:status_height_index>
 *                |                |            +-<tx_hash_2, value:status_height_index>
 *                |                |
 *                |                +-<tx_total_count>
 *                |
 *                +-|DOMAIN|-+-|DOMAIN_1|-+-|ASSETS|-+-<asset_1, value:precision>
 *                |          |            |          +-<asset_2, value:precision>
 *                |          |            |
 *                |          |            +-|ACCOUNTS|-|NAME_1|-+-|ASSETS|-+-<asset_1, value:quantity>
 *                |          |                                  |          +-<asset_2, value:quantity>
 *                |          |                                  |
 *                |          |                                  +-|OPTIONS|-+-<quorum>
 *                |          |                                  |           +-<asset_size>
 *                |          |                                  |           +-<total, value: count>
 *                |          |                                  |
 *                |          |                                  +-|DETAILS|-+-<writer>-<key, value>
 *                |          |                                  |
 *                |          |                                  +-|ROLES|-+-<role_1, value:flag>
 *                |          |                                  |         +-<role_2, value:flag>
 *                |          |                                  |
 *                |          |                                  +-|GRANTABLE_PER|-+-<permitee_id_1, value:permissions>
 *                |          |                                  |                 +-<permitee_id_2, value:permissions>
 *                |          |                                  |
 *                |          |                                  +-|SIGNATORIES|-+-<signatory_1>
 *                |          |                                                  +-<signatory_2>
 *                |          |
 *                |          +-<domain_1, value: default_role>
 *                |          +-<total_count, value>
 *                |
 *                +-<version>
 *
 *
 * ######################################
 * ############# LEGEND MAP #############
 * ######################################
 *
 * ######################################
 * ###   Directory   ##   Mnemonics   ###
 * ######################################
 * ### DELIMITER     ##       /       ###
 * ### ROOT          ##    <empty>    ###
 * ### STORE         ##       s       ###
 * ### WSV           ##       w       ###
 * ### NETWORK       ##       n       ###
 * ### SETTINGS      ##       i       ###
 * ### ASSETS        ##       x       ###
 * ### ROLES         ##       r       ###
 * ### TRANSACTIONS  ##       t       ###
 * ### ACCOUNTS      ##       a       ###
 * ### PEERS         ##       p       ###
 * ### S_PEERS       ##       l       ###
 * ### STATUSES      ##       u       ###
 * ### DETAILS       ##       d       ###
 * ### GRANTABLE_PER ##       g       ###
 * ### POSITION      ##       P       ###
 * ### TIMESTAMP     ##       T       ###
 * ### DOMAIN        ##       D       ###
 * ### SIGNATORIES   ##       S       ###
 * ### OPTIONS       ##       O       ###
 * ### ADDRESS       ##       M       ###
 * ### TLS           ##       N       ###
 * ######################################
 *
 * ######################################
 * ###     File      ##   Mnemonics   ###
 * ######################################
 * ### F_QUORUM      ##       q       ###
 * ### F_ASSET SIZE  ##       I       ###
 * ### F_TOP BLOCK   ##       Q       ###
 * ### F_PEERS COUNT ##       Z       ###
 * ### F_TOTAL COUNT ##       V       ###
 * ### F_VERSION     ##       v       ###
 * ######################################
 *
 * ######################################
 * ############# EXAMPLE ################
 * ######################################
 *
 * GetAccountTransactions(ACCOUNT, TS) -> KEY: wta/ACCOUNT/T/TS/
 * GetAccountAssets(DOMAIN,ACCOUNT)    -> KEY: wD/DOMAIN/a/ACCOUNT/x
 */
// clang-format on

#define RDB_DELIMITER "/"
#define RDB_XXX RDB_DELIMITER "{}" RDB_DELIMITER

#define RDB_ROOT ""
#define RDB_STORE "s"
#define RDB_WSV "w"
#define RDB_NETWORK "n"
#define RDB_SETTINGS "i"
#define RDB_ASSETS "x"
#define RDB_ROLES "r"
#define RDB_TRANSACTIONS "t"
#define RDB_ACCOUNTS "a"
#define RDB_PEERS "p"
#define RDB_S_PEERS "l"
#define RDB_STATUSES "u"
#define RDB_DETAILS "d"
#define RDB_GRANTABLE_PER "g"
#define RDB_POSITION "P"
#define RDB_TIMESTAMP "T"
#define RDB_DOMAIN "D"
#define RDB_SIGNATORIES "S"
#define RDB_OPTIONS "O"
#define RDB_ADDRESS "M"
#define RDB_TLS "N"

#define RDB_F_QUORUM "q"
#define RDB_F_ASSET_SIZE "I"
#define RDB_F_TOP_BLOCK "Q"
#define RDB_F_PEERS_COUNT "Z"
#define RDB_F_TOTAL_COUNT "V"
#define RDB_F_VERSION "v"

#define RDB_PATH_DOMAIN RDB_ROOT /**/ RDB_WSV /**/ RDB_DOMAIN /**/ RDB_XXX
#define RDB_PATH_ACCOUNT RDB_PATH_DOMAIN /**/ RDB_ACCOUNTS /**/ RDB_XXX

namespace iroha::ametsuchi::fmtstrings {
  static constexpr size_t kDelimiterSize =
      sizeof(RDB_DELIMITER) / sizeof(RDB_DELIMITER[0]) - 1ull;

  static constexpr size_t kDelimiterCountForAField = 2ull;

  static const std::string kDelimiter{RDB_DELIMITER};

  /**
   * ######################################
   * ############## PATHS #################
   * ######################################
   */
  // domain_id/account_name
  static auto constexpr kPathAccountRoles{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ROLES)};

  static auto constexpr kPathWsv{FMT_STRING(RDB_ROOT /**/ RDB_WSV)};

  static auto constexpr kPathStore{FMT_STRING(RDB_ROOT /**/ RDB_STORE)};

  // domain_id/account_name
  static auto constexpr kPathAccount{FMT_STRING(RDB_PATH_ACCOUNT)};

  // no params
  static auto constexpr kPathPeers{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/ RDB_ADDRESS)};

  // no params
  static auto constexpr kPathSPeers{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_S_PEERS /**/
                     RDB_ADDRESS)};

  // domain_id/account_name
  static auto constexpr kPathSignatories{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_SIGNATORIES)};

  // no param
  static auto constexpr kPathRoles{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_ROLES)};

  // account
  static auto constexpr kPathTransactionByTs{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/
                     RDB_ACCOUNTS /**/ RDB_XXX /**/ RDB_TIMESTAMP)};

  // account
  static auto constexpr kPathTransactionByPosition{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/
                     RDB_ACCOUNTS /**/ RDB_XXX /**/ RDB_POSITION)};

  // domain_id/account_name ➡️ value
  static auto constexpr kPathAccountDetail{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_DETAILS)};

  // account_domain_id/account_name/asset_id
  static auto constexpr kPathAccountAssets{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ASSETS)};

  /**
   * ######################################
   * ############# FOLDERS ################
   * ######################################
   */
  // height ➡️ block data
  static auto constexpr kBlockDataInStore{
      FMT_STRING(RDB_ROOT /**/ RDB_STORE /**/ RDB_XXX)};

  // account/height/index/ts ➡️ tx_hash
  static auto constexpr kTransactionByPosition{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/ RDB_ACCOUNTS /**/
          RDB_XXX /**/ RDB_POSITION /**/ RDB_XXX /**/ RDB_XXX /**/ RDB_XXX)};

  // account/ts/height/index ➡️ tx_hash
  static auto constexpr kTransactionByTs{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/ RDB_ACCOUNTS /**/
          RDB_XXX /**/ RDB_TIMESTAMP /**/ RDB_XXX /**/ RDB_XXX /**/ RDB_XXX)};

  // account/height ➡️ tx_hash
  static auto constexpr kTransactionByHeight{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/ RDB_ACCOUNTS /**/
          RDB_XXX /**/ RDB_POSITION /**/ RDB_XXX)};

  // account/ts/height/index ➡️ tx_hash
  static auto constexpr kTransactionByTsLowerBound{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/ RDB_ACCOUNTS /**/
          RDB_XXX /**/ RDB_TIMESTAMP /**/ RDB_XXX)};

  // tx_hash ➡️ status
  static auto constexpr kTransactionStatus{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/
                     RDB_STATUSES /**/ RDB_XXX)};

  // domain_id/account_name/role_name
  static auto constexpr kAccountRole{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ROLES /**/ RDB_XXX)};

  // role_name ➡️ permissions
  static auto constexpr kRole{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_ROLES /**/
                     RDB_XXX)};

  // domain_id/account_name/pubkey ➡️ ""
  static auto constexpr kSignatory{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_SIGNATORIES /**/ RDB_XXX)};

  // domain_id/asset_name ➡️ precision
  static auto constexpr kAsset{
      FMT_STRING(RDB_PATH_DOMAIN /**/ RDB_ASSETS /**/ RDB_XXX)};

  // account_domain_id/account_name/asset_id ➡️ amount
  static auto constexpr kAccountAsset{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ASSETS /**/ RDB_XXX)};

  // domain_id/account_name/writer_id/key ➡️
  // value
  static auto constexpr kAccountDetail{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_DETAILS /**/ RDB_XXX /**/ RDB_XXX)};

  // pubkey ➡️ address
  static auto constexpr kPeerAddress{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/
                     RDB_ADDRESS /**/ RDB_XXX)};

  // pubkey ➡️ address
  static auto constexpr kSPeerAddress{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_S_PEERS /**/
                     RDB_ADDRESS /**/ RDB_XXX)};

  // pubkey ➡️ tls
  static auto constexpr kPeerTLS{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/
                     RDB_TLS /**/ RDB_XXX)};

  // pubkey ➡️ tls
  static auto constexpr kSPeerTLS{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_S_PEERS /**/
                     RDB_TLS /**/ RDB_XXX)};

  // domain_id/account_name/grantee_domain_id/grantee_account_name
  // ➡️ permissions
  static auto constexpr kGranted{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_GRANTABLE_PER /**/ RDB_XXX)};

  // key ➡️ value
  static auto constexpr kSetting{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_SETTINGS /**/ RDB_XXX)};

  /**
   * ######################################
   * ############## FILES #################
   * ######################################
   */
  // domain_id ➡️ default role
  static auto constexpr kDomain{FMT_STRING(RDB_PATH_DOMAIN)};

  // "" ➡️ height # hash
  static auto constexpr kTopBlock{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_STORE /**/
                     RDB_F_TOP_BLOCK)};

  // domain_id/account_name
  static auto constexpr kQuorum{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_QUORUM)};

  // account_domain_id/account_name ➡️ size
  static auto constexpr kAccountAssetSize{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_ASSET_SIZE)};

  static auto constexpr kPeersCount{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/
                     RDB_F_PEERS_COUNT)};

  static auto constexpr kSPeersCount{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_S_PEERS /**/
                     RDB_F_PEERS_COUNT)};

  // account ➡️ txs total count
  static auto constexpr kTxsTotalCount{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/
                     RDB_ACCOUNTS /**/ RDB_XXX /**/ RDB_F_TOTAL_COUNT)};

  // ➡️ value
  static auto constexpr kBlocksTotalCount{
      FMT_STRING(RDB_ROOT /**/ RDB_STORE /**/ RDB_F_TOTAL_COUNT)};

  // ➡️ txs total count
  static auto constexpr kAllTxsTotalCount{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/ RDB_F_TOTAL_COUNT)};

  // ➡️ domains total count
  static auto constexpr kDomainsTotalCount{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_DOMAIN /**/ RDB_F_TOTAL_COUNT)};

  // domain_id/account_name/ ➡️ value
  static auto constexpr kAccountDetailsCount{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_TOTAL_COUNT)};

  // ➡️ value
  static auto constexpr kStoreVersion{
      FMT_STRING(RDB_ROOT /**/ RDB_STORE /**/ RDB_F_VERSION)};

  // ➡️ value
  static auto constexpr kWsvVersion{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_F_VERSION)};

}  // namespace iroha::ametsuchi::fmtstrings

namespace {
  auto constexpr kValue{FMT_STRING("{}")};
}

namespace iroha::ametsuchi {

  struct RocksDBPort;
  class RocksDbCommon;

  /**
   * RocksDB transaction context.
   */
  struct RocksDBContext {
    RocksDBContext(RocksDBContext const &) = delete;
    RocksDBContext &operator=(RocksDBContext const &) = delete;

    explicit RocksDBContext(
        std::shared_ptr<RocksDBPort> dbp,
        std::shared_ptr<DatabaseCache<std::string>> cache = nullptr)
        : cache_(std::move(cache)), db_port(std::move(dbp)) {
      assert(db_port);
    }

   private:
    friend class RocksDbCommon;
    friend struct RocksDBPort;

    /// RocksDB transaction
    std::unique_ptr<rocksdb::Transaction> transaction;

    /// Buffer for key data
    fmt::memory_buffer key_buffer;

    /// Buffer for value data
    std::string value_buffer;

    /// Cache with extra loaded values
    std::shared_ptr<DatabaseCache<std::string>> cache_;

    /// Database port
    std::shared_ptr<RocksDBPort> db_port;

    /// Mutex to guard multithreaded access to this context
    std::recursive_mutex this_context_cs;
  };

  enum DbErrorCode {
    kErrorNoPermissions = 2,
    kNotFound = 3,
    kNoAccount = 3,
    kMustNotExist = 4,
    kInvalidPagination = 4,
    kInvalidStatus = 12,
    kInitializeFailed = 15,
    kOperationFailed = 16,
  };

  /// Db errors structure
  struct DbError final {
    uint32_t code;
    std::string description;
  };

  template <typename T, typename... Args>
  inline expected::Result<T, DbError> makeError(uint32_t code,
                                                char const *format,
                                                Args &&... args) {
    assert(format != nullptr);
    return expected::makeError(
        DbError{code, fmt::format(format, std::forward<Args>(args)...)});
  }

  template <typename T>
  inline expected::Result<T, DbError> makeError(uint32_t code, DbError &&e) {
    return expected::makeError(DbError{code, std::move(e.description)});
  }

  /**
   * Port to provide access to RocksDB instance.
   */
  struct RocksDBPort {
    RocksDBPort(RocksDBPort const &) = delete;
    RocksDBPort &operator=(RocksDBPort const &) = delete;
    RocksDBPort() = default;

    expected::Result<void, DbError> initialize(std::string const &db_name) {
      db_name_ = db_name;
      return reinitDB();
    }

   private:
    expected::Result<void, DbError> reinitDB() {
      assert(db_name_);

      rocksdb::BlockBasedTableOptions table_options;
      table_options.block_cache =
          rocksdb::NewLRUCache(1 * 1024 * 1024 * 1024LL);
      table_options.block_size = 32 * 1024;
      // table_options.pin_l0_filter_and_index_blocks_in_cache = true;
      table_options.cache_index_and_filter_blocks = true;

      rocksdb::Options options;
      options.create_if_missing = true;
      options.optimize_filters_for_hits = true;
      options.table_factory.reset(
          rocksdb::NewBlockBasedTableFactory(table_options));

      rocksdb::OptimisticTransactionDB *transaction_db;
      auto status = rocksdb::OptimisticTransactionDB::Open(
          options, *db_name_, &transaction_db);

      if (!status.ok())
        return makeError<void>(DbErrorCode::kInitializeFailed,
                               "Db '{}' initialization failed with status: {}.",
                               *db_name_,
                               status.ToString());

      transaction_db_.reset(transaction_db);
      return {};
    }

    template <typename LoggerT>
    void printStatus(LoggerT &log) {
      if (transaction_db_) {
        auto read_property = [&](const rocksdb::Slice &property) {
          uint64_t value;
          transaction_db_->GetIntProperty(property, &value);
          return value;
        };

        auto read_property_str = [&](const rocksdb::Slice &property) {
          std::string value;
          transaction_db_->GetProperty(property, &value);
          return value;
        };

        log.info(
            "[ROCKSDB MEMORY STATUS]\nrocksdb.block-cache-usage: "
            "{}\nrocksdb.block-cache-pinned-usage: "
            "{}\nrocksdb.estimate-table-readers-mem: "
            "{}\nrocksdb.cur-size-all-mem-tables: {}\nrocksdb.num-snapshots: "
            "{}\nrocksdb.total-sst-files-size: "
            "{}\nrocksdb.block-cache-capacity: {}\nrocksdb.stats: {}",
            read_property("rocksdb.block-cache-usage"),
            read_property("rocksdb.block-cache-pinned-usage"),
            read_property("rocksdb.estimate-table-readers-mem"),
            read_property("rocksdb.cur-size-all-mem-tables"),
            read_property("rocksdb.num-snapshots"),
            read_property("rocksdb.total-sst-files-size"),
            read_property("rocksdb.block-cache-capacity"),
            read_property_str("rocksdb.stats"));
      }
    }

    std::optional<uint64_t> getPropUInt64(const rocksdb::Slice &property) {
      if (transaction_db_) {
        uint64_t value;
        transaction_db_->GetIntProperty(property, &value);
        return value;
      }
      return std::nullopt;
    }

    std::optional<std::string> getPropStr(const rocksdb::Slice &property) {
      if (transaction_db_) {
        std::string value;
        transaction_db_->GetProperty(property, &value);
        return value;
      }
      return std::nullopt;
    }

   private:
    std::unique_ptr<rocksdb::OptimisticTransactionDB> transaction_db_;
    std::optional<std::string> db_name_;
    friend class RocksDbCommon;

    void prepareTransaction(RocksDBContext &tx_context) {
      assert(transaction_db_);
      tx_context.transaction.reset(
          transaction_db_->BeginTransaction(rocksdb::WriteOptions()));
    }
  };

#define RDB_ERROR_CHECK(...)                   \
  if (auto _tmp_gen_var = (__VA_ARGS__);       \
      iroha::expected::hasError(_tmp_gen_var)) \
  return _tmp_gen_var.assumeError()

#define RDB_ERROR_CHECK_TO_STR(...)            \
  if (auto _tmp_gen_var = (__VA_ARGS__);       \
      iroha::expected::hasError(_tmp_gen_var)) \
  return _tmp_gen_var.assumeError().description

#define RDB_TRY_GET_VALUE(name, ...)                   \
  typename decltype(__VA_ARGS__)::ValueInnerType name; \
  if (auto _tmp_gen_var = (__VA_ARGS__);               \
      iroha::expected::hasError(_tmp_gen_var))         \
    return _tmp_gen_var.assumeError();                 \
  else                                                 \
    name = std::move(_tmp_gen_var.assumeValue())

#define RDB_TRY_GET_VALUE_OR_STR_ERR(name, ...)        \
  typename decltype(__VA_ARGS__)::ValueInnerType name; \
  if (auto _tmp_gen_var = (__VA_ARGS__);               \
      iroha::expected::hasError(_tmp_gen_var))         \
    return _tmp_gen_var.assumeError().description;     \
  else                                                 \
    name = std::move(_tmp_gen_var.assumeValue())

  /**
   * Base functions to interact with RocksDB data.
   */
  class RocksDbCommon {
   public:
    explicit RocksDbCommon(std::shared_ptr<RocksDBContext> tx_context)
        : tx_context_(std::move(tx_context)),
          context_guard_(tx_context_->this_context_cs) {
      assert(tx_context_);
      assert(tx_context_->db_port);
    }

    /// Get value buffer
    auto &valueBuffer() {
      return tx_context_->value_buffer;
    }

    /// Get key buffer
    auto &keyBuffer() {
      return tx_context_->key_buffer;
    }

   private:
    auto &transaction() {
      if (!tx_context_->transaction)
        tx_context_->db_port->prepareTransaction(*tx_context_);
      return tx_context_->transaction;
    }

    auto &cache() {
      return tx_context_->cache_;
    }

    [[nodiscard]] bool isTransaction() const {
      return tx_context_->transaction != nullptr;
    }

    /// Iterate over all the keys begins from it, and matches a prefix from
    /// keybuffer and call lambda with key-value. To stop enumeration callback F
    /// must return false.
    template <typename F>
    auto enumerate(std::unique_ptr<rocksdb::Iterator> &it, F &&func) {
      if (!it->status().ok())
        return it->status();

      static_assert(
          std::is_convertible_v<std::result_of_t<F &(decltype(it), size_t)>,
                                bool>,
          "Required F(unique_ptr<rocksdb::Iterator>,size_t) -> bool");

      /// TODO(iceseer): remove this and recursive_mutex in RocksdbCommon when
      /// BlockStore and WsvCommand begin to work with the single context
      /// correctly
      std::string const tmp_key(keyBuffer().data(), keyBuffer().size());
      rocksdb::Slice const key(tmp_key.data(), tmp_key.size());
      for (; it->Valid() && it->key().starts_with(key); it->Next())
        if constexpr (std::is_void_v<decltype(
                          std::declval<F>()(it, key.size()))>) {
          std::forward<F>(func)(it, key.size());
        } else {
          if (!std::forward<F>(func)(it, key.size()))
            break;
        }

      return it->status();
    }

    void storeInCache(std::string_view key) {
      if (auto c = cache(); c && c->isCacheable(key))
        c->set(key, valueBuffer());
    }

    void dropCache() {
      if (auto c = cache())
        c->drop();
    }

   public:
    template <typename LoggerT>
    void printStatus(LoggerT &log) {
      tx_context_->db_port->printStatus(log);
    }

    auto propGetBlockCacheUsage() {
      return tx_context_->db_port->getPropUInt64("rocksdb.block-cache-usage");
    }

    auto propGetCurSzAllMemTables() {
      return tx_context_->db_port->getPropUInt64(
          "rocksdb.cur-size-all-mem-tables");
    }

    auto propGetNumSnapshots() {
      return tx_context_->db_port->getPropUInt64("rocksdb.num-snapshots");
    }

    auto propGetTotalSSTFilesSize() {
      return tx_context_->db_port->getPropUInt64(
          "rocksdb.total-sst-files-size");
    }

    auto propGetBlockCacheCapacity() {
      return tx_context_->db_port->getPropUInt64(
          "rocksdb.block-cache-capacity");
    }

    /// Makes commit to DB
    auto commit() {
      rocksdb::Status status;
      if (isTransaction())
        status = transaction()->Commit();

      transaction().reset();
      return status;
    }

    /// Rollback all transaction changes
    auto rollback() {
      rocksdb::Status status;
      if (isTransaction())
        status = transaction()->Rollback();

      dropCache();
      transaction().reset();
      return status;
    }

    auto release() {
      rocksdb::Status status;
      if (isTransaction())
        status = transaction()->PopSavePoint();
      return status;
    }

    /// Prepare tx for 2pc
    auto prepare() {
      rocksdb::Status status;
      if (isTransaction())
        status = transaction()->Prepare();
      return status;
    }

    /// Skips all changes made in this transaction
    void skip() {
      if (isTransaction())
        transaction().reset();

      dropCache();
    }

    /// Saves current state of a transaction
    void savepoint() {
      if (isTransaction())
        transaction()->SetSavePoint();
    }

    /// Restores to the previously saved savepoint
    auto rollbackToSavepoint() {
      rocksdb::Status status;
      if (isTransaction())
        status = transaction()->RollbackToSavePoint();

      dropCache();
      return status;
    }

    /// Encode number into @see valueBuffer
    auto encode(uint64_t number) {
      valueBuffer().clear();
      fmt::format_to(std::back_inserter(valueBuffer()), kValue, number);
    }

    /// Decode number from @see valueBuffer
    auto decode(uint64_t &number) {
      return std::from_chars(valueBuffer().data(),
                             valueBuffer().data() + valueBuffer().size(),
                             number);
    }

    /// Read data from database to @see valueBuffer
    template <typename S, typename... Args>
    auto get(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      valueBuffer().clear();
      rocksdb::Slice const slice(keyBuffer().data(), keyBuffer().size());

      if (auto c = cache(); c && c->isCacheable(slice.ToStringView())
          && c->get(slice.ToStringView(), [&](auto const &str) {
               valueBuffer() = str;
               return true;
             })) {
        return rocksdb::Status();
      }

      rocksdb::ReadOptions ro;
      ro.fill_cache = false;

      auto status = transaction()->Get(ro, slice, &valueBuffer());
      if (status.ok())
        storeInCache(slice.ToStringView());

      return status;
    }

    /// Put data from @see valueBuffer to database
    template <typename S, typename... Args>
    auto put(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      rocksdb::Slice const slice(keyBuffer().data(), keyBuffer().size());
      auto status = transaction()->Put(slice, valueBuffer());

      if (status.ok())
        storeInCache(slice.ToStringView());

      return status;
    }

    /// Delete database entry by the key
    template <typename S, typename... Args>
    auto del(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      rocksdb::Slice const slice(keyBuffer().data(), keyBuffer().size());
      if (auto c = cache(); c && c->isCacheable(slice.ToStringView()))
        c->erase(slice.ToStringView());

      return transaction()->Delete(slice);
    }

    /// Searches for the first key that matches a prefix
    template <typename S, typename... Args>
    auto seek(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      rocksdb::ReadOptions ro;
      ro.fill_cache = false;

      std::unique_ptr<rocksdb::Iterator> it(transaction()->GetIterator(ro));
      it->Seek(rocksdb::Slice(keyBuffer().data(), keyBuffer().size()));

      return it;
    }

    /// Iterate over all the keys begins from it, and matches a prefix and call
    /// lambda with key-value. To stop enumeration callback F must return false.
    template <typename F, typename S, typename... Args>
    auto enumerate(std::unique_ptr<rocksdb::Iterator> &it,
                   F &&func,
                   S const &fmtstring,
                   Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);
      return enumerate(it, std::forward<F>(func));
    }

    /// Iterate over all the keys that matches a prefix and call lambda
    /// with key-value. To stop enumeration callback F must return false.
    template <typename F, typename S, typename... Args>
    auto enumerate(F &&func, S const &fmtstring, Args &&... args) {
      auto it = seek(fmtstring, std::forward<Args>(args)...);
      return enumerate(it, std::forward<F>(func));
    }

    /// Removes range of items by key-filter
    template <typename S, typename... Args>
    auto filterDelete(S const &fmtstring, Args &&... args) {
      auto it = seek(fmtstring, std::forward<Args>(args)...);
      if (!it->status().ok())
        return it->status();

      rocksdb::Slice const key(keyBuffer().data(), keyBuffer().size());
      if (auto c = cache(); c && c->isCacheable(key.ToStringView()))
        c->filterDelete(key.ToStringView());

      for (; it->Valid() && it->key().starts_with(key); it->Next())
        if (auto status = transaction()->Delete(it->key()); !status.ok())
          return status;

      return it->status();
    }

   private:
    std::shared_ptr<RocksDBContext> tx_context_;
    std::lock_guard<std::recursive_mutex> context_guard_;
  };

  /**
   * Supported operations.
   */
  enum struct kDbOperation {
    kGet,    /// read the value by the key
    kCheck,  /// check the entry exists by the key
    kPut,    /// put the value with the key
    kDel     /// delete entry by the key
  };

  /**
   * DB operation result assertion. If the result is not matches the assertion
   * than error will be generated
   */
  enum struct kDbEntry {
    kMustExist,     /// entry must exist and data must be accessible
    kMustNotExist,  /// entry must NOT exist. If it exist than error will be
                    /// generated
    kCanExist  /// entry can exist or not. kDbOperation::kGet will return data
               /// only if present, otherwise null-data
  };

  /// Enumerating through all the keys matched to prefix without reading value
  template <typename F, typename S, typename... Args>
  inline auto enumerateKeys(RocksDbCommon &rdb,
                            F &&func,
                            S const &strformat,
                            Args &&... args) {
    static_assert(
        std::is_convertible_v<std::result_of_t<F &(rocksdb::Slice)>, bool>,
        "Must F(rocksdb::Slice) -> bool");
    return rdb.enumerate(
        [func{std::forward<F>(func)}](auto const &it,
                                      auto const prefix_size) mutable {
          assert(it->Valid());
          auto const key = it->key();
          return std::forward<F>(func)(rocksdb::Slice(
              key.data() + prefix_size + fmtstrings::kDelimiterSize,
              key.size() - prefix_size
                  - fmtstrings::kDelimiterCountForAField
                      * fmtstrings::kDelimiterSize));
        },
        strformat,
        std::forward<Args>(args)...);
  }

  template <typename F>
  inline auto makeKVLambda(F &&func) {
    return [func{std::forward<F>(func)}](auto const &it,
                                         auto const prefix_size) mutable {
      assert(it->Valid());
      auto const key = it->key();
      return std::forward<F>(func)(
          rocksdb::Slice(key.data() + prefix_size + fmtstrings::kDelimiterSize,
                         key.size() - prefix_size
                             - fmtstrings::kDelimiterCountForAField
                                 * fmtstrings::kDelimiterSize),
          it->value());
    };
  }

  /// Enumerating through all the keys matched to prefix and read the value
  template <typename F, typename S, typename... Args>
  inline auto enumerateKeysAndValues(RocksDbCommon &rdb,
                                     F &&func,
                                     S const &strformat,
                                     Args &&... args) {
    return rdb.enumerate(makeKVLambda(std::forward<F>(func)),
                         strformat,
                         std::forward<Args>(args)...);
  }

  /// Enumerating through the keys, begins from it and matched to prefix and
  /// read the value
  template <typename F, typename S, typename... Args>
  inline auto enumerateKeysAndValues(RocksDbCommon &rdb,
                                     F &&func,
                                     std::unique_ptr<rocksdb::Iterator> &it,
                                     S const &strformat,
                                     Args &&... args) {
    return rdb.enumerate(it,
                         makeKVLambda(std::forward<F>(func)),
                         strformat,
                         std::forward<Args>(args)...);
  }

  template <typename F>
  inline expected::Result<void, DbError> mustNotExist(
      rocksdb::Status const &status, F &&op_formatter) {
    if (status.IsNotFound())
      return {};

    if (!status.ok())
      return makeError<void>(DbErrorCode::kInvalidStatus,
                             "'{}' failed with status: {}.",
                             std::forward<F>(op_formatter)(),
                             status.ToString());

    return makeError<void>(DbErrorCode::kMustNotExist,
                           "Key '{}' must not exist.",
                           std::forward<F>(op_formatter)());
  }

  template <typename F>
  inline expected::Result<void, DbError> mustExist(
      rocksdb::Status const &status, F &&op_formatter) {
    if (status.IsNotFound())
      return makeError<void>(DbErrorCode::kNotFound,
                             "{}. Was not found.",
                             std::forward<F>(op_formatter)());

    if (!status.ok())
      return makeError<void>(DbErrorCode::kInvalidStatus,
                             "{}. Failed with status: {}.",
                             std::forward<F>(op_formatter)(),
                             status.ToString());

    return {};
  }

  template <typename F>
  inline expected::Result<void, DbError> canExist(rocksdb::Status const &status,
                                                  F &&op_formatter) {
    if (status.IsNotFound() || status.ok())
      return {};

    return makeError<void>(DbErrorCode::kInvalidStatus,
                           "{}. Failed with status: {}.",
                           std::forward<F>(op_formatter)(),
                           status.ToString());
  }

  template <kDbEntry kSc, typename F>
  inline expected::Result<void, DbError> checkStatus(rocksdb::Status status,
                                                     F &&op_formatter) {
    if constexpr (kSc == kDbEntry::kMustExist)
      return mustExist(status, std::forward<F>(op_formatter));
    else if constexpr (kSc == kDbEntry::kMustNotExist)
      return mustNotExist(status, std::forward<F>(op_formatter));
    else if constexpr (kSc == kDbEntry::kCanExist)
      return canExist(status, std::forward<F>(op_formatter));

    static_assert(kSc == kDbEntry::kMustExist || kSc == kDbEntry::kMustNotExist
                      || kSc == kDbEntry::kCanExist,
                  "Unexpected status check value");
  }

  template <kDbOperation kOp,
            kDbEntry kSc,
            typename OperationDescribtionF,
            typename... Args>
  inline expected::Result<rocksdb::Status, DbError> executeOperation(
      RocksDbCommon &common,
      OperationDescribtionF &&op_formatter,
      Args &&... args) {
    rocksdb::Status status;
    if constexpr (kOp == kDbOperation::kGet || kOp == kDbOperation::kCheck)
      status = common.get(std::forward<Args>(args)...);
    else if constexpr (kOp == kDbOperation::kPut)
      status = common.put(std::forward<Args>(args)...);
    else if constexpr (kOp == kDbOperation::kDel)
      status = common.del(std::forward<Args>(args)...);

    static_assert(kOp == kDbOperation::kGet || kOp == kDbOperation::kCheck
                      || kOp == kDbOperation::kPut || kOp == kDbOperation::kDel,
                  "Unexpected operation value!");

    static_assert(
        kOp != kDbOperation::kDel || kSc != kDbEntry::kMustExist,
        "Delete operation does not report if key existed before deletion!");

    RDB_ERROR_CHECK(checkStatus<kSc>(
        status, std::forward<OperationDescribtionF>(op_formatter)));
    return status;
  }

  template <kDbOperation kOp,
            typename T,
            typename = std::enable_if_t<std::is_same<T, uint64_t>::value>>
  inline std::optional<uint64_t> loadValue(
      RocksDbCommon &common,
      expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<uint64_t> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok()) {
        DISABLE_WARNING_PUSH
        DISABLE_WARNING_uninitialized DISABLE_WARNING_maybe_uninitialized
            uint64_t _;
        DISABLE_WARNING_POP
        common.decode(_);
        value = _;
      }
    }
    return value;
  }

  template <
      kDbOperation kOp,
      typename T,
      typename = std::enable_if_t<std::is_same<T, std::string_view>::value>>
  inline std::optional<std::string_view> loadValue(
      RocksDbCommon &common,
      expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<std::string_view> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok())
        value = common.valueBuffer();
    }
    return value;
  }

  template <
      kDbOperation kOp,
      typename T,
      typename = std::enable_if_t<
          std::is_same<T, shared_model::interface::RolePermissionSet>::value>>
  inline std::optional<shared_model::interface::RolePermissionSet> loadValue(
      RocksDbCommon &common,
      expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<shared_model::interface::RolePermissionSet> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok())
        value =
            shared_model::interface::RolePermissionSet{common.valueBuffer()};
    }
    return value;
  }

  template <kDbOperation kOp,
            typename T,
            typename = std::enable_if_t<std::is_same<T, IrohadVersion>::value>>
  inline std::optional<IrohadVersion> loadValue(
      RocksDbCommon &common,
      expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<IrohadVersion> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok()) {
        auto const &[major, minor, patch] =
            staticSplitId<3ull>(common.valueBuffer(), "#");
        IrohadVersion version{0ul, 0ul, 0ul};
        std::from_chars(
            major.data(), major.data() + major.size(), version.major);
        std::from_chars(
            minor.data(), minor.data() + minor.size(), version.minor);
        std::from_chars(
            patch.data(), patch.data() + patch.size(), version.patch);
        value = version;
      }
    }
    return value;
  }

  template <kDbOperation kOp,
            typename T,
            typename = std::enable_if_t<
                std::is_same<T, shared_model::interface::Amount>::value>>
  inline std::optional<shared_model::interface::Amount> loadValue(
      RocksDbCommon &common,
      expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<shared_model::interface::Amount> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok())
        value.emplace(common.valueBuffer());
    }
    return value;
  }

  template <kDbOperation kOp,
            typename T,
            typename = std::enable_if_t<std::is_same<
                T,
                shared_model::interface::GrantablePermissionSet>::value>>
  inline std::optional<shared_model::interface::GrantablePermissionSet>
  loadValue(RocksDbCommon &common,
            expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<shared_model::interface::GrantablePermissionSet> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok())
        value = shared_model::interface::GrantablePermissionSet{
            common.valueBuffer()};
    }
    return value;
  }

  template <kDbOperation kOp,
            typename T,
            typename = std::enable_if_t<std::is_same<T, bool>::value>>
  inline std::optional<bool> loadValue(
      RocksDbCommon &,
      expected::Result<rocksdb::Status, DbError> const &status) {
    std::optional<bool> value;
    if constexpr (kOp == kDbOperation::kGet) {
      assert(expected::hasValue(status));
      if (status.assumeValue().ok())
        value = true;
    }
    return value;
  }

  template <typename RetT, kDbOperation kOp, kDbEntry kSc, typename... Args>
  inline expected::Result<std::optional<RetT>, DbError> dbCall(
      RocksDbCommon &common, Args &&... args) {
    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format(std::forward<Args>(args)...); },
        std::forward<Args>(args)...);
    RDB_ERROR_CHECK(status);
    return loadValue<kOp, RetT>(common, status);
  }

  /**
   * Access to account details count.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError>
  forAccountDetailsCount(RocksDbCommon &common,
                         std::string_view account,
                         std::string_view domain) {
    return dbCall<uint64_t, kOp, kSc>(
        common, fmtstrings::kAccountDetailsCount, domain, account);
  }

  /**
   * Access to store version.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<IrohadVersion>, DbError>
  forStoreVersion(RocksDbCommon &common) {
    return dbCall<IrohadVersion, kOp, kSc>(common, fmtstrings::kStoreVersion);
  }

  /**
   * Access to WSV version.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<IrohadVersion>, DbError> forWSVVersion(
      RocksDbCommon &common) {
    return dbCall<IrohadVersion, kOp, kSc>(common, fmtstrings::kWsvVersion);
  }

  /**
   * Access to Stored blocks data.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param height of the block
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError> forBlock(
      RocksDbCommon &common, uint64_t height) {
    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kBlockDataInStore, height);
  }

  /**
   * Access to Block store size.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forBlocksTotalCount(
      RocksDbCommon &common) {
    return dbCall<uint64_t, kOp, kSc>(common, fmtstrings::kBlocksTotalCount);
  }

  /**
   * Access to account quorum file.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forQuorum(
      RocksDbCommon &common,
      std::string_view account,
      std::string_view domain) {
    return dbCall<uint64_t, kOp, kSc>(
        common, fmtstrings::kQuorum, domain, account);
  }

  /**
   * Access to account's txs total count.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param account_id name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forTxsTotalCount(
      RocksDbCommon &common, std::string_view account_id) {
    return dbCall<uint64_t, kOp, kSc>(
        common, fmtstrings::kTxsTotalCount, account_id);
  }

  /**
   * Access to all txs total count.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forTxsTotalCount(
      RocksDbCommon &common) {
    return dbCall<uint64_t, kOp, kSc>(common, fmtstrings::kAllTxsTotalCount);
  }

  /**
   * Access to domains total count.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError>
  forDomainsTotalCount(RocksDbCommon &common) {
    return dbCall<uint64_t, kOp, kSc>(common, fmtstrings::kDomainsTotalCount);
  }

  /**
   * Access to account folder
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline auto forAccount(RocksDbCommon &common,
                         std::string_view account,
                         std::string_view domain) {
    return forQuorum<kOp, kSc>(common, account, domain);
  }

  /**
   * Access to role file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param role id
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::
      Result<std::optional<shared_model::interface::RolePermissionSet>, DbError>
      forRole(RocksDbCommon &common, std::string_view role) {
    return dbCall<shared_model::interface::RolePermissionSet, kOp, kSc>(
        common, fmtstrings::kRole, role);
  }

  /**
   * Access to peers and syncing peers count file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forPeersCount(
      RocksDbCommon &common, bool is_syncing_peer) {
    if (is_syncing_peer)
      return dbCall<uint64_t, kOp, kSc>(common, fmtstrings::kSPeersCount);

    return dbCall<uint64_t, kOp, kSc>(common, fmtstrings::kPeersCount);
  }

  /**
   * Access to transactions statuses
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param tx_hash is a current transaction hash
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError>
  forTransactionStatus(RocksDbCommon &common,
                       shared_model::crypto::Hash const &tx_hash) {
    return dbCall<std::string_view, kOp, kSc>(
        common,
        fmtstrings::kTransactionStatus,
        std::string_view((char const *)tx_hash.blob().data(),
                         tx_hash.blob().size()));
  }

  /**
   * Access to transactions by position
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param account name
   * @param height of the block
   * @param index of the transaction
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError>
  forTransactionByPosition(RocksDbCommon &common,
                           std::string_view account,
                           uint64_t ts,
                           uint64_t height,
                           uint64_t index) {
    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kTransactionByPosition, account, height, index, ts);
  }

  /**
   * Access to transactions by timestamp
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param account name
   * @param ts is a transaction timestamp
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError>
  forTransactionByTimestamp(RocksDbCommon &common,
                            std::string_view account,
                            uint64_t ts,
                            uint64_t height,
                            uint64_t index) {
    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kTransactionByTs, account, ts, height, index);
  }

  /**
   * Access to setting file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param key setting name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError> forSettings(
      RocksDbCommon &common, std::string_view key) {
    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kSetting, key);
  }

  /**
   * Access to peer and syncing peer address file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param pubkey public key of the peer
   * @param is_sync_peer node mode
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError>
  forPeerAddress(RocksDbCommon &common,
                 std::string_view pubkey,
                 bool is_sync_peer) {
    if (is_sync_peer)
      return dbCall<std::string_view, kOp, kSc>(
          common, fmtstrings::kSPeerAddress, pubkey);

    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kPeerAddress, pubkey);
  }

  /**
   * Access to peer and syncing peer TLS file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param pubkey is a public key of the peer
   * @param is_sync_peer node mode
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError> forPeerTLS(
      RocksDbCommon &common, std::string_view pubkey, bool is_sync_peer) {
    if (is_sync_peer)
      return dbCall<std::string_view, kOp, kSc>(
          common, fmtstrings::kSPeerTLS, pubkey);

    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kPeerTLS, pubkey);
  }

  /**
   * Access to asset file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain is
   * @param asset name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forAsset(
      RocksDbCommon &common, std::string_view asset, std::string_view domain) {
    return dbCall<uint64_t, kOp, kSc>(
        common, fmtstrings::kAsset, domain, asset);
  }

  /**
   * Access to top blocks height and hash
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  expected::Result<std::optional<std::string_view>, DbError> forTopBlockInfo(
      RocksDbCommon &common) {
    return dbCall<std::string_view, kOp, kSc>(common, fmtstrings::kTopBlock);
  }

  /**
   * Access to account role file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param role id
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<bool>, DbError> forAccountRole(
      RocksDbCommon &common,
      std::string_view account,
      std::string_view domain,
      std::string_view role) {
    return dbCall<bool, kOp, kSc>(
        common, fmtstrings::kAccountRole, domain, account, role);
  }

  /**
   * Access to account details file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param creator_domain id
   * @param creator_account name
   * @param key name of the details entry
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError>
  forAccountDetail(RocksDbCommon &common,
                   std::string_view account,
                   std::string_view domain,
                   std::string_view creator_id,
                   std::string_view key) {
    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kAccountDetail, domain, account, creator_id, key);
  }

  /**
   * Access to account signatory file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param pubkey public key of the signatory
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<bool>, DbError> forSignatory(
      RocksDbCommon &common,
      std::string_view account,
      std::string_view domain,
      std::string_view pubkey) {
    return dbCall<bool, kOp, kSc>(
        common, fmtstrings::kSignatory, domain, account, pubkey);
  }

  /**
   * Access to domain file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError> forDomain(
      RocksDbCommon &common, std::string_view domain) {
    return dbCall<std::string_view, kOp, kSc>(
        common, fmtstrings::kDomain, domain);
  }

  /**
   * Access to account size file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kCanExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forAccountAssetSize(
      RocksDbCommon &common,
      std::string_view account,
      std::string_view domain) {
    return dbCall<uint64_t, kOp, kSc>(
        common, fmtstrings::kAccountAssetSize, domain, account);
  }

  /**
   * Access to account assets file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param asset name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kCanExist>
  inline expected::Result<std::optional<shared_model::interface::Amount>,
                          DbError>
  forAccountAsset(RocksDbCommon &common,
                  std::string_view account,
                  std::string_view domain,
                  std::string_view asset) {
    return dbCall<shared_model::interface::Amount, kOp, kSc>(
        common, fmtstrings::kAccountAsset, domain, account, asset);
  }

  /**
   * Access to account grantable permissions
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param grantee_domain id
   * @param grantee_account name
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kCanExist>
  inline expected::Result<
      std::optional<shared_model::interface::GrantablePermissionSet>,
      DbError>
  forGrantablePermissions(RocksDbCommon &common,
                          std::string_view account,
                          std::string_view domain,
                          std::string_view grantee_account_id) {
    return dbCall<shared_model::interface::GrantablePermissionSet, kOp, kSc>(
        common, fmtstrings::kGranted, domain, account, grantee_account_id);
  }

  /**
   * Get all permissions for the account
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @return permission set for the account
   */
  inline expected::Result<shared_model::interface::RolePermissionSet, DbError>
  accountPermissions(RocksDbCommon &common,
                     std::string_view account,
                     std::string_view domain) {
    assert(!domain.empty());
    assert(!account.empty());

    /// TODO(iceseer): remove this vector(some kind of stack allocator)
    /// or to store key prefix value and make another db call inside lambda
    std::vector<std::string> roles;
    auto status = enumerateKeys(common,
                                [&](auto role) {
                                  if (!role.empty())
                                    roles.emplace_back(role.ToStringView());
                                  else {
                                    assert(!"Role can not be empty string!");
                                  }
                                  return true;
                                },
                                fmtstrings::kPathAccountRoles,
                                domain,
                                account);

    if (!status.ok())
      return makeError<shared_model::interface::RolePermissionSet>(
          DbErrorCode::kNoAccount,
          "Enumerate account {}@{} roles failed with status: {}.",
          account,
          domain,
          status.ToString());

    shared_model::interface::RolePermissionSet permissions;
    for (auto &role : roles) {
      auto opt_perm =
          forRole<kDbOperation::kGet, kDbEntry::kMustExist>(common, role);
      RDB_ERROR_CHECK(opt_perm);
      permissions |= *opt_perm.assumeValue();
    }

    return permissions;
  }

  template <size_t N>
  inline expected::Result<void, DbError> checkPermissions(
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::permissions::Role const (&to_check)[N]) {
    for (auto const &role : to_check)
      if (permissions.isSet(role))
        return {};

    return makeError<void>(DbErrorCode::kErrorNoPermissions, "No permissions.");
  }

  inline expected::Result<void, DbError> checkPermissions(
      std::string_view domain_id,
      std::string_view creator_domain_id,
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::permissions::Role const all,
      shared_model::interface::permissions::Role const domain) {
    if (permissions.isSet(all))
      return {};

    if (domain_id == creator_domain_id && permissions.isSet(domain))
      return {};

    return makeError<void>(DbErrorCode::kErrorNoPermissions, "No permissions.");
  }

  inline expected::Result<void, DbError> checkGrantablePermissions(
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::GrantablePermissionSet const
          &grantable_permissions,
      shared_model::interface::permissions::Grantable const granted) {
    if (grantable_permissions.isSet(granted)
        || permissions.isSet(shared_model::interface::permissions::Role::kRoot))
      return {};

    return makeError<void>(DbErrorCode::kErrorNoPermissions, "No permissions.");
  }

  inline expected::Result<void, DbError> checkPermissions(
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::GrantablePermissionSet const
          &grantable_permissions,
      shared_model::interface::permissions::Role const role,
      shared_model::interface::permissions::Grantable const granted) {
    if (permissions.isSet(role))
      return {};

    if (grantable_permissions.isSet(granted))
      return {};

    return makeError<void>(DbErrorCode::kErrorNoPermissions, "No permissions.");
  }

  inline expected::Result<void, DbError> checkPermissions(
      std::string_view domain_id,
      std::string_view creator_domain_id,
      std::string_view qry_account_id,
      std::string_view creator_id,
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::permissions::Role const all,
      shared_model::interface::permissions::Role const domain,
      shared_model::interface::permissions::Role const my) {
    if (permissions.isSet(all))
      return {};

    if (domain_id == creator_domain_id && permissions.isSet(domain))
      return {};

    if (qry_account_id == creator_id && permissions.isSet(my))
      return {};

    return makeError<void>(DbErrorCode::kErrorNoPermissions, "No permissions.");
  }

  struct PaginationContext {
    struct FirstEntry {
      std::string writer_from;
      std::string key_from;
    };

    std::optional<FirstEntry> first;
    uint64_t page_size;
  };

  inline expected::Result<std::string, DbError> aggregateAccountDetails(
      RocksDbCommon &common,
      std::string_view account,
      std::string_view domain,
      uint64_t &total,
      std::string_view writer_filter = std::string_view{},
      std::string_view key_filter = std::string_view{},
      std::optional<PaginationContext> pagination = std::nullopt,
      std::string *next_writer = nullptr,
      std::string *next_key = nullptr) {
    std::string result = "{";
    std::string prev_writer;

    auto remains = pagination ? pagination->page_size + 1ull
                              : std::numeric_limits<uint64_t>::max();
    bool found = !pagination || !pagination->first;
    bool have_entries = false;

    // TODO(iceseer): find first entry by log(N)
    total = 0ull;
    auto status = ametsuchi::enumerateKeysAndValues(
        common,
        [&](auto path, auto value) {
          auto const &[cur_writer, _, cur_key] =
              staticSplitId<3>(path.ToStringView(), fmtstrings::kDelimiter);

          have_entries = true;
          if (!writer_filter.empty() && cur_writer != writer_filter)
            return true;
          if (!key_filter.empty() && cur_key != key_filter)
            return true;

          ++total;
          if (!found) {
            if (cur_writer != pagination->first->writer_from
                || cur_key != pagination->first->key_from)
              return true;
            found = true;
          }

          if (remains == 0ull) {
            return true;
          } else if (remains-- == 1ull) {
            if (next_writer != nullptr)
              *next_writer = cur_writer;
            if (next_key != nullptr)
              *next_key = cur_key;
            return true;
          }

          if (prev_writer != cur_writer) {
            if (prev_writer.empty())
              result += '\"';
            else
              result += "}, \"";
            result += cur_writer;
            result += "\": {";
            prev_writer = cur_writer;
          } else
            result += ", ";

          result += '\"';
          result += cur_key;
          result += "\": \"";
          result += value.ToStringView();
          result += '\"';

          return true;
        },
        fmtstrings::kPathAccountDetail,
        domain,
        account);
    RDB_ERROR_CHECK(canExist(status, [&]() {
      return fmt::format("Aggregate account {}@{} data", account, domain);
    }));

    if (!found && have_entries)
      return makeError<std::string>(DbErrorCode::kInvalidPagination,
                                    "Invalid pagination.");

    result += result.size() == 1ull ? "}" : "}}";
    return result;
  }

  inline expected::Result<void, DbError> dropWSV(RocksDbCommon &common) {
    if (auto status = common.filterDelete(fmtstrings::kPathWsv); !status.ok())
      return makeError<void>(DbErrorCode::kOperationFailed,
                             "Clear WSV failed.");
    return {};
  }

}  // namespace iroha::ametsuchi

#endif
