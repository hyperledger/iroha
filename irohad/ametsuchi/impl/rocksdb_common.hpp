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
#include <rocksdb/utilities/optimistic_transaction_db.h>
#include <rocksdb/utilities/transaction.h>
#include "common/result.hpp"
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
 *        |
 *        +-|WSV|-+-|NETWORK|-+-|PEERS|-+-|ADDRESS|-+-<peer_1_pubkey, value:address>
 *                |           |         |           +-<peer_2_pubkey, value:address>
 *                |           |         |
 *                |           |         +-|TLS|-+-<peer_1, value:tls>
 *                |           |         |       +-<peer_2, value:tls>
 *                |           |         |
 *                |           |         +-<count, value>
 *                |           |
 *                |           +-|STORE|-+-<top_block, value: store height#top block hash>
 *                |                     +-<total transactions count>
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
 *                |                |            |                           +-<ts_2, value:tx_hash_2>
 *                |                |            |                           +-<ts_3, value:tx_hash_3>
 *                |                |            |
 *                |                |            +-<account_2>-+-|POSITION|-+-<height_index, value:tx_hash_4>
 *                |                |                          |            +-<height_index, value:tx_hash_5>
 *                |                |                          |            +-<height_index, value:tx_hash_6>
 *                |                |                          |
 *                |                |                          +-|TIMESTAMP|-+-<ts_1, value:tx_hash_4>
 *                |                |                                        +-<ts_2, value:tx_hash_5>
 *                |                |                                        +-<ts_3, value:tx_hash_6>
 *                |                |
 *                |                +-|STATUSES|-+-<tx_hash_1, value:status_height_index>
 *                |                             +-<tx_hash_2, value:status_height_index>
 *                |
 *                +-|DOMAIN|-+-|DOMAIN_1|-+-|ASSETS|-+-<asset_1, value:precision>
 *                           |            |          +-<asset_2, value:precision>
 *                           |            |
 *                           |            +-|ACCOUNTS|-|NAME_1|-+-|ASSETS|-+-<asset_1, value:quantity>
 *                           |                                  |          +-<asset_2, value:quantity>
 *                           |                                  |
 *                           |                                  +-|OPTIONS|-+-<quorum>
 *                           |                                  |           +-<asset_size>
 *                           |                                  |
 *                           |                                  +-|DETAILS|-+-<domain>-<account>-<key>
 *                           |                                  |
 *                           |                                  +-|ROLES|-+-<role_1, value:flag>
 *                           |                                  |         +-<role_2, value:flag>
 *                           |                                  |
 *                           |                                  +-|GRANTABLE_PER|-+-<domain_account_1, value:permissions>
 *                           |                                  |                 +-<domain_account_2, value:permissions>
 *                           |                                  |
 *                           |                                  +-|SIGNATORIES|-+-<signatory_1>
 *                           |                                                  +-<signatory_2>
 *                           |
 *                           +-<domain_1, value: default_role>
 *
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

  // domain_id/account_name
  static auto constexpr kPathAccount{FMT_STRING(RDB_PATH_ACCOUNT)};

  // no params
  static auto constexpr kPathPeers{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/ RDB_ADDRESS)};

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

  /**
   * ######################################
   * ############# FOLDERS ################
   * ######################################
   */
  // account/height/index ➡️ tx_hash
  static auto constexpr kTransactionByPosition{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_TRANSACTIONS /**/ RDB_ACCOUNTS /**/
          RDB_XXX /**/ RDB_POSITION /**/ RDB_XXX /**/ RDB_XXX)};

  // account/ts ➡️ tx_hash
  static auto constexpr kTransactionByTs{FMT_STRING(
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

  // pubkey ➡️ tls
  static auto constexpr kPeerTLS{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/
                     RDB_TLS /**/ RDB_XXX)};

  // domain_id/account_name/grantee_domain_id/grantee_account_name
  // ➡️ permissions
  static auto constexpr kGranted{FMT_STRING(
      RDB_PATH_ACCOUNT /**/ RDB_GRANTABLE_PER /**/ RDB_XXX /**/ RDB_XXX)};

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

}  // namespace iroha::ametsuchi::fmtstrings

#undef RDB_ADDRESS
#undef RDB_TLS
#undef RDB_OPTIONS
#undef RDB_F_ASSET_SIZE
#undef RDB_PATH_DOMAIN
#undef RDB_PATH_ACCOUNT
#undef RDB_F_QUORUM
#undef RDB_DELIMITER
#undef RDB_ROOT
#undef RDB_STORE
#undef RDB_WSV
#undef RDB_NETWORK
#undef RDB_SETTINGS
#undef RDB_ASSETS
#undef RDB_ROLES
#undef RDB_TRANSACTIONS
#undef RDB_ACCOUNTS
#undef RDB_PEERS
#undef RDB_STATUSES
#undef RDB_DETAILS
#undef RDB_GRANTABLE_PER
#undef RDB_POSITION
#undef RDB_TIMESTAMP
#undef RDB_DOMAIN
#undef RDB_SIGNATORIES
#undef RDB_ITEM
#undef RDB_F_TOP_BLOCK
#undef RDB_F_PEERS_COUNT

namespace {
  auto constexpr kValue{FMT_STRING("{}")};
}

namespace iroha::ametsuchi {

  static constexpr uint32_t kErrorNoPermissions = 2;

  struct RocksDBPort;
  class RocksDbCommon;

  struct RocksDBPort;
  class RocksDbCommon;

  /**
   * RocksDB transaction context.
   */
  struct RocksDBContext {
    explicit RocksDBContext(std::shared_ptr<RocksDBPort> dbp)
        : db_port(std::move(dbp)) {
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

    /// Database port
    std::shared_ptr<RocksDBPort> db_port;

    /// Mutex to guard multithreaded access to this context
    std::mutex this_context_cs;

    RocksDBContext(RocksDBContext const &) = delete;
    RocksDBContext &operator=(RocksDBContext const &) = delete;
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

  /**
   * Port to provide access to RocksDB instance.
   */
  struct RocksDBPort {
    RocksDBPort(RocksDBPort const &) = delete;
    RocksDBPort &operator=(RocksDBPort const &) = delete;
    RocksDBPort() = default;

    expected::Result<void, DbError> initialize(std::string const &db_name) {
      rocksdb::Options options;
      options.create_if_missing = true;
      options.error_if_exists = true;

      rocksdb::OptimisticTransactionDB *transaction_db;
      auto status = rocksdb::OptimisticTransactionDB::Open(
          options, db_name, &transaction_db);

      std::unique_ptr<rocksdb::OptimisticTransactionDB> tdb(transaction_db);
      if (!status.ok())
        return makeError<void>(15,
                               "Db {} initialization failed with status: {}.",
                               db_name,
                               status.ToString());

      transaction_db_.swap(tdb);
      return {};
    }

   private:
    std::unique_ptr<rocksdb::OptimisticTransactionDB> transaction_db_;
    friend class RocksDbCommon;

    void prepareTransaction(RocksDBContext &tx_context) {
      assert(transaction_db_);
      tx_context.transaction.reset(
          transaction_db_->BeginTransaction(rocksdb::WriteOptions()));
    }
  };

#define RDB_ERROR_CHECK(...)                                               \
  if (auto _tmp_gen_var = (__VA_ARGS__); expected::hasError(_tmp_gen_var)) \
  return _tmp_gen_var.assumeError()

#define RDB_TRY_GET_VALUE(name, ...)                                       \
  typename decltype(__VA_ARGS__)::ValueInnerType name;                     \
  if (auto _tmp_gen_var = (__VA_ARGS__); expected::hasError(_tmp_gen_var)) \
    return _tmp_gen_var.assumeError();                                     \
  else                                                                     \
    name = std::move(_tmp_gen_var.assumeValue())

  /**
   * Base functions to interact with RocksDB data.
   */
  class RocksDbCommon {
    auto &transaction() {
      if (!tx_context_->transaction)
        tx_context_->db_port->prepareTransaction(*tx_context_);
      return tx_context_->transaction;
    }

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

    /// Makes commit to DB
    auto commit() {
      auto res = transaction()->Commit();
      transaction().reset();
      return res;
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
      return transaction()->Get(
          rocksdb::ReadOptions(),
          rocksdb::Slice(keyBuffer().data(), keyBuffer().size()),
          &valueBuffer());
    }

    /// Put data from @see valueBuffer to database
    template <typename S, typename... Args>
    auto put(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      return transaction()->Put(
          rocksdb::Slice(keyBuffer().data(), keyBuffer().size()),
          valueBuffer());
    }

    /// Delete database entry by the key
    template <typename S, typename... Args>
    auto del(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      return transaction()->Delete(
          rocksdb::Slice(keyBuffer().data(), keyBuffer().size()));
    }

    /// Searches for the first key that matches a prefix
    template <typename S, typename... Args>
    auto seek(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      std::unique_ptr<rocksdb::Iterator> it(
          transaction()->GetIterator(rocksdb::ReadOptions()));
      it->Seek(rocksdb::Slice(keyBuffer().data(), keyBuffer().size()));

      return it;
    }

    /// Iterate over all the keys that matches a prefix and call lambda
    /// with key-value. To stop enumeration callback F must return false.
    template <typename F, typename S, typename... Args>
    auto enumerate(F &&func, S const &fmtstring, Args &&... args) {
      auto it = seek(fmtstring, std::forward<Args>(args)...);
      if (!it->status().ok())
        return it->status();

      rocksdb::Slice const key(keyBuffer().data(), keyBuffer().size());
      for (; it->Valid() && it->key().starts_with(key); it->Next())
        if (!std::forward<F>(func)(it, key.size()))
          break;

      return it->status();
    }

   private:
    std::shared_ptr<RocksDBContext> tx_context_;
    std::lock_guard<std::mutex> context_guard_;
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
    return rdb.enumerate(
        [func{std::forward<F>(func)}](auto const &it,
                                      auto const prefix_size) mutable {
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

  /// Enumerating through all the keys matched to prefix and read the value
  template <typename F, typename S, typename... Args>
  inline auto enumerateKeysAndValues(RocksDbCommon &rdb,
                                     F &&func,
                                     S const &strformat,
                                     Args &&... args) {
    return rdb.enumerate(
        [func{std::forward<F>(func)}](auto const &it,
                                      auto const prefix_size) mutable {
          auto const key = it->key();
          return func(rocksdb::Slice(
                          key.data() + prefix_size + fmtstrings::kDelimiterSize,
                          key.size() - prefix_size
                              - fmtstrings::kDelimiterCountForAField
                                  * fmtstrings::kDelimiterSize),
                      it->value());
        },
        strformat,
        std::forward<Args>(args)...);
  }

  template <typename F>
  inline expected::Result<void, DbError> mustNotExist(
      rocksdb::Status const &status, F &&op_formatter) {
    if (status.IsNotFound())
      return {};

    if (!status.ok())
      return makeError<void>(12,
                             "{}. Failed with status: {}.",
                             std::forward<F>(op_formatter)(),
                             status.ToString());

    return makeError<void>(
        4, "{}. Must not exist.", std::forward<F>(op_formatter)());
  }

  template <typename F>
  inline expected::Result<void, DbError> mustExist(
      rocksdb::Status const &status, F &&op_formatter) {
    if (status.IsNotFound())
      return makeError<void>(
          3, "{}. Was not found.", std::forward<F>(op_formatter)());

    if (!status.ok())
      return makeError<void>(15,
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

    return makeError<void>(18,
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

    RDB_ERROR_CHECK(checkStatus<kSc>(
        status, std::forward<OperationDescribtionF>(op_formatter)));
    return status;
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
    assert(!domain.empty());
    assert(!account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Account {}@{}", account, domain); },
        fmtstrings::kQuorum,
        domain,
        account);
    RDB_ERROR_CHECK(status);

    std::optional<uint64_t> quorum;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok()) {
        uint64_t _;
        common.decode(_);
        quorum = _;
      }
    return quorum;
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
    assert(!role.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Find role {}", role); },
        fmtstrings::kRole,
        role);
    RDB_ERROR_CHECK(status);

    std::optional<shared_model::interface::RolePermissionSet> perm;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        perm = shared_model::interface::RolePermissionSet{common.valueBuffer()};

    return perm;
  }

  /**
   * Access to peers count file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<uint64_t>, DbError> forPeersCount(
      RocksDbCommon &common) {
    auto status =
        executeOperation<kOp, kSc>(common,
                                   [&] { return fmt::format("Peers count"); },
                                   fmtstrings::kPeersCount);
    RDB_ERROR_CHECK(status);

    std::optional<uint64_t> count;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok()) {
        uint64_t _;
        common.decode(_);
        count = _;
      }

    return count;
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
  forTransactionStatus(RocksDbCommon &common, std::string_view tx_hash) {
    assert(!tx_hash.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Transaction {}", tx_hash); },
        fmtstrings::kTransactionStatus,
        tx_hash);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> tx;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        tx = common.valueBuffer();

    return tx;
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
                           uint64_t height,
                           uint64_t index) {
    assert(!account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Transaction from {} by position {}:{}", account, height, index);
        },
        fmtstrings::kTransactionByPosition,
        account,
        height,
        index);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> tx;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        tx = common.valueBuffer();

    return tx;
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
                            uint64_t ts) {
    assert(!account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Transaction from {} by timestamp {}", account, ts);
        },
        fmtstrings::kTransactionByTs,
        account,
        ts);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> tx;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        tx = common.valueBuffer();

    return tx;
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
    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Setting {}", key); },
        fmtstrings::kSetting,
        key);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> value;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        value = common.valueBuffer();

    return value;
  }

  /**
   * Access to peer address file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param pubkey public key of the peer
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError>
  forPeerAddress(RocksDbCommon &common, std::string_view pubkey) {
    assert(!pubkey.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Peer {} address", pubkey); },
        fmtstrings::kPeerAddress,
        pubkey);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> address;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        address = common.valueBuffer();

    return address;
  }

  /**
   * Access to peer TLS file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @param common @see RocksDbCommon
   * @param pubkey is a public key of the peer
   * @return operation result
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kMustExist>
  inline expected::Result<std::optional<std::string_view>, DbError> forPeerTLS(
      RocksDbCommon &common, std::string_view pubkey) {
    assert(!pubkey.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Peer {} TLS", pubkey); },
        fmtstrings::kPeerTLS,
        pubkey);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> tls;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        tls = common.valueBuffer();

    return tls;
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
    assert(!domain.empty());
    assert(!asset.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Asset {}#{}", asset, domain); },
        fmtstrings::kAsset,
        domain,
        asset);
    RDB_ERROR_CHECK(status);

    std::optional<uint64_t> precision;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok()) {
        uint64_t _;
        common.decode(_);
        precision = _;
      }

    return precision;
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
    auto status =
        executeOperation<kOp, kSc>(common,
                                   [&] { return fmt::format("Top block"); },
                                   fmtstrings::kTopBlock);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> info;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        info = common.valueBuffer();

    return info;
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
  inline expected::Result<void, DbError> forAccountRole(
      RocksDbCommon &common,
      std::string_view account,
      std::string_view domain,
      std::string_view role) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!role.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Get account {}@{} role {}", account, domain, role);
        },
        fmtstrings::kAccountRole,
        domain,
        account,
        role);
    RDB_ERROR_CHECK(status);

    return {};
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
    assert(!domain.empty());
    assert(!account.empty());
    assert(!creator_id.empty());
    assert(!key.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format("Account {} detail for {}@{} with key {}",
                             creator_id,
                             account,
                             domain,
                             key);
        },
        fmtstrings::kAccountDetail,
        domain,
        account,
        creator_id,
        key);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> value;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        value = common.valueBuffer();

    return value;
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
  inline expected::Result<void, DbError> forSignatory(RocksDbCommon &common,
                                                      std::string_view account,
                                                      std::string_view domain,
                                                      std::string_view pubkey) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!pubkey.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Signatory {} for account {}@{}", pubkey, account, domain);
        },
        fmtstrings::kSignatory,
        domain,
        account,
        pubkey);
    RDB_ERROR_CHECK(status);
    return {};
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
    assert(!domain.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Domain {}", domain); },
        fmtstrings::kDomain,
        domain);
    RDB_ERROR_CHECK(status);

    std::optional<std::string_view> default_role;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        default_role = common.valueBuffer();

    return default_role;
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
    assert(!domain.empty());
    assert(!account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format("Account {}@{} asset size", account, domain);
        },
        fmtstrings::kAccountAssetSize,
        domain,
        account);
    RDB_ERROR_CHECK(status);

    std::optional<uint64_t> account_asset_size;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok()) {
        uint64_t _;
        common.decode(_);
        account_asset_size = _;
      }

    return account_asset_size;
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
    assert(!domain.empty());
    assert(!account.empty());
    assert(!asset.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format("Account {}@{} assets {}", account, domain, asset);
        },
        fmtstrings::kAccountAsset,
        domain,
        account,
        asset);
    RDB_ERROR_CHECK(status);

    std::optional<shared_model::interface::Amount> amount;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        amount.emplace(common.valueBuffer());

    return amount;
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
                          std::string_view grantee_account,
                          std::string_view grantee_domain) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!grantee_domain.empty());
    assert(!grantee_account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Get account {}@{} grantable permissions for {}@{}",
              account,
              domain,
              grantee_account,
              grantee_domain);
        },
        fmtstrings::kGranted,
        domain,
        account,
        grantee_domain,
        grantee_account);
    RDB_ERROR_CHECK(status);

    std::optional<shared_model::interface::GrantablePermissionSet> permissions;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.assumeValue().ok())
        permissions = shared_model::interface::GrantablePermissionSet{
            common.valueBuffer()};

    return permissions;
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
          3,
          "Enumerate account {}@{} roles failed with status: {}.",
          account,
          domain,
          status.ToString());

    if (roles.empty())
      return makeError<shared_model::interface::RolePermissionSet>(
          4, "Account {}@{} have ho roles.", account, domain);

    shared_model::interface::RolePermissionSet permissions;
    for (auto &role : roles) {
      auto opt_perm =
          forRole<kDbOperation::kGet, kDbEntry::kMustExist>(common, role);
      RDB_ERROR_CHECK(opt_perm);
      permissions |= *opt_perm.assumeValue();
    }

    return permissions;
  }

  inline expected::Result<void, DbError> checkPermissions(
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::permissions::Role const to_check) {
    if (permissions.isSet(to_check))
      return {};

    return makeError<void>(kErrorNoPermissions, "No permissions.");
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

    return makeError<void>(kErrorNoPermissions, "No permissions.");
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

    return makeError<void>(kErrorNoPermissions, "No permissions.");
  }

}  // namespace iroha::ametsuchi

#endif
