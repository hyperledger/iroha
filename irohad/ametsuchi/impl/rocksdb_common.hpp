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
#include <rocksdb/utilities/optimistic_transaction_db.h>
#include <rocksdb/utilities/transaction.h>
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
 *                |           |                 +-<peer_2, value:tls>
 *                |           |
 *                |           +-|STORE|-+-<store height>
 *                |                     +-<top block hash>
 *                |                     +-<transactions count>
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

#define RDB_PATH_DOMAIN RDB_ROOT /**/ RDB_WSV /**/ RDB_DOMAIN /**/ RDB_XXX
#define RDB_PATH_ACCOUNT RDB_PATH_DOMAIN /**/ RDB_ACCOUNTS /**/ RDB_XXX

namespace iroha::ametsuchi::fmtstrings {
  static constexpr size_t kDelimiterSize =
      sizeof(RDB_DELIMITER) / sizeof(RDB_DELIMITER[0]) - 1ul;

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

  /**
   * ######################################
   * ############# FOLDERS ################
   * ######################################
   */
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

  // domain_id/account_name/writer_domain_id/writer_account_name/key ➡️
  // value
  static auto constexpr kAccountDetail{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_DETAILS /**/ RDB_XXX /**/
                     RDB_XXX /**/ RDB_XXX)};

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

  // domain_id/account_name
  static auto constexpr kQuorum{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_QUORUM)};

  // account_domain_id/account_name ➡️ size
  static auto constexpr kAccountAssetSize{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_ASSET_SIZE)};
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

namespace {
  auto constexpr kValue{FMT_STRING("{}")};
}

namespace iroha::ametsuchi {

  /**
   * RocksDB transaction context.
   */
  struct RocksDBContext {
    /// RocksDB transaction
    std::unique_ptr<rocksdb::Transaction> transaction;

    /// Buffer for key data
    fmt::memory_buffer key_buffer;

    /// Buffer for value data
    std::string value_buffer;
  };

  /**
   * Port to provide access to RocksDB instance.
   */
  struct RocksDBPort : std::enable_shared_from_this<RocksDBPort> {
    RocksDBPort(RocksDBPort const &) = delete;
    RocksDBPort &operator=(RocksDBPort const &) = delete;
    RocksDBPort() = default;

    void initialize(std::string const &db_name) {
      rocksdb::Options options;
      options.create_if_missing = true;
      options.error_if_exists = true;

      rocksdb::OptimisticTransactionDB *transaction_db;
      auto status = rocksdb::OptimisticTransactionDB::Open(
          options, db_name, &transaction_db);
      transaction_db_.reset(transaction_db);

      if (!status.ok())
        throw std::runtime_error(status.ToString());
    }

    void prepareTransaction(RocksDBContext &tx_context) {
      assert(transaction_db_);
      tx_context.transaction.reset(
          transaction_db_->BeginTransaction(rocksdb::WriteOptions()));
      tx_context.key_buffer.clear();
      tx_context.value_buffer.clear();
    }

   private:
    std::unique_ptr<rocksdb::OptimisticTransactionDB> transaction_db_;
  };

  class IrohaDbError : public std::runtime_error {
    uint32_t code_;

   public:
    IrohaDbError(uint32_t code, std::string const &msg)
        : std::runtime_error(msg), code_{code} {}

    uint32_t code() const {
      return code_;
    }
  };

  /**
   * Base functions to interact with RocksDB data.
   */
  class RocksDbCommon {
    inline auto &transaction() {
      return tx_context_->transaction;
    }

   public:
    RocksDbCommon(std::shared_ptr<RocksDBContext> tx_context)
        : tx_context_(std::move(tx_context)) {
      assert(tx_context_);
    }

    /// Get value buffer
    inline auto &valueBuffer() {
      return tx_context_->value_buffer;
    }

    /// Get key buffer
    inline auto &keyBuffer() {
      return tx_context_->key_buffer;
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
          std::string_view(keyBuffer().data(), keyBuffer().size()),
          &valueBuffer());
    }

    /// Put data from @see valueBuffer to database
    template <typename S, typename... Args>
    auto put(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      return transaction()->Put(
          std::string_view(keyBuffer().data(), keyBuffer().size()),
          valueBuffer());
    }

    /// Delete database entry by the key
    template <typename S, typename... Args>
    auto del(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      return transaction()->Delete(
          std::string_view(keyBuffer().data(), keyBuffer().size()));
    }

    /// Searches for the first key that matches a prefix
    template <typename S, typename... Args>
    auto seek(S const &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, std::forward<Args>(args)...);

      std::unique_ptr<rocksdb::Iterator> it(
          transaction()->GetIterator(rocksdb::ReadOptions()));
      it->Seek(std::string_view(keyBuffer().data(), keyBuffer().size()));

      return it;
    }

    /// Iterate over all the keys that matches a prefix and call lambda
    /// with key-value. If lambda-callback returns false than loop breaks
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
    kAll,           /// entry must exist and data must be accessible
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
              key.size() - prefix_size - 2ull * fmtstrings::kDelimiterSize));
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
        [func{std::forward<F>(func)}](auto const &it, auto const prefix_size) {
          auto const key = it->key();
          return func(
              rocksdb::Slice(
                  key.data() + prefix_size + fmtstrings::kDelimiterSize,
                  key.size() - prefix_size - 2ull * fmtstrings::kDelimiterSize),
              it->value());
        },
        strformat,
        std::forward<Args>(args)...);
  }

  template <typename F>
  inline void mustNotExist(rocksdb::Status status, F &&op_formatter) {
    if (status.IsNotFound())
      return;

    if (!status.ok())
      throw IrohaDbError(12,
                         fmt::format("{}. Failed with status: {}.",
                                     std::forward<F>(op_formatter)(),
                                     status.ToString()));

    throw IrohaDbError(
        13, fmt::format("{}. Exists.", std::forward<F>(op_formatter)()));
  }

  template <typename F>
  inline void mustExist(rocksdb::Status status, F &&op_formatter) {
    if (status.IsNotFound())
      throw IrohaDbError(
          14,
          fmt::format("{}. Was not found.", std::forward<F>(op_formatter)()));

    if (!status.ok())
      throw IrohaDbError(15,
                         fmt::format("{}. Failed with status: {}.",
                                     std::forward<F>(op_formatter)(),
                                     status.ToString()));
  }

  template <typename F>
  inline void canExist(rocksdb::Status status, F &&op_formatter) {
    if (status.IsNotFound() || status.ok())
      return;

    throw IrohaDbError(18,
                       fmt::format("{}. Failed with status: {}.",
                                   std::forward<F>(op_formatter)(),
                                   status.ToString()));
  }

  template <kDbEntry kSc, typename F>
  static void checkStatus(rocksdb::Status status, F &&op_formatter) {
    if constexpr (kSc == kDbEntry::kAll || kSc == kDbEntry::kMustExist)
      return mustExist(status, std::forward<F>(op_formatter));
    else if constexpr (kSc == kDbEntry::kMustNotExist)
      return mustNotExist(status, std::forward<F>(op_formatter));
    else if constexpr (kSc == kDbEntry::kCanExist)
      return canExist(status, std::forward<F>(op_formatter));
    else
      assert(!"Unexpected status check value");
  }

  template <kDbOperation kOp, kDbEntry kSc, typename F, typename... Args>
  rocksdb::Status executeOperation(RocksDbCommon &common,
                                   F &&op_formatter,
                                   Args &&... args) {
    rocksdb::Status status;
    if constexpr (kOp == kDbOperation::kGet || kOp == kDbOperation::kCheck)
      status = common.get(std::forward<Args>(args)...);
    else if constexpr (kOp == kDbOperation::kPut)
      status = common.put(std::forward<Args>(args)...);
    else if constexpr (kOp == kDbOperation::kDel)
      status = common.del(std::forward<Args>(args)...);
    else
      assert(!"Unexpected operation value!");

    checkStatus<kSc>(status, std::forward<F>(op_formatter));
    return status;
  }

  /**
   * Access to account quorum file.
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forQuorum(RocksDbCommon &common,
                        std::string_view domain,
                        std::string_view account,
                        F &&func) {
    assert(!domain.empty());
    assert(!account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Account {}#{}", account, domain); },
        fmtstrings::kQuorum,
        domain,
        account);

    std::optional<uint64_t> quorum;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok()) {
        uint64_t _;
        common.decode(_);
        quorum = _;
      }

    return std::forward<F>(func)(account, domain, std::move(quorum));
  }

  /**
   * Access to account folder
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forAccount(RocksDbCommon &common,
                         std::string_view domain,
                         std::string_view account,
                         F &&func) {
    return forQuorum<kOp, kSc>(
        common,
        domain,
        account,
        [func{std::forward<F>(func)}](
            auto account, auto domain, auto /*quorum*/) mutable {
          return std::forward<F>(func)(account, domain);
        });
  }

  /**
   * Access to role file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param role id
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forRole(RocksDbCommon &common, std::string_view role, F &&func) {
    assert(!role.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Find role {}", role); },
        fmtstrings::kRole,
        role);

    std::optional<shared_model::interface::RolePermissionSet> perm;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        perm = shared_model::interface::RolePermissionSet{common.valueBuffer()};

    return std::forward<F>(func)(role, std::move(perm));
  }

  /**
   * Access to setting file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param key setting name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forSettings(RocksDbCommon &common,
                          std::string_view key,
                          F &&func) {
    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Setting {}", key); },
        fmtstrings::kSetting,
        key);

    std::optional<std::string> value;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        value = common.valueBuffer();

    return std::forward<F>(func)(key, std::move(value));
  }

  /**
   * Access to peer address file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param pubkey public key of the peer
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forPeerAddress(RocksDbCommon &common,
                             std::string_view pubkey,
                             F &&func) {
    assert(!pubkey.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Peer {} address", pubkey); },
        fmtstrings::kPeerAddress,
        pubkey);

    std::optional<std::string> address;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        address = common.valueBuffer();

    return std::forward<F>(func)(pubkey, std::move(address));
  }

  /**
   * Access to peer TLS file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param pubkey is a public key of the peer
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forPeerTLS(RocksDbCommon &common,
                         std::string_view pubkey,
                         F &&func) {
    assert(!pubkey.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Peer {} TLS", pubkey); },
        fmtstrings::kPeerTLS,
        pubkey);

    std::optional<std::string> tls;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        tls = common.valueBuffer();

    return std::forward<F>(func)(pubkey, std::move(tls));
  }

  /**
   * Access to asset file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain is
   * @param asset name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forAsset(RocksDbCommon &common,
                       std::string_view domain,
                       std::string_view asset,
                       F &&func) {
    assert(!domain.empty());
    assert(!asset.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Asset {}#{}", asset, domain); },
        fmtstrings::kAsset,
        domain,
        asset);

    std::optional<uint64_t> precision;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok()) {
        uint64_t _;
        common.decode(_);
        precision = _;
      }

    return std::forward<F>(func)(asset, domain, std::move(precision));
  }

  /**
   * Access to account role file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param role id
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forAccountRole(RocksDbCommon &common,
                             std::string_view domain,
                             std::string_view account,
                             std::string_view role,
                             F &&func) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!role.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Get account {}#{} role {}", account, domain, role);
        },
        fmtstrings::kAccountRole,
        domain,
        account,
        role);

    return std::forward<F>(func)(account, domain, role);
  }

  /**
   * Access to account details file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param creator_domain id
   * @param creator_account name
   * @param key name of the details entry
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forAccountDetail(RocksDbCommon &common,
                               std::string_view domain,
                               std::string_view account,
                               std::string_view creator_domain,
                               std::string_view creator_account,
                               std::string_view key,
                               F &&func) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!creator_domain.empty());
    assert(!creator_account.empty());
    assert(!key.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format("Account {}#{} detail for {}#{} with key {}",
                             account,
                             domain,
                             creator_account,
                             creator_domain,
                             key);
        },
        fmtstrings::kAccountDetail,
        domain,
        account,
        creator_domain,
        creator_account,
        key);

    std::optional<std::string> value;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        value = common.valueBuffer();

    return std::forward<F>(func)(account,
                                 domain,
                                 creator_account,
                                 creator_domain,
                                 key,
                                 std::move(value));
  }

  /**
   * Access to account signatory file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param pubkey public key of the signatory
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forSignatory(RocksDbCommon &common,
                           std::string_view domain,
                           std::string_view account,
                           std::string_view pubkey,
                           F &&func) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!pubkey.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Signatory {} for account {}#{}", pubkey, account, domain);
        },
        fmtstrings::kSignatory,
        domain,
        account,
        pubkey);

    return std::forward<F>(func)(account, domain, pubkey);
  }

  /**
   * Access to domain file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kAll,
            typename F>
  inline auto forDomain(RocksDbCommon &common,
                        std::string_view domain,
                        F &&func) {
    assert(!domain.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] { return fmt::format("Domain {}", domain); },
        fmtstrings::kDomain,
        domain);

    std::optional<std::string> default_role;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        default_role = common.valueBuffer();

    return std::forward<F>(func)(domain, std::move(default_role));
  }

  /**
   * Access to account size file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kCanExist,
            typename F>
  inline auto forAccountAssetSize(RocksDbCommon &common,
                                  std::string_view domain,
                                  std::string_view account,
                                  F &&func) {
    assert(!domain.empty());
    assert(!account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format("Account {}#{} asset size", account, domain);
        },
        fmtstrings::kAccountAssetSize,
        domain,
        account);

    std::optional<uint64_t> account_asset_size;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok()) {
        uint64_t _;
        common.decode(_);
        account_asset_size = _;
      }
    return std::forward<F>(func)(
        account, domain, std::move(account_asset_size));
  }

  /**
   * Access to account assets file
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param asset name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kCanExist,
            typename F>
  inline auto forAccountAssets(RocksDbCommon &common,
                               std::string_view domain,
                               std::string_view account,
                               std::string_view asset,
                               F &&func) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!asset.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format("Account {}#{} assets {}", account, domain, asset);
        },
        fmtstrings::kAccountAsset,
        domain,
        account,
        asset);

    std::optional<shared_model::interface::Amount> amount;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        amount = shared_model::interface::Amount(common.valueBuffer());

    return std::forward<F>(func)(account, domain, asset, std::move(amount));
  }

  /**
   * Access to account grantable permissions
   * @tparam kOp @see kDbOperation
   * @tparam kSc @see kDbEntry
   * @tparam F callback with operation result
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @param grantee_domain id
   * @param grantee_account name
   * @param func callback with the result
   * @return determined by the callback
   */
  template <kDbOperation kOp = kDbOperation::kGet,
            kDbEntry kSc = kDbEntry::kCanExist,
            typename F>
  inline auto forGrantablePermissions(RocksDbCommon &common,
                                      std::string_view domain,
                                      std::string_view account,
                                      std::string_view grantee_domain,
                                      std::string_view grantee_account,
                                      F &&func) {
    assert(!domain.empty());
    assert(!account.empty());
    assert(!grantee_domain.empty());
    assert(!grantee_account.empty());

    auto status = executeOperation<kOp, kSc>(
        common,
        [&] {
          return fmt::format(
              "Get account {}#{} grantable permissions for {}#{}",
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

    std::optional<shared_model::interface::GrantablePermissionSet> permissions;
    if constexpr (kOp == kDbOperation::kGet)
      if (status.ok())
        permissions = shared_model::interface::GrantablePermissionSet{
            common.valueBuffer()};

    return std::forward<F>(func)(account,
                                 domain,
                                 grantee_account,
                                 grantee_domain,
                                 std::move(permissions));
  }

  /**
   * Get all permissions for the account
   * @param common @see RocksDbCommon
   * @param domain id
   * @param account name
   * @return permission set for the account
   */
  inline shared_model::interface::RolePermissionSet accountPermissions(
      RocksDbCommon &common,
      std::string_view domain,
      std::string_view account) {
    assert(!domain.empty());
    assert(!account.empty());

    /// TODO(iceseer): remove this vector!
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
      throw IrohaDbError(
          3,
          fmt::format("Enumerate account {}#{} roles failed with status: {}.",
                      account,
                      domain,
                      status.ToString()));

    if (roles.empty())
      throw IrohaDbError(
          4, fmt::format("Account {}#{} have ho roles.", account, domain));

    shared_model::interface::RolePermissionSet permissions;
    for (auto &role : roles)
      permissions |=
          *forRole(common, role, [](auto /*role*/, auto perm) { return perm; });

    return permissions;
  }

  inline void checkPermissions(
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::permissions::Role const to_check) {
    if (permissions.isSet(to_check))
      return;

    throw IrohaDbError(11, fmt::format("No permissions."));
  }

  inline void checkPermissions(
      std::string_view domain_id,
      std::string_view creator_domain_id,
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::permissions::Role const all,
      shared_model::interface::permissions::Role const domain) {
    if (permissions.isSet(all))
      return;

    if (domain_id == creator_domain_id && permissions.isSet(domain))
      return;

    throw IrohaDbError(7, fmt::format("No permissions."));
  }

  inline void checkPermissions(
      shared_model::interface::RolePermissionSet const &permissions,
      shared_model::interface::GrantablePermissionSet const
          &grantable_permissions,
      shared_model::interface::permissions::Role const role,
      shared_model::interface::permissions::Grantable const granted) {
    if (permissions.isSet(role))
      return;

    if (grantable_permissions.isSet(granted))
      return;

    throw IrohaDbError(14, fmt::format("No permissions."));
  }

}  // namespace iroha::ametsuchi

#endif
