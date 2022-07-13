/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_wsv_query.hpp"

#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "backend/plain/peer.hpp"
#include "common/common.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"

namespace iroha::ametsuchi {

  using shared_model::interface::types::AccountIdType;
  using shared_model::interface::types::AddressType;
  using shared_model::interface::types::TLSCertificateType;

  template <typename T, typename Func, typename Error>
  boost::optional<T> execute(std::shared_ptr<RocksDBContext> &context,
                             logger::LoggerPtr &log,
                             Func &&func,
                             Error &&error) {
    assert(log);

    RocksDbCommon common(context);
    if (auto result = std::forward<Func>(func)(common);
        expected::hasError(result)) {
      log->error("Command: {}, DB error: {} with description {}",
                 std::forward<Error>(error)(),
                 result.assumeError().code,
                 result.assumeError().description);
      return boost::none;
    } else
      return std::move(result.assumeValue());
  }

  RocksDBWsvQuery::RocksDBWsvQuery(std::shared_ptr<RocksDBContext> db_context,
                                   logger::LoggerPtr log)
      : db_context_(std::move(db_context)), log_(std::move(log)) {
    assert(db_context_);
  }

  boost::optional<std::vector<std::string>> RocksDBWsvQuery::getSignatories(
      const AccountIdType &account_id) {
    using RetType = std::vector<std::string>;
    return execute<RetType>(
        db_context_,
        log_,
        [&](auto &common) -> expected::Result<RetType, DbError> {
          auto names = staticSplitId<2ull>(account_id);
          auto &account_name = names.at(0);
          auto &domain_id = names.at(1);

          RetType signatories;
          auto const status = enumerateKeys(
              common,
              [&](auto const &signatory) {
                signatories.emplace_back(signatory.ToStringView());
                return true;
              },
              RocksDBPort::ColumnFamilyType::kWsv,
              fmtstrings::kPathSignatories,
              domain_id,
              account_name);
          RDB_ERROR_CHECK(canExist(status, [&]() {
            return fmt::format("Enumerate signatories for account {}",
                               account_id);
          }));
          return signatories;
        },
        [&]() {
          return fmt::format("Get signatories for account {}", account_id);
        });
  }

  boost::optional<std::vector<std::shared_ptr<shared_model::interface::Peer>>>
  RocksDBWsvQuery::getPeers(bool syncing_peers) {
    using RetType = std::vector<std::shared_ptr<shared_model::interface::Peer>>;
    return execute<RetType>(
        db_context_,
        log_,
        [&](auto &common) -> expected::Result<RetType, DbError> {
          RetType peers;

          auto callback = [&](auto pubkey, auto address) {
            if (!pubkey.empty())
              peers.emplace_back(std::make_shared<shared_model::plain::Peer>(
                  address.ToStringView(),
                  std::string{pubkey.ToStringView()},
                  std::nullopt,
                  syncing_peers));
            else
              assert(!"Pubkey can not be empty!");

            return true;
          };

          rocksdb::Status status;
          if (syncing_peers)
            status = enumerateKeysAndValues(common,
                                            std::move(callback),
                                            RocksDBPort::ColumnFamilyType::kWsv,
                                            fmtstrings::kPathSPeers);
          else
            status = enumerateKeysAndValues(common,
                                            std::move(callback),
                                            RocksDBPort::ColumnFamilyType::kWsv,
                                            fmtstrings::kPathPeers);

          RDB_ERROR_CHECK(canExist(
              status, [&]() { return fmt::format("Enumerate peers"); }));

          for (auto &peer : peers) {
            RDB_TRY_GET_VALUE(
                opt_tls,
                forPeerTLS<kDbOperation::kGet, kDbEntry::kCanExist>(
                    common, peer->pubkey(), syncing_peers));

            if (opt_tls)
              utils::reinterpret_pointer_cast<shared_model::plain::Peer>(peer)
                  ->setTlsCertificate(
                      shared_model::interface::types::TLSCertificateType{
                          *opt_tls});
          }

          return peers;
        },
        [&]() { return fmt::format("Get peers"); });
  }

  boost::optional<std::shared_ptr<shared_model::interface::Peer>>
  RocksDBWsvQuery::getPeerByPublicKey(
      shared_model::interface::types::PublicKeyHexStringView public_key) {
    using RetType = std::shared_ptr<shared_model::interface::Peer>;
    return execute<RetType>(
        db_context_,
        log_,
        [&](auto &common) -> expected::Result<RetType, DbError> {
          auto pubkey = (std::string_view)public_key;

          std::string result;
          std::transform(pubkey.begin(),
                         pubkey.end(),
                         std::back_inserter(result),
                         [](auto c) { return std::tolower(c); });

          bool syncing_node = false;
          auto res = forPeerAddress<kDbOperation::kGet, kDbEntry::kMustExist>(
              common, result, syncing_node);
          if (expected::hasError(res)) {
            syncing_node = true;
            if (res = forPeerAddress<kDbOperation::kGet, kDbEntry::kMustExist>(
                    common, result, syncing_node);
                expected::hasError(res))
              return res.assumeError();
          }

          auto peer = std::make_shared<shared_model::plain::Peer>(
              std::move(*res.assumeValue()),
              std::string(pubkey),
              std::nullopt,
              syncing_node);

          RDB_TRY_GET_VALUE(opt_tls,
                            forPeerTLS<kDbOperation::kGet, kDbEntry::kCanExist>(
                                common, result, syncing_node));
          if (opt_tls)
            peer->setTlsCertificate(*opt_tls);

          return peer;
        },
        [&]() {
          return fmt::format("Get peer by pubkey {}",
                             (std::string_view)public_key);
        });
  }

  iroha::expected::Result<iroha::TopBlockInfo, std::string>
  RocksDBWsvQuery::getTopBlockInfo() const {
    RocksDbCommon common(db_context_);
    if (auto result =
            forTopBlockInfo<kDbOperation::kGet, kDbEntry::kMustExist>(common);
        expected::hasError(result)) {
      auto err_msg = fmt::format(
          "Command: get top block info, DB error: {} with description {}",
          result.assumeError().code,
          result.assumeError().description);
      log_->error(err_msg);
      return expected::makeError(std::move(err_msg));
    } else {
      auto const data = staticSplitId<2ull>(*result.assumeValue());
      auto const &height_str = data.at(0);
      auto const &hash_str = data.at(1);

      assert(!height_str.empty());
      assert(!hash_str.empty());

      uint64_t number;
      auto [ptr, ec]{std::from_chars(
          height_str.data(), height_str.data() + height_str.size(), number)};
      if (ec == std::errc())
        return iroha::TopBlockInfo(
            number,
            shared_model::crypto::Hash(
                shared_model::crypto::Blob::fromHexString(
                    std::string{hash_str})));
      else
        return expected::makeError(
            "Height in top block info is not a valid number.");
    }
  }

  iroha::expected::Result<size_t, std::string> RocksDBWsvQuery::countPeers(
      bool syncing_peers) {
    RocksDbCommon common(db_context_);
    RDB_TRY_GET_VALUE_OR_STR_ERR(
        opt_count,
        forPeersCount<kDbOperation::kGet, kDbEntry::kMustExist>(common,
                                                                syncing_peers));

    return *opt_count;
  }

  iroha::expected::Result<size_t, std::string> RocksDBWsvQuery::countDomains() {
    RocksDbCommon common(db_context_);
    RDB_TRY_GET_VALUE_OR_STR_ERR(
        opt_count,
        forDomainsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(common));

    return opt_count ? *opt_count : 0ull;
  }

  iroha::expected::Result<size_t, std::string>
  RocksDBWsvQuery::countTransactions() {
    RocksDbCommon common(db_context_);
    RDB_TRY_GET_VALUE_OR_STR_ERR(
        opt_count,
        forTxsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(common));

    return opt_count ? *opt_count : 0ull;
  }

}  // namespace iroha::ametsuchi
