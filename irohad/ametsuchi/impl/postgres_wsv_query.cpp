/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_wsv_query.hpp"

#include <soci/boost-tuple.h>

#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "backend/plain/peer.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"

namespace {
  template <typename T>
  boost::optional<std::vector<std::shared_ptr<shared_model::interface::Peer>>>
  getPeersFromSociRowSet(T &&rowset, bool syncing_peer) {
    return iroha::ametsuchi::flatMapValues<
        std::vector<std::shared_ptr<shared_model::interface::Peer>>>(
        std::forward<T>(rowset),
        [&](auto &public_key, auto &address, auto &tls_certificate) {
          return boost::make_optional(
              std::make_shared<shared_model::plain::Peer>(address,
                                                          std::move(public_key),
                                                          tls_certificate,
                                                          syncing_peer));
        });
  }
}  // namespace

namespace iroha {
  namespace ametsuchi {

    using shared_model::interface::types::AccountIdType;
    using shared_model::interface::types::AddressType;
    using shared_model::interface::types::TLSCertificateType;

    PostgresWsvQuery::PostgresWsvQuery(soci::session &sql,
                                       logger::LoggerPtr log)
        : sql_(sql), log_(std::move(log)) {}

    PostgresWsvQuery::PostgresWsvQuery(std::unique_ptr<soci::session> sql,
                                       logger::LoggerPtr log)
        : psql_(std::move(sql)), sql_(*psql_), log_(std::move(log)) {}

    template <typename T, typename F>
    auto PostgresWsvQuery::execute(F &&f) -> boost::optional<soci::rowset<T>> {
      try {
        return soci::rowset<T>{std::forward<F>(f)()};
      } catch (const std::exception &e) {
        log_->error("Failed to execute query: {}", e.what());
        return boost::none;
      }
    }

    boost::optional<std::vector<std::string>> PostgresWsvQuery::getSignatories(
        const AccountIdType &account_id) {
      using T = boost::tuple<std::string>;
      auto result = execute<T>([&] {
        return (sql_.prepare
                    << "SELECT public_key FROM account_has_signatory WHERE "
                       "account_id = :account_id",
                soci::use(account_id));
      });

      return mapValues<std::vector<std::string>>(
          result, [&](auto &public_key) { return public_key; });
    }

    boost::optional<std::vector<std::shared_ptr<shared_model::interface::Peer>>>
    PostgresWsvQuery::getPeers(bool syncing_peers) {
      using T = boost::
          tuple<std::string, AddressType, std::optional<TLSCertificateType>>;
      auto result = execute<T>([&] {
        return (
            sql_.prepare
            << (syncing_peers
                    ? "SELECT public_key, address, tls_certificate FROM "
                      "sync_peer"
                    : "SELECT public_key, address, tls_certificate FROM peer"));
      });

      return getPeersFromSociRowSet(result, syncing_peers);
    }

    iroha::expected::Result<size_t, std::string> PostgresWsvQuery::count(
        std::string_view table, std::string_view column /* ="*" */) try {
      int count;
      sql_ << "SELECT count(" << column << ") FROM " << table,
          soci::into(count);
      return count;
    } catch (const std::exception &e) {
      auto msg = fmt::format("Failed to count {}, query: {}", table, e.what());
      log_->error(msg);
      return iroha::expected::makeError(msg);
    }

    iroha::expected::Result<size_t, std::string> PostgresWsvQuery::countPeers(
        bool syncing_peers) {
      return count(syncing_peers ? "sync_peer" : "peer");
    }

    iroha::expected::Result<size_t, std::string>
    PostgresWsvQuery::countDomains() {
      return count("domain");
    }

    iroha::expected::Result<size_t, std::string>
    PostgresWsvQuery::countTransactions() {
      return count("tx_positions", "DISTINCT hash");
      // OR return count("tx_status_from_hash", "*", "WHERE status=true");
      // //select count(*) from tx_status_by_hash where status=true
    }

    boost::optional<std::shared_ptr<shared_model::interface::Peer>>
    PostgresWsvQuery::getPeerByPublicKey(
        shared_model::interface::types::PublicKeyHexStringView public_key) {
      using T = boost::
          tuple<std::string, AddressType, std::optional<TLSCertificateType>>;
      std::string target_public_key{public_key};
      auto result = execute<T>([&] {
        return (sql_.prepare << R"(
            SELECT public_key, address, tls_certificate FROM peer WHERE public_key = :public_key
            UNION
            SELECT public_key, address, tls_certificate FROM sync_peer WHERE public_key = :public_key)",
                soci::use(target_public_key, "public_key"));
      });

      return getPeersFromSociRowSet(result, false) | [](auto &&peers)
                 -> boost::optional<
                     std::shared_ptr<shared_model::interface::Peer>> {
        if (!peers.empty()) {
          assert(peers.size() == 1);
          return boost::make_optional(std::move(peers.front()));
        }
        return boost::none;
      };
    }

    iroha::expected::Result<iroha::TopBlockInfo, std::string>
    PostgresWsvQuery::getTopBlockInfo() const {
      try {
        soci::rowset<boost::tuple<size_t, std::string>> rowset(
            sql_.prepare << "select height, hash from top_block_info;");
        auto range = boost::make_iterator_range(rowset.begin(), rowset.end());
        if (range.empty()) {
          return "No top block information in WSV.";
        }
        shared_model::interface::types::HeightType height = 0;
        std::string hex_hash;
        boost::tie(height, hex_hash) = range.front();
        shared_model::crypto::Hash hash(
            shared_model::crypto::Blob::fromHexString(hex_hash));
        assert(not hash.blob().empty());
        return iroha::TopBlockInfo{height, hash};
      } catch (std::exception &e) {
        return e.what();
      }
    }

  }  // namespace ametsuchi
}  // namespace iroha
