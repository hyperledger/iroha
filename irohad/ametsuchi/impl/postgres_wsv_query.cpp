/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_wsv_query.hpp"

#include <soci/boost-tuple.h>
#include "ametsuchi/impl/soci_utils.hpp"
#include "backend/plain/peer.hpp"
#include "common/result.hpp"
#include "cryptography/public_key.hpp"
#include "logger/logger.hpp"

namespace {
  template <typename T>
  boost::optional<std::vector<std::shared_ptr<shared_model::interface::Peer>>>
  getPeersFromSociRowSet(T &&rowset) {
    return iroha::ametsuchi::flatMapValues<
        std::vector<std::shared_ptr<shared_model::interface::Peer>>>(
        std::forward<T>(rowset),
        [&](auto &public_key, auto &address, auto &tls_certificate) {
          return boost::make_optional(
              std::make_shared<shared_model::plain::Peer>(
                  address,
                  shared_model::crypto::PublicKey{
                      shared_model::crypto::Blob::fromHexString(public_key)},
                  tls_certificate));
        });
  }
}  // namespace

namespace iroha {
  namespace ametsuchi {

    using shared_model::interface::types::AccountIdType;
    using shared_model::interface::types::AddressType;
    using shared_model::interface::types::PubkeyType;
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

    boost::optional<std::vector<PubkeyType>> PostgresWsvQuery::getSignatories(
        const AccountIdType &account_id) {
      using T = boost::tuple<std::string>;
      auto result = execute<T>([&] {
        return (sql_.prepare
                    << "SELECT public_key FROM account_has_signatory WHERE "
                       "account_id = :account_id",
                soci::use(account_id));
      });

      return mapValues<std::vector<PubkeyType>>(result, [&](auto &public_key) {
        return shared_model::crypto::PublicKey{
            shared_model::crypto::Blob::fromHexString(public_key)};
      });
    }

    boost::optional<std::vector<std::shared_ptr<shared_model::interface::Peer>>>
    PostgresWsvQuery::getPeers() {
      using T = boost::
          tuple<std::string, AddressType, boost::optional<TLSCertificateType>>;
      auto result = execute<T>([&] {
        return (sql_.prepare
                << "SELECT public_key, address, tls_certificate FROM peer");
      });

      return getPeersFromSociRowSet(result);
    }

    boost::optional<std::shared_ptr<shared_model::interface::Peer>>
    PostgresWsvQuery::getPeerByPublicKey(const PubkeyType &public_key) {
      using T = boost::
          tuple<std::string, AddressType, boost::optional<TLSCertificateType>>;
      auto result = execute<T>([&] {
        return (sql_.prepare << R"(
            SELECT public_key, address, tls_certificate
            FROM peer
            WHERE public_key = :public_key)",
                soci::use(public_key.hex(), "public_key"));
      });

      return getPeersFromSociRowSet(result) | [](auto &&peers)
                 -> boost::optional<
                     std::shared_ptr<shared_model::interface::Peer>> {
        if (!peers.empty()) {
          assert(peers.size() == 1);
          return boost::make_optional(std::move(peers.front()));
        }
        return boost::none;
      };
    }
  }  // namespace ametsuchi
}  // namespace iroha
