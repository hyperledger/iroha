/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_wsv_query.hpp"

#include <soci/boost-tuple.h>
#include "ametsuchi/impl/soci_utils.hpp"
#include "backend/plain/peer.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/public_key.hpp"
#include "logger/logger.hpp"

using namespace iroha::expected;

using iroha::operator|;

namespace {
  template <typename T>
  Result<std::vector<std::shared_ptr<shared_model::interface::Peer>>,
         std::string>
  getPeersFromSociRowSet(T &&rowset) {
    return std::forward<T>(rowset) | [](auto &&rowset) {
      auto create_peer = [](auto &public_key,
                            auto &address,
                            auto &tls_certificate) {
        return shared_model::crypto::Blob::fromHexString(public_key) |
            [&address, &tls_certificate](
                   std::shared_ptr<shared_model::crypto::Blob> &&public_key) {
              return std::make_shared<shared_model::plain::Peer>(
                  address,
                  shared_model::crypto::PublicKey{std::move(public_key)},
                  tls_certificate);
            };
      };
      return resultsToResultOfValues<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>(
          rowset | boost::adaptors::transformed([&](auto &t) {
            return iroha::ametsuchi::apply(t, create_peer);
          }));
    };
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
      return execute<boost::tuple<std::string>>([&] {
               return (
                   sql_.prepare
                       << "SELECT public_key FROM account_has_signatory WHERE "
                          "account_id = :account_id",
                   soci::use(account_id));
             })
          |
          [&](auto &&result) {
            auto create_public_key = [](auto &public_key) {
              return shared_model::crypto::Blob::fromHexString(public_key) |
                  [](auto &&public_key) {
                    return shared_model::crypto::PublicKey{
                        std::move(public_key)};
                  };
            };
            auto signatories = resultsToResultOfValues<std::vector<PubkeyType>>(
                result | boost::adaptors::transformed([&](auto &t) {
                  return iroha::ametsuchi::apply(t, create_public_key);
                }));

            if (auto e = resultToOptionalError(signatories)) {
              log_->error("getSignatories({}): {}", account_id, e.value());
            }
            return resultToOptionalValue(signatories);
          };
    }

    boost::optional<std::vector<std::shared_ptr<shared_model::interface::Peer>>>
    PostgresWsvQuery::getPeers() {
      using T = boost::
          tuple<std::string, AddressType, boost::optional<TLSCertificateType>>;
      auto rowset = execute<T>([&] {
        return (sql_.prepare
                << "SELECT public_key, address, tls_certificate FROM peer");
      });

      auto peers = getPeersFromSociRowSet(rowset);
      if (auto e = resultToOptionalError(peers)) {
        log_->error("getPeers(): {}", e.value());
      }
      return resultToOptionalValue(peers);
    }

    boost::optional<std::shared_ptr<shared_model::interface::Peer>>
    PostgresWsvQuery::getPeerByPublicKey(const PubkeyType &public_key) {
      using T = boost::
          tuple<std::string, AddressType, boost::optional<TLSCertificateType>>;
      auto rowset = execute<T>([&] {
        return (sql_.prepare << R"(
            SELECT public_key, address, tls_certificate
            FROM peer
            WHERE public_key = :public_key)",
                soci::use(public_key.hex(), "public_key"));
      });

      using ReturnType =
          boost::optional<std::shared_ptr<shared_model::interface::Peer>>;
      return getPeersFromSociRowSet(rowset).match(
          [](auto &&peers) -> ReturnType {
            if (not peers.value.empty()) {
              assert(peers.value.size() == 1);
              return boost::make_optional(std::move(peers.value.front()));
            }
            return boost::none;
          },
          [&](const auto &error) -> ReturnType {
            log_->error("getPeerByPublicKey({}): {}", public_key, error.error);
            return boost::none;
          });
    }
  }  // namespace ametsuchi
}  // namespace iroha
