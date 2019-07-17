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

namespace iroha {
  namespace ametsuchi {

    using shared_model::interface::types::AccountIdType;
    using shared_model::interface::types::AddressType;
    using shared_model::interface::types::PubkeyType;

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
      using T = boost::tuple<std::string, AddressType>;
      auto result = execute<T>([&] {
        return (sql_.prepare << "SELECT public_key, address FROM peer");
      });

      return flatMapValues<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>(
          result, [&](auto &public_key, auto &address) {
            return boost::make_optional(
                std::make_shared<shared_model::plain::Peer>(
                    address,
                    shared_model::crypto::PublicKey{
                        shared_model::crypto::Blob::fromHexString(
                            public_key)}));
          });
    }
  }  // namespace ametsuchi
}  // namespace iroha
