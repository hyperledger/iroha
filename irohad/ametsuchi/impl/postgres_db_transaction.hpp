/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_DB_TRANSACTION_HPP
#define IROHA_POSTGRES_DB_TRANSACTION_HPP

#include "ametsuchi/impl/db_transaction.hpp"

#include <soci/soci.h>

namespace iroha::ametsuchi {

  class PostgresDbTransaction final : public DatabaseTransaction {
   public:
    PostgresDbTransaction(PostgresDbTransaction const &) = delete;
    PostgresDbTransaction(PostgresDbTransaction &&) = delete;

    PostgresDbTransaction &operator=(PostgresDbTransaction const &) = delete;
    PostgresDbTransaction &operator=(PostgresDbTransaction &&) = delete;

    PostgresDbTransaction(soci::session &sql) : sql_(sql) {}

    void begin() override {
      sql_ << "BEGIN";
    }

    void prepare(std::string const &name) override {
      sql_ << "PREPARE TRANSACTION '" + name + "';";
    }

    void commitPrepared(std::string const &name) override {
      sql_ << "COMMIT PREPARED '" + name + "';";
    }

    void savepoint(std::string const &name) override {
      sql_ << "SAVEPOINT " + name + ";";
    }

    void releaseSavepoint(std::string const &name) override {
      sql_ << "RELEASE SAVEPOINT " + name + ";";
    }

    void commit() override {
      sql_ << "COMMIT";
    }

    void rollback() override {
      sql_ << "ROLLBACK";
    }

    void rollbackToSavepoint(std::string const &name) override {
      sql_ << "ROLLBACK TO SAVEPOINT " + name + ";";
    }

   private:
    soci::session &sql_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_DB_TRANSACTION_HPP
