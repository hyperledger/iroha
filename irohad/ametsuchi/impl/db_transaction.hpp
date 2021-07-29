/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_DB_TRANSACTION_HPP
#define IROHA_DB_TRANSACTION_HPP

#include <string>

namespace iroha::ametsuchi {

  class DatabaseTransaction {
   public:
    virtual void begin() = 0;
    virtual void savepoint(std::string const &name) = 0;
    virtual void commit() = 0;
    virtual void rollback() = 0;
    virtual void rollbackToSavepoint(std::string const &name) = 0;
    virtual void releaseSavepoint(std::string const &name) = 0;
    virtual void prepare(std::string const &name) = 0;
    virtual void commitPrepared(std::string const &name) = 0;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_DB_TRANSACTION_HPP
