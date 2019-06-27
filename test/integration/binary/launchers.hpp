/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_LAUNCHERS_HPP
#define IROHA_LAUNCHERS_HPP

#include <chrono>
#include <string>

#include <boost/process.hpp>
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/transaction.hpp"
#include "cryptography/keypair.hpp"

namespace binary_test {

  /**
   * Specifies interface for running language-dependent generators of
   * transactions' and queries' binaries for test cases.
   */
  class Launcher {
   public:
    /**
     * Composes language-dependent command for launching a script for a certain
     * test case.
     *
     * @param test_case - name of test case
     * @return - string, a command to be executed
     */
    virtual std::string launchCommand(const std::string &test_case) = 0;

    /**
     * Runs external binaries generator for a specific test_case and consumes
     * its output. Initializes admin_key, transactions vector, and queries
     * vector fields.
     *
     * @param example - name of test_case scenario
     */
    void operator()(const std::string &example);

    /**
     * Asserts that amount of received transactions and queries equals to
     * expected values.
     *
     * @param transactions_expected - expected amount of transactions
     * @param queries_expected - expected amount of queries
     * @return - assertion result
     */
    bool initialized(const unsigned &transactions_expected = 0,
                     const unsigned &queries_expected = 0);

    boost::optional<shared_model::crypto::Keypair> admin_key;
    std::vector<shared_model::proto::Transaction> transactions;
    std::vector<shared_model::proto::Query> queries;

   protected:
    /**
     * Parses binaries generator output and initalizes class fields.
     *
     * @param data - standard output of external binaries generator.
     *     It is expected that entities are divided by newline separator.
     *     The first entity is expected to be a binary of admin's keypair.
     *     The next lines are transactions' or queries' binaries.
     *     The first read transaction will be considered as genesis transaction.
     */
    void readBinaries(const std::string &data);
    void checkAsserts(const unsigned &transactions_expected,
                      const unsigned &queries_expected);
  };

  class PythonLauncher : public Launcher {
   public:
    std::string launchCommand(const std::string &example) override;
  };

  class JavaLauncher : public Launcher {
   public:
    std::string launchCommand(const std::string &example) override;
  };

}  // namespace binary_test

#endif  // IROHA_LAUNCHERS_HPP
