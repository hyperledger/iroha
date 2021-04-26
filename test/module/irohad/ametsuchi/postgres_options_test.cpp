/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_options.hpp"

#include <gtest/gtest.h>

#include <boost/format.hpp>
#include <regex>

#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"

using namespace iroha::ametsuchi;

static const logger::LoggerPtr test_log =
    getTestLoggerManager()->getChild("PostgresOptions")->getLogger();

static const std::string default_working_dbname{"working_dbname"};
static const std::string default_maintenance_dbname{"postgres"};

/**
 * Check that the given connection string contains field=value entry.
 * @param conn_str The source string.
 * @param field The requested field.
 * @param value The expected value of the field.
 */
static void checkField(const std::string &conn_str,
                       const std::string &field,
                       const std::string &value) {
  const std::regex e((boost::format(R"(\b%1%=([^ ]+)\b)") % field).str());
  std::smatch m;
  if (not std::regex_search(conn_str, m, e)) {
    ADD_FAILURE() << field << " not found";
    return;
  }
  EXPECT_EQ(m[1], value);
}

/**
 * Check that the given connection string contains the required set of fields &
 * values.
 * @param conn_str The source string.
 * @param host The expected value of "host" field.
 * @param port The expected value of "port" field.
 * @param user The expected value of "user" field.
 * @param password The expected value of "password" field.
 * @param dbname The expected value of "dbname" field.
 */
static void checkConnString(const std::string &conn_str,
                            const std::string &host,
                            const std::string &port,
                            const std::string &user,
                            const std::string &password,
                            const std::string &dbname) {
  checkField(conn_str, "host", host);
  checkField(conn_str, "port", port);
  checkField(conn_str, "user", user);
  checkField(conn_str, "password", password);
  checkField(conn_str, "dbname", dbname);
}

/**
 * Check that the given postgres options object provides connection strings for
 * maintenance and working databases that contain the required set of fields &
 * values.
 * @param pg_opt The checked postgres options object.
 * @param host The expected value of "host" field of both connection strings.
 * @param port The expected value of "port" field of both connection strings.
 * @param user The expected value of "user" field of both connection strings.
 * @param password The expected value of "password" field of both connection
 * strings.
 * @param working_dbname The expected value of "dbname" field of working
 * connection string.
 * @param maintenance_dbname The expected value of "dbname" field of maintenance
 * connection string.
 */
static void checkPgOpts(const PostgresOptions &pg_opt,
                        const std::string &host,
                        const std::string &port,
                        const std::string &user,
                        const std::string &password,
                        const std::string &working_dbname,
                        const std::string &maintenance_dbname) {
  checkConnString(pg_opt.workingConnectionString(),
                  host,
                  port,
                  user,
                  password,
                  working_dbname);
  checkConnString(pg_opt.maintenanceConnectionString(),
                  host,
                  port,
                  user,
                  password,
                  maintenance_dbname);
}

/**
 *
 * @given pg_opt string with param1, param2 and dbname
 * @when PostgresOptions object is created from given pg_opt string
 * @then PostgresOptions contains dbname
 * AND workingConnectionString is equal to the one given in pg_opt string
 * AND maintenanceConnectionString is equal to the one given in constructor
 * AND optionsStringWithoutDbName is equal to credentrials string without dbname
 */
TEST(PostgresOptionsTest, DBnameParamExist) {
  std::string dbname = "irohadb";
  std::string pg_opt_string =
      (boost::format("user=petya dbname=%1% "
                     "port=1991 password=friend host=down")
       % dbname)
          .str();
  auto pg_opt =
      PostgresOptions(pg_opt_string, default_working_dbname, test_log);

  checkPgOpts(pg_opt,
              "down",
              "1991",
              "petya",
              "friend",
              dbname,
              default_maintenance_dbname);
}

/**
 * @given pg_opt string param1 and param2
 * @when PostgresOptions object is created from given pg_opt string
 * @then workingConnectionString is equal to the one given in constructor
 * AND maintenanceConnectionString is equal to the one given in constructor
 * AND optionsStringWithoutDbName is equal to credentrials string
 *
 * TODO 2019.06.26 mboldyrev IR-556 remove
 */
TEST(PostgresOptionsTest, DBnameParamNotExist) {
  std::string pg_opt_string = "user=crab port=1991 password=friend host=down";
  auto pg_opt =
      PostgresOptions(pg_opt_string, default_working_dbname, test_log);

  checkPgOpts(pg_opt,
              "down",
              "1991",
              "crab",
              "friend",
              default_working_dbname,
              default_maintenance_dbname);
}

/**
 * @given PostgresOptions initialized with separate params
 * @when connection strings are requested
 * @then all params match initialization
 */
TEST(PostgresOptionsTest, SeparateParams) {
  auto pg_opt = PostgresOptions("down",
                                1991,
                                "whales",
                                "donald",
                                default_working_dbname,
                                "maintenance_dbname",
                                test_log);
  checkPgOpts(pg_opt,
              "down",
              "1991",
              "whales",
              "donald",
              default_working_dbname,
              "maintenance_dbname");
}
