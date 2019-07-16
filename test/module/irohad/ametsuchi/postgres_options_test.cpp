/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_options.hpp"

#include <gtest/gtest.h>
#include <regex>
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"

using namespace iroha::ametsuchi;

static const logger::LoggerPtr test_log =
    getTestLoggerManager()->getChild("PostgresOptions")->getLogger();

static const std::string default_working_dbname{"default_dbname"};
static const std::string default_maintenance_dbname{"iroha"};

static void checkDbNameFromConnectionString(const std::string &conn_str,
                                            const std::string &dbname) {
  const static std::regex e("\\bdbname=([^ ]*)");
  std::smatch m;
  if (not std::regex_search(conn_str, m, e)) {
    ADD_FAILURE() << "dbname not found";
    return;
  }
  EXPECT_EQ(m[1], dbname);
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
  std::string pg_opt_string = "param1=val1 dbname=" + dbname + " param2=val2";
  auto pg_opt = PostgresOptions(pg_opt_string,
                                default_working_dbname,
                                default_maintenance_dbname,
                                test_log);

  checkDbNameFromConnectionString(
      pg_opt.workingConnectionString(),
      dbname  // TODO 2019.06.26 mboldyrev IR-556 change dbname to
              // default_working_dbname
  );
  checkDbNameFromConnectionString(pg_opt.maintenanceConnectionString(),
                                  default_maintenance_dbname);
  EXPECT_EQ(pg_opt.connectionStringWithoutDbName(), "param1=val1 param2=val2");
}

/**
 * @given pg_opt string param1 and param2
 * @when PostgresOptions object is created from given pg_opt string
 * @then workingConnectionString is equal to the one given in constructor
 * AND maintenanceConnectionString is equal to the one given in constructor
 * AND optionsStringWithoutDbName is equal to credentrials string
 */
TEST(PostgresOptionsTest, DBnameParamNotExist) {
  std::string pg_opt_string = "param1=val1 param2=val2";
  auto pg_opt = PostgresOptions(pg_opt_string,
                                default_working_dbname,
                                default_maintenance_dbname,
                                test_log);

  checkDbNameFromConnectionString(pg_opt.workingConnectionString(),
                                  default_working_dbname);
  checkDbNameFromConnectionString(pg_opt.maintenanceConnectionString(),
                                  default_maintenance_dbname);
  EXPECT_EQ(pg_opt.connectionStringWithoutDbName(), pg_opt_string);
}
