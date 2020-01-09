/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_TRUNCATE_POSTGRES_WSV_HPP
#define IROHA_TEST_TRUNCATE_POSTGRES_WSV_HPP

#include <soci/soci.h>

namespace iroha {
  namespace ametsuchi {
    inline void truncateWsv(soci::session &sql) {
      sql <<
          R"(
        TRUNCATE TABLE top_block_info;
        TRUNCATE TABLE account_has_signatory RESTART IDENTITY CASCADE;
        TRUNCATE TABLE account_has_asset RESTART IDENTITY CASCADE;
        TRUNCATE TABLE role_has_permissions RESTART IDENTITY CASCADE;
        TRUNCATE TABLE account_has_roles RESTART IDENTITY CASCADE;
        TRUNCATE TABLE account_has_grantable_permissions RESTART IDENTITY CASCADE;
        TRUNCATE TABLE account RESTART IDENTITY CASCADE;
        TRUNCATE TABLE asset RESTART IDENTITY CASCADE;
        TRUNCATE TABLE domain RESTART IDENTITY CASCADE;
        TRUNCATE TABLE signatory RESTART IDENTITY CASCADE;
        TRUNCATE TABLE peer RESTART IDENTITY CASCADE;
        TRUNCATE TABLE role RESTART IDENTITY CASCADE;
        TRUNCATE TABLE position_by_hash RESTART IDENTITY CASCADE;
        TRUNCATE TABLE tx_status_by_hash RESTART IDENTITY CASCADE;
        TRUNCATE TABLE tx_position_by_creator RESTART IDENTITY CASCADE;
        TRUNCATE TABLE position_by_account_asset RESTART IDENTITY CASCADE;
        TRUNCATE TABLE setting RESTART IDENTITY CASCADE;
            )";
    }
  }  // namespace ametsuchi
}  // namespace iroha

#endif
