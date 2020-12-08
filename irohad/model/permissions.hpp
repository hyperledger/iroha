/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SHARED_MODEL_PERMISSIONS_HPP
#define SHARED_MODEL_PERMISSIONS_HPP

#include <set>
#include <string>

namespace shared_model {
  namespace permissions {

    /* ~~~~~~~~       Command-related permissions        ~~~~~~~~ */

    //  The set of permissions below refer to the specific commands.
    //  During stateful validations, these permissions are checked
    //  to be assigned to transaction creator.

    /*                            Role                            */
    const std::string can_append_role = "can_append_role";
    const std::string can_create_role = "can_create_role";
    const std::string can_detach_role = "can_detach_role";

    /*                       Asset quantity                       */
    const std::string can_add_asset_qty = "can_add_asset_qty";
    const std::string can_subtract_asset_qty = "can_subtract_asset_qty";

    /*                            Peer                            */
    const std::string can_add_peer = "can_add_peer";

    /*                          Signatory                         */
    const std::string can_add_signatory = "can_add_signatory";
    const std::string can_add_my_signatory = "can_add_my_signatory";
    const std::string can_remove_signatory = "can_remove_signatory";
    const std::string can_remove_my_signatory = "can_remove_my_signatory";
    const std::string can_set_quorum = "can_set_quorum";
    const std::string can_set_my_quorum = "can_set_my_quorum";

    /*                          Account                           */
    const std::string can_create_account = "can_create_account";
    const std::string can_set_detail = "can_set_detail";
    const std::string can_set_my_account_detail = "can_set_my_account_detail";

    /*                           Asset                            */
    const std::string can_create_asset = "can_create_asset";
    const std::string can_transfer = "can_transfer";
    const std::string can_transfer_my_assets = "can_transfer_my_assets";
    const std::string can_receive = "can_receive";

    /*                           Domain                           */
    const std::string can_create_domain = "can_create_domain";

    /* ~~~~~~~~       Query-related permissions        ~~~~~~~~   */

    //  The set of permissions below refer to the specific queries.
    //  During stateful validations, these permissions are checked
    //  to be assigned to query creator.
    //  These permissions are divided into three groups:
    // * my — query creator can query its data
    // * domain — query creator can only query the data from the domain
    //   where the account was created
    // * all — query creator can query all the data in the system

    /*                           Asset                           */
    const std::string can_read_assets = "can_read_assets";

    /*                           Roles                           */
    const std::string can_get_roles = "can_get_roles";

    /*                          Account                          */
    const std::string can_get_my_account = "can_get_my_account";
    const std::string can_get_all_accounts = "can_get_all_accounts";
    const std::string can_get_domain_accounts = "can_get_domain_accounts";

    /*                        Signatories                        */
    const std::string can_get_my_signatories = "can_get_my_signatories";
    const std::string can_get_all_signatories = "can_get_all_signatories";
    const std::string can_get_domain_signatories = "can_get_domain_signatories";

    /*                        Engine receipts                    */
    const std::string can_get_my_engine_receipts = "can_get_my_engine_receipts";
    const std::string can_get_domain_engine_receipts =
        "can_get_domain_engine_receipts";
    const std::string can_get_all_engine_receipts =
        "can_get_all_engine_receipts";

    /*                     Account asset (wallet)                */
    const std::string can_get_my_acc_ast = "can_get_my_acc_ast";
    const std::string can_get_all_acc_ast = "can_get_all_acc_ast";
    const std::string can_get_domain_acc_ast = "can_get_domain_acc_ast";

    /*           Account details (JSON key-value map)            */
    const std::string can_get_my_acc_detail = "can_get_my_acc_detail";
    const std::string can_get_all_acc_detail = "can_get_all_acc_detail";
    const std::string can_get_domain_acc_detail = "can_get_domain_acc_detail";

    /*                   Account transactions                    */
    const std::string can_get_my_acc_txs = "can_get_my_acc_txs";
    const std::string can_get_all_acc_txs = "can_get_all_acc_txs";
    const std::string can_get_domain_acc_txs = "can_get_domain_acc_txs";

    /*                Account asset transactions                 */
    const std::string can_get_my_acc_ast_txs = "can_get_my_acc_ast_txs";
    const std::string can_get_all_acc_ast_txs = "can_get_all_acc_ast_txs";
    const std::string can_get_domain_acc_ast_txs = "can_get_domain_acc_ast_txs";

    /*       Account transactions (only mine or for everyone)    */
    const std::string can_get_my_txs = "can_get_my_txs";
    const std::string can_get_all_txs = "can_get_all_txs";

    /*                           Blocks                           */
    const std::string can_get_blocks = "can_get_blocks";

    /* ~~~~~~~~                 Groups                ~~~~~~~~   */
    const std::set<std::string> read_self_group = {can_get_my_account,
                                                   can_get_my_signatories,
                                                   can_get_my_acc_ast,
                                                   can_get_my_acc_detail,
                                                   can_get_my_acc_txs,
                                                   can_get_my_acc_ast_txs,
                                                   can_get_my_txs,
                                                   can_get_my_engine_receipts};

    const std::set<std::string> read_all_group = {can_get_all_accounts,
                                                  can_get_all_signatories,
                                                  can_get_all_acc_ast,
                                                  can_get_all_acc_detail,
                                                  can_get_all_acc_txs,
                                                  can_get_all_acc_ast_txs,
                                                  can_get_all_txs,
                                                  can_get_roles,
                                                  can_read_assets,
                                                  can_get_blocks,
                                                  can_get_all_engine_receipts};

    const std::set<std::string> read_domain_group = {
        can_get_domain_accounts,
        can_get_domain_signatories,
        can_get_domain_acc_ast,
        can_get_domain_acc_detail,
        can_get_domain_acc_txs,
        can_get_domain_acc_ast_txs,
        can_get_domain_engine_receipts,
    };

    /*                   Grantable permissions                   */
    const std::string can_grant = "can_grant_";
    const std::set<std::string> grant_group = {
        can_grant + can_set_my_quorum,
        can_grant + can_add_my_signatory,
        can_grant + can_remove_my_signatory,
        can_grant + can_transfer_my_assets,
        can_grant + can_set_my_account_detail};

    const std::set<std::string> edit_self_group = {
        can_set_quorum, can_add_signatory, can_remove_signatory};

    const std::set<std::string> asset_creator_group = {can_create_asset,
                                                       can_add_asset_qty};

    const std::set<std::string> role_perm_group = {
        can_append_role,
        can_create_role,
        can_detach_role,
        can_add_asset_qty,
        can_subtract_asset_qty,
        can_add_peer,
        can_add_signatory,
        can_remove_signatory,
        can_set_quorum,
        can_create_account,
        can_set_detail,
        can_create_asset,
        can_transfer,
        can_receive,
        can_create_domain,
        can_read_assets,
        can_get_roles,
        can_get_my_account,
        can_get_all_accounts,
        can_get_domain_accounts,
        can_get_my_engine_receipts,
        can_get_domain_engine_receipts,
        can_get_all_engine_receipts,
        can_get_my_signatories,
        can_get_all_signatories,
        can_get_domain_signatories,
        can_get_my_acc_ast,
        can_get_all_acc_ast,
        can_get_domain_acc_ast,
        can_get_my_acc_detail,
        can_get_all_acc_detail,
        can_get_domain_acc_detail,
        can_get_my_acc_txs,
        can_get_all_acc_txs,
        can_get_domain_acc_txs,
        can_get_my_acc_ast_txs,
        can_get_all_acc_ast_txs,
        can_get_domain_acc_ast_txs,
        can_get_my_txs,
        can_get_all_txs,
        can_grant + can_set_my_quorum,
        can_grant + can_add_my_signatory,
        can_grant + can_remove_my_signatory,
        can_grant + can_transfer_my_assets,
        can_grant + can_set_my_account_detail};

    /*                    All permissions                        */
    const std::set<std::string> all_perm_group = {
        can_append_role,
        can_create_role,
        can_detach_role,
        can_add_asset_qty,
        can_subtract_asset_qty,
        can_add_peer,
        can_add_signatory,
        can_remove_signatory,
        can_set_quorum,
        can_create_account,
        can_set_detail,
        can_create_asset,
        can_transfer,
        can_receive,
        can_create_domain,
        can_read_assets,
        can_get_roles,
        can_get_my_account,
        can_get_all_accounts,
        can_get_domain_accounts,
        can_get_my_signatories,
        can_get_all_signatories,
        can_get_domain_signatories,
        can_get_my_engine_receipts,
        can_get_domain_engine_receipts,
        can_get_all_engine_receipts,
        can_get_my_acc_ast,
        can_get_all_acc_ast,
        can_get_domain_acc_ast,
        can_get_my_acc_detail,
        can_get_all_acc_detail,
        can_get_domain_acc_detail,
        can_get_my_acc_txs,
        can_get_all_acc_txs,
        can_get_domain_acc_txs,
        can_get_my_acc_ast_txs,
        can_get_all_acc_ast_txs,
        can_get_domain_acc_ast_txs,
        can_get_my_txs,
        can_get_all_txs,
        can_grant + can_set_my_quorum,
        can_grant + can_add_my_signatory,
        can_grant + can_remove_my_signatory,
        can_grant + can_transfer_my_assets,
        can_grant + can_set_my_account_detail,
        // TODO: IR 1190 kamilsa 30.03.2018 move permissions below to separated
        // group
        can_add_my_signatory,
        can_remove_my_signatory,
        can_set_my_quorum,
        can_set_my_account_detail,
        can_transfer_my_assets,
        can_get_blocks};

  }  // namespace permissions
}  // namespace shared_model

#endif  // SHARED_MODEL_PERMISSIONS_HPP
