/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/pb_query_factory.hpp"

#include "logger/logger.hpp"
#include "model/common.hpp"
#include "model/queries/get_account.hpp"
#include "model/queries/get_account_assets.hpp"
#include "model/queries/get_account_detail.hpp"
#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"
#include "model/queries/get_signatories.hpp"
#include "model/queries/get_transactions.hpp"
#include "queries.pb.h"

namespace iroha {
  namespace model {
    namespace converters {

      PbQueryFactory::PbQueryFactory(logger::LoggerPtr log)
          : log_{std::move(log)} {
        serializers_[typeid(GetAccount)] = &PbQueryFactory::serializeGetAccount;
        serializers_[typeid(GetAccountAssets)] =
            &PbQueryFactory::serializeGetAccountAssets;
        serializers_[typeid(GetAccountDetail)] =
            &PbQueryFactory::serializeGetAccountDetail;
        serializers_[typeid(GetAccountTransactions)] =
            &PbQueryFactory::serializeGetAccountTransactions;
        serializers_[typeid(GetAccountAssetTransactions)] =
            &PbQueryFactory::serializeGetAccountAssetTransactions;
        serializers_[typeid(GetTransactions)] =
            &PbQueryFactory::serializeGetTransactions;
        serializers_[typeid(GetSignatories)] =
            &PbQueryFactory::serializeGetSignatories;
        serializers_[typeid(GetRolePermissions)] =
            &PbQueryFactory::serializeGetRolePermissions;
        serializers_[typeid(GetAssetInfo)] =
            &PbQueryFactory::serializeGetAssetInfo;
        serializers_[typeid(GetRoles)] = &PbQueryFactory::serializeGetRoles;
      }

      optional_ptr<model::Query> PbQueryFactory::deserialize(
          const protocol::Query &pb_query) const {
        std::shared_ptr<model::Query> val;

        const auto &pl = pb_query.payload();

        {
          using protocol::Query_Payload;
          switch (pl.query_case()) {
            case Query_Payload::QueryCase::kGetAccount: {
              // Convert to get Account
              const auto &pb_cast = pl.get_account();
              auto account_query = GetAccount();
              account_query.account_id = pb_cast.account_id();
              val = std::make_shared<model::GetAccount>(account_query);
              break;
            }
            case Query_Payload::QueryCase::kGetAccountAssets: {
              // Convert to get Account Asset
              const auto &pb_cast = pl.get_account_assets();
              auto query = GetAccountAssets();
              query.account_id = pb_cast.account_id();
              val = std::make_shared<model::GetAccountAssets>(query);
              break;
            }
            case Query_Payload::QueryCase::kGetAccountDetail: {
              // Convert to get Account Detail
              const auto &pb_cast = pl.get_account_detail();
              auto query = GetAccountDetail();
              query.account_id = pb_cast.account_id();
              val = std::make_shared<model::GetAccountDetail>(query);
              break;
            }
            case Query_Payload::QueryCase::kGetAccountAssetTransactions: {
              const auto &pb_cast = pl.get_account_asset_transactions();
              auto query = GetAccountAssetTransactions();
              query.account_id = pb_cast.account_id();
              query.asset_id = pb_cast.asset_id();
              val = std::make_shared<model::GetAccountAssetTransactions>(query);
              break;
            }
            case Query_Payload::QueryCase::kGetSignatories: {
              // Convert to get Signatories
              const auto &pb_cast = pl.get_signatories();
              auto query = GetSignatories();
              query.account_id = pb_cast.account_id();
              val = std::make_shared<model::GetSignatories>(query);
              break;
            }
            case Query_Payload::QueryCase::kGetAccountTransactions: {
              // Convert to get Signatories
              const auto &pb_cast = pl.get_account_transactions();
              auto query = GetAccountTransactions();
              query.account_id = pb_cast.account_id();
              val = std::make_shared<model::GetAccountTransactions>(query);
              break;
            }
            case Query_Payload::QueryCase::kGetTransactions: {
              // Convert to get transactions
              const auto &pb_cast = pl.get_transactions();
              auto query = GetTransactions();
              std::transform(pb_cast.tx_hashes().begin(),
                             pb_cast.tx_hashes().end(),
                             std::back_inserter(query.tx_hashes),
                             [](auto tx_hash) {
                               return iroha::hash256_t::from_hexstring(tx_hash)
                                   .assumeValue();
                             });
              val = std::make_shared<GetTransactions>(query);
              break;
            }
            case Query_Payload::QueryCase::kGetRoles: {
              val = std::make_shared<GetRoles>();
              break;
            }
            case Query_Payload::QueryCase::kGetAssetInfo: {
              // Convert to get asset info
              const auto &pb_cast = pl.get_asset_info();
              val = std::make_shared<GetAssetInfo>(pb_cast.asset_id());
              break;
            }
            case Query_Payload::QueryCase::kGetRolePermissions: {
              const auto &pb_cast = pl.get_role_permissions();
              val = std::make_shared<GetRolePermissions>(pb_cast.role_id());
              break;
            }
            default: {
              // Query not implemented
              return boost::none;
            }
          }
        }

        const auto &pb_sign = pb_query.signature();

        Signature sign{};
        sign.pubkey =
            pubkey_t::from_hexstring(pb_sign.public_key()).assumeValue();
        sign.signature =
            sig_t::from_hexstring(pb_sign.signature()).assumeValue();

        val->query_counter = pl.meta().query_counter();
        val->signature = sign;
        val->created_ts = pl.meta().created_time();
        val->creator_account_id = pl.meta().creator_account_id();
        return val;
      }

      void PbQueryFactory::serializeQueryMetaData(
          protocol::Query &pb_query, std::shared_ptr<const Query> query) const {
        auto *meta = pb_query.mutable_payload()->mutable_meta();
        meta->set_created_time(query->created_ts);
        meta->set_creator_account_id(query->creator_account_id);
        meta->set_query_counter(query->query_counter);
        // Set signatures
        auto sig = pb_query.mutable_signature();
        sig->set_signature(query->signature.signature.to_hexstring());
        sig->set_public_key(query->signature.pubkey.to_hexstring());
      }

      boost::optional<protocol::Query> PbQueryFactory::serialize(
          std::shared_ptr<const Query> query) const {
        auto qry = query.get();
        auto it = serializers_.find(typeid(*qry));
        if (it != serializers_.end()) {
          return (this->*it->second)(query);
        }
        log_->error("Query type not found");
        return boost::none;
      }

      protocol::Query PbQueryFactory::serializeGetAccount(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        auto pl = pb_query.mutable_payload();
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetAccount>(query);
        auto account_id = tmp->account_id;
        auto pb_query_mut = pl->mutable_get_account();
        pb_query_mut->set_account_id(account_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetAccountAssets(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetAccountAssets>(query);
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_account_assets();
        pb_query_mut->set_account_id(tmp->account_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetAccountDetail(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetAccountDetail>(query);
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_account_detail();
        pb_query_mut->set_account_id(tmp->account_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetAccountTransactions(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp =
            std::static_pointer_cast<const GetAccountTransactions>(query);
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_account_transactions();
        pb_query_mut->set_account_id(tmp->account_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetAccountAssetTransactions(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp =
            std::static_pointer_cast<const GetAccountAssetTransactions>(query);
        auto account_id = tmp->account_id;
        auto asset_id = tmp->asset_id;
        auto pb_query_mut = pb_query.mutable_payload()
                                ->mutable_get_account_asset_transactions();
        pb_query_mut->set_account_id(account_id);
        pb_query_mut->set_asset_id(asset_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetTransactions(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetTransactions>(query);
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_transactions();
        std::for_each(tmp->tx_hashes.begin(),
                      tmp->tx_hashes.end(),
                      [&pb_query_mut](auto tx_hash) {
                        auto adder = pb_query_mut->add_tx_hashes();
                        *adder = tx_hash.to_hexstring();
                      });
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetSignatories(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetSignatories>(query);
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_signatories();
        pb_query_mut->set_account_id(tmp->account_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetAssetInfo(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetAssetInfo>(query);
        auto ast_id = tmp->asset_id;
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_asset_info();
        pb_query_mut->set_asset_id(ast_id);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetRoles(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        pb_query.mutable_payload()->mutable_get_roles();
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetRoles>(query);
        return pb_query;
      }

      protocol::Query PbQueryFactory::serializeGetRolePermissions(
          std::shared_ptr<const Query> query) const {
        protocol::Query pb_query;
        serializeQueryMetaData(pb_query, query);
        auto tmp = std::static_pointer_cast<const GetRolePermissions>(query);
        auto role = tmp->role_id;
        auto pb_query_mut =
            pb_query.mutable_payload()->mutable_get_role_permissions();
        pb_query_mut->set_role_id(role);
        return pb_query;
      }

    }  // namespace converters
  }    // namespace model
}  // namespace iroha
