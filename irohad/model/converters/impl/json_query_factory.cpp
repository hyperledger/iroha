/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_query_factory.hpp"

#include "logger/logger.hpp"
#include "model/queries/get_account.hpp"
#include "model/queries/get_account_assets.hpp"
#include "model/queries/get_account_detail.hpp"
#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"
#include "model/queries/get_signatories.hpp"
#include "model/queries/get_transactions.hpp"

using namespace rapidjson;

namespace iroha {
  namespace model {
    namespace converters {
      JsonQueryFactory::JsonQueryFactory(logger::LoggerPtr log)
          : log_{std::move(log)} {
        deserializers_ = {
            {"GetAccount", &JsonQueryFactory::deserializeGetAccount},
            {"GetAccountAssets",
             &JsonQueryFactory::deserializeGetAccountAssets},
            {"GetAccountDetail",
             &JsonQueryFactory::deserializeGetAccountDetail},
            {"GetAccountTransactions",
             &JsonQueryFactory::deserializeGetAccountTransactions},
            {"GetAccountAssetTransactions",
             &JsonQueryFactory::deserializeGetAccountAssetTransactions},
            {"GetTransactions", &JsonQueryFactory::deserializeGetTransactions},
            {"GetAccountSignatories",
             &JsonQueryFactory::deserializeGetSignatories},
            {"GetRoles", &JsonQueryFactory::deserializeGetRoles},
            {"GetRolePermissions",
             &JsonQueryFactory::deserializeGetRolePermissions},
            {"GetAssetInfo", &JsonQueryFactory::deserializeGetAssetInfo}};
        // Serializers
        serializers_ = {
            {typeid(GetAccount), &JsonQueryFactory::serializeGetAccount},
            {typeid(GetSignatories),
             &JsonQueryFactory::serializeGetSignatories},
            {typeid(GetAccountAssets),
             &JsonQueryFactory::serializeGetAccountAssets},
            {typeid(GetAccountDetail),
             &JsonQueryFactory::serializeGetAccountDetail},
            {typeid(GetAccountTransactions),
             &JsonQueryFactory::serializeGetAccountTransactions},
            {typeid(GetAccountAssetTransactions),
             &JsonQueryFactory::serializeGetAccountAssetTransactions},
            {typeid(GetTransactions),
             &JsonQueryFactory::serializeGetTransactions},
            {typeid(GetAssetInfo), &JsonQueryFactory::serializeGetAssetInfo},
            {typeid(GetRoles), &JsonQueryFactory::serializeGetRoles},
            {typeid(GetRolePermissions),
             &JsonQueryFactory::serializeGetRolePermissions}};
      }

      optional_ptr<Query> JsonQueryFactory::deserialize(
          const std::string &query_json) {
        return stringToJson(query_json) |
            [this](auto &&json) { return this->deserialize(json); };
      }

      optional_ptr<Query> JsonQueryFactory::deserialize(
          const rapidjson::Document &document) {
        auto des = makeFieldDeserializer(document);
        return des.String("query_type") | makeOptionalGet(deserializers_)
            | makeMethodInvoke(*this, document)
            | des.Uint64(&Query::created_ts, "created_ts")
            | des.String(&Query::creator_account_id, "creator_account_id")
            | des.Uint64(&Query::query_counter, "query_counter")
            | des.Object(&Query::signature, "signature") |
            [](auto query) { return boost::make_optional(std::move(query)); };
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetAccount(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetAccount>()
            | des.String(&GetAccount::account_id, "account_id") | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetSignatories(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetSignatories>()
            | des.String(&GetSignatories::account_id, "account_id") | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetAccountTransactions(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetAccountTransactions>()
            | des.String(&GetAccountTransactions::account_id, "account_id")
            | toQuery;
      }

      optional_ptr<Query>
      JsonQueryFactory::deserializeGetAccountAssetTransactions(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetAccountAssetTransactions>()
            | des.String(&GetAccountAssetTransactions::account_id, "account_id")
            | des.String(&GetAccountAssetTransactions::asset_id, "asset_id")
            | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetAccountDetail(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetAccountDetail>()
            | des.String(&GetAccountDetail::account_id, "account_id") | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetTransactions(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetTransactions>()
            | des.Array(&GetTransactions::tx_hashes, "tx_hashes") | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetAccountAssets(
          const Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetAccountAssets>()
            | des.String(&GetAccountAssets::account_id, "account_id") | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetAssetInfo(
          const rapidjson::Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetAssetInfo>()
            | des.String(&GetAssetInfo::asset_id, "asset_id") | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetRoles(
          const rapidjson::Value &obj_query) {
        return make_optional_ptr<GetRoles>() | toQuery;
      }

      optional_ptr<Query> JsonQueryFactory::deserializeGetRolePermissions(
          const rapidjson::Value &obj_query) {
        auto des = makeFieldDeserializer(obj_query);
        return make_optional_ptr<GetRolePermissions>()
            | des.String(&GetRolePermissions::role_id, "role_id") | toQuery;
      }

      // --- Serialization:

      std::string JsonQueryFactory::serialize(
          std::shared_ptr<const Query> model_query) {
        Document doc;
        auto &allocator = doc.GetAllocator();
        doc.SetObject();
        doc.AddMember(
            "creator_account_id", model_query->creator_account_id, allocator);
        doc.AddMember("query_counter", model_query->query_counter, allocator);
        doc.AddMember("created_ts", model_query->created_ts, allocator);
        Value signature;
        signature.SetObject();
        signature.CopyFrom(
            serializeSignature(model_query->signature, allocator), allocator);

        doc.AddMember("signature", signature, allocator);

        auto qry = model_query.get();
        makeMethodInvoke(
            *this, doc, model_query)(serializers_.at(typeid(*qry)));
        return jsonToString(doc);
      }

      void JsonQueryFactory::serializeGetAccount(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetAccount", allocator);
        auto get_account = std::static_pointer_cast<const GetAccount>(query);
        json_doc.AddMember("account_id", get_account->account_id, allocator);
      }

      void JsonQueryFactory::serializeGetAccountAssets(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetAccountAssets", allocator);
        auto casted_query =
            std::static_pointer_cast<const GetAccountAssets>(query);
        json_doc.AddMember("account_id", casted_query->account_id, allocator);
      }

      void JsonQueryFactory::serializeGetAccountDetail(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetAccountDetail", allocator);
        auto casted_query =
            std::static_pointer_cast<const GetAccountDetail>(query);
        json_doc.AddMember("account_id", casted_query->account_id, allocator);
      }

      void JsonQueryFactory::serializeGetSignatories(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetAccountSignatories", allocator);
        auto get_account =
            std::static_pointer_cast<const GetSignatories>(query);
        json_doc.AddMember("account_id", get_account->account_id, allocator);
      }

      void JsonQueryFactory::serializeGetAccountTransactions(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetAccountTransactions", allocator);
        auto get_account =
            std::static_pointer_cast<const GetAccountTransactions>(query);
        json_doc.AddMember("account_id", get_account->account_id, allocator);
      }

      void JsonQueryFactory::serializeGetAccountAssetTransactions(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember(
            "query_type", "GetAccountAssetTransactions", allocator);
        auto get_account_asset =
            std::static_pointer_cast<const GetAccountAssetTransactions>(query);
        json_doc.AddMember(
            "account_id", get_account_asset->account_id, allocator);
        json_doc.AddMember("asset_id", get_account_asset->asset_id, allocator);
      }

      void JsonQueryFactory::serializeGetTransactions(
          Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetTransactions", allocator);
        auto get_transactions =
            std::static_pointer_cast<const GetTransactions>(query);
        Value json_tx_hashes;
        json_tx_hashes.SetArray();
        const auto &tx_hashes = get_transactions->tx_hashes;
        std::for_each(tx_hashes.begin(),
                      tx_hashes.end(),
                      [&json_tx_hashes, &allocator](auto tx_hash) {
                        Value json_tx_hash;
                        json_tx_hash.Set(tx_hash.to_hexstring(), allocator);
                        json_tx_hashes.PushBack(json_tx_hash, allocator);
                      });
        json_doc.AddMember("tx_hashes", json_tx_hashes, allocator);
      }

      void JsonQueryFactory::serializeGetAssetInfo(
          rapidjson::Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetAssetInfo", allocator);
        auto cmd = std::static_pointer_cast<const GetAssetInfo>(query);
        json_doc.AddMember("asset_id", cmd->asset_id, allocator);
      }

      void JsonQueryFactory::serializeGetRolePermissions(
          rapidjson::Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetRolePermissions", allocator);
        auto cmd = std::static_pointer_cast<const GetRolePermissions>(query);
        json_doc.AddMember("role_id", cmd->role_id, allocator);
      }

      void JsonQueryFactory::serializeGetRoles(
          rapidjson::Document &json_doc, std::shared_ptr<const Query> query) {
        auto &allocator = json_doc.GetAllocator();
        json_doc.AddMember("query_type", "GetRoles", allocator);
      }

    }  // namespace converters
  }    // namespace model
}  // namespace iroha
