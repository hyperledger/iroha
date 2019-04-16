/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_JSON_QUERY_FACTORY_HPP
#define IROHA_JSON_QUERY_FACTORY_HPP

#include <typeindex>
#include <unordered_map>
#include "logger/logger_fwd.hpp"
#include "model/common.hpp"
#include "model/converters/json_common.hpp"
#include "model/query.hpp"
#include "queries.pb.h"

namespace iroha {
  namespace model {
    namespace converters {
      class JsonQueryFactory {
       public:
        explicit JsonQueryFactory(logger::LoggerPtr log);

        /**
         * get query from string json
         * @param query_json string representation of query
         * @return deserialized query
         */
        optional_ptr<Query> deserialize(const std::string &query_json);

        /**
         * Convert model Query to json string
         * @param model_query - model representation of query
         * @return serialized Query in json format
         */
        std::string serialize(std::shared_ptr<const model::Query> model_query);

       private:
        Convert<std::shared_ptr<model::Query>> toQuery;

        optional_ptr<Query> deserialize(const rapidjson::Document &document);

        using Deserializer =
            optional_ptr<Query> (JsonQueryFactory::*)(const rapidjson::Value &);

        std::unordered_map<std::string, Deserializer> deserializers_;
        // Deserialize handlers
        optional_ptr<Query> deserializeGetAccount(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetSignatories(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetAccountTransactions(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetAccountAssetTransactions(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetTransactions(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetAccountAssets(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetAccountDetail(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetAssetInfo(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetRoles(
            const rapidjson::Value &obj_query);
        optional_ptr<Query> deserializeGetRolePermissions(
            const rapidjson::Value &obj_query);
        // Serializers:
        using Serializer = void (JsonQueryFactory::*)(
            rapidjson::Document &, std::shared_ptr<const model::Query>);
        std::unordered_map<std::type_index, Serializer> serializers_;
        // Serialization handlers
        void serializeGetAccount(rapidjson::Document &json_doc,
                                 std::shared_ptr<const model::Query> query);
        void serializeGetAccountAssets(
            rapidjson::Document &json_doc,
            std::shared_ptr<const model::Query> query);
        void serializeGetAccountDetail(
            rapidjson::Document &json_doc,
            std::shared_ptr<const model::Query> query);
        void serializeGetAccountTransactions(
            rapidjson::Document &json_doc,
            std::shared_ptr<const model::Query> query);
        void serializeGetAccountAssetTransactions(
            rapidjson::Document &json_doc,
            std::shared_ptr<const model::Query> query);
        void serializeGetTransactions(rapidjson::Document &json_doc,
                                      std::shared_ptr<const Query> query);
        void serializeGetSignatories(rapidjson::Document &json_doc,
                                     std::shared_ptr<const model::Query> query);

        void serializeGetAssetInfo(rapidjson::Document &json_doc,
                                   std::shared_ptr<const model::Query> query);
        void serializeGetRoles(rapidjson::Document &json_doc,
                               std::shared_ptr<const model::Query> query);
        void serializeGetRolePermissions(
            rapidjson::Document &json_doc,
            std::shared_ptr<const model::Query> query);

        // Logger
        logger::LoggerPtr log_;
      };
    }  // namespace converters
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_JSON_QUERY_FACTORY_HPP
