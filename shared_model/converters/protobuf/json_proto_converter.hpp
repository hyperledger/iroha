/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_JSON_PROTO_CONVERTER_HPP
#define IROHA_JSON_PROTO_CONVERTER_HPP

#include <google/protobuf/util/json_util.h>
#include <string>
#include "backend/protobuf/block.hpp"
#include "commands.pb.h"

namespace shared_model {
  namespace converters {
    namespace protobuf {

      /**
       * Converts protobuf model object into json string
       * @tparam T is the type of converting message
       * @param message is the message to be converted
       * @return json string
       */
      template <typename T>
      std::string modelToJson(const T &message) {
        std::string result;
        google::protobuf::util::MessageToJsonString(message.getTransport(),
                                                    &result);
        return result;
      }

      /**
       * Converts json string into arbitrary protobuf object
       * @tparam T type of model which json converts to
       * @param json is the json string
       * @return optional of protobuf object which contains value if json
       * conversion was successful and none otherwise
       */
      template <typename T>
      boost::optional<T> jsonToProto(std::string json) {
        T result;
        auto status =
            google::protobuf::util::JsonStringToMessage(json, &result);
        if (status.ok()) {
          return result;
        }
        return boost::none;
      }

      /**
       * Converts json into arbitrary transaction shared model object
       * @tparam T type of shared model object converted from json
       * @param json is the json string containing protobuf object
       * @return optional of shared model object, containing the
       * object if conversion was successful and none otherwise
       */
      template <typename T>
      boost::optional<T> jsonToModel(std::string json) {
        auto tx = jsonToProto<typename T::TransportType>(json);
        if (tx) {
          return T(std::move(tx.value()));
        }
        return boost::none;
      }

    }  // namespace protobuf
  }    // namespace converters
}  // namespace shared_model

#endif  // IROHA_JSON_PROTO_CONVERTER_HPP
