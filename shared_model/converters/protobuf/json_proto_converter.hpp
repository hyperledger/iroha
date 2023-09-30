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
#include "common/result.hpp"

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
       * conversion was successful and error otherwise
       */
      template <typename T>
      iroha::expected::Result<T, std::string> jsonToProto(std::string json) {
        T result;
        auto status =
            google::protobuf::util::JsonStringToMessage(json, &result);
        if (status.ok()) {
          return result;
        }
        return status.message();
      }
    }  // namespace protobuf
  }    // namespace converters
}  // namespace shared_model

#endif  // IROHA_JSON_PROTO_CONVERTER_HPP
