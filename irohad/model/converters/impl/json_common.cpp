/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_common.hpp"

using namespace rapidjson;

namespace iroha {
  namespace model {
    namespace converters {
      Value serializeSignature(const Signature &signature,
                               Document::AllocatorType &allocator) {
        Value document;
        document.SetObject();

        document.AddMember(
            "pubkey", signature.pubkey.to_hexstring(), allocator);
        document.AddMember(
            "signature", signature.signature.to_hexstring(), allocator);

        return document;
      }

      boost::optional<Document> stringToJson(const std::string &string) {
        Document document;
        document.Parse(string);
        if (document.HasParseError()) {
          return boost::none;
        }
        return document;
      }

      std::string jsonToString(const Document &document) {
        StringBuffer sb;
        PrettyWriter<StringBuffer> writer(sb);
        document.Accept(writer);
        return sb.GetString();
      }
    }  // namespace converters
  }    // namespace model
}  // namespace iroha
