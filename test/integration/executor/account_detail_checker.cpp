/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/account_detail_checker.hpp"

#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/rapidjson.h>

namespace executor_testing {

  void checkJsonData(const std::string &test_data,
                     const DetailsByKeyByWriter &reference_data) {
    rapidjson::Document doc;
    if (doc.Parse(test_data).HasParseError()) {
      ADD_FAILURE() << "Malformed JSON!";
      return;
    }
    if (not doc.IsObject()) {
      ADD_FAILURE() << "JSON top entity must be an object!";
      return;
    }
    const auto top_obj = doc.GetObject();

    EXPECT_EQ(top_obj.MemberEnd() - top_obj.MemberBegin(),
              reference_data.size())
        << "Wrong number of writers!";

    for (const auto &ref_writer_and_data : reference_data) {
      const auto &ref_writer = ref_writer_and_data.first;
      const auto &ref_data_by_writer = ref_writer_and_data.second;

      // get the writer in JSON
      const auto json_writer_it = top_obj.FindMember(ref_writer);
      if (json_writer_it == top_obj.MemberEnd()) {
        ADD_FAILURE() << ref_writer << " not present in JSON!";
        continue;
      }
      const rapidjson::Value &json_data_by_writer = json_writer_it->value;
      if (not json_data_by_writer.IsObject()) {
        ADD_FAILURE() << "JSON entity for writer " << ref_writer
                      << " must be an object!";
        continue;
      }
      const auto json_data_by_writer_obj = json_data_by_writer.GetObject();

      EXPECT_EQ(json_data_by_writer_obj.MemberEnd()
                    - json_data_by_writer_obj.MemberBegin(),
                ref_data_by_writer.size())
          << "Wrong number of keys!";

      // check the values
      for (const auto &key_and_value : ref_data_by_writer) {
        const auto &ref_key = key_and_value.first;
        const auto &ref_val = key_and_value.second;

        const auto it = json_data_by_writer_obj.FindMember(ref_key);
        if (it == top_obj.MemberEnd()) {
          ADD_FAILURE() << ref_key << " for writer " << ref_writer
                        << " not present in JSON!";
        } else {
          const rapidjson::Value &data_by_key = it->value;
          if (not data_by_key.IsString()) {
            ADD_FAILURE() << "JSON entity for writer " << ref_writer << ", key "
                          << ref_key << " must be a string!";
          } else {
            EXPECT_EQ(data_by_key.GetString(), ref_val);
          }
        }
      }
    }
  }

}  // namespace executor_testing
