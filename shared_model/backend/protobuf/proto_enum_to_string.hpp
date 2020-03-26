/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ENUM_TO_STRING_HPP
#define IROHA_PROTO_ENUM_TO_STRING_HPP

#include <string>

#include <google/protobuf/generated_enum_reflection.h>

#define IROHA_DEFINE_PROTO_ENUM_TO_STRING_FWD(EnumType) \
  namespace iroha {                                     \
    namespace to_string {                               \
      std::string toString(const EnumType &val);        \
    }                                                   \
  }

#define IROHA_DEFINE_PROTO_ENUM_TO_STRING(EnumType)                       \
  namespace iroha {                                                       \
    namespace to_string {                                                 \
      std::string toString(const EnumType &val) {                         \
        const ::google::protobuf::EnumDescriptor *const descriptor =      \
            ::google::protobuf::GetEnumDescriptor<EnumType>();            \
        return ::google::protobuf::internal::NameOfEnum(descriptor, val); \
      }                                                                   \
    }                                                                     \
  }

#define IROHA_DEFINE_IFACE_ENUM_TO_PROTO_STRING_FWD(IfaceEnumType, map) \
  namespace iroha {                                                     \
    namespace to_string {                                               \
      std::string toString(const IfaceEnumType &val);                   \
    }                                                                   \
  }

#define IROHA_DEFINE_IFACE_ENUM_TO_PROTO_STRING(IfaceEnumType, map) \
  namespace iroha {                                                 \
    namespace to_string {                                           \
      std::string toString(const IfaceEnumType &val) {              \
        auto it = map.find(val);                                    \
        if (it == map.end()) {                                      \
          assert(it != map.end());                                  \
          return "<unknown>";                                       \
        }                                                           \
        return ::iroha::to_string::toString(it->second);            \
      }                                                             \
    }                                                               \
  }

#endif
