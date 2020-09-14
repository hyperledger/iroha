/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_JSON_COMMON_HPP
#define IROHA_JSON_COMMON_HPP

#include <numeric>
#include <string>
#include <unordered_map>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "common/obj_utils.hpp"
#include "model/block.hpp"
#include "model/common.hpp"
#include "model/queries/get_transactions.hpp"
#include "model/signature.hpp"

namespace iroha {
  namespace model {
    namespace converters {
      /**
       * Convert functor which specifies output type
       * @tparam V - output type
       */
      template <typename V>
      struct Convert {
        /**
         * Convert input type to defined type
         * @tparam T - input type
         * @param x - input value
         * @return optional of output type from input value
         */
        template <typename T>
        auto operator()(T &&x) const {
          return boost::optional<V>(std::forward<T>(x));
        }
      };

      template <size_t size>
      struct Convert<blob_t<size>> {
        template <typename T>
        auto operator()(T &&x) const {
          return hexstringToArray<size>(std::forward<T>(x));
        }
      };

      /**
       * Deserialize field from given document with given type
       * @tparam T - getter return type
       * @tparam D - document type
       * @param document - document value for deserialization
       * @param field - field name for deserialization
       * @return deserialized field on success, nullopt otherwise
       */
      template <typename T, typename D>
      boost::optional<T> deserializeField(const D &document,
                                          const std::string &field) {
        if (document.HasMember(field.c_str())
            and document[field.c_str()].template Is<T>()) {
          return document[field.c_str()].template Get<T>();
        }
        return boost::none;
      }

      /**
       * Functor for deserialization from given document
       * @tparam D - document type
       */
      template <typename D>
      struct FieldDeserializer {
        /**
         * @param document - document for field deserialization
         */
        explicit FieldDeserializer(const D &document) : document(document) {}

        /**
         * Create function, which deserializes document field,
         * transforms the value to required type, and
         * assigns it to block member
         * @tparam T - getter return type
         * @tparam V - block member type
         * @tparam B - block type
         * @tparam Convert - transform function type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @param transform - transform function from T to V
         * @return function, which takes block, returns block with deserialized
         * member on success, nullopt otherwise
         */
        template <typename T,
                  typename V,
                  typename B,
                  typename Convert = Convert<V>>
        auto deserialize(V B::*member,
                         const std::string &field,
                         Convert transform = Convert()) {
          return [this, member, field, transform](auto block) {
            return deserializeField<T>(document, field) | transform
                | assignObjectField(block, member);
          };
        }

        /**
         * Deserialize field of Uint type to given member field of block
         * @tparam V - block member type
         * @tparam B - block type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @return @see deserialize
         */
        template <typename V, typename B>
        auto Uint(V B::*member, const std::string &field) {
          return deserialize<uint32_t>(member, field);
        }

        /**
         * Deserialize field of Uint64 type to given member field of block
         * @tparam V - block member type
         * @tparam B - block type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @return @see deserialize
         */
        template <typename V, typename B>
        auto Uint64(V B::*member, const std::string &field) {
          return deserialize<uint64_t>(member, field);
        }

        /**
         * Deserialize field of Bool type to given member field of block
         * @tparam V - block member type
         * @tparam B - block type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @return @see deserialize
         */
        template <typename V, typename B>
        auto Bool(V B::*member, const std::string &field) {
          return deserialize<bool>(member, field);
        }

        /**
         * Deserialize field of String type to given member field of block
         * @tparam V - block member type
         * @tparam B - block type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @return @see deserialize
         */
        template <typename V, typename B>
        auto String(V B::*member, const std::string &field) {
          return deserialize<std::string>(member, field);
        }

        /**
         * Deserialize field of String type
         * @param field - field name for deserialization
         * @return deserialized field on success, nullopt otherwise
         */
        auto String(const std::string &field) {
          return deserializeField<std::string>(document, field);
        }

        /**
         * Deserialize field of Array type to given member field of block,
         * using provided transform function
         * @tparam V - block member type
         * @tparam B - block type
         * @tparam Convert - transform function type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @param transform - transform function from Array to V
         * @return @see deserialize
         */
        template <typename V, typename B, typename Convert = Convert<V>>
        auto Array(V B::*member,
                   const std::string &field,
                   Convert transform = Convert()) {
          return deserialize<rapidjson::Value::ConstArray>(
              member, field, transform);
        }

        /**
         * Deserialize field of Object type to given member field of block
         * @tparam V - block member type
         * @tparam B - block type
         * @param member - pointer to member in block
         * @param field - field name for deserialization
         * @return @see deserialize
         */
        template <typename V, typename B, typename Convert = Convert<V>>
        auto Object(V B::*member,
                    const std::string &field,
                    Convert transform = Convert()) {
          return deserialize<rapidjson::Value::ConstObject>(
              member, field, transform);
        }

        // document for deserialization
        const D &document;
      };

      /**
       * Factory method for FieldDeserializer functor
       * @tparam D - document type
       * @param document - document for deserialization
       * @return FieldDeserializer instance for given arguments
       */
      template <typename D>
      auto makeFieldDeserializer(const D &document) {
        return FieldDeserializer<D>(document);
      }

      template <>
      struct Convert<Signature> {
        template <typename T>
        auto operator()(T &&x) const {
          auto des = makeFieldDeserializer(std::forward<T>(x));
          return boost::make_optional(Signature())
              | des.String(&Signature::pubkey, "pubkey")
              | des.String(&Signature::signature, "signature");
        }
      };

      template <>
      struct Convert<Block::SignaturesType> {
        template <typename T>
        auto operator()(T &&x) const {
          auto acc_signatures = [](auto init, auto &x) {
            return init | [&x](auto signatures) {
              return Convert<Signature>()(x) | [&signatures](auto signature) {
                signatures.push_back(signature);
                return boost::make_optional(std::move(signatures));
              };
            };
          };
          return std::accumulate(x.begin(),
                                 x.end(),
                                 boost::make_optional(Block::SignaturesType()),
                                 acc_signatures);
        }
      };

      template <>
      struct Convert<GetTransactions::TxHashCollectionType> {
        template <typename T>
        auto operator()(T &&x) const {
          auto acc_hashes = [](auto init, auto &x) {
            return init | [&x](auto tx_hashes)
                       -> boost::optional<
                           GetTransactions::TxHashCollectionType> {
              // If invalid type included, returns nullopt
              if (not x.IsString()) {
                return boost::none;
              }
              auto tx_hash_opt =
                  Convert<GetTransactions::TxHashType>()(x.GetString());
              if (not tx_hash_opt) {
                // If the the hash is wrong, just skip.
                return boost::make_optional(std::move(tx_hashes));
              }
              return tx_hash_opt | [&tx_hashes](auto tx_hash) {
                tx_hashes.push_back(tx_hash);
                return boost::make_optional(std::move(tx_hashes));
              };
            };
          };
          return std::accumulate(
              x.begin(),
              x.end(),
              boost::make_optional(GetTransactions::TxHashCollectionType()),
              acc_hashes);
        }
      };

      /**
       * Serialize signature to JSON with given allocator
       * @param signature - signature for serialization
       * @param allocator - allocator for JSON value
       * @return JSON value with signature
       */
      rapidjson::Value serializeSignature(
          const Signature &signature,
          rapidjson::Document::AllocatorType &allocator);

      /**
       * Try to parse JSON from string
       * @param string - string for parsing
       * @return JSON document on success, nullopt otherwise
       */
      boost::optional<rapidjson::Document> stringToJson(
          const std::string &string);

      /**
       * Pretty print JSON document to string
       * @param document - document for printing
       * @return pretty printed JSON document
       */
      std::string jsonToString(const rapidjson::Document &document);
    }  // namespace converters
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_JSON_COMMON_HPP
