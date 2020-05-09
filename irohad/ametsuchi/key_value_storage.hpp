/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KV_STORAGE_HPP
#define IROHA_KV_STORAGE_HPP

#include <optional>
#include <string>
#include <vector>

namespace iroha {

  namespace ametsuchi {

    /**
     * Solid storage interface
     */
    class KeyValueStorage {
     public:
      /**
       * Type of storage key
       */
      using Identifier = uint32_t;
      using Bytes = std::vector<uint8_t>;

      /**
       * Add entity with binary data
       * @param id - reference key
       * @param blob - data associated with key
       */
      virtual bool add(Identifier id, const Bytes &blob) = 0;

      /**
       * Get data associated with
       * @param id - reference key
       * @return - blob, if exists
       */
      virtual std::optional<Bytes> get(Identifier id) const = 0;

      /**
       * @return folder of storage
       */
      virtual std::string directory() const = 0;

      /**
       * @return chronologically last not null key
       */
      virtual Identifier last_id() const = 0;

      virtual void dropAll() = 0;

      virtual ~KeyValueStorage() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_KV_STORAGE_HPP
