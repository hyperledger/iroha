/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KAGOME_BUFFER_HPP
#define KAGOME_BUFFER_HPP

#include <vector>

#include <boost/container_hash/hash.hpp>
#include <boost/operators.hpp>
#include "common/result.hpp"

namespace kagome {
  namespace common {

    /**
     * @brief Class represents arbitrary (including empty) byte buffer.
     */
    class Buffer : public boost::equality_comparable<Buffer>,
                   public boost::equality_comparable<std::vector<uint8_t>> {
     public:
      using iterator = std::vector<uint8_t>::iterator;
      using const_iterator = std::vector<uint8_t>::const_iterator;
      using value_type = uint8_t;
      // with this gsl::span can be built from Buffer
      using pointer = typename std::vector<uint8_t>::pointer;
      using const_pointer = typename std::vector<uint8_t>::const_pointer;

      /**
       * @brief allocates buffer of size={@param size}, filled with {@param
       * byte}
       */
      Buffer(size_t size, uint8_t byte);

      ~Buffer() = default;

      /**
       * @brief lvalue construct buffer from a byte vector
       */
      explicit Buffer(std::vector<uint8_t> v);

      Buffer(const uint8_t *begin, const uint8_t *end);

      Buffer() = default;
      Buffer(const Buffer &b) = default;
      Buffer(Buffer &&b) noexcept = default;
      Buffer(std::initializer_list<uint8_t> b);

      Buffer &reserve(size_t size);
      Buffer &resize(size_t size);

      Buffer &operator=(const Buffer &other) = default;
      Buffer &operator=(Buffer &&other) noexcept = default;

      Buffer &operator+=(const Buffer &other) noexcept;

      /**
       * @brief Accessor of byte elements given {@param index} in bytearray
       */
      uint8_t operator[](size_t index) const;

      /**
       * @brief Accessor of byte elements given {@param index} in bytearray
       */
      uint8_t &operator[](size_t index);

      /**
       * @brief Lexicographical comparison of two buffers
       */
      bool operator==(const Buffer &b) const noexcept;

      /**
       * @brief Lexicographical comparison of buffer and vector of bytes
       */
      bool operator==(const std::vector<uint8_t> &b) const noexcept;

      /**
       * @brief Iterator, which points to begin of this buffer.
       */
      iterator begin();

      /**
       * @brief Iterator, which points to the element next to the last in this
       * buffer.
       */
      iterator end();

      /**
       * @brief Iterator, which points to begin of this buffer.
       */
      const_iterator begin() const;

      /**
       * @brief Iterator, which points to the element next to the last in this
       * buffer.
       */
      const_iterator end() const;

      /**
       * @brief Getter for size of this buffer.
       */
      size_t size() const;

      /**
       * @brief Put a 8-bit {@param n} in this buffer.
       * @return this buffer, suitable for chaining.
       */
      Buffer &putUint8(uint8_t n);

      /**
       * @brief Put a 32-bit {@param n} number in this buffer. Will be
       * serialized as big-endian number.
       * @return this buffer, suitable for chaining.
       */
      Buffer &putUint32(uint32_t n);

      /**
       * @brief Put a 64-bit {@param n} number in this buffer. Will be
       * serialized as big-endian number.
       * @return this buffer, suitable for chaining.
       */
      Buffer &putUint64(uint64_t n);

      /**
       * @brief Put a string into byte buffer
       * @param s arbitrary string
       * @return this buffer, suitable for chaining.
       */
      Buffer &put(const std::string &str);

      /**
       * @brief Put a vector of bytes into byte buffer
       * @param s arbitrary vector of bytes
       * @return this buffer, suitable for chaining.
       */
      Buffer &put(const std::vector<uint8_t> &v);

      /**
       * @brief Put a array of bytes bounded by pointers into byte buffer
       * @param begin pointer to the array start
       *        end pointer to the address after the last element
       * @return this buffer, suitable for chaining.
       */
      Buffer &putBytes(const uint8_t *begin, const uint8_t *end);

      /**
       * @brief Put another buffer content at the end of current one
       * @param buf another buffer
       * @return this buffer suitable for chaining.
       */
      Buffer &putBuffer(const Buffer &buf);

      /**
       * Clear the contents of the Buffer
       */
      void clear();

      /**
       * @brief getter for raw array of bytes
       */
      const uint8_t *data() const;
      uint8_t *data();

      /**
       * @brief getter for vector of bytes
       */
      const std::vector<uint8_t> &toVector() const;

      std::vector<uint8_t> &toVector();

      /**
       * @brief encode bytearray as hex
       * @return hex-encoded string
       */
      std::string toHex() const;

      /**
       * bytestring
       */
      std::string toByteString() const;

      /**
       * Check if this buffer is empty
       * @return true, if buffer is empty, false otherwise
       */
      bool empty() const;

      /**
       * @brief Construct Buffer from hex string
       * @param hex hex-encoded string
       * @return result containing constructed buffer if input string is
       * hex-encoded string.
       */
      static iroha::expected::Result<Buffer, std::string> fromHex(
          const std::string &hex);

     private:
      std::vector<uint8_t> data_;

      template <typename T>
      Buffer &putRange(const T &begin, const T &end);
    };

    /**
     * @brief override operator<< for all streams except std::ostream
     * @tparam Stream stream type
     * @param s stream reference
     * @param buffer value to encode
     * @return reference to stream
     */
    template <class Stream,
              typename = std::enable_if_t<Stream::is_encoder_stream>>
    Stream &operator<<(Stream &s, const Buffer &buffer) {
      return s << buffer.toVector();
    }

    /**
     * @brief decodes buffer object from stream
     * @tparam Stream input stream type
     * @param s stream reference
     * @param buffer value to decode
     * @return reference to stream
     */
    template <class Stream,
              typename = std::enable_if_t<Stream::is_decoder_stream>>
    Stream &operator>>(Stream &s, Buffer &buffer) {
      std::vector<uint8_t> data;
      s >> data;
      buffer.put(data);
      return s;
    }

    std::ostream &operator<<(std::ostream &os, const Buffer &buffer);

  }  // namespace common
}  // namespace kagome

namespace std {
  template <>
  struct hash<kagome::common::Buffer> {
    size_t operator()(const kagome::common::Buffer &x) const {
      return boost::hash_range(x.begin(), x.end());
    }
  };
}  // namespace std

#endif  // KAGOME_BUFFER_HPP
