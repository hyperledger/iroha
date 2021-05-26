/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MURMUR_2_HPP
#define IROHA_MURMUR_2_HPP

namespace iroha::ct_hash {

  class Hasher {
    static constexpr /* h */ uint32_t __init__(uint32_t len) {
      return 0 ^ len;
    }

    template <typename __T>
    static constexpr uint32_t __load__(__T &data, uint32_t offset) {
      return data[offset + 0] | (data[offset + 1] << 8)
          | (data[offset + 2] << 16) | (data[offset + 3] << 24);
    }

    static constexpr uint32_t __mul__(uint32_t val1, uint32_t val2) {
      return val1 * val2;
    }

    static constexpr uint32_t __sl__(uint32_t value, uint32_t count) {
      return (value << count);
    }

    static constexpr uint32_t __sr__(uint32_t value, uint32_t count) {
      return (value >> count);
    }

    static constexpr uint32_t __xor__(uint32_t h, uint32_t k) {
      return h ^ k;
    }

    static constexpr uint32_t __xor_with_sr__(uint32_t k, uint32_t r) {
      return __xor__(k, __sr__(k, r));
    }

    template <typename __Type>
    static constexpr /* h */ uint32_t __proc__(__Type &data,
                                               uint32_t len,
                                               uint32_t offset,
                                               uint32_t h,
                                               uint32_t m,
                                               uint32_t r) {
      return len >= 4
          ? __proc__(data,
                     len - 4,
                     offset + 4,
                     __xor__(__mul__(h, m),
                             __mul__(__xor_with_sr__(
                                         __mul__(__load__(data, offset), m), r),
                                     m)),
                     m,
                     r)
          : len == 3
              ? __proc__(data,
                         len - 1,
                         offset,
                         __xor__(h, __sl__(data[offset + 2], 16)),
                         m,
                         r)
              : len == 2 ? __proc__(data,
                                    len - 1,
                                    offset,
                                    __xor__(h, __sl__(data[offset + 1], 8)),
                                    m,
                                    r)
                         : len == 1
                      ? __proc__(data,
                                 len - 1,
                                 offset,
                                 __xor__(h, data[offset]) * m,
                                 m,
                                 r)
                      : __xor__(__mul__(__xor_with_sr__(h, 13), m),
                                __sr__(__mul__(__xor_with_sr__(h, 13), m), 15));
    }

   public:
    template <typename __Type>
    static constexpr uint32_t murmur2(__Type &data, uint32_t len) {
      return __proc__(data, len, 0, __init__(len), 0x5bd1e995, 24);
    }
  };

}  // namespace iroha::ct_hash

#ifndef CT_MURMUR2
#define CT_MURMUR2(x) \
  ::iroha::ct_hash::Hasher::murmur2(x, (sizeof(x) / sizeof(x[0])) - 1)
#endif  // CT_MURMUR2

static_assert(CT_MURMUR2("Called the One Ring, or the Ruling Ring.")
              == 1333588607);
static_assert(
    CT_MURMUR2("Fashioned by Sauron a decade after the making of the Elven "
               "rings in the fires of Mount Doom in Mordor and which")
    == 1319897327);
static_assert(CT_MURMUR2("could only be destroyed in that same fire.")
              == 702138758);

#endif  // IROHA_MURMUR_2_HPP
