/**
 * to_string.hpp - Provides compile-time integer-to-string conversion.
 * Written by Clyne Sullivan.
 * https://github.com/tcsullivan/constexpr-to-string
 */

#ifndef TCSULLIVAN_TO_STRING_HPP_
#define TCSULLIVAN_TO_STRING_HPP_

#include <type_traits>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-qualifiers"


namespace constexpr_to_string {

  inline constexpr char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/**
 * @struct to_string_t
 * @brief Provides the ability to convert any integral to a string at compile-time.
 * @tparam N Number to convert
 * @tparam base Desired base, can be from 2 to 36
 */
  template<auto N, int base, typename char_type,
      std::enable_if_t<std::is_integral_v<decltype(N)>, int> = 0,
      std::enable_if_t<(base > 1 && base < sizeof(digits)), int> = 0>
  struct to_string_t {
    // The lambda calculates what the string length of N will be, so that `buf`
    // fits to the number perfectly.
    char_type buf[([]() constexpr noexcept {
      unsigned int len = N > 0 ? 1 : 2;
      for (auto n = N; n; len++, n /= base);
      return len;
    }())] = {};

   public:
    /**
     * Constructs the object, filling `buf` with the string representation of N.
     */
    constexpr to_string_t() noexcept {
      auto ptr = end();
      *--ptr = '\0';
      if (N != 0) {
        for (auto n = N; n; n /= base)
          *--ptr = digits[(N < 0 ? -1 : 1) * (n % base)];
        if (N < 0)
          *--ptr = '-';
      } else {
        buf[0] = '0';
      }
    }

    // Support implicit casting to `char *` or `const char *`.
    constexpr operator char_type *() noexcept { return buf; }
    constexpr operator const char_type *() const noexcept { return buf; }

    constexpr auto size() const noexcept { return sizeof(buf) / sizeof(buf[0]); }
    // Element access
    constexpr auto data() noexcept { return buf; }
    constexpr const auto data() const noexcept { return buf; }
    constexpr auto& operator[](unsigned int i) noexcept { return buf[i]; }
    constexpr const auto& operator[](unsigned int i) const noexcept { return buf[i]; }
    constexpr auto& front() noexcept { return buf[0]; }
    constexpr const auto& front() const noexcept { return buf[0]; }
    constexpr auto& back() noexcept { return buf[size() - 1]; }
    constexpr const auto& back() const noexcept { return buf[size() - 1]; }
    // Iterators
    constexpr auto begin() noexcept { return buf; }
    constexpr const auto begin() const noexcept { return buf; }
    constexpr auto end() noexcept { return buf + size(); }
    constexpr const auto end() const noexcept { return buf + size(); }
  };

} // namespace constexpr_to_string

/**
 * Simplifies use of `to_string_t` from `to_string_t<N>()` to `to_string<N>`.
 */
template<auto N, int base = 10, typename char_type = char>
constexpr constexpr_to_string::to_string_t<N, base, char_type> to_string;

#pragma GCC diagnostic pop

#endif // TCSULLIVAN_TO_STRING_HPP_
