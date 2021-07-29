/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_REMOVE_ESCAPE_SYMBOLS_HPP
#define IROHA_REMOVE_ESCAPE_SYMBOLS_HPP

#include <string>
#include <type_traits>

namespace iroha {

  template <typename _CharT,
            typename = std::enable_if_t<std::is_same<_CharT, char>::value>>
  inline char slashCode() {
    return '\\';
  }

  template <typename _CharT,
            typename = std::enable_if_t<std::is_same<_CharT, wchar_t>::value>>
  inline wchar_t slashCode() {
    return L'\\';
  }

  template <typename _CharT,
            typename = std::enable_if_t<std::is_same<_CharT, char>::value>>
  inline char endlCode() {
    return '\0';
  }

  template <typename _CharT,
            typename = std::enable_if_t<std::is_same<_CharT, wchar_t>::value>>
  inline wchar_t endlCode() {
    return L'\0';
  }

  template <typename _CharT, typename _Traits, typename _Alloc>
  inline void removeEscapeSymbols(
      std::basic_string<_CharT, _Traits, _Alloc> &data) {
    _CharT const *rptr = data.data();
    _CharT *wptr = (_CharT *)rptr;

    if (rptr[0] != endlCode<_CharT>())
      do {
        rptr += *rptr == slashCode<_CharT>() ? 1ul : 0ul;
        *wptr++ = *rptr;
      } while (*rptr++ != endlCode<_CharT>());
    data.resize(data.size() - size_t(rptr - wptr));
  }

}  // namespace iroha
#endif  // IROHA_REMOVE_ESCAPE_SYMBOLS_HPP
