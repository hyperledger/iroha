/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_MACRO_HPP
#define IROHA_MACRO_HPP

#ifdef IROHA_ALIGN
#   error IROHA_ALIGN already defined.
#endif//IROHA_ALIGN

#ifdef IROHA_ALIGN_TYPE
#   error IROHA_ALIGN_TYPE already defined.
#endif//IROHA_ALIGN_TYPE

#if defined(_MSC_VER)
#   define IROHA_ALIGN(x) __declspec(align(x))
#else
#   if defined(__GNUC__)
#       define IROHA_ALIGN(x) __attribute__ ((aligned(x)))
#   endif
#endif
#define IROHA_ALIGN_TYPE(t,x) typedef t IROHA_ALIGN(x)

#ifndef IROHA_ALIGN_MEM
#   define IROHA_ALIGN_MEM(mem,base) ((((size_t)mem) + static_cast<size_t>(base - 1)) & ~static_cast<size_t>(base - 1))
#endif//IROHA_ALIGN_MEM

#endif//IROHA_MACRO_HPP
