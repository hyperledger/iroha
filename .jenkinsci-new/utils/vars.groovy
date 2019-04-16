#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// vars to map compiler versions
//

def compilerMapping () {
  return ['gcc5': ['cxx_compiler':'g++-5', 'cc_compiler':'gcc-5'],
          'gcc7' : ['cxx_compiler':'g++-7', 'cc_compiler':'gcc-7'],
          'clang6': ['cxx_compiler':'clang++-6.0', 'cc_compiler':'clang-6.0'],
          'clang7': ['cxx_compiler':'clang++-7', 'cc_compiler':'clang-7'],
          'appleclang': ['cxx_compiler':'clang++', 'cc_compiler':'clang'],
         ]
  }


return this
