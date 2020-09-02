#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// vars to map compiler versions
//

def compilerMapping () {
  return ['gcc9': ['cxx_compiler':'g++-9', 'cc_compiler':'gcc-9'],
          'gcc10' : ['cxx_compiler':'g++-10', 'cc_compiler':'gcc-10'],
          'clang10': ['cxx_compiler':'clang++-10', 'cc_compiler':'clang-10'],
          'appleclang': ['cxx_compiler':'clang++', 'cc_compiler':'clang'],
         ]
  }


return this
