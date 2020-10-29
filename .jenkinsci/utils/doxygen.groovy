#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
//  Builds and push Doxygen docks
//

def doDoxygen() {
  sh "doxygen Doxyfile"
  archiveArtifacts artifacts: 'docs/doxygen/html/*', allowEmptyArchive: true
}

return this
