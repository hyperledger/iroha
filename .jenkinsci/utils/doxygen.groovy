#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
//  Builds and push Doxygen docks
//

def doDoxygen(boolean specialBranch, String local_branch) {
  sh "doxygen Doxyfile"
  if (specialBranch) {
    def branch = local_branch == "master" ? local_branch : "develop"
    sshagent(['jenkins-artifact']) {
      sh "ssh-agent"
      sh """
        rsync \
        -e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no' \
        -rzcv --delete \
        docs/doxygen/html/* \
        ubuntu@docs.iroha.tech:/var/nexus-efs/doxygen/${branch}/
      """
    }
  } else {
    archiveArtifacts artifacts: 'docs/doxygen/html/*', allowEmptyArchive: true
  }
}

return this
