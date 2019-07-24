#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

def vagrantSetupMacOS(String currentPackerTemplateURL, String referencePackerTemplateURL, List environment):
  def utils = load '.jenkinsci-new/utils/utils.groovy'
  randDir = sh(script: "cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 10", returnStdout: true).trim()
  currentPackerTemplate = utils.getUrl(currentPackerTemplateURL, "/tmp/${randDir}/currentPackerTemplate", true)
  referencePackerTemplate = utils.getUrl(referencePackerTemplateURL, "/tmp/${randDir}/referencePackerTemplate", true)
  // if (utils.filesDiffer(currentPackerTemplate, referencePackerTemplate)) {
  //   withCredentials([string(credentialsId: 'vagrantcloud-soramitsu', variable: 'VAGRANT_CLOUD_TOKEN')]) {
  //     // mainline branch -> publish an image on Vagrantcloud
  //     if (scmVars.GIT_LOCAL_BRANCH == 'master') {
  //       sh "cd ./.packer/macos && packer build macos-build.json"
  //       sh "vagrant init soramitsu/iroha-develop-build && vagrant up"
  //     }
  //     // do not publish an image on Vagrantcloud if something has changed in the non-mainline branch
  //     // build it locally
  //     else {
  //       sh "cd ./.packer/macos && packer build -except=vagrant-cloud macos-build.json"
  //       // TODO: How to run?
  //       sh "cd "
  //     }
  //   }
  // }
  // else {
    sh "vagrant init soramitsu/iroha-develop-build && vagrant up"
  // }

def vagrantTeardownMacOS() {
  sh "vagrant destroy"
}

return this
