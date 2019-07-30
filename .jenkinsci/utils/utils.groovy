#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Small utils that can be used multiple times
//

def selectedBranchesCoverage(List branches) {
  return env.GIT_LOCAL_BRANCH in branches
}

def ccacheSetup(int maxSize) {
  sh """
    ccache --version
    ccache --show-stats
    ccache --zero-stats
    ccache --max-size=${maxSize}G
  """
}

def dockerPush(dockerImageObj, String imageName) {
  docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
    dockerImageObj.push(imageName)
  }
}

def getUrl(String url, String savePath, boolean createDstDir=false) {
  if (createDstDir) {
    sh "curl -L -o ${savePath} --create-dirs ${url}"
  }
  else {
    sh "curl -L -o ${savePath} ${url}"
  }
  return savePath
}

def filesDiffer(String f1, String f2) {
  diffExitCode = sh(script: "diff -q ${f1} ${f2}", returnStatus: true)
  return diffExitCode != 0
}

return this
