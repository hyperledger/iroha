#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// This module helps automatically build new docker develop-build image if Dockerfile changed
//

def buildOptionsString(options) {
  def s = ''
  if (options) {
    options.each { k, v ->
      s += "--build-arg ${k}=${v} "
    }
  }
  return s
}

def dockerPullOrBuild(imageName, currentDockerfileURL, referenceDockerfileURL, scmVars, environment, forceBuild=false, buildOptions=null) {
  buildOptions = buildOptionsString(buildOptions)
  withEnv(environment) {
    def utils = load '.jenkinsci/utils/utils.groovy'
    sh("docker pull ${env.DOCKER_REGISTRY_BASENAME}:${imageName} || true")
    randDir = sh(script: "cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 10", returnStdout: true).trim()
    currentDockerfile = utils.getUrl(currentDockerfileURL, "/tmp/${randDir}/currentDockerfile", true)
    referenceDockerfile = utils.getUrl(referenceDockerfileURL, "/tmp/${randDir}/referenceDockerfile")
    if (utils.filesDiffer(currentDockerfile, referenceDockerfile) || forceBuild) {
      // Dockerfile has been changed compared to reference file
      // We cannot rely on the local cache
      // because Dockerfile may contain apt-get entries that would try to update
      // from invalid (stale) addresses
      iC = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${randDir}-${BUILD_NUMBER}", "${buildOptions} --no-cache -f ${currentDockerfile} .")
    }
    iC = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${randDir}-${BUILD_NUMBER}", "${buildOptions}  -f ${currentDockerfile} .")
  }
  return iC
}

return this
