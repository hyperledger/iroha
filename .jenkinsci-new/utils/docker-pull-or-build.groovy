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

def dockerPullOrBuild(imageName, currentDockerfileURL, previousDockerfileURL, referenceDockerfileURL, currentVCPKGSHAURL, previousVCPKGSHAURL, referenceVCPKGSHAURL, scmVars, environment, forceBuild=false, buildOptions=null) {
  buildOptions = buildOptionsString(buildOptions)
  withEnv(environment) {
    def utils = load '.jenkinsci-new/utils/utils.groovy'
    randDir = sh(script: "cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 10", returnStdout: true).trim()
    currentDockerfile = utils.getUrl(currentDockerfileURL, "/tmp/${randDir}/currentDockerfile", true)
    previousDockerfile = utils.getUrl(previousDockerfileURL, "/tmp/${randDir}/previousDockerfile")
    referenceDockerfile = utils.getUrl(referenceDockerfileURL, "/tmp/${randDir}/referenceDockerfile")
    currentVCPKGSHA = utils.getUrl(currentVCPKGSHAURL, "/tmp/${randDir}/currentVCPKGSHA", true)
    previousVCPKGSHA = utils.getUrl(previousVCPKGSHAURL, "/tmp/${randDir}/previousVCPKGSHA", true)
    referenceVCPKGSHA = utils.getUrl(referenceVCPKGSHAURL, "/tmp/${randDir}/referenceVCPKGSHA", true)
    contextDir = "/tmp/${randDir}"
    if (utils.filesDiffer(currentDockerfile, referenceDockerfile) || utils.filesDiffer(currentVCPKGSHA, referenceVCPKGSHA) || forceBuild ) {
      // Either Dockerfile or VCPKG SHA differs from reference
      if (utils.filesDiffer(currentDockerfile, previousDockerfile)) {
        // Either Dockerfile or VCPKG SHA have been changed compared to both the previous commit and reference files
        // Worst case scenario. We cannot count on the local cache
        // because Dockerfile may contain apt-get entries that would try to update
        // from invalid (stale) addresses
        iC = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${randDir}-${BUILD_NUMBER}", "${buildOptions} --no-cache -f ${currentDockerfile} ${contextDir}")
      } else {
        // if we're lucky to build on the same agent, image will be built using cache
        iC = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${randDir}-${BUILD_NUMBER}", "${buildOptions}  -f ${currentDockerfile} ${contextDir}")
      }
    }
    else {
      // Dockerfile is same as reference
      if ( scmVars.GIT_LOCAL_BRANCH == "master" && (utils.filesDiffer(currentDockerfile, previousDockerfile) || utils.filesDiffer(currentVCPKGSHA, previousVCPKGSHA)) {
        // we are in master branch and either Dockerfile or VCPKG SHA have changed
        iC = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${randDir}-${BUILD_NUMBER}", "${buildOptions} --no-cache -f ${currentDockerfile} ${contextDir}")
      } else {
        // try pulling image from Dockerhub, probably image is already there
        def testExitCode = sh(script: "docker pull ${env.DOCKER_REGISTRY_BASENAME}:${imageName}", returnStatus: true)
        if (testExitCode != 0) {
          // image does not (yet) exist on Dockerhub. Build it
          iC = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${randDir}-${BUILD_NUMBER}", "$buildOptions --no-cache -f ${currentDockerfile} ${contextDir}")
        }
        else {
          // no difference found compared to both (previous and reference Dockerfile) OR (previous and reference VCPKG SHA)
          iC = docker.image("${env.DOCKER_REGISTRY_BASENAME}:${imageName}")
        }
      }
    }
  }
  return iC
}

return this
