#!/usr/bin/env groovy

def remoteFilesDiffer(f1, f2) {
  sh "curl -L -o /tmp/${env.GIT_COMMIT}/f1 --create-dirs ${f1}"
  sh "curl -L -o /tmp/${env.GIT_COMMIT}/f2 ${f2}"
  diffExitCode = sh(script: "diff -q /tmp/${env.GIT_COMMIT}/f1 /tmp/${env.GIT_COMMIT}/f2", returnStatus: true)
  return diffExitCode != 0
}

def buildOptionsString(options) {
  def s = ''
  if (options) {
    options.each { k, v ->
      s += "--build-arg ${k}=${v} "
    }
  }
  return s
}

def dockerPullOrUpdate(imageName, currentDockerfileURL, previousDockerfileURL, referenceDockerfileURL, buildOptions=null) {
  buildOptions = buildOptionsString(buildOptions)
  def commit = sh(script: "echo ${GIT_LOCAL_BRANCH} | md5sum | cut -c 1-8", returnStdout: true).trim()
  if(remoteFilesDiffer(currentDockerfileURL, referenceDockerfileURL)) {
    // Dockerfile is differ from develop
    if (remoteFilesDiffer(currentDockerfileURL, previousDockerfileURL)) {
      // Dockerfile has been changed compared to the previous commit
      // Worst case scenario. We cannot count on the local cache
      // because Dockerfile may contain apt-get entries that would try to update
      // from invalid (stale) addresses
      iC = docker.build("${DOCKER_REGISTRY_BASENAME}:${commit}-${BUILD_NUMBER}", "${buildOptions} --no-cache -f /tmp/${env.GIT_COMMIT}/f1 /tmp/${env.GIT_COMMIT}")
    } else {
      // if we're lucky to build on the same agent, image will be built using cache
      iC = docker.build("${DOCKER_REGISTRY_BASENAME}:${commit}-${BUILD_NUMBER}", "$buildOptions -f /tmp/${env.GIT_COMMIT}/f1 /tmp/${env.GIT_COMMIT}")
    }
  } else {
    // Dockerfile is same as develop
    if (GIT_LOCAL_BRANCH == "develop" && remoteFilesDiffer(currentDockerfileURL, previousDockerfileURL)) {
     // we in dev branch and docker file was changed
     iC = docker.build("${DOCKER_REGISTRY_BASENAME}:${commit}-${BUILD_NUMBER}", "${buildOptions} --no-cache -f /tmp/${env.GIT_COMMIT}/f1 /tmp/${env.GIT_COMMIT}")
    } else {
      // Dockerfile is same as develop, we can just pull it
      def testExitCode = sh(script: "docker pull ${DOCKER_REGISTRY_BASENAME}:${imageName}", returnStatus: true)
      if (testExitCode != 0) {
        // image does not (yet) exist on Dockerhub. Build it
        iC = docker.build("${DOCKER_REGISTRY_BASENAME}:${commit}-${BUILD_NUMBER}", "$buildOptions --no-cache -f /tmp/${env.GIT_COMMIT}/f1 /tmp/${env.GIT_COMMIT}")
      } else {
        // no difference found compared to both previous and reference Dockerfile
        iC = docker.image("${DOCKER_REGISTRY_BASENAME}:${imageName}")
      }
    }
  }
  if (GIT_LOCAL_BRANCH ==~ /develop|master/ || CHANGE_BRANCH_LOCAL == 'develop') {
    docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
      iC.push(imageName)
    }
  }
  return iC
}

return this
