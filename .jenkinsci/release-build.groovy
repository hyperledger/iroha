#!/usr/bin/env groovy

def doReleaseBuild() {
  def parallelism = params.PARALLELISM
  def manifest = load ".jenkinsci/docker-manifest.groovy"
  // params are always null unless job is started
  // this is the case for the FIRST build only.
  // So just set this to same value as default.
  // This is a known bug. See https://issues.jenkins-ci.org/browse/JENKINS-41929
  if (!parallelism) {
    parallelism = 4
  }
  if (env.NODE_NAME.contains('arm7')) {
    parallelism = 1
  }
  def platform = sh(script: 'uname -m', returnStdout: true).trim()
  sh "mkdir /tmp/${env.GIT_COMMIT}-${BUILD_NUMBER} || true"
  iC = docker.image("${DOCKER_REGISTRY_BASENAME}:${platform}-develop-build")
  iC.pull()
  iC.inside(""
    + " -v /tmp/${GIT_COMMIT}-${BUILD_NUMBER}:/tmp/${GIT_COMMIT}"
    + " -v /var/jenkins/ccache:${CCACHE_RELEASE_DIR}") {

    def scmVars = checkout scm
    env.IROHA_VERSION = "0x${scmVars.GIT_COMMIT}"
    env.IROHA_HOME = "/opt/iroha"
    env.IROHA_BUILD = "${env.IROHA_HOME}/build"

    sh """
      ccache --version
      ccache --show-stats
      ccache --zero-stats
      ccache --max-size=5G
    """
    sh """
      cmake \
        -H. \
        -Bbuild \
        -DCMAKE_BUILD_TYPE=Release \
        -DIROHA_VERSION=${env.IROHA_VERSION} \
        -DPACKAGE_DEB=ON \
        -DPACKAGE_TGZ=ON \
        -DCOVERAGE=OFF \
        -DTESTING=OFF
    """
    sh "cmake --build build --target package -- -j${parallelism}"
    sh "ccache --show-stats"

    // move build package to the volume
    sh "mv ./build/iroha-*.deb /tmp/${GIT_COMMIT}/iroha.deb"
    sh "mv ./build/*.tar.gz /tmp/${GIT_COMMIT}/iroha.tar.gz"
  }

  sh "curl -L -o /tmp/${env.GIT_COMMIT}/Dockerfile --create-dirs ${env.GIT_RAW_BASE_URL}/${env.GIT_COMMIT}/docker/release/Dockerfile"
  sh "curl -L -o /tmp/${env.GIT_COMMIT}/entrypoint.sh ${env.GIT_RAW_BASE_URL}/${env.GIT_COMMIT}/docker/release/entrypoint.sh"
  sh "curl -L -o /tmp/${env.GIT_COMMIT}/wait-for-it.sh ${env.GIT_RAW_BASE_URL}/${env.GIT_COMMIT}/docker/release/wait-for-it.sh"
  sh "mv /tmp/${GIT_COMMIT}-${BUILD_NUMBER}/iroha.deb /tmp/${env.GIT_COMMIT}"
  iCRelease = docker.build("${DOCKER_REGISTRY_BASENAME}:${GIT_COMMIT}-${BUILD_NUMBER}-release", "--no-cache -f /tmp/${env.GIT_COMMIT}/Dockerfile /tmp/${env.GIT_COMMIT}")

  // push Docker image in case the current branch is develop,
  // or it is a commit into PR which base branch is develop (usually develop -> master)
  checkTag = sh(script: 'git describe --tags --exact-match ${GIT_COMMIT}', returnStatus: true)
  if (GIT_LOCAL_BRANCH == 'develop' || CHANGE_BRANCH_LOCAL == 'develop') {
    docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
      iCRelease.push("${platform}-develop")
    }
    if (manifest.manifestSupportEnabled()) {
      manifest.manifestCreate("${DOCKER_REGISTRY_BASENAME}:develop",
        ["${DOCKER_REGISTRY_BASENAME}:x86_64-develop"])
      manifest.manifestAnnotate("${DOCKER_REGISTRY_BASENAME}:develop",
        [
          [manifest: "${DOCKER_REGISTRY_BASENAME}:x86_64-develop",
           arch: 'amd64', os: 'linux', osfeatures: [], variant: '']
        ])
      withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'login', passwordVariable: 'password')]) {
        manifest.manifestPush("${DOCKER_REGISTRY_BASENAME}:develop", login, password)
      }
    }
  }
  else if (GIT_LOCAL_BRANCH == 'master') {
    docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
      iCRelease.push("${platform}-latest")
    }
    if (manifest.manifestSupportEnabled()) {
      manifest.manifestCreate("${DOCKER_REGISTRY_BASENAME}:latest",
        ["${DOCKER_REGISTRY_BASENAME}:x86_64-latest"])
      manifest.manifestAnnotate("${DOCKER_REGISTRY_BASENAME}:latest",
        [
          [manifest: "${DOCKER_REGISTRY_BASENAME}:x86_64-latest",
           arch: 'amd64', os: 'linux', osfeatures: [], variant: '']
        ])
      withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'login', passwordVariable: 'password')]) {
        manifest.manifestPush("${DOCKER_REGISTRY_BASENAME}:latest", login, password)
      }
    }
    if (checkTag == 0) {
      def tag = sh(script: 'git describe --tags --exact-match ${GIT_COMMIT}', returnStdout: true).trim().replaceAll('-','_')
      docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
        iCRelease.push("${platform}-${tag}")
      }
      if (manifest.manifestSupportEnabled()) {
        manifest.manifestCreate("${DOCKER_REGISTRY_BASENAME}:${tag}",
          ["${DOCKER_REGISTRY_BASENAME}:x86_64-${tag}"])
        manifest.manifestAnnotate("${DOCKER_REGISTRY_BASENAME}:${tag}",
          [
            [manifest: "${DOCKER_REGISTRY_BASENAME}:x86_64-${tag}",
            arch: 'amd64', os: 'linux', osfeatures: [], variant: '']
          ])
        withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'login', passwordVariable: 'password')]) {
          manifest.manifestPush("${DOCKER_REGISTRY_BASENAME}:${tag}", login, password)
        }
      }
    }
  }
  sh "docker rmi ${iCRelease.id}"
}
return this
