#!/usr/bin/env groovy

def doDebugBuild(coverageEnabled=false) {
  def dPullOrBuild = load ".jenkinsci/docker-pull-or-build.groovy"
  def manifest = load ".jenkinsci/docker-manifest.groovy"
  def pCommit = load ".jenkinsci/previous-commit.groovy"
  def parallelism = params.PARALLELISM
  def sanitizeEnabled = params.sanitize
  def fuzzingEnabled = params.fuzzing
  def platform = sh(script: 'uname -m', returnStdout: true).trim()
  def previousCommit = pCommit.previousCommitOrCurrent()
  // params are always null unless job is started
  // this is the case for the FIRST build only.
  // So just set this to same value as default.
  // This is a known bug. See https://issues.jenkins-ci.org/browse/JENKINS-41929
  if (sanitizeEnabled == null){
    sanitizeEnabled = true
  }
  if (!parallelism) {
    parallelism = 4
  }
  if (env.NODE_NAME.contains('arm7')) {
    parallelism = 1
  }

  // enable coredumps collecting
  if (params.coredump) {
    sh "echo %e.%p.coredump > /proc/sys/kernel/core_pattern"
    sh "ulimit -c unlimited"
  }

  sh "docker network create ${env.IROHA_NETWORK}"
  def iC = dPullOrBuild.dockerPullOrUpdate("${platform}-develop-build",
                                           "${env.GIT_RAW_BASE_URL}/${env.GIT_COMMIT}/docker/develop/Dockerfile",
                                           "${env.GIT_RAW_BASE_URL}/${previousCommit}/docker/develop/Dockerfile",
                                           "${env.GIT_RAW_BASE_URL}/develop/docker/develop/Dockerfile",
                                           ['PARALLELISM': parallelism])
  // push Docker image in case the current branch is develop,
  // or it is a commit into PR which base branch is develop (usually develop -> master)
  if ((GIT_LOCAL_BRANCH == 'develop' || CHANGE_BRANCH_LOCAL == 'develop') && manifest.manifestSupportEnabled()) {
    manifest.manifestCreate("${DOCKER_REGISTRY_BASENAME}:develop-build",
      ["${DOCKER_REGISTRY_BASENAME}:x86_64-develop-build"]
    )
    manifest.manifestAnnotate("${DOCKER_REGISTRY_BASENAME}:develop-build",
      [
        [manifest: "${DOCKER_REGISTRY_BASENAME}:x86_64-develop-build",
         arch: 'amd64', os: 'linux', osfeatures: [], variant: '']
      ])
    withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'login', passwordVariable: 'password')]) {
      manifest.manifestPush("${DOCKER_REGISTRY_BASENAME}:develop-build", login, password)
    }
  }

  // enable prepared transactions so that 2 phase commit works
  // we set it to 100 as a safe value
  sh "docker run -td -e POSTGRES_USER=${env.IROHA_POSTGRES_USER} \
  -e POSTGRES_PASSWORD=${env.IROHA_POSTGRES_PASSWORD} --name ${env.IROHA_POSTGRES_HOST} \
  --network=${env.IROHA_NETWORK} postgres:9.5 -c 'max_prepared_transactions=100'"
  iC.inside(""
    + " -e IROHA_POSTGRES_HOST=${env.IROHA_POSTGRES_HOST}"
    + " -e IROHA_POSTGRES_PORT=${env.IROHA_POSTGRES_PORT}"
    + " -e IROHA_POSTGRES_USER=${env.IROHA_POSTGRES_USER}"
    + " -e IROHA_POSTGRES_PASSWORD=${env.IROHA_POSTGRES_PASSWORD}"
    + " --network=${env.IROHA_NETWORK}"
    + " -v /var/jenkins/ccache:${CCACHE_DIR}"
    + " -v /tmp/${GIT_COMMIT}-${BUILD_NUMBER}:/tmp/${GIT_COMMIT}") {

    def scmVars = checkout scm
    def cmakeOptions = ""
    if ( coverageEnabled ) {
      cmakeOptions += " -DCOVERAGE=ON "
    }
    if ( sanitizeEnabled ){
      cmakeOptions += " -DSANITIZE='address;leak' "
    }
    if ( fuzzingEnabled ){
      cmakeOptions += " -DCMAKE_C_COMPILER=clang-6.0 -DCMAKE_CXX_COMPILER=clang++-6.0 -DFUZZING=ON "
    }
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
        -DTESTING=ON \
        -H. \
        -Bbuild \
        -DCMAKE_BUILD_TYPE=Debug \
        -DIROHA_VERSION=${env.IROHA_VERSION} \
        ${cmakeOptions}
    """
    sh "cmake --build build -- -j${parallelism}"
    sh "ccache --show-stats"
    if ( coverageEnabled ) {
      sh "cmake --build build --target coverage.init.info"
    }
    //If fuzzing Enabled do not run tests, they never stop
    if ( !fuzzingEnabled ){
      sh "cd build; ctest --output-on-failure --no-compress-output -T Test || true"
      sh 'python .jenkinsci/helpers/platform_tag.py "Linux \$(uname -m)" \$(ls build/Testing/*/Test.xml)'
      // Mark build as UNSTABLE if there are any failed tests (threshold <100%)
      xunit testTimeMargin: '3000', thresholdMode: 2, thresholds: [passed(unstableThreshold: '100')], \
        tools: [CTest(deleteOutputFiles: true, failIfNotNew: false, \
        pattern: 'build/Testing/**/Test.xml', skipNoTestFiles: false, stopProcessingIfError: true)]
    }
    if ( coverageEnabled ) {
      sh "cmake --build build --target cppcheck"
      // Sonar
      if (env.CHANGE_ID != null) {
        sh """
          sonar-scanner \
            -Dsonar.github.disableInlineComments \
            -Dsonar.github.repository='${DOCKER_REGISTRY_BASENAME}' \
            -Dsonar.analysis.mode=preview \
            -Dsonar.login=${SONAR_TOKEN} \
            -Dsonar.projectVersion=${BUILD_TAG} \
            -Dsonar.github.oauth=${SORABOT_TOKEN} \
            -Dsonar.github.pullRequest=${CHANGE_ID}
        """
      }
      sh "cmake --build build --target coverage.info"
      sh "python /tmp/lcov_cobertura.py build/reports/coverage.info -o build/reports/coverage.xml"
      cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/build/reports/coverage.xml', conditionalCoverageTargets: '75, 50, 0', failUnhealthy: false, failUnstable: false, lineCoverageTargets: '75, 50, 0', maxNumberOfBuilds: 50, methodCoverageTargets: '75, 50, 0', onlyStable: false, zoomCoverageChart: false
    }
  }
}

return this
