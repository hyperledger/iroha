properties([parameters([
  booleanParam(defaultValue: true, description: 'Build `iroha`', name: 'iroha'),
  booleanParam(defaultValue: true, description: '', name: 'x86_64_linux'),
  booleanParam(defaultValue: false, description: '', name: 'armv7_linux'),
  booleanParam(defaultValue: false, description: '', name: 'armv8_linux'),
  booleanParam(defaultValue: true, description: '', name: 'x86_64_macos'),
  booleanParam(defaultValue: false, description: '', name: 'x86_64_win'),
  choice(choices: 'Debug\nRelease', description: 'Iroha build type', name: 'build_type'),
  booleanParam(defaultValue: true, description: 'Build docs', name: 'Doxygen'),
  booleanParam(defaultValue: true, description: 'Sanitize address;leak', name: 'sanitize'),
  booleanParam(defaultValue: false, description: 'Build fuzzing, but do not run tests', name: 'fuzzing'),
  booleanParam(defaultValue: true, description: 'Collect coredumps', name: 'coredump'),
  string(defaultValue: '8', description: 'Expect ~3GB memory consumtion per CPU core', name: 'PARALLELISM')])])


pipeline {
  environment {
    CCACHE_DIR = '/opt/.ccache'
    CCACHE_RELEASE_DIR = '/opt/.ccache-release'
    SORABOT_TOKEN = credentials('SORABOT_TOKEN')
    SONAR_TOKEN = credentials('SONAR_TOKEN')
    GIT_RAW_BASE_URL = "https://raw.githubusercontent.com/hyperledger/iroha"
    DOCKER_REGISTRY_BASENAME = "hyperledger/iroha"

    IROHA_NETWORK = "iroha-0${CHANGE_ID}-${GIT_COMMIT}-${BUILD_NUMBER}"
    IROHA_POSTGRES_HOST = "pg-0${CHANGE_ID}-${GIT_COMMIT}-${BUILD_NUMBER}"
    IROHA_POSTGRES_USER = "pguser${GIT_COMMIT}"
    IROHA_POSTGRES_PASSWORD = "${GIT_COMMIT}"
    IROHA_POSTGRES_PORT = 5432
    CHANGE_BRANCH_LOCAL = ''
  }

  options {
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timestamps()
  }

  agent any
  stages {
    stage ('Stop same job builds') {
      agent { label 'master' }
      steps {
        script {
          // need this for develop->master PR cases
          // CHANGE_BRANCH is not defined if this is a branch build
          try {
            CHANGE_BRANCH_LOCAL = env.CHANGE_BRANCH
          }
          catch(MissingPropertyException e) { }
          if (GIT_LOCAL_BRANCH != "develop" && CHANGE_BRANCH_LOCAL != "develop") {
            def builds = load ".jenkinsci/cancel-builds-same-job.groovy"
            builds.cancelSameJobBuilds()
          }
        }
      }
    }
    stage('Build Debug') {
      when {
        allOf {
          expression { params.build_type == 'Debug' }
          expression { return params.iroha }
        }
      }
      parallel {
        stage ('x86_64_linux') {
          when {
            beforeAgent true
            expression { return params.x86_64_linux }
          }
          agent { label 'docker-build-agent' }
          steps {
            script {
              debugBuild = load ".jenkinsci/debug-build.groovy"
              coverage = load ".jenkinsci/selected-branches-coverage.groovy"
              if (coverage.selectedBranchesCoverage(['master'])) {
                debugBuild.doDebugBuild(true)
              }
              else {
                debugBuild.doDebugBuild()
              }
              if (GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
                releaseBuild = load ".jenkinsci/release-build.groovy"
                releaseBuild.doReleaseBuild()
              }
            }
          }
          post {
            always {
              script {
                post = load ".jenkinsci/linux-post-step.groovy"
                post.linuxPostStep()
              }
            }
          }
        }
        stage('armv7_linux') {
          when {
            beforeAgent true
            expression { return params.armv7_linux }
          }
          agent { label 'armv7' }
          steps {
            script {
              debugBuild = load ".jenkinsci/debug-build.groovy"
              coverage = load ".jenkinsci/selected-branches-coverage.groovy"
              if (!params.x86_64_linux && !params.armv8_linux && !params.x86_64_macos && (coverage.selectedBranchesCoverage(['master']))) {
                debugBuild.doDebugBuild(true)
              }
              else {
                debugBuild.doDebugBuild()
              }
              if (GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
                releaseBuild = load ".jenkinsci/release-build.groovy"
                releaseBuild.doReleaseBuild()
              }
            }
          }
          post {
            always {
              script {
                post = load ".jenkinsci/linux-post-step.groovy"
                post.linuxPostStep()
              }
            }
          }
        }
        stage('armv8_linux') {
          when {
            beforeAgent true
            expression { return params.armv8_linux }
          }
          agent { label 'armv8' }
          steps {
            script {
              debugBuild = load ".jenkinsci/debug-build.groovy"
              coverage = load ".jenkinsci/selected-branches-coverage.groovy"
              if (!params.x86_64_linux && !params.x86_64_macos && (coverage.selectedBranchesCoverage(['master']))) {
                debugBuild.doDebugBuild(true)
              }
              else {
                debugBuild.doDebugBuild()
              }
              if (GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
                releaseBuild = load ".jenkinsci/release-build.groovy"
                releaseBuild.doReleaseBuild()
              }
            }
          }
          post {
            always {
              script {
                post = load ".jenkinsci/linux-post-step.groovy"
                post.linuxPostStep()
              }
            }
          }
        }
        stage('x86_64_macos'){
          when {
            beforeAgent true
            expression { return params.x86_64_macos }
          }
          agent { label 'mac' }
          steps {
            script {
              def coverageEnabled = false
              def cmakeOptions = ""
              coverage = load ".jenkinsci/selected-branches-coverage.groovy"
              if (!params.x86_64_linux && (coverage.selectedBranchesCoverage(['master']))) {
                coverageEnabled = true
                cmakeOptions = " -DCOVERAGE=ON "
              }
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
                  -DTESTING=ON \
                  -H. \
                  -Bbuild \
                  -DCMAKE_BUILD_TYPE=${params.build_type} \
                  -DIROHA_VERSION=${env.IROHA_VERSION} \
                  ${cmakeOptions}
              """
              sh "cmake --build build -- -j${params.PARALLELISM}"
              sh "ccache --show-stats"
              if ( coverageEnabled ) {
                sh "cmake --build build --target coverage.init.info"
              }
              sh """
                export IROHA_POSTGRES_PASSWORD=${IROHA_POSTGRES_PASSWORD}; \
                export IROHA_POSTGRES_USER=${IROHA_POSTGRES_USER}; \
                mkdir -p /var/jenkins/${GIT_COMMIT}-${BUILD_NUMBER}; \
                initdb -D /var/jenkins/${GIT_COMMIT}-${BUILD_NUMBER}/ -U ${IROHA_POSTGRES_USER} --pwfile=<(echo ${IROHA_POSTGRES_PASSWORD}); \
                pg_ctl -D /var/jenkins/${GIT_COMMIT}-${BUILD_NUMBER}/ -o '-p 5433 -c max_prepared_transactions=100' -l /var/jenkins/${GIT_COMMIT}-${BUILD_NUMBER}/events.log start; \
                psql -h localhost -d postgres -p 5433 -U ${IROHA_POSTGRES_USER} --file=<(echo create database ${IROHA_POSTGRES_USER};)
              """
              sh "cd build; IROHA_POSTGRES_HOST=localhost IROHA_POSTGRES_PORT=5433 ctest --output-on-failure --no-compress-output -T Test || true"
              sh 'python .jenkinsci/helpers/platform_tag.py "Darwin \$(uname -m)" \$(ls build/Testing/*/Test.xml)'
              // Mark build as UNSTABLE if there are any failed tests (threshold <100%)
              xunit testTimeMargin: '3000', thresholdMode: 2, thresholds: [passed(unstableThreshold: '100')], \
                tools: [CTest(deleteOutputFiles: true, failIfNotNew: false, \
                pattern: 'build/Testing/**/Test.xml', skipNoTestFiles: false, stopProcessingIfError: true)]
              if ( coverageEnabled ) {
                sh "cmake --build build --target cppcheck"
                // Sonar
                if (env.CHANGE_ID != null) {
                  sh """
                    sonar-scanner \
                      -Dsonar.github.disableInlineComments \
                      -Dsonar.github.repository='hyperledger/iroha' \
                      -Dsonar.analysis.mode=preview \
                      -Dsonar.login=${SONAR_TOKEN} \
                      -Dsonar.projectVersion=${BUILD_TAG} \
                      -Dsonar.github.oauth=${SORABOT_TOKEN}
                  """
                }
                sh "cmake --build build --target coverage.info"
                sh "python /usr/local/bin/lcov_cobertura.py build/reports/coverage.info -o build/reports/coverage.xml"
                cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/build/reports/coverage.xml', conditionalCoverageTargets: '75, 50, 0', failUnhealthy: false, failUnstable: false, lineCoverageTargets: '75, 50, 0', maxNumberOfBuilds: 50, methodCoverageTargets: '75, 50, 0', onlyStable: false, zoomCoverageChart: false
              }
              if (GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
                releaseBuild = load ".jenkinsci/mac-release-build.groovy"
                releaseBuild.doReleaseBuild()
              }
            }
          }
          post {
            always {
              script {
                timeout(time: 600, unit: "SECONDS") {
                  try {
                    if (currentBuild.currentResult == "SUCCESS" && GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
                      def artifacts = load ".jenkinsci/artifacts.groovy"
                      def commit = env.GIT_COMMIT
                      filePaths = [ '\$(pwd)/build/*.tar.gz' ]
                      artifacts.uploadArtifacts(filePaths, sprintf('iroha/macos/%1$s-%2$s-%3$s', [GIT_LOCAL_BRANCH, sh(script: 'date "+%Y%m%d"', returnStdout: true).trim(), commit.substring(0,6)]))
                    }
                  }
                  finally {
                    cleanWs()
                    sh """
                      pg_ctl -D /var/jenkins/${GIT_COMMIT}-${BUILD_NUMBER}/ stop && \
                      rm -rf /var/jenkins/${GIT_COMMIT}-${BUILD_NUMBER}/
                    """
                  }
                }
              }
            }
          }
        }
      }
    }
    stage('Build Release') {
      when {
        expression { params.build_type == 'Release' }
        expression { return params.iroha }
      }
      parallel {
        stage('x86_64_linux') {
          when {
            beforeAgent true
            expression { return params.x86_64_linux }
          }
          agent { label 'docker-build-agent' }
          steps {
            script {
              def releaseBuild = load ".jenkinsci/release-build.groovy"
              releaseBuild.doReleaseBuild()
            }
          }
          post {
            always {
              script {
                post = load ".jenkinsci/linux-post-step.groovy"
                post.linuxPostStep()
              }
            }
          }
        }
        stage('armv7_linux') {
          when {
            beforeAgent true
            expression { return params.armv7_linux }
          }
          agent { label 'armv7' }
          steps {
            script {
              def releaseBuild = load ".jenkinsci/release-build.groovy"
              releaseBuild.doReleaseBuild()
            }
          }
          post {
            always {
              script {
                post = load ".jenkinsci/linux-post-step.groovy"
                post.linuxPostStep()
              }
            }
          }
        }
        stage('armv8_linux') {
          when {
            beforeAgent true
            expression { return params.armv8_linux }
          }
          agent { label 'armv8' }
          steps {
            script {
              def releaseBuild = load ".jenkinsci/release-build.groovy"
              releaseBuild.doReleaseBuild()
            }
          }
          post {
            always {
              script {
                post = load ".jenkinsci/linux-post-step.groovy"
                post.linuxPostStep()
              }
            }
          }
        }
        stage('x86_64_macos') {
          when {
            beforeAgent true
            expression { return params.x86_64_macos }
          }
          agent { label 'mac' }
          steps {
            script {
              def releaseBuild = load ".jenkinsci/mac-release-build.groovy"
              releaseBuild.doReleaseBuild()
            }
          }
          post {
            always {
              script {
                timeout(time: 600, unit: "SECONDS") {
                  try {
                    if (currentBuild.currentResult == "SUCCESS" && GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
                      def artifacts = load ".jenkinsci/artifacts.groovy"
                      def commit = env.GIT_COMMIT
                      filePaths = [ '\$(pwd)/build/*.tar.gz' ]
                      artifacts.uploadArtifacts(filePaths, sprintf('iroha/macos/%1$s-%2$s-%3$s', [GIT_LOCAL_BRANCH, sh(script: 'date "+%Y%m%d"', returnStdout: true).trim(), commit.substring(0,6)]))
                    }
                  }
                  finally {
                    cleanWs()
                  }
                }
              }
            }
          }
        }
      }
    }
    stage('Build docs') {
      when {
        beforeAgent true
        expression { return params.Doxygen }
      }
      agent { label 'docker-build-agent' }
      steps {
        script {
          def doxygen = load ".jenkinsci/doxygen.groovy"
          def dPullOrBuild = load ".jenkinsci/docker-pull-or-build.groovy"
          def platform = sh(script: 'uname -m', returnStdout: true).trim()
          def iC = dPullOrBuild.dockerPullOrUpdate(
            "$platform-develop-build",
            "${env.GIT_RAW_BASE_URL}/${env.GIT_COMMIT}/docker/develop/Dockerfile",
            "${env.GIT_RAW_BASE_URL}/${env.GIT_PREVIOUS_COMMIT}/docker/develop/Dockerfile",
            "${env.GIT_RAW_BASE_URL}/develop/docker/develop/Dockerfile",
            ['PARALLELISM': params.PARALLELISM])
          iC.inside() {
            doxygen.doDoxygen()
          }
        }
      }
      post {
        cleanup {
          cleanWs()
        }
      }
    }
  }
}
