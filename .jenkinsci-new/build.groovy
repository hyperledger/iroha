#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// functions we use when build iroha
//

def cmakeConfigure(String buildDir, String cmakeOptions, String sourceTreeDir=".") {
  sh "cmake -H${sourceTreeDir} -B${buildDir} ${cmakeOptions}"
}

def cmakeBuild(String buildDir, String cmakeOptions, int parallelism) {
  sh "cmake --build ${buildDir} ${cmakeOptions} -- -j${parallelism}"
  sh "ccache --show-stats"
}

def cmakeBuildWindows(String buildDir, String cmakeOptions) {
  sh "cmake --build ${buildDir} ${cmakeOptions}"
}

def cppCheck(String buildDir, int parallelism) {
  // github.com/jenkinsci/cppcheck-plugin/pull/36
  sh "cppcheck -j${parallelism} --enable=all -i${buildDir} --template='{file},,{line},,{severity},,{id},,{message}' . 2> cppcheck.txt"
  warnings (
    parserConfigurations: [[parserName: 'Cppcheck', pattern: "cppcheck.txt"]], categoriesPattern: '',
    defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', unHealthy: ''
  )
}

def sonarScanner(scmVars, environment) {
  withEnv(environment) {
    withCredentials([string(credentialsId: 'SONAR_TOKEN', variable: 'SONAR_TOKEN'), string(credentialsId: 'SORABOT_TOKEN', variable: 'SORABOT_TOKEN')]) {
      sonar_option = ""
      if (scmVars.CHANGE_ID != null)
        sonar_option = "-Dsonar.github.pullRequest=${scmVars.CHANGE_ID}"
      else
        print "************** Warning No 'CHANGE_ID' Present run sonar without org.sonar.plugins.github.PullRequestProjectBuilder *****************"

      sh """
        sonar-scanner \
          -Dsonar.github.disableInlineComments \
          -Dsonar.github.repository='${env.DOCKER_REGISTRY_BASENAME}' \
          -Dsonar.analysis.mode=preview \
          -Dsonar.login=${SONAR_TOKEN} \
          -Dsonar.projectVersion=${BUILD_TAG} \
          -Dsonar.github.oauth=${SORABOT_TOKEN}  ${sonar_option}
      """
    }
  }
}

def initialCoverage(String buildDir) {
  sh "cmake --build ${buildDir} --target coverage.init.info"
}

def postCoverage(buildDir, String cobertura_bin) {
  sh "cmake --build ${buildDir} --target coverage.info"
  sh "python ${cobertura_bin} ${buildDir}/reports/coverage.info -o ${buildDir}/reports/coverage.xml"
  cobertura autoUpdateHealth: false, autoUpdateStability: false,
    coberturaReportFile: "**/${buildDir}/reports/coverage.xml", conditionalCoverageTargets: '75, 50, 0',
    failUnhealthy: false, failUnstable: false, lineCoverageTargets: '75, 50, 0', maxNumberOfBuilds: 50,
    methodCoverageTargets: '75, 50, 0', onlyStable: false, zoomCoverageChart: false
}
return this
