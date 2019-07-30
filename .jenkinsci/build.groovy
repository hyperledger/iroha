#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// functions we use when build iroha
//

def removeDirectory(String buildDir) {
  sh "rm -rf ${buildDir}"
}

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
      if (env.CHANGE_ID != null) {
        sonar_option = "-Dsonar.github.pullRequest=${env.CHANGE_ID}"
      }
      else {
        print "************** Warning No 'CHANGE_ID' Present run sonar without org.sonar.plugins.github.PullRequest *****************"
      }
      // do analysis by sorabot
      sh """
        sonar-scanner \
          -Dsonar.github.disableInlineComments=true \
          -Dsonar.github.repository='${env.DOCKER_REGISTRY_BASENAME}' \
          -Dsonar.analysis.mode=preview \
          -Dsonar.login=${SONAR_TOKEN} \
          -Dsonar.projectVersion=${BUILD_TAG} \
          -Dsonar.github.oauth=${SORABOT_TOKEN}  ${sonar_option}
      """
      if (scmVars.GIT_BRANCH == "master" )
        // push analysis results to sonar
        sh """
          sonar-scanner \
            -Dsonar.login=${SONAR_TOKEN}
        """
    }
  }
}

def clangFormat (scmVars, environment) {
  withEnv(environment) {
    if (env.CHANGE_TARGET){
      sh"""
        git diff origin/${env.CHANGE_TARGET} --name-only | grep -E '\\.(cc|cpp|cxx|C|c\\+\\+|c|CPP|h|hpp|hh|icc)\$' | xargs clang-format-7 -style=file -i || true
        git diff | tee  clang-format-report.txt
        if [ \$(cat clang-format-report.txt | wc -l ) -eq 0 ]; then
          echo "All clean!" >> clang-format-report.txt
        fi
        git reset HEAD --hard
      """
      archiveArtifacts artifacts: 'clang-format-report.txt', allowEmptyArchive: true
    }
    else
       print "This is not a PR, env.CHANGE_TARGET not found"
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
