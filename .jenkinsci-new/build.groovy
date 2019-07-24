#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// functions we use when build iroha
//

def removeDirectory(String buildDir, Map remote) {
  sh (script: "rm -rf ${buildDir}", remote: remote)
}

def cmakeConfigure(String buildDir, String cmakeOptions, String sourceTreeDir=".", Map remote) {
  sh (script: "cmake -H${sourceTreeDir} -B${buildDir} ${cmakeOptions}", remote: remote)
}

def cmakeBuild(String buildDir, String cmakeOptions, int parallelism, Map remote) {
  sh (script: """
    cmake --build ${buildDir} ${cmakeOptions} -- -j${parallelism} \
    ccache --show-stats
  """, remote: remote)
}

def cmakeBuildWindows(String buildDir, String cmakeOptions, Map remote) {
  sh (script: "cmake --build ${buildDir} ${cmakeOptions}", remote: remote)
}

def cppCheck(String buildDir, int parallelism, Map remote) {
  // github.com/jenkinsci/cppcheck-plugin/pull/36
  sh (script: "cppcheck -j${parallelism} --enable=all -i${buildDir} --template='{file},,{line},,{severity},,{id},,{message}' . 2> cppcheck.txt", remote: remote)
  if (remote) {
    sh "vagrant rsync"
  }
  warnings (
    parserConfigurations: [[parserName: 'Cppcheck', pattern: "cppcheck.txt"]], categoriesPattern: '',
    defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', unHealthy: ''
  )
}

def sonarScanner(scmVars, environment, Map remote) {
  withEnv(environment) {
    withCredentials([string(credentialsId: 'SONAR_TOKEN', variable: 'SONAR_TOKEN'), string(credentialsId: 'SORABOT_TOKEN', variable: 'SORABOT_TOKEN')]) {
      sonar_option = ""
      if (CHANGE_ID != null)
        sonar_option = "-Dsonar.github.pullRequest=${CHANGE_ID}"
      else
        print "************** Warning No 'CHANGE_ID' Present run sonar without org.sonar.plugins.github.PullRequest *****************"
      // do analysis by sorabot
      sh (script: """
        sonar-scanner \
          -Dsonar.github.disableInlineComments=true \
          -Dsonar.github.repository='${env.DOCKER_REGISTRY_BASENAME}' \
          -Dsonar.analysis.mode=preview \
          -Dsonar.login=${SONAR_TOKEN} \
          -Dsonar.projectVersion=${BUILD_TAG} \
          -Dsonar.github.oauth=${SORABOT_TOKEN}  ${sonar_option}
      """, remote: remote)
      if (scmVars.GIT_BRANCH == "master" )
        // push analysis results to sonar
        sh (script: """
          sonar-scanner \
            -Dsonar.login=${SONAR_TOKEN}
        """, remote: remote)
    }
  }
}

def clangFormat (scmVars, environment, Map remote) {
  withEnv(environment) {
    if (env.CHANGE_TARGET){
      sh (script: """
        git diff origin/${env.CHANGE_TARGET} --name-only | grep -E '\\.(cc|cpp|cxx|C|c\\+\\+|c|CPP|h|hpp|hh|icc)\$' | xargs clang-format-7 -style=file -i || true
        git diff | tee  clang-format-report.txt
        git reset HEAD --hard
      """, remote: remote)
      if (remote) {
        sh "vagrant rsync"
      }
      archiveArtifacts artifacts: 'clang-format-report.txt', allowEmptyArchive: true
    }
    else
       print "This is not a PR, env.CHANGE_TARGET not found"
  }
}

def initialCoverage(String buildDir, Map remote) {
  sh (script: "cmake --build ${buildDir} --target coverage.init.info", remote: remote)
}

def postCoverage(buildDir, String cobertura_bin, Map remote) {
  sh(script: """
    cmake --build ${buildDir} --target coverage.info \
    python ${cobertura_bin} ${buildDir}/reports/coverage.info -o ${buildDir}/reports/coverage.xml
  """, remote: remote)
  if (remote) {
    sh "vagrant rsync"
  }
  cobertura autoUpdateHealth: false, autoUpdateStability: false,
    coberturaReportFile: "**/${buildDir}/reports/coverage.xml", conditionalCoverageTargets: '75, 50, 0',
    failUnhealthy: false, failUnstable: false, lineCoverageTargets: '75, 50, 0', maxNumberOfBuilds: 50,
    methodCoverageTargets: '75, 50, 0', onlyStable: false, zoomCoverageChart: false
}

return this
