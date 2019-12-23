#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Windows Build steps
//

def testSteps(String buildDir, List environment, String testList) {
  withEnv(environment) {
    bat 'cd .\\build & ctest --output-on-failure --no-compress-output'
    // sh "cd ${buildDir}; rm -f Testing/*/Test.xml; ctest --output-on-failure --no-compress-output --tests-regex '${testList}'  --test-action Test || true"
    // sh """ python .jenkinsci/helpers/platform_tag.py "Linux \$(uname -m)" \$(ls ${buildDir}/Testing/*/Test.xml) """
    // Mark build as UNSTABLE if there are any failed tests (threshold <100%)
    // xunit testTimeMargin: '3000', thresholdMode: 2, thresholds: [passed(unstableThreshold: '100')], \
      // tools: [CTest(deleteOutputFiles: true, failIfNotNew: false, \
      // pattern: "${buildDir}/Testing/**/Test.xml", skipNoTestFiles: false, stopProcessingIfError: true)]
  }
}

def buildSteps(int parallelism, List compilerVersions, String buildType, boolean coverage, boolean testing, String testList,
       boolean packageBuild, boolean useBTF, List environment) {
  withEnv(environment) {
    scmVars = checkout scm
    for (compiler in compilerVersions) {
      stage ("build ${compiler}"){
        bat '''
cmake -H.\\ -B.\\build -DBENCHMARKING=ON -DCMAKE_TOOLCHAIN_FILE=C:\\vcpkg\\scripts\\buildsystems\\vcpkg.cmake -G "Visual Studio 16 2019" -A x64 -T host=x64 &&^
cmake --build .\\build
        '''
      }
    }
  }
}

def successPostSteps(scmVars, boolean packagePush, List environment) {
  stage('Windows success PostSteps') {
    withEnv(environment) {
      if (packagePush){
        timeout(time: 600, unit: "SECONDS") {
           archiveArtifacts artifacts: 'build\\bin\\Debug\\iroha*.exe', allowEmptyArchive: true
        }
      }
    }
  }
}

def alwaysPostSteps(List environment) {
  stage('Windows always PostSteps') {
    withEnv(environment) {
      cleanWs()
    }
  }
}
return this
