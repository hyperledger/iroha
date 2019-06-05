#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Windows Build steps
//

def buildSteps(int parallelism, List compilerVersions, String build_type, boolean coverage, boolean testing, String testList,
       boolean packagebuild, boolean useBTF, List environment) {
  withEnv(environment) {
    scmVars = checkout scm
    for (compiler in compilerVersions) {
      stage ("build ${compiler}"){
        bat '''
            cmake -H.\\ -B.\\build -DCMAKE_TOOLCHAIN_FILE=C:\\vcpkg\\scripts\\buildsystems\\vcpkg.cmake -G "Visual Studio 15 2017 Win64" -T host=x64
            cmake --build .\\build --target irohad
            cmake --build .\\build --target iroha-cli
        '''
      }
    }
  }
}

def successPostSteps(scmVars, boolean packagePush, List environment) {
  stage('Windows success PostSteps') {
    withEnv(environment) {
      timeout(time: 600, unit: "SECONDS") {
         archiveArtifacts artifacts: 'build\\iroha*.exe', allowEmptyArchive: true
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