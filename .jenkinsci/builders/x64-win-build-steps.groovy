#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Windows Build steps
//

def buildSteps(int parallelism, List compilerVersions, String buildType, boolean coverage, boolean testing, String testList,
       boolean packageBuild, boolean useBTF, List environment) {
  withEnv(environment) {
    def utils
    stage('Prepare Windows environment') {
      scmVars = checkout scm
      utils = load ".jenkinsci/utils/utils.groovy"

      win_local_vcpkg_hash = bat(script: "python .jenkinsci\\helpers\\hash.py vcpkg", returnStdout: true).trim().readLines()[-1].trim()
      win_vcpkg_path = "C:\\vcpkg-${win_local_vcpkg_hash}"
      win_vcpkg_toolchain_file = "${win_vcpkg_path}\\scripts\\buildsystems\\vcpkg.cmake"

      utils.build_vcpkg(win_vcpkg_path,win_vcpkg_toolchain_file)
    }
    for (compiler in compilerVersions) {
      stage ("build ${compiler}"){
        bat """
cmake -H.\\ -B.\\build -DCMAKE_TOOLCHAIN_FILE=${win_vcpkg_toolchain_file} -G "Visual Studio 16 2019" -A x64 -T host=x64 &&^
cmake --build .\\build --target irohad &&^
cmake --build .\\build --target iroha-cli
        """
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
