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
    bat "cd .\\${buildDir} & del /q /f /s Test.xml & ctest --output-on-failure --no-compress-output --tests-regex \"${testList}\" --test-action Test || exit 0"
    bat "for /f \"usebackq tokens=*\" %%a in (`dir .\\${buildDir} /s /b ^| findstr Testing ^| findstr Test.xml`) do python .\\.jenkinsci\\helpers\\platform_tag.py \"Windows %PROCESSOR_ARCHITECTURE%\" %%a"
    bat "for /f \"usebackq tokens=*\" %%a in (`dir .\\${buildDir} /s /b ^| findstr Testing ^| findstr Test.xml`) do python .\\.jenkinsci\\helpers\\transform_xml.py .\\.jenkinsci\\helpers\\ctest-to-junit.xsl %%a"
    junit "${buildDir}/Testing/**/Test.xml"
  }
}

def buildSteps(int parallelism, List compilerVersions, String buildType, boolean coverage, boolean testing, String testList,
       boolean packageBuild, boolean benchmarking, boolean useBTF, List environment) {
  withEnv(environment) {
    def utils
    stage('Prepare Windows environment') {
      scmVars = checkout scm
      buildDir = 'build'
      utils = load ".jenkinsci/utils/utils.groovy"
      cmakeBooleanOption = [ (true): 'ON', (false): 'OFF' ]

      win_local_vcpkg_hash = bat(script: "python .jenkinsci\\helpers\\hash.py vcpkg", returnStdout: true).trim().readLines()[-1].trim()
      win_vcpkg_path = "C:\\vcpkg-${win_local_vcpkg_hash}"
      win_vcpkg_toolchain_file = "${win_vcpkg_path}\\scripts\\buildsystems\\vcpkg.cmake"

      utils.build_vcpkg(win_vcpkg_path,win_vcpkg_toolchain_file)
    }
    compilerVersions.each { compiler ->
      stage ("build ${compiler}"){
        bat """
call \"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat\" &&^
cmake -H.\\ -B.\\${buildDir} -DCMAKE_BUILD_TYPE=${buildType} -DTESTING=${cmakeBooleanOption[testing]} -DBENCHMARKING=${cmakeBooleanOption[benchmarking]} -DUSE_BTF=${cmakeBooleanOption[useBTF]} -DCMAKE_TOOLCHAIN_FILE=${win_vcpkg_toolchain_file} -GNinja &&^
cmake --build .\\${buildDir} -- -j${parallelism}
        """
      }
      if (testing) {
          stage("Test ${compiler}") {
            // coverage ? build.initialCoverage(buildDir) : echo('Skipping initial coverage...')
            testSteps(buildDir, environment, testList)
            // coverage ? build.postCoverage(buildDir, '/tmp/lcov_cobertura.py') : echo('Skipping post coverage...')
            // We run coverage once, using the first compiler as it is enough
            // coverage = false
          }
        } //end if
    } //end for
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
