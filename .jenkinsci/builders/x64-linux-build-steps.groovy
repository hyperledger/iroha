#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Linux Build steps
//

def dockerManifestPush(dockerImageObj, String dockerTag, environment) {
  def manifest = load ".jenkinsci/utils/docker-manifest.groovy"
  withEnv(environment) {
    if (manifest.manifestSupportEnabled()) {
      manifest.manifestCreate("${env.DOCKER_REGISTRY_BASENAME}:${dockerTag}",
        ["${env.DOCKER_REGISTRY_BASENAME}:x86_64-${dockerTag}"])
      manifest.manifestAnnotate("${env.DOCKER_REGISTRY_BASENAME}:${dockerTag}",
        [
          [manifest: "${env.DOCKER_REGISTRY_BASENAME}:x86_64-${dockerTag}",
           arch: 'amd64', os: 'linux', osfeatures: [], variant: ''],
        ])
      withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'login', passwordVariable: 'password')]) {
        manifest.manifestPush("${env.DOCKER_REGISTRY_BASENAME}:${dockerTag}", login, password)
      }
    }
    else {
      echo('[WARNING] Docker CLI does not support manifest management features. Manifest will not be updated')
    }
  }
}

def testSteps(String buildDir, List environment, String testList) {
  withEnv(environment) {
    sh "cd ${buildDir}; rm -f Testing/*/Test.xml; ctest --output-on-failure --no-compress-output --tests-regex '${testList}'  --test-action Test || true"
    sh """ python .jenkinsci/helpers/platform_tag.py "Linux \$(uname -m)" \$(ls ${buildDir}/Testing/*/Test.xml) """
    // Mark build as UNSTABLE if there are any failed tests (threshold <100%)
    xunit testTimeMargin: '3000', thresholdMode: 2, thresholds: [passed(unstableThreshold: '100')], \
      tools: [CTest(deleteOutputFiles: true, failIfNotNew: false, \
      pattern: "${buildDir}/Testing/**/Test.xml", skipNoTestFiles: false, stopProcessingIfError: true)]
  }
}

def buildSteps(int parallelism, List compilerVersions, String build_type, boolean build_shared_libs, boolean specialBranch, boolean coverage,
      boolean testing, String testList, boolean cppcheck, boolean sonar, boolean codestyle, boolean docs, boolean packagebuild, boolean sanitize,
      boolean fuzzing, boolean benchmarking, boolean coredumps, boolean useBTF, boolean use_libursa, boolean forceDockerDevelopBuild, List environment) {
  withEnv(environment) {
    scmVars = checkout scm
    def build = load '.jenkinsci/build.groovy'
    def vars = load ".jenkinsci/utils/vars.groovy"
    def utils = load ".jenkinsci/utils/utils.groovy"
    def dockerUtils = load ".jenkinsci/utils/docker-pull-or-build.groovy"
    def doxygen = load ".jenkinsci/utils/doxygen.groovy"
    buildDir = 'build'
    compilers = vars.compilerMapping()
    cmakeBooleanOption = [ (true): 'ON', (false): 'OFF' ]
    platform = sh(script: 'uname -m', returnStdout: true).trim()
    cmakeBuildOptions = ""
    cmakeOptions = ""
    if (packagebuild){
      cmakeBuildOptions = " --target package "
    }
    if (sanitize){
      cmakeOptions += " -DSANITIZE='address;leak' "
    }
    // enable coredumps collecting
    if (coredumps) {
      sh "echo %e.%p.coredump > /proc/sys/kernel/core_pattern"
      sh "ulimit -c unlimited"
    }
    // Create postgres
    // enable prepared transactions so that 2 phase commit works
    // we set it to 100 as a safe value
    sh """#!/bin/bash -xe
      if [ ! "\$(docker ps -q -f name=${env.IROHA_POSTGRES_HOST})" ]; then
        docker network create ${env.IROHA_NETWORK}
        docker run -td -e POSTGRES_USER=${env.IROHA_POSTGRES_USER} \
           -e POSTGRES_PASSWORD=${env.IROHA_POSTGRES_PASSWORD} --name ${env.IROHA_POSTGRES_HOST} \
           --network=${env.IROHA_NETWORK} postgres:9.5 -c 'max_prepared_transactions=100'
      fi
    """
    referenceBranchOrCommit = 'master'
    if (scmVars.GIT_LOCAL_BRANCH == referenceBranchOrCommit && scmVars.GIT_PREVIOUS_COMMIT) {
      referenceBranchOrCommit = scmVars.GIT_PREVIOUS_COMMIT
    }
    iC = dockerUtils.dockerPullOrBuild("${platform}-develop-build",
        "${env.GIT_RAW_BASE_URL}/${scmVars.GIT_COMMIT}/docker/develop/Dockerfile",
        "${env.GIT_RAW_BASE_URL}/${referenceBranchOrCommit}/docker/develop/Dockerfile",
        scmVars,
        environment,
        forceDockerDevelopBuild,
        ['PARALLELISM': parallelism])

    iC.inside(""
    + " -e IROHA_POSTGRES_HOST=${env.IROHA_POSTGRES_HOST}"
    + " -e IROHA_POSTGRES_PORT=${env.IROHA_POSTGRES_PORT}"
    + " -e IROHA_POSTGRES_USER=${env.IROHA_POSTGRES_USER}"
    + " -e IROHA_POSTGRES_PASSWORD=${env.IROHA_POSTGRES_PASSWORD}"
    + " --network=${env.IROHA_NETWORK}"
    + " -v /var/jenkins/ccache:${env.CCACHE_DEBUG_DIR}") {
      utils.ccacheSetup(5)
      for (compiler in compilerVersions) {
        stage ("build ${compiler}"){
          // Remove artifacts from the previous build
          build.removeDirectory(buildDir)
          build.cmakeConfigure(buildDir, "-DCMAKE_CXX_COMPILER=${compilers[compiler]['cxx_compiler']} \
            -DCMAKE_C_COMPILER=${compilers[compiler]['cc_compiler']} \
            -DCMAKE_BUILD_TYPE=${build_type} \
            -DBUILD_SHARED_LIBS=${cmakeBooleanOption[build_shared_libs]} \
            -DCOVERAGE=${cmakeBooleanOption[coverage]} \
            -DTESTING=${cmakeBooleanOption[testing]} \
            -DFUZZING=${cmakeBooleanOption[fuzzing]} \
            -DBENCHMARKING=${cmakeBooleanOption[benchmarking]} \
            -DPACKAGE_DEB=${cmakeBooleanOption[packagebuild]} \
            -DPACKAGE_TGZ=${cmakeBooleanOption[packagebuild]} \
            -DUSE_BTF=${cmakeBooleanOption[useBTF]} \
            -DUSE_LIBURSA=${cmakeBooleanOption[use_libursa]} \
            -DCMAKE_TOOLCHAIN_FILE=/opt/dependencies/scripts/buildsystems/vcpkg.cmake ${cmakeOptions}")
          build.cmakeBuild(buildDir, cmakeBuildOptions, parallelism)
        }
        if (testing) {
          stage("Test ${compiler}") {
            coverage ? build.initialCoverage(buildDir) : echo('Skipping initial coverage...')
            testSteps(buildDir, environment, testList)
            coverage ? build.postCoverage(buildDir, '/tmp/lcov_cobertura.py') : echo('Skipping post coverage...')
            // We run coverage once, using the first compiler as it is enough
            coverage = false
          }
        } //end if
      } //end for
      stage("Analysis") {
            cppcheck ? build.cppCheck(buildDir, parallelism) : echo('Skipping Cppcheck...')
            sonar ? build.sonarScanner(scmVars, environment) : echo('Skipping Sonar Scanner...')
            codestyle ? build.clangFormat(scmVars, environment) : echo('Skipping Code Style...')
      }
      stage('Build docs'){
        docs ? doxygen.doDoxygen(specialBranch, scmVars.GIT_LOCAL_BRANCH) : echo("Skipping Doxygen...")
      }
    } // end iC.inside
    stage ('Docker ManifestPush'){
      if (specialBranch && !env.TAG_NAME || forceDockerDevelopBuild) {
        utils.dockerPush(iC, "${platform}-develop-build")
        dockerManifestPush(iC, "develop-build", environment)
      }
    }
  }
}

def successPostSteps(scmVars, boolean packagePush, String dockerTag, List environment) {
  stage('Linux success PostSteps') {
    withEnv(environment) {
      if (packagePush) {
        def artifacts = load ".jenkinsci/artifacts.groovy"
        def utils = load ".jenkinsci/utils/utils.groovy"
        platform = sh(script: 'uname -m', returnStdout: true).trim()
        def commit = scmVars.GIT_COMMIT

        // if we use several compilers only the last compiler, used for the build, will be used for iroha.deb and iroha.tar.gz archives
        sh """
          ls -lah ./build
          mv ./build/iroha-*.deb ./build/iroha.deb
          mv ./build/iroha-*.tar.gz ./build/iroha.tar.gz
          cp ./build/iroha.deb docker/release/iroha.deb
          mkdir -p build/artifacts
          mv ./build/iroha.deb ./build/iroha.tar.gz build/artifacts
        """
        // publish docker
        iCRelease = docker.build("${env.DOCKER_REGISTRY_BASENAME}:${commit}-${env.BUILD_NUMBER}-release", "--no-cache -f docker/release/Dockerfile ${WORKSPACE}/docker/release")
        utils.dockerPush(iCRelease, "${platform}-${dockerTag}")
        dockerManifestPush(iCRelease, dockerTag, environment)
        sh "docker rmi ${iCRelease.id}"

        // publish packages
        filePaths = [ './build/artifacts/iroha.deb', './build/artifacts/iroha.tar.gz' ]
        artifacts.uploadArtifacts(filePaths, sprintf('/iroha/linux/%4$s/%1$s-%2$s-%3$s', [scmVars.GIT_LOCAL_BRANCH, sh(script: 'date "+%Y%m%d"', returnStdout: true).trim(), commit.substring(0,6), platform]))
      } else {
        archiveArtifacts artifacts: 'build/iroha*.tar.gz', allowEmptyArchive: true
        archiveArtifacts artifacts: 'build/iroha*.deb', allowEmptyArchive: true
      }
    }
  }
}

def alwaysPostSteps(scmVars, List environment, boolean coredumps) {
  stage('Linux always PostSteps') {
    // handling coredumps (if tests crashed)
    if (currentBuild.currentResult != "SUCCESS" && coredumps) {
      def dumpsFileName = sprintf('coredumps-%1$s.bzip2',
        [scmVars.GIT_COMMIT.substring(0,8)])

      sh(script: "echo 'build/bin' > coredumps.upload")
      sh(script: "find . -type f -name '*.coredump' -exec echo '{}' \\; >> coredumps.upload")
      sh(script: "tar -cjvf ${dumpsFileName} -T coredumps.upload")
      if( fileExists(dumpsFileName)) {
        withCredentials([usernamePassword(credentialsId: 'ci_nexus', passwordVariable: 'NEXUS_PASS', usernameVariable: 'NEXUS_USER')]) {
          sh(script: "curl -u ${NEXUS_USER}:${NEXUS_PASS} --upload-file ${WORKSPACE}/${dumpsFileName} https://nexus.iroha.tech/repository/artifacts/iroha/coredumps/${dumpsFileName}")
        }
        echo "Build is not SUCCESS! Download core dumps at: https://nexus.iroha.tech/repository/artifacts/iroha/coredumps/${dumpsFileName}"
      }
    }
    withEnv(environment) {
      sh "docker rm -f ${env.IROHA_POSTGRES_HOST} || true"
      sh "docker network rm ${env.IROHA_NETWORK}"
      cleanWs()
    }
  }
}

return this
