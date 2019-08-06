/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import org.jenkinsci.plugins.workflow.steps.FlowInterruptedException

def tasks = [:]

class Worker {
  String label
  int cpusAvailable
}

class Builder {
  // can't get to work without 'static'
  static class PostSteps {
    List success = []
    List failure = []
    List unstable = []
    List always = []
    List aborted = []
  }
  List buildSteps = []
  PostSteps postSteps
}

class Build {
  String name = ''
  String type = ''
  Builder builder
  Worker worker
}

def build(Build build) {
  return {
    node(build.worker.label) {
      try {
        echo "Worker: ${env.NODE_NAME}"
        gitNotify ("Jenkins: " + build.name, "Started...", 'PENDING')
        build.builder.buildSteps.each {
          it()
        }
        if (currentBuild.currentResult == 'SUCCESS') {
          build.builder.postSteps.success.each {
            it()
          }
        } else if(currentBuild.currentResult == 'UNSTABLE') {
          build.builder.postSteps.unstable.each {
            it()
          }
        }
      } catch(FlowInterruptedException e) {
        print "Looks like we ABORTED"
        currentBuild.result = 'ABORTED'
        build.builder.postSteps.aborted.each {
          it()
        }
      } catch(Exception e) {
        print "Error was detected: " + e
        currentBuild.result = 'FAILURE'
        build.builder.postSteps.failure.each {
          it()
        }
      }
      // ALWAYS
      finally {
        if (currentBuild.currentResult == 'SUCCESS')
          gitNotify ("Jenkins: " + build.name, "Finish", 'SUCCESS')
        else
          gitNotify ("Jenkins: " + build.name, currentBuild.currentResult, 'FAILURE')

        build.builder.postSteps.always.each {
          it()
        }
      }
    }
  }
}

// sanitise the string it should contain only 'key1=value1;key2=value2;...'
def cmd_sanitize(String cmd){
  if (cmd.contains("//"))
    return false

  for (i in cmd.split(";")){
    if (i.split("=").size() != 2 )
       return false
    for (j in i.split("=")){
      if (j.trim().contains(" "))
      return false
    }
  }
  return true
}

def gitNotify (context, description, status, targetUrl='' ){
  if (build_scenario != 'Nightly build') {
    githubNotify context: context, credentialsId: 'SORABOT_TOKEN_AND_LOGIN', description: description, status: status, targetUrl: targetUrl
  }
}

stage('Prepare environment'){
timestamps(){


node ('master') {
  scmVars = checkout scm
  def textVariables = load '.jenkinsci/text-variables.groovy'
  properties([
      parameters([
          choice(choices: textVariables.param_chose_opt, description: textVariables.param_descriptions, name: 'build_scenario'),
          string(defaultValue: '', description: textVariables.cmd_description, name: 'custom_cmd', trim: true)
      ]),
      buildDiscarder(logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '', numToKeepStr: '30'))
  ])
  environmentList = []
  environment = [:]
  environment = [
    "CCACHE_DEBUG_DIR": "/opt/.ccache",
    "CCACHE_RELEASE_DIR": "/opt/.ccache",
    "DOCKER_REGISTRY_BASENAME": "hyperledger/iroha",
    "IROHA_NETWORK": "iroha-${scmVars.CHANGE_ID}-${scmVars.GIT_COMMIT}-${env.BUILD_NUMBER}",
    "IROHA_POSTGRES_HOST": "pg-${scmVars.CHANGE_ID}-${scmVars.GIT_COMMIT}-${env.BUILD_NUMBER}",
    "IROHA_POSTGRES_USER": "pguser${scmVars.GIT_COMMIT}",
    "IROHA_POSTGRES_PASSWORD": "${scmVars.GIT_COMMIT}",
    "IROHA_POSTGRES_PORT": "5432",
    "GIT_RAW_BASE_URL": "https://raw.githubusercontent.com/hyperledger/iroha"
  ]
  environment.each { e ->
    environmentList.add("${e.key}=${e.value}")
  }

  // Define variable and params

  //All variable and Default values
  x64linux_compiler_list = ['gcc5']
  mac_compiler_list = []
  win_compiler_list = []

  testing = true
  testList = '(module)'
  fuzzing = true // testing = true

  sanitize = false
  cppcheck = false
  coredumps = true
  sonar = false
  codestyle = false
  coverage = false
  coverage_mac = false
  doxygen = false

  build_type = 'Debug'
  packageBuild = false
  pushDockerTag = 'not-supposed-to-be-pushed'
  packagePush = false
  specialBranch = false
  parallelism = 0
  useBTF = false
  forceDockerDevelopBuild = false
  checkTag = sh(script: "git describe --tags --exact-match ${scmVars.GIT_COMMIT}", returnStatus: true)

  if (scmVars.GIT_LOCAL_BRANCH in ["master"] || checkTag == 0 )
    specialBranch =  true
  else
    specialBranch = false

  if (specialBranch){
    // if specialBranch == true the release build will run, so set packagePush
    packagePush = true
    doxygen = true
  }

  if (scmVars.GIT_LOCAL_BRANCH == "master")
    pushDockerTag = 'master'
  else if (checkTag == 0 )
    pushDockerTag = sh(script: "git describe --tags --exact-match ${scmVars.GIT_COMMIT}", returnStdout: true).trim().replaceAll('-','_')
  else
    pushDockerTag = 'not-supposed-to-be-pushed'

  if (params.build_scenario == 'Default')
    if ( scmVars.GIT_BRANCH.startsWith('PR-'))
      if (BUILD_NUMBER == '1')
        build_scenario='On open PR'
      else
        build_scenario='Commit in Open PR'
    else
      build_scenario='Branch commit'
  else
    build_scenario = params.build_scenario


  print("Selected Build Scenario '${build_scenario}'")
  switch(build_scenario) {
     case 'Branch commit':
        echo "All Default"
        break;
     case 'On open PR':
        // Just hint, not the main way to Notify about build status.
        gitNotify ("Jenkins: Merge to trunk", "Please, run: 'Before merge to trunk'", 'PENDING', env.JOB_URL + "/build")
        mac_compiler_list = ['appleclang']
        win_compiler_list = ['msvc']
        testList = '()'
        coverage = true
        cppcheck = true
        sonar = true
        codestyle = true
        break;
     case 'Commit in Open PR':
        gitNotify ("Jenkins: Merge to trunk", "Please, run: 'Before merge to trunk'", 'PENDING', env.JOB_URL + "/build")
        echo "All Default"
        break;
     case 'Before merge to trunk':
        gitNotify ("Jenkins: Merge to trunk", "Started...", 'PENDING')
        x64linux_compiler_list = ['gcc5','gcc7', 'clang6' , 'clang7']
        mac_compiler_list = ['appleclang']
        win_compiler_list = ['msvc']
        testing = true
        testList = '()'
        coverage = true
        cppcheck = true
        sonar = true
        codestyle = true
        useBTF = true
        break;
     case 'Nightly build':
        x64linux_compiler_list = ['gcc5','gcc7', 'clang6' , 'clang7']
        mac_compiler_list = ['appleclang']
        win_compiler_list = ['msvc']
        testing = true
        testList = '()'
        coverage = true
        cppcheck = true
        sonar = true
        codestyle = true
        useBTF = true
        sanitize = true
        specialBranch=false
        packagePush=false
        doxygen=false
        break;
     case 'Custom command':
        if (cmd_sanitize(params.custom_cmd)){
          evaluate (params.custom_cmd)
          // A very rare scenario when linux compiler is not selected but we still need coverage
          if (x64linux_compiler_list.isEmpty() && coverage ){
            coverage_mac = true
          }
        } else {
           println("Unable to parse '${params.custom_cmd}'")
           sh "exit 1"
        }
        break;
     default:
        println("The value build_scenario='${build_scenario}' is not implemented");
        sh "exit 1"
        break;
  }

  echo """
       specialBranch=${specialBranch}, packageBuild=${packageBuild}, pushDockerTag=${pushDockerTag}, packagePush=${packagePush}
       testing=${testing}, testList=${testList}, parallelism=${parallelism}, useBTF=${useBTF}
       x64linux_compiler_list=${x64linux_compiler_list}, mac_compiler_list=${mac_compiler_list}, win_compiler_list = ${win_compiler_list}"
       sanitize=${sanitize}, cppcheck=${cppcheck}, fuzzing=${fuzzing}, coredumps=${coredumps}, sonar=${sonar},
       codestyle=${codestyle},coverage=${coverage}, coverage_mac=${coverage_mac} doxygen=${doxygen}"
       forceDockerDevelopBuild=${forceDockerDevelopBuild}, checkTag=${checkTag}
    """
  print scmVars
  print environmentList


  // Load Scripts
  def x64LinuxBuildScript = load '.jenkinsci/builders/x64-linux-build-steps.groovy'
  def x64BuildScript = load '.jenkinsci/builders/x64-mac-build-steps.groovy'
  def x64WinBuildScript = load '.jenkinsci/builders/x64-win-build-steps.groovy'

  // Define Workers
  x64LinuxWorker = new Worker(label: 'docker-build-agent', cpusAvailable: 4)
  x64MacWorker = new Worker(label: 'mac', cpusAvailable: 4)
  x64WinWorker = new Worker(label: 'windows-iroha-agent', cpusAvailable: 8)


  // Define all possible steps
  def x64LinuxBuildSteps
  def x64LinuxPostSteps = new Builder.PostSteps()
  if(!x64linux_compiler_list.isEmpty()){
    x64LinuxBuildSteps = [{x64LinuxBuildScript.buildSteps(
      parallelism==0 ?x64LinuxWorker.cpusAvailable : parallelism, x64linux_compiler_list, build_type, specialBranch, coverage,
      testing, testList, cppcheck, sonar, codestyle, doxygen, packageBuild, sanitize, fuzzing, coredumps, useBTF, forceDockerDevelopBuild, environmentList)}]
    //If "master" or "dev" also run Release build
    if(specialBranch && build_type == 'Debug'){
      x64LinuxBuildSteps += [{x64LinuxBuildScript.buildSteps(
      parallelism==0 ?x64LinuxWorker.cpusAvailable : parallelism, x64linux_compiler_list, 'Release', specialBranch, false,
      false, testList, false, false, false, false, true, false, false, false, false, false, environmentList)}]
    }
    x64LinuxPostSteps = new Builder.PostSteps(
      always: [{x64LinuxBuildScript.alwaysPostSteps(scmVars, environmentList, coredumps)}],
      success: [{x64LinuxBuildScript.successPostSteps(scmVars, packagePush, pushDockerTag, environmentList)}])
  }
  def x64MacBuildSteps
  def x64MacBuildPostSteps = new Builder.PostSteps()
  if(!mac_compiler_list.isEmpty()){
    x64MacBuildSteps = [{x64BuildScript.buildSteps(parallelism==0 ?x64MacWorker.cpusAvailable : parallelism,
      mac_compiler_list, build_type, coverage_mac, testing, testList, packageBuild, fuzzing, useBTF, environmentList)}]
    //If "master" or "dev" also run Release build
    if(specialBranch && build_type == 'Debug'){
      x64MacBuildSteps += [{x64BuildScript.buildSteps(parallelism==0 ?x64MacWorker.cpusAvailable : parallelism,
        mac_compiler_list, 'Release', false, false, testList, true, false, false, environmentList)}]
    }
    x64MacBuildPostSteps = new Builder.PostSteps(
      always: [{x64BuildScript.alwaysPostSteps(environmentList)}],
      success: [{x64BuildScript.successPostSteps(scmVars, packagePush, environmentList)}])
  }

  def x64WinBuildSteps
  def x64WinBuildPostSteps = new Builder.PostSteps()
  if(!win_compiler_list.isEmpty()){
    x64WinBuildSteps = [{x64WinBuildScript.buildSteps(parallelism==0 ?x64WinWorker.cpusAvailable : parallelism,
      win_compiler_list, build_type, false, testing, testList, packageBuild, useBTF, environmentList)}]
    x64WinBuildPostSteps = new Builder.PostSteps(
      always: [{x64WinBuildScript.alwaysPostSteps(environmentList)}],
      success: [{x64WinBuildScript.successPostSteps(scmVars, packagePush, environmentList)}])
  }

  // Define builders
  x64LinuxBuilder = new Builder(buildSteps: x64LinuxBuildSteps, postSteps: x64LinuxPostSteps)
  x64MacBuilder = new Builder(buildSteps: x64MacBuildSteps, postSteps: x64MacBuildPostSteps )
  x64WinBuilder = new Builder(buildSteps: x64WinBuildSteps, postSteps: x64WinBuildPostSteps )

  // Define Build
  x64LinuxBuild = new Build(name: "x86_64 Linux ${build_type}",
                                    type: build_type,
                                    builder: x64LinuxBuilder,
                                    worker: x64LinuxWorker)
  x64MacBuild = new Build(name: "Mac ${build_type}",
                                     type: build_type,
                                     builder: x64MacBuilder,
                                     worker: x64MacWorker)
  x64WinBuild = new Build(name: "Windows ${build_type}",
                                     type: build_type,
                                     builder: x64WinBuilder,
                                     worker: x64WinWorker)

  if(!x64linux_compiler_list.isEmpty())
    tasks[x64LinuxBuild.name] = build(x64LinuxBuild)
  if(!mac_compiler_list.isEmpty())
    tasks[x64MacBuild.name] = build(x64MacBuild)
  if(!win_compiler_list.isEmpty())
    tasks[x64WinBuild.name] = build(x64WinBuild)

  cleanWs()
  parallel tasks

  if(codestyle){
    report_file = "${BUILD_URL}artifact/clang-format-report.txt"
    line = sh(script: "curl -s ${report_file} | wc -l", returnStdout: true).trim().toInteger()
    if ( line == 1 )
      gitNotify ("Jenkins: ClangFormat", "SUCCESS", 'SUCCESS', report_file )
    else
       gitNotify ("Jenkins: ClangFormat", "You need to format ~ ${line/2} lines", 'FAILURE', report_file )
  }
  if (build_scenario == 'Before merge to trunk')
    if (currentBuild.currentResult == 'SUCCESS')
      gitNotify ("Jenkins: Merge to trunk", "Finish", 'SUCCESS')
    else
      gitNotify ("Jenkins: Merge to trunk", currentBuild.currentResult, 'FAILURE')
}

}
}
