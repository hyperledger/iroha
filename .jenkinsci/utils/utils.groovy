#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Small utils that can be used multiple times
//

def selectedBranchesCoverage(List branches) {
  return env.GIT_LOCAL_BRANCH in branches
}

def ccacheSetup(int maxSize) {
  sh """
    ccache --version
    ccache --show-stats
    ccache --zero-stats
    ccache --max-size=${maxSize}G
  """
}

def dockerPush(dockerImageObj, String imageName) {
  docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
    dockerImageObj.push(imageName)
  }
}

def getUrl(String url, String savePath, boolean createDstDir=false) {
  if (createDstDir) {
    sh "curl -L -o ${savePath} --create-dirs ${url}"
  }
  else {
    sh "curl -L -o ${savePath} ${url}"
  }
  return savePath
}

def filesDiffer(String f1, String f2) {
  diffExitCode = sh(script: "diff -q ${f1} ${f2}", returnStatus: true)
  return diffExitCode != 0
}

def build_vcpkg(String vcpkg_path, String vcpkg_toolchain_file, boolean forceBuild=false){
  if (!(fileExists(vcpkg_toolchain_file)) || forceBuild) {
    print "Building vcpkg toolchain..."
    if (isUnix()){
      sh """
        rm -rf /opt/dependencies/${vcpkg_path}
        echo "\$(date +%F_%T): ${scmVars.GIT_LOCAL_BRANCH} start  build ${vcpkg_path}..." >> /opt/dependencies/vcpkg-map.txt
        bash vcpkg/build_iroha_deps.sh '${vcpkg_path}' '${env.WORKSPACE}/vcpkg'
        echo "\$(date +%F_%T): ${scmVars.GIT_LOCAL_BRANCH} finish build ${vcpkg_path}" >> /opt/dependencies/vcpkg-map.txt
        ls -la ${vcpkg_path}
      """
    } else{
      powershell """
          \$env:GIT_REDIRECT_STDERR = '2>&1'
          if (Test-Path '${vcpkg_path}' ) { Remove-Item '${vcpkg_path}' -Recurse -Force; }
          Add-Content c:\\vcpkg-map.txt "\$(Get-Date): ${scmVars.GIT_LOCAL_BRANCH} start  build ${vcpkg_path}..."
          .\\.packer\\win\\scripts\\vcpkg.ps1 -vcpkg_path "${vcpkg_path}" -iroha_vcpkg_path "${env.WORKSPACE}\\vcpkg"
          Add-Content c:\\vcpkg-map.txt "\$(Get-Date): ${scmVars.GIT_LOCAL_BRANCH} finish build ${vcpkg_path}"
      """
    }
  } else{
    print "The toolchain '${vcpkg_toolchain_file}' exists!"
  }
}

return this
