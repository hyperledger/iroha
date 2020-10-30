#!/usr/bin/env groovy
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//
// Upload Artifacts to nexus
//

def uploadArtifacts(filePaths, uploadPath, artifactServers=['nexus.iroha.tech']) {
  def filePathsConverted = []
  def agentType = sh(script: 'uname -sm', returnStdout: true).trim()
  filePaths.each {
    def fp = sh(script: "ls -d ${it} | tr '\n' ','", returnStdout: true).trim()
    filePathsConverted.addAll(fp.split(','))
  }
  def shaSumBinary = 'sha256sum'
  def md5SumBinary = 'md5sum'
  def gpgKeyBinary = 'gpg --armor --detach-sign --no-tty --batch --yes --passphrase-fd 0'
  if (agentType == 'Darwin x86_64') {
    shaSumBinary = 'shasum -a 256'
    md5SumBinary = 'md5 -r'
    gpgKeyBinary = 'GPG_TTY=\$(tty) gpg --pinentry-mode loopback --armor --detach-sign --no-tty --batch --yes --passphrase-fd 0'
  } else if (agentType == 'Linux s390x') {
    gpgKeyBinary = 'gpg --pinentry-mode loopback --armor --detach-sign --no-tty --batch --yes --passphrase-fd 0'
  }
  sh "> \$(pwd)/batch.txt"

  withCredentials([file(credentialsId: 'ci_gpg_privkey', variable: 'CI_GPG_PRIVKEY'), string(credentialsId: 'ci_gpg_masterkey', variable: 'CI_GPG_MASTERKEY')]) {
    if (!agentType.contains('MSYS_NT')) {
      sh "gpg --yes --batch --no-tty --import ${CI_GPG_PRIVKEY} || true"
    }
    filePathsConverted.each {
      sh "echo ${it} >> \$(pwd)/batch.txt;"
      sh "$shaSumBinary ${it} | cut -d' ' -f1 > \$(pwd)/\$(basename ${it}).sha256"
      sh "$md5SumBinary ${it} | cut -d' ' -f1 > \$(pwd)/\$(basename ${it}).md5"
      if (!agentType.contains('MSYS_NT')) {
        sh "echo \"${CI_GPG_MASTERKEY}\" | $gpgKeyBinary -o \$(pwd)/\$(basename ${it}).ascfile ${it}"
        sh "echo \$(pwd)/\$(basename ${it}).ascfile >> \$(pwd)/batch.txt;"
      }
      sh "echo \$(pwd)/\$(basename ${it}).sha256 >> \$(pwd)/batch.txt;"
      sh "echo \$(pwd)/\$(basename ${it}).md5 >> \$(pwd)/batch.txt;"
    }
  }

  withCredentials([usernamePassword(credentialsId: 'ci_nexus', passwordVariable: 'NEXUS_PASS', usernameVariable: 'NEXUS_USER')]) {
    artifactServers.each {
      sh(script: "while read line; do curl --http1.1 -u ${NEXUS_USER}:${NEXUS_PASS} --upload-file \$line https://${it}/repository/artifacts/${uploadPath}/ ; done < \$(pwd)/batch.txt")
    }
  }
}

return this

