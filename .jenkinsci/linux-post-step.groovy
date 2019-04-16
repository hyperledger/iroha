def linuxPostStep() {
  timeout(time: 600, unit: "SECONDS") {
    try {
      // stop write core dumps
      sh "ulimit -c 0"
      // handling coredumps (if tests crashed)
      if (currentBuild.currentResult != "SUCCESS" && params.coredump) {
        def dumpsFileName = sprintf('coredumps-%1$s.bzip2',
          [GIT_COMMIT.substring(0,8)])

        sh(script: "find . -type f -name '*.coredump' -exec tar -cjvf ${dumpsFileName} {} \\+;")
        if( fileExists(dumpsFileName)) {
          withCredentials([usernamePassword(credentialsId: 'ci_nexus', passwordVariable: 'NEXUS_PASS', usernameVariable: 'NEXUS_USER')]) {
            sh(script: "curl -u ${NEXUS_USER}:${NEXUS_PASS} --upload-file ${WORKSPACE}/${dumpsFileName} https://nexus.iroha.tech/repository/artifacts/iroha/coredumps/${dumpsFileName}")
          }
          echo "Build is not SUCCESS! See core dumps at: https://nexus.iroha.tech/repository/artifacts/iroha/coredumps/${dumpsFileName}"
        }
      }
      if (currentBuild.currentResult == "SUCCESS" && GIT_LOCAL_BRANCH ==~ /(master|develop)/) {
        def artifacts = load ".jenkinsci/artifacts.groovy"
        def commit = env.GIT_COMMIT
        def platform = sh(script: 'uname -m', returnStdout: true).trim()
        filePaths = [ '/tmp/${GIT_COMMIT}-${BUILD_NUMBER}/*' ]
        artifacts.uploadArtifacts(filePaths, sprintf('/iroha/linux/%4$s/%1$s-%2$s-%3$s', [GIT_LOCAL_BRANCH, sh(script: 'date "+%Y%m%d"', returnStdout: true).trim(), commit.substring(0,6), platform]))
      }
    }
    finally {
      def cleanup = load ".jenkinsci/docker-cleanup.groovy"
      cleanup.doDockerCleanup()
      cleanWs()
    }
  }
}

return this
