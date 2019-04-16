#!/usr/bin/env groovy

def remoteFilesDiffer(f1, f2) {
  sh "curl -sSL -o /tmp/${env.GIT_COMMIT}/f1 --create-dirs ${f1}"
  sh "curl -sSL -o /tmp/${env.GIT_COMMIT}/f2 ${f2}"
  diffExitCode = sh(script: "diff -q /tmp/${env.GIT_COMMIT}/f1 /tmp/${env.GIT_COMMIT}/f2", returnStatus: true)
  return  diffExitCode != 0
}

return this
