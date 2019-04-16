#!/usr/bin/env groovy

def doDockerCleanup() {

    sh """
      # Check whether the image is the last-standing man
      # i.e., no other tags exist for this image
      docker rmi \$(docker images --no-trunc --format '{{.Repository}}:{{.Tag}}\\t{{.ID}}' | grep \$(docker images --no-trunc --format '{{.ID}}' ${iC.id}) | head -n -1 | cut -f 1) || true
      sleep 5
      docker rm -f ${env.IROHA_POSTGRES_HOST} || true
      docker network rm $IROHA_NETWORK || true
      #remove folder with iroha.deb package and Dockerfiles
      rm -rf /tmp/${env.GIT_COMMIT}-${BUILD_NUMBER}
      rm -rf /tmp/${env.GIT_COMMIT}
    """
}

return this
