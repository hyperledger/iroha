#!/usr/bin/env bash
set -x

IROHA_HOME=$(dirname $(realpath ${BASH_SOURCE[0]}))/..
MOUNT=/tmp/iroha
BUILD_PATH=/tmp/build
PROJ_BIN=/opt/iroha
docker pull hyperledger/iroha-docker-develop:v1
# docker build $IROHA_HOME/docker/develop -t iroha-dev
echo $IROHA_HOME\;$MOUNT\;$BUILD_PATH\;$PROJ_BIN
# docker run -tdv $IROHA_HOME:$MOUNT hyperledger/iroha-docker-develop:v1 "/bin/bash" >/tmp/iroha-build.id
CONTAINER=$(cat /tmp/iroha-build.id)
docker exec $CONTAINER sh <<EOF
mkdir -p $BUILD_PATH $PROJ_BIN;
cd $BUILD_PATH && cmake -DTESTING=OFF $MOUNT && make;
cp $BUILD_PATH/bin/* $PROJ_BIN;
ldd $PROJ_BIN/* | egrep -o '\/.*?\.(so(\..*?)?|a)\s' | grep $MOUNT | uniq | xargs cp -t $PROJ_BIN | true;
EOF

docker commit $CONTAINER iroha-dev
docker stop $CONTAINER && docker rm $CONTAINER;
docker save -o "$IROHA_HOME"/build/iroha-dev.tar hyperledger/iroha-docker

