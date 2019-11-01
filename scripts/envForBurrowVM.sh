#!/bin/sh

# docker should be runned with sudo (sudo bash scripts/run-iroha-dev.sh)

# remove preinstalled version of go
apt remove golang-go
apt autoremove 

# update golang version since Burrow uses later version than preinstalled in the docker environment
git clone https://github.com/udhos/update-golang
cd update-golang
./update-golang.sh

# remove go sources after installing
cd ..
rm -rf update-golang
# hope go2 will be released not so soon
rm -rf go1*

# set folder which will contain all go sources that Burrow needs
export GOPATH="/opt/iroha/goSrc"
export PATH=/usr/local/go/bin:$PATH
