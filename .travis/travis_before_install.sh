#!/bin/sh

# Exit immediately at non-zero exit code
set -ev

#######################
## Install Bitcoin Core
#######################

export CORE_VERSION="0.17.1"

wget https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz
tar -xzf bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz -C ${TRAVIS_BUILD_DIR}
sudo cp ${TRAVIS_BUILD_DIR}/bitcoin-${CORE_VERSION}/bin/bitcoind /usr/local/bin/bitcoind
sudo cp ${TRAVIS_BUILD_DIR}/bitcoin-${CORE_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli


#############
# Install LND
#############

export LND_VERSION="v0.6-beta"

# Install LND
wget https://github.com/lightningnetwork/lnd/releases/download/${LND_VERSION}/lnd-linux-amd64-${LND_VERSION}.tar.gz
tar -xzf lnd-linux-amd64-${LND_VERSION}.tar.gz -C ${TRAVIS_BUILD_DIR}
sudo cp ${TRAVIS_BUILD_DIR}/lnd-linux-amd64-${LND_VERSION}/lnd /usr/local/bin/lnd
sudo cp ${TRAVIS_BUILD_DIR}/lnd-linux-amd64-${LND_VERSION}/lncli /usr/local/bin/lncli


##############
# Install loop
##############

export LOOP_VERSION="v0.1.1-alpha"

# Install Loop
wget https://github.com/lightninglabs/loop/releases/download/${LOOP_VERSION}/loop-linux-amd64-${LOOP_VERSION}.tar.gz
tar -xzf loop-linux-amd64-${LOOP_VERSION}.tar.gz -C ${TRAVIS_BUILD_DIR}
sudo cp ${TRAVIS_BUILD_DIR}/loop-linux-amd64-${LOOP_VERSION}/loopd /usr/local/bin/loopd
sudo cp ${TRAVIS_BUILD_DIR}/loop-linux-amd64-${LOOP_VERSION}/loop /usr/local/bin/loop