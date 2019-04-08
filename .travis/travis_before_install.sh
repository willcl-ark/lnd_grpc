#!/bin/sh

# Exit immediately at non-zero exit code
set -ev

#######################
## Install Bitcoin Core
#######################

wget https://bitcoincore.org/bin/bitcoin-core-0.17.0/bitcoin-0.17.0-x86_64-linux-gnu.tar.gz
tar -xzf bitcoin-0.17.0-x86_64-linux-gnu.tar.gz
sudo cp /home/travis/build/willcl-ark/lnd_grpc/bitcoin-0.17.0/bin/bitcoind /usr/local/bin/bitcoind
sudo cp /home/travis/build/willcl-ark/lnd_grpc/bitcoin-0.17.0/bin/bitcoin-cli /usr/local/bin/bitcoin-cli


######################
# Install LND v-0.6-beta
######################

# Install LND
wget https://github.com/lightningnetwork/lnd/releases/download/v0.6-beta-rc3/lnd-linux-amd64-v0.6-beta-rc3.tar.gz
tar -xzf lnd-linux-amd64-v0.6-beta-rc3.tar.gz
sudo cp /home/travis/build/willcl-ark/lnd_grpc/lnd-linux-amd64-v0.6-beta-rc3/lnd /usr/local/bin/lnd
sudo cp /home/travis/build/willcl-ark/lnd_grpc/lnd-linux-amd64-v0.6-beta-rc3/lncli /usr/local/bin/lncli
