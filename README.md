# lnd-grpc

Version 0.3.2

Requires python >=3.6

[![Build Status](https://travis-ci.org/willcl-ark/lnd_grpc.svg?branch=master)](https://travis-ci.org/willcl-ark/lnd_grpc)  [![CodeFactor](https://www.codefactor.io/repository/github/willcl-ark/lnd_grpc/badge)](https://www.codefactor.io/repository/github/willcl-ark/lnd_grpc)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A simple library to provide a Python 3 interface to the lnd lightning client gRPC.

This version of the library has been compiled with lnd proto files from the v0.6.1-beta tag on github.
This version has been tested using Bitcoin Core v0.18.0 as a backend

## Install requires:
* `grpcio`
* `grpcio-tools`
* `googleapis-common-protos`

Note: Configuration for coins other than bitcoin will require modifying the source code directly.

## Installation
#### Via pip:

`pip install lnd-grpc`

#### Cloning and installing source as editable package:

`git clone https://github.com/willcl-ark/lnd_grpc.git`

`cd lnd_grpc`

Activate virtual env as required

`pip install -e .`

## Bitcoin setup

bitcoind or btcd must be running and be ready to accept rpc connections from lnd.

## LND setup
lnd daemon must be running on the host machine. This can typically be accomplished in a screen/tmux session.

If lnd.conf is not already configured to communicate with your bitcoin client, an example lnd daemon startup command for bitcoind connection might look like:

```
lnd --bitcoin.active \
--bitcoin.mainnet \
--debuglevel=debug \
--bitcoin.node=bitcoind \
--bitcoind.rpcuser=xxxxx \
--bitcoind.rpcpass=xxxxxxxxxxxxxx \
--externalip=xx.xx.xx.xx \
--bitcoind.zmqpubrawblock=tcp://host:port \
--bitcoind.zmqpubrawtx=tcp://host:port \
--rpclisten=host:port
```

## Using
Import the module into your project:

`import lnd_grpc`

Create an instance of the client class: 

`lnd_rpc = lnd_grpc.Client()`

Note: The class is instantiated to work with default bitcoind rpc port and lnd in default installation directory, on mainnet, unless additional arguments are passed.

The class instantiation takes the the following arguments which you can change as required:

```
    (
    lnd_dir: str = None, \
    macaroon_path: str = None, \
    tls_cert_path: str = None \
    network: str = 'mainnet', \
    grpc_host: str = 'localhost', \
    grpc_port: str = '10009'
    )
```

#### Initialization of a new lnd installation

Note: If you have already created a wallet during lnd setup/installation you can skip this section.

If this is the first time you have run lnd you will not have a wallet created. 'Macaroons', the authentication technique used to communicate securely with lnd, are tied to a wallet (seed) and therefore an alternative connection must be made with lnd to create the wallet, before recreating the connection stub using the wallet's macaroon.

Initialization requires the following steps:
1. Generate a new seed `lnd_rpc.gen_seed()`
2. Initialize a new wallet `lnd_rpc.init_wallet()`


## Connecting and re-connecting after wallet created
If you did not run the initialization sequence above, you will only need to unlock your wallet before issuing further RPC commands:

`lnd_rpc.unlock_wallet(password='wallet_password')`

## Interface conventions
Further RPC commands can then be issued to the lnd gRPC interface using the following convention, where LND gRPC commands are converted from CamelCase to lowercase_with_underscores and keyword arguments named to exactly match the parameters the gRPC uses:

`lnd_rpc.grpc_command(keyword_arg=value)`

Valid gRPC commands and their keyword arguments can be found [here](https://api.lightning.community/?python#lnd-grpc-api-reference)
 
Connection stubs will be generated dynamically as required to ensure channel freshness. 

## Iterables 
Response-streaming RPCs now return the python iterators themselves to be operated on, e.g. with `.__next__()` or `for resp in response:`

## Threading
The backend LND server (Golang) has asynchronous capability so any limitations are on the client side. 
The Python gRPC Client is not natively async-compatible (e.g. using asyncio). There are wrappers which exist that can 'wrap' python gRPC Client methods into async methods, but using threading is the officially support technique at this moment.

For Python client threading to work correctly you must use the same **channel** for each thread. This is easy with this library if you use a single Client() instance in your application, as the same channel is used for each RPC for that Client object. This makes threading relatively easy, e.g.:

```
# get a queue to add responses to
queue = queue.Queue()

# create a function to perform the work you want the thread to target:
def inv_sub_worker(_hash):
    for _response in lnd_rpc.subscribe_single_invoice(_hash):
        queue.put(_response)

# create the thread
# useful to use daemon mode for subscriptions
inv_sub = threading.Thread(target=inv_sub_worker, args=[_hash, ], daemon=True)

# start the thread
inv_sub.start()
```

# Loop 
LND must be re-built and installed as per the loop instructions found at the [Loop Readme](https://github.com/lightninglabs/loop/blob/master/README.md).

Loopd should then be installed as per the same instructions and started manually.

Then you can import and use the RPC client using the following code:

```
import loop_rpc

loop = loop_rpc.LoopClient()
```