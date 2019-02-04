# lnd-grpc

A simple library to provide a Python 3 interface to the lnd lightning client gRPC.

This version of the library has been compiled with rpc.proto from the v0.5.1-beta tag on github

## Install requires:
* `grpcio`
* `grpcio-tools`
* `googleapis-common-protos`

Note: Configuration for coins other than bitcoin will require modifying the source code directly.

## Installation via pip

`pip install lnd-grpc`

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

## Usage
Import the module into your project:

`from lnd_grpc import lnd_grpc`

Create an instance of the client class: 

`rpc = lnd_grpc.Client()`

Note: The class is instantiated to work with default bitcoind rpc port and lnd in default installation path unless additional arguments are passed.

The class instantiation takes the the following arguments which you can change as required by your bitcoin node setup:

```
    (
    lnd_dir: str = None, \
    macaroon_path: str = None, \
    network: str = 'mainnet', \
    grpc_host: str = 'localhost', \
    grpc_port: str = '10009'
    )
```



#### Initialization of a new lnd installation

Note: If you have already created a wallet during lnd setup/installation you can skip this section.

If this is the first time you have run lnd you will not have a wallet created. 'Macaroons', the authentication technique used to communicate securely with lnd, are tied to a wallet (seed) and therefore an alternative connection must be made with lnd to create the wallet, before recreating the connection stub using the wallet's macaroon.

Initialization requires the following steps:
1. Generate a new seed `rpc.gen_seed()`
2. Initialize a new wallet `rpc.init_wallet()`


## Connecting and re-connecting after wallet created
If you did not run the initialization sequence above, you will only need to unlock your wallet before issuing further RPC commands:

`rpc.unlock_wallet()`

# General usage

Further RPC commands can then be issued to the lnd gRPC interface using the following convention, where gRPC commands are converted from CamelCase to lowercase_with_underscores and keyword arguments named to exactly match the parameters the gRPC uses:

`rpc.grpc_command(keyword_arg=value)`

Valid gRPC commands and their keyword arguments can be found [here](https://api.lightning.community/?python#lnd-grpc-api-reference)
 
### Additional Notes
This library will handle gRPC errors for functions decorated with @handle_error and will also alert for invalid/missing tls cert and macaroon.