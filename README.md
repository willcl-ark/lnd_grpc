# lnd-grpc

A simple library to provide a Python 3 interface to the lnd lightning client gRPC.

##Install requires:
* `grpcio`
* `grpcio-tools`
* `googleapis-common-protos`
* `codecs` 

Note: Configuration for coins other than bitcoin will require modifying the source code directly.

##LND setup
To begin lnd daemon must be running on the host machine. This can typically be accomplished in a screen/tmux session.

If lnd.conf is not configured already to communicate with your bitcoin client, an example lnd daemon startup command might look like:

`lnd --bitcoin.active --bitcoin.mainnet --debuglevel=debug --bitcoin.node=bitcoind --bitcoind.rpcuser=xxxxx --bitcoind.rpcpass=xxxxxxxxxxxxxx --externalip=xx.xx.xx.xx --bitcoind.zmqpubrawblock=tcp://host:port --bitcoind.zmqpubrawtx=tcp://host:port --rpclisten=host:port`

##Usage
First import the module into your project:

`import lnd_grpc`

Next create an instance of the client class: 

`rpc = lnd_grpc.Client()`

####Initialization of a new lnd installation
Note: If you have already created a wallet during lnd setup/installation you can skip this section.

If this is the first time you have run lnd you will not have a wallet created. 'Macaroons', the authentication technique used to communicate securely with lnd, are tied to a wallet (seed) and therefore an alternative connection must be made with lnd to create the wallet, before recreating the connection stub using the wallet's macaroon.

Initialization requires the following steps:
1. Create connection stub using 'wallet unlocker' `rpc.wallet_unlocker()`
2. Generate a new seed `rpc.gen_seed()`
3. Initialize a new wallet `rpc.init_wallet()`
4. Recreate the connection stub using wallet's admin.macaroon: `rpc.connect_macaroon()`

These steps have been combined into a helper function which does not exist in the lnd gRPC, called 'initialize', which means you can simply run one function, passing the arguments required for that combination of functions to it. E.g.:

```python
rpc.initialize(aezeed_passphrase:str = 'xxxxx',
               wallet_password:str = 'xxxxx',
               recovery_window: int = xxxxx,
               seed_entropy: bytes = xxxxx)
```
The only required argument is wallet_password.

The helper function will return the cipher_seed_mnemonic and the enciphered_seed in case these were not provided and therefore were auto-generated.

## Connecting and re-connecting after wallet created
If you did not run the initialization sequence above, you will need to make the connection stub using the admin.macaroon:

`rpc.connect_macaroon()`

Next you can unlock your wallet using:

`rpc.unlock_wallet(wallet_password: str = 'xxxxx')`

# General usage

Further RPC commands can then be issued to the lnd gRPC interface using the following convention, where gRPC commands are converted to lowercase_with_underscores and keyword arguments named exactly matching the parameters the gRPC uses:

`rpc.grpc_command(keyword_arg=value)`

Valid gRPC commands can be found here:

https://api.lightning.community/?python#lnd-grpc-api-reference
 
### Additional Notes
This library does not handle any errors directly, except for notifying the user of missing tls certificate or macaroon.