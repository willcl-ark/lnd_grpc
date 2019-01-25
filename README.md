# lnd-grpc

A simple package to provide a Python 3 interface for the lnd lightning client.

Install requires:
* `grpcio`
* `grpcio-tools`
* `googleapis-common-protos`
* `codecs` (for macaroon authentication)

Configuration for coins other than bitcoin will require modifying the source code directly.


If not run before, initialize(), then connect()
If run before, just connect()

we are not handling errors except for missing cert or macaroon