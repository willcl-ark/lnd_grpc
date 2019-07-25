# LND default params
# source: https://github.com/lightningnetwork/lnd/blob/master/config.go

defaultConfigFilename = "lnd.conf"
defaultDataDirname = "data"
defaultChainSubDirname = "chain"
defaultGraphSubDirname = "graph"
defaultTLSCertFilename = "tls.cert"
defaultTLSKeyFilename = "tls.key"
defaultAdminMacFilename = "admin.macaroon"
defaultReadMacFilename = "readonly.macaroon"
defaultInvoiceMacFilename = "invoice.macaroon"
defaultLogLevel = "info"
defaultLogDirname = "logs"
defaultLogFilename = "lnd.log"
defaultRPCPort = 10009
defaultRESTPort = 8080
defaultPeerPort = 9735
defaultRPCHost = "localhost"
defaultNetwork = "mainnet"
defaultNoSeedBackup = False
defaultTorSOCKSPort = 9050
defaultTorDNSHost = "soa.nodes.lightning.directory"
defaultTorDNSPort = 53
defaultTorControlPort = 9051
defaultTorV2PrivateKeyFilename = "v2_onion_private_key"
defaultTorV3PrivateKeyFilename = "v3_onion_private_key"

# lnd_grpc default params
GRPC_OPTIONS = [
    ("grpc.max_receive_message_length", 33554432),
    ("grpc.max_send_message_length", 33554432),
]
