from lnd_grpc.base_client import BaseClient
from lnd_grpc.invoices import Invoices
from lnd_grpc.lightning import Lightning
from lnd_grpc.wallet_unlocker import WalletUnlocker


class Client(Lightning, WalletUnlocker, Invoices):
    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = 'mainnet',
                 grpc_host: str = 'localhost',
                 grpc_port: str = '10009'):
        super().__init__(lnd_dir=lnd_dir,
                         macaroon_path=macaroon_path,
                         tls_cert_path=tls_cert_path,
                         network=network,
                         grpc_host=grpc_host,
                         grpc_port=grpc_port)


__all__ = ['BaseClient', 'WalletUnlocker', 'Lightning', 'Invoices', 'Client']
