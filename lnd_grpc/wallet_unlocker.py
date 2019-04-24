from os import environ

import grpc

import lnd_grpc.protos.rpc_pb2 as ln
import lnd_grpc.protos.rpc_pb2_grpc as lnrpc
from lnd_grpc.base_client import BaseClient

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class WalletUnlocker(BaseClient):

    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = 'mainnet',
                 grpc_host: str = 'localhost',
                 grpc_port: str = '10009'):
        self._w_stub: lnrpc.WalletUnlockerStub = None

        super().__init__(lnd_dir=lnd_dir,
                         macaroon_path=macaroon_path,
                         tls_cert_path=tls_cert_path,
                         network=network,
                         grpc_host=grpc_host,
                         grpc_port=grpc_port)

    @property
    def wallet_unlocker_stub(self) -> lnrpc.WalletUnlockerStub:
        if self._w_stub is None:
            ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
            _w_channel = grpc.secure_channel(target=self.grpc_address,
                                             credentials=ssl_creds,
                                             options=self.grpc_options)
            self._w_stub = lnrpc.WalletUnlockerStub(_w_channel)

        # simulate connection status change after wallet stub used (typically wallet unlock) which
        # stimulates lightning stub regeneration when necessary
        self.connection_status_change = True

        return self._w_stub

    def gen_seed(self, **kwargs):
        request = ln.GenSeedRequest(**kwargs)
        response = self.wallet_unlocker_stub.GenSeed(request)
        return response

    def init_wallet(self,
                    wallet_password: str = None, **kwargs):
        request = ln.InitWalletRequest(wallet_password=wallet_password.encode('utf-8'), **kwargs)
        response = self.wallet_unlocker_stub.InitWallet(request)
        return response

    def unlock_wallet(self, wallet_password: str, recovery_window: int = 0):
        request = ln.UnlockWalletRequest(wallet_password=wallet_password.encode('utf-8'),
                                         recovery_window=recovery_window)
        response = self.wallet_unlocker_stub.UnlockWallet(request)
        return response

    def change_password(self, current_password: str, new_password: str):
        request = ln.ChangePasswordRequest(current_password=current_password.encode('utf-8'),
                                           new_password=new_password.encode('utf-8'))
        response = self.wallet_unlocker_stub.ChangePassword(request)
        return response
