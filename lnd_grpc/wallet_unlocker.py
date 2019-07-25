from os import environ

import grpc

import lnd_grpc.protos.rpc_pb2 as ln
import lnd_grpc.protos.rpc_pb2_grpc as lnrpc
from lnd_grpc.base_client import BaseClient
from lnd_grpc.config import defaultNetwork, defaultRPCHost, defaultRPCPort

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = "HIGH+ECDSA"


class WalletUnlocker(BaseClient):
    """
    A superclass of BaseClient to interact with the WalletUnlocker sub-service
    """

    def __init__(
        self,
        lnd_dir: str = None,
        macaroon_path: str = None,
        tls_cert_path: str = None,
        network: str = defaultNetwork,
        grpc_host: str = defaultRPCHost,
        grpc_port: str = defaultRPCPort,
    ):
        self._w_stub: lnrpc.WalletUnlockerStub = None

        super().__init__(
            lnd_dir=lnd_dir,
            macaroon_path=macaroon_path,
            tls_cert_path=tls_cert_path,
            network=network,
            grpc_host=grpc_host,
            grpc_port=grpc_port,
        )

    @property
    def wallet_unlocker_stub(self) -> lnrpc.WalletUnlockerStub:
        if self._w_stub is None:
            ssl_creds = grpc.ssl_channel_credentials(self.tls_cert)
            _w_channel = grpc.secure_channel(
                target=self.grpc_address,
                credentials=ssl_creds,
                options=self.grpc_options,
            )
            self._w_stub = lnrpc.WalletUnlockerStub(_w_channel)

        # simulate connection status change after wallet stub used (typically wallet unlock) which
        # stimulates lightning stub regeneration when necessary
        self.connection_status_change = True

        return self._w_stub

    def gen_seed(self, **kwargs):
        """
        the first method that should be used to instantiate a new lnd instance. This method
        allows a caller to generate a new aezeed cipher seed given an optional passphrase. If
        provided, the passphrase will be necessary to decrypt the cipherseed to expose the
        internal wallet seed. Once the cipherseed is obtained and verified by the user,
        the InitWallet method should be used to commit the newly generated seed, and create the
        wallet.

        :return: GenSeedResponse with 2 attributes: 'cipher_seed_mnemonic' and 'enciphered_seed'
        """
        request = ln.GenSeedRequest(**kwargs)
        response = self.wallet_unlocker_stub.GenSeed(request)
        return response

    def init_wallet(self, wallet_password: str = None, **kwargs):
        """
        used when lnd is starting up for the first time to fully initialize the daemon and its
        internal wallet. At the very least a wallet password must be provided. This will be used
        to encrypt sensitive material on disk. In the case of a recovery scenario, the user can
        also specify their aezeed mnemonic and passphrase. If set, then the daemon will use this
        prior state to initialize its internal wallet. Alternatively, this can be used along with
        the GenSeed RPC to obtain a seed, then present it to the user. Once it has been verified
        by the user, the seed can be fed into this RPC in order to commit the new wallet.

        :return: InitWalletResponse with no attributes
        """
        request = ln.InitWalletRequest(
            wallet_password=wallet_password.encode("utf-8"), **kwargs
        )
        response = self.wallet_unlocker_stub.InitWallet(request)
        return response

    def unlock_wallet(self, wallet_password: str, recovery_window: int = 0):
        """
        used at startup of lnd to provide a password to unlock the wallet database

        :return: UnlockWalletResponse with no attributes
        """
        request = ln.UnlockWalletRequest(
            wallet_password=wallet_password.encode("utf-8"),
            recovery_window=recovery_window,
        )
        response = self.wallet_unlocker_stub.UnlockWallet(request)
        return response

    def change_password(self, current_password: str, new_password: str):
        """
        changes the password of the encrypted wallet. This will automatically unlock the wallet
        database if successful.

        :return: ChangePasswordResponse with no attributes
        """
        request = ln.ChangePasswordRequest(
            current_password=current_password.encode("utf-8"),
            new_password=new_password.encode("utf-8"),
        )
        response = self.wallet_unlocker_stub.ChangePassword(request)
        return response
