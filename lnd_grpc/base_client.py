import codecs
import sys
from os import environ

import grpc

from lnd_grpc.config import *
import lnd_grpc.protos.rpc_pb2 as ln
from lnd_grpc.utilities import get_lnd_dir

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class BaseClient:
    """
    A Base client which the other client services can build from. Can find tls cert and keys,
    and macaroons in 'default' locations based off lnd_dir and network parameters.

    Has some static helper methods for various applications.
    """

    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = defaultNetwork,
                 grpc_host: str = defaultRPCHost,
                 grpc_port: str = defaultRPCPort):

        self.lnd_dir = lnd_dir
        self.macaroon_path = macaroon_path
        self.tls_cert_path = tls_cert_path
        self.network = network
        self.grpc_host = grpc_host
        self.grpc_port = str(grpc_port)
        self.channel = None
        self.connection_status = None
        self.connection_status_change = False
        self.grpc_options = GRPC_OPTIONS

    @property
    def lnd_dir(self):
        """
        try automatically if not set as object init attribute
        :return: lnd_dir
        """
        if self._lnd_dir:
            return self._lnd_dir
        else:
            self._lnd_dir = get_lnd_dir()
            return self._lnd_dir

    @lnd_dir.setter
    def lnd_dir(self, path):
        self._lnd_dir = path

    @property
    def tls_cert_path(self):
        """
        :return: tls_cert_path
        """
        if self._tls_cert_path is None:
            self._tls_cert_path = self.lnd_dir + defaultTLSCertFilename
        return self._tls_cert_path

    @tls_cert_path.setter
    def tls_cert_path(self, path):
        self._tls_cert_path = path

    @property
    def tls_cert(self) -> bytes:
        """
        :return: tls.cert as bytestring
        """
        try:
            with open(self.tls_cert_path, 'rb') as r:
                _tls_cert = r.read()
        except FileNotFoundError:
            sys.stderr.write("TLS cert not found at %s" % self.tls_cert_path)
            raise
        try:
            assert _tls_cert.startswith(b'-----BEGIN CERTIFICATE-----')
            return _tls_cert
        except (AssertionError, AttributeError):
            sys.stderr.write("TLS cert at %s did not start with b'-----BEGIN CERTIFICATE-----')"
                             % self.tls_cert_path)
            raise

    @property
    def macaroon_path(self) -> str:
        """
        :return: macaroon path
        """
        if not self._macaroon_path:
            self._macaroon_path = \
                self.lnd_dir + f'{defaultDataDirname}/{defaultChainSubDirname}/bitcoin/' \
                    f'{self.network}/{defaultAdminMacFilename}'
            return self._macaroon_path
        else:
            return self._macaroon_path

    @macaroon_path.setter
    def macaroon_path(self, path: str):
        self._macaroon_path = path

    @property
    def macaroon(self):
        """
        try to open the macaroon and return it as a byte string
        """
        try:
            with open(self.macaroon_path, 'rb') as f:
                macaroon_bytes = f.read()
                macaroon = codecs.encode(macaroon_bytes, 'hex')
                return macaroon
        except FileNotFoundError:
            sys.stderr.write(f"Could not find macaroon in {self.macaroon_path}. This might happen"
                             f"in versions of lnd < v0.5-beta or those not using default"
                             f"installation path. Set client object's macaroon_path attribute"
                             f"manually.")

    def metadata_callback(self, context, callback):
        """
        automatically incorporate the macaroon into all requests
        :return: macaroon callback
        """
        callback([('macaroon', self.macaroon)], None)

    def connectivity_event_logger(self, channel_connectivity):
        """
        Channel connectivity callback logger
        """
        self.connection_status = channel_connectivity._name_
        if self.connection_status == 'SHUTDOWN' or self.connection_status == 'TRANSIENT_FAILURE':
            self.connection_status_change = True

    @property
    def combined_credentials(self) -> grpc.CallCredentials:
        """
        Combine ssl and macaroon credentials
        :return: grpc.composite_channel_credentials
        """
        cert_creds = grpc.ssl_channel_credentials(self.tls_cert)
        auth_creds = grpc.metadata_call_credentials(self.metadata_callback)
        return grpc.composite_channel_credentials(cert_creds, auth_creds)

    @property
    def grpc_address(self) -> str:
        return str(self.grpc_host + ':' + self.grpc_port)

    @staticmethod
    def channel_point_generator(funding_txid, output_index):
        """
        Generate a ln.ChannelPoint object from a funding_txid and output_index
        :return: ln.ChannelPoint
        """
        return ln.ChannelPoint(funding_txid_str=funding_txid, output_index=int(output_index))

    @staticmethod
    def lightning_address(pubkey, host):
        """
        Generate a ln.LightningAddress object from a pubkey + host
        :return: ln.LightningAddress
        """
        return ln.LightningAddress(pubkey=pubkey, host=host)

    @staticmethod
    def hex_to_bytes(hex_string: str):
        return bytes.fromhex(hex_string)

    @staticmethod
    def bytes_to_hex(bytestring: bytes):
        return bytestring.hex()
