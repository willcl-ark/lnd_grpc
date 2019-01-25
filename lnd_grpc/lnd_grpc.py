import codecs
import grpc
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import utilities as u
from os import environ
import sys

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class Client:

    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 network: str = 'mainnet',
                 grpc_host: str = 'localhost',
                 grpc_port: str = '10009'):

        self.lnd_dir = lnd_dir
        self.macaroon_path = macaroon_path
        self.network = network
        self.grpc_host = grpc_host
        self.grpc_port = grpc_port
        self.cert_creds = None
        self.auth_creds = None
        self.combined_creds = None
        self.channel = None
        self.address = str(self.grpc_host + ':' + self.grpc_port)
        self.grpc_options = [
            ('grpc.max_recieve_message_length = 1024*1024*50')]
        self.conn = None

    @property
    def lnd_dir(self):
        if self._lnd_dir:
            return self._lnd_dir
        else:
            self._lnd_dir = u.get_lnd_dir()
            return self._lnd_dir

    @lnd_dir.setter
    def lnd_dir(self, path):
        self._lnd_dir = path

    @property
    def tls_cert_path(self):
        self._tls_cert_path = self.lnd_dir + 'tls.cert'
        return self._tls_cert_path

    @tls_cert_path.setter
    def tls_cert_path(self, path):
        self._tls_cert_path = path

    @property
    def tls_cert_key(self):
        try:
            self._tls_cert_key = open(self.tls_cert_path, 'rb').read()
        except FileNotFoundError:
            sys.stderr.write("TLS cert not found at %s" % self.tls_cert_path)
        try:
            assert self._tls_cert_key.startswith(b'-----BEGIN CERTIFICATE-----')
            return self._tls_cert_key
        except (AssertionError, AttributeError):
            sys.stderr.write("TLS cert at %s did not start with b'-----BEGIN CERTIFICATE-----')" \
                  % self.tls_cert_path)

    @property
    def macaroon_path(self):
        if not self._macaroon_path:
            self._macaroon_path = self.lnd_dir + \
                                  'data/chain/bitcoin/%s/admin.macaroon' \
                                  % self.network
            return self._macaroon_path
        else:
            return self._macaroon_path

    @macaroon_path.setter
    def macaroon_path(self, path):
        self._macaroon_path = path

    @property
    def macaroon(self):
        try:
            with open(self.macaroon_path, 'rb') as f:
                macaroon_bytes = f.read()
                self._macaroon = codecs.encode(macaroon_bytes, 'hex')
                return self._macaroon
        except FileNotFoundError:
            sys.stderr.write("Could not find macaroon in %s\n" % self.macaroon_path)

    def metadata_callback(self, context, callback):
        callback([('macaroon', self.macaroon)], None)

    def build_credentials(self):
        self.cert_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        self.auth_creds = grpc.metadata_call_credentials(self.metadata_callback)
        self.combined_creds = grpc.composite_channel_credentials(self.cert_creds, self.auth_creds)

    def connect_macaroon(self,
                         cert_path: str = None,
                         macaroon_path: str = None):
        if cert_path is not None:
            self.tls_cert_path = cert_path
        if macaroon_path is not None:
            self.macaroon_path = macaroon_path
        self.build_credentials()
        self.channel = grpc.secure_channel(self.address,
                                           self.combined_creds)
        # TODO options=self.grpc_options)
        self.conn = lnrpc.LightningStub(self.channel)

    def connect_ssl(self,
                    cert_path: str = None):
        if cert_path is not None:
            self.tls_cert_path = cert_path
        self.ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        self.channel = grpc.secure_channel('localhost:10009', self.ssl_creds)
        self.conn = lnrpc.WalletUnlockerStub(self.channel)

    def initialize(self,
                   aezeed_passphrase: str = None,
                   wallet_password: str = None,
                   recovery_window: int = None,
                   seed_entropy: bytes = None):
        self.connect_ssl()
        sys.stdout.write('Connected using SSL\n')
        _seed = self.gen_seed(aezeed_passphrase=aezeed_passphrase, seed_entropy=seed_entropy)
        self.init_wallet(wallet_password=wallet_password,
                         cipher_seed_mnemonic=_seed.cipher_seed_mnemonic,
                         aezeed_passphrase=aezeed_passphrase,
                         recovery_window=recovery_window)
        self.conn = None
        sys.stdout.write('Disconnected from SSL connection\n')
        self.connect_macaroon()
        sys.stdout.write('Reconnected securely using macaroon\n')
        return _seed.cipher_seed_mnemonic, _seed.enciphered_seed

    def gen_seed(self,
                 aezeed_passphrase: str = None,
                 seed_entropy: bytes = None):
        request = ln.GenSeedRequest()
        if aezeed_passphrase is not None:
            request.aezeed_passphrase = aezeed_passphrase.encode('latin1')
        if seed_entropy is not None:
            request.seed_entropy = seed_entropy
        response = self.conn.GenSeed(request)
        return response

    def init_wallet(self,
                    wallet_password: str = None,
                    cipher_seed_mnemonic=None,
                    aezeed_passphrase: str = None,
                    recovery_window: int = None):
        try:
            assert len(wallet_password) >= 8
        except AssertionError:
            sys.stdout.write('Wallet password must be at least 8 characters long')
        request = ln.InitWalletRequest()
        request.wallet_password = wallet_password.encode('latin1')
        if cipher_seed_mnemonic is not None:
            request.cipher_seed_mnemonic.extend(cipher_seed_mnemonic)
        if aezeed_passphrase is not None:
            request.aezeed_passphrase = aezeed_passphrase.encode('latin1')
        if recovery_window is not None:
            request.recovery_window = recovery_window
        response = self.conn.InitWallet(request)
        return response

    def unlock_wallet(self, wallet_password: str, recovery_window: int = None):
        request = ln.UnlockWalletRequest()
        request.wallet_password = wallet_password.encode('latin1')
        request.recovery_window = recovery_window
        response = self.conn.UnlockWallet(request)
        return response

    def change_password(self, current_password, new_password):
        request = ln.ChangePasswordRequest()
        request.current_password = current_password.encode('latin1')
        request.new_password = new_password.encode('latin1')
        response = self.conn.GetNodeInfo(request)
        return response

    def wallet_balance(self):
        request = ln.WalletBalanceRequest()
        response = self.conn.WalletBalance(request)
        return response

    def channel_balance(self):
        request = ln.ChannelBalanceRequest()
        response = self.conn.ChannelBalance(request)
        return response

    def get_transactions(self):
        request = ln.GetTransactionsRequest()
        response = self.conn.GetTransactions(request)
        return response

    def send_coins(self, addr, amount, target_conf, sat_per_byte, send_all):
        request = ln.SendCoinsRequest()
        request.addr = addr
        request.amount = amount
        request.target_conf = target_conf
        request.sat_per_byte = sat_per_byte
        request.send_all = send_all
        response = self.conn.SendCoins(request)
        return response

    def list_unspent(self, min_confs, max_confs):
        request = ln.ListUnspentRequest()
        request.min_confs = min_confs
        request.max_confs = max_confs
        response = self.conn.ListUnspent(request)
        return response

    def subscribe_transactions(self):
        request = ln.SubscribeTransactionsRequest()
        response = self.conn.SubscribeTransactions(request)
        return response

    def send_many(self, addr_to_amount, target_conf, sat_per_byte):
        request = ln.SendManyRequest()
        request.addr_to_amount = addr_to_amount
        request.target_conf = target_conf
        request.sat_per_byte = sat_per_byte
        response = self.conn.SendMany(request)
        return response

    def new_address(self, address_type='NESTED_PUBKEY_HASH'):
        request = ln.NewAddressRequest()
        request.type = address_type
        response = self.conn.NewAddress(request)
        return response

    def get_info(self):
        request = ln.GetInfoRequest()
        response = self.conn.GetInfo(request)
        return response

    def get_node_info(self, pubkey: str):
        request = ln.NodeInfoRequest()
        request.pub_key = pubkey
        response = self.conn.GetNodeInfo(request)
        return response

    def connect_peer(self, pubkey: str, host: str):
        address = ln.LightningAddress(pubkey=pubkey, host=host)
        request = ln.ConnectPeerRequest(addr=address)
        response = self.conn.ConnectPeer(request)
        return response

    def list_peers(self):
        request = ln.ListPeersRequest()
        response = self.conn.ListPeers(request)
        return response.peers

    def list_channels(self):
        request = ln.ListChannelsRequest()
        response = self.conn.ListChannels(request)
        return response.channels

    def list_pending_channels(self):
        request = ln.PendingChannelsRequest()
        response = self.conn.PendingChannels(request)
        return response

    def open_channel(self, **kwargs):
        kwargs['node_pubkey'] = codecs.decode(kwargs['node_pubkey_string'],
                                              'hex')
        request = ln.OpenChannelRequest(**kwargs)
        response = self.conn.OpenChannel(request)
        return response

    def create_invoice(self, **kwargs):
        request = ln.Invoice(**kwargs)
        response = self.conn.AddInvoice(request)
        return response

    def get_graph(self):
        request = ln.ChannelGraphRequest()
        request.include_unannounced = False
        response = self.conn.DescribeGraph(request)
        return response
