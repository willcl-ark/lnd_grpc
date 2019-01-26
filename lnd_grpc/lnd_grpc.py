import codecs
import grpc
import json
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
            ('grpc.max_receive_message_length', 33554432),
            ('grpc.max_send_message_length', 33554432),
        ]
        # TODO should the _stub's be a @property's as they are dynamic
        self.l_stub = None
        self.w_stub = None

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

        # set options
        if cert_path is not None:
            self.tls_cert_path = cert_path
        if macaroon_path is not None:
            self.macaroon_path = macaroon_path

        self.build_credentials()
        self.channel = grpc.secure_channel(target=self.address,
                                           credentials=self.combined_creds,
                                           options=self.grpc_options)
        self.l_stub = lnrpc.LightningStub(self.channel)
        self.w_stub = lnrpc.WalletUnlockerStub(self.channel)

    def connect_ssl(self,
                    cert_path: str = None):
        if cert_path is not None:
            self.tls_cert_path = cert_path
        self.ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        self.channel = grpc.secure_channel('localhost:10009', self.ssl_creds)
        self.w_stub = lnrpc.WalletUnlockerStub(self.channel)

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
        self.l_stub = None
        sys.stdout.write('Disconnected from SSL connection\n')
        self.connect_macaroon()
        sys.stdout.write('Reconnected securely using macaroon\n')
        return _seed.cipher_seed_mnemonic, _seed.enciphered_seed

    def gen_seed(self,
                 aezeed_passphrase: str = None,
                 seed_entropy=None):
        request = ln.GenSeedRequest()

        # set options
        if aezeed_passphrase is not None:
            request.aezeed_passphrase = aezeed_passphrase.encode('utf-8')
        if seed_entropy is not None:
            request.seed_entropy = seed_entropy.encode('utf-8')

        response = self.w_stub.GenSeed(request)
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
        request.wallet_password = wallet_password.encode('utf-8')

        # set options
        if cipher_seed_mnemonic is not None:
            request.cipher_seed_mnemonic.extend(cipher_seed_mnemonic)
        if aezeed_passphrase is not None:
            request.aezeed_passphrase = aezeed_passphrase.encode('utf-8')
        if recovery_window is not None:
            request.recovery_window = recovery_window

        response = self.w_stub.InitWallet(request)
        return response

    def unlock_wallet(self,
                      wallet_password: str,
                      recovery_window: int = None):
        request = ln.UnlockWalletRequest()
        request.wallet_password = wallet_password.encode('utf-8')
        if recovery_window is not None:
            request.recovery_window = recovery_window
        response = self.w_stub.UnlockWallet(request)
        return response

    def change_password(self,
                        current_password: str,
                        new_password: str):
        request = ln.ChangePasswordRequest()
        request.current_password = current_password.encode('utf-8')
        request.new_password = new_password.encode('utf-8')
        response = self.w_stub.ChangePassword(request)
        return response

    def wallet_balance(self):
        request = ln.WalletBalanceRequest()
        response = self.l_stub.WalletBalance(request)
        return response

    def channel_balance(self):
        request = ln.ChannelBalanceRequest()
        response = self.l_stub.ChannelBalance(request)
        return response

    def get_transactions(self):
        request = ln.GetTransactionsRequest()
        response = self.l_stub.GetTransactions(request)
        return response

    def send_coins(self,
                   addr: str,
                   amount: int,
                   target_conf: int = None,
                   sat_per_byte: int = None,
                   send_all: bool = None):
        request = ln.SendCoinsRequest(
                addr=addr,
                amount=amount,
        )

        # set options
        if target_conf is not None:
            request.target_conf = target_conf
        if sat_per_byte is not None:
            request.sat_per_byte = sat_per_byte
        if send_all is not None:
            request.send_all = send_all

        response = self.l_stub.SendCoins(request)
        return response

    def list_unspent(self,
                     min_confs: int,
                     max_confs: int):
        request = ln.ListUnspentRequest(
                min_confs=min_confs,
                max_confs=max_confs,
        )
        response = self.l_stub.ListUnspent(request)
        return response

    def subscribe_transactions(self):
        request = ln.SubscribeTransactionsRequest()
        response = self.l_stub.SubscribeTransactions(request)
        return response

    def send_many(self,
                  addr_to_amount: json,     # TODO worth importing json just for type hint?
                  target_conf: int = None,
                  sat_per_byte: int = None):
        request = ln.SendManyRequest()
        request.addr_to_amount = addr_to_amount

        # set options
        if target_conf is not None:
            request.target_conf = target_conf
        if sat_per_byte is not None:
            request.sat_per_byte = sat_per_byte

        response = self.l_stub.SendMany(request)
        return response

    def new_address(self, address_type: int):       # TODO why do only '1' and '2' work here?
        request = ln.NewAddressRequest(type=address_type)
        response = self.l_stub.NewAddress(request)
        return response

    def sign_message(self, msg: str):
        msg_bytes = msg.encode('utf-8')
        request = ln.SignMessageRequest(msg=msg_bytes)
        response = self.l_stub.SignMessage(request)
        return response

    def verify_message(self, msg: str, signature: str):
        msg_bytes = msg.encode('utf-8')
        request = ln.VerifyMessageRequest(msg=msg_bytes, signature=signature)
        response = self.l_stub.VerifyMessage(request)
        return response

    def connect_peer(self, pubkey: str, host: str, perm: bool = None):
        address = ln.LightningAddress(pubkey=pubkey, host=host)
        request = ln.ConnectPeerRequest(addr=address)
        if perm is not None:
            request.perm = perm
        response = self.l_stub.ConnectPeer(request)
        return response

    def disconnect_peer(self, pubkey: str):
        request = ln.DisconnectPeerRequest(pubkey=pubkey)
        response = self.l_stub.DisconnectPeer(request)
        return response

    def list_peers(self):
        request = ln.ListPeersRequest()
        response = self.l_stub.ListPeers(request)
        return response.peers

    def get_info(self):
        request = ln.GetInfoRequest()
        response = self.l_stub.GetInfo(request)
        return response

    def pending_channels(self):
        request = ln.PendingChannelsRequest()
        response = self.l_stub.PendingChannels(request)
        return response

    def list_channels(self,
                      active_only: bool = None,
                      inactive_only: bool = None,
                      public_only: bool = None,
                      private_only: bool = None):
        request = ln.ListChannelsRequest()

        # set options
        if active_only is not None:
            request.active_only = 1
        elif inactive_only is not None:
            request.inactive_only = 1
        elif public_only is not None:
            request.public_only = 1
        elif private_only is not None:
            request.private_only = 1

        response = self.l_stub.ListChannels(request)
        return response.channels

    def closed_channels(self,
                        cooperative: bool = None,
                        local_force: bool = None,
                        remote_force: bool = None,
                        breach: bool = None,
                        funding_cancelled: bool = None,
                        abandoned: bool = None):
        request = ln.ClosedChannelsRequest()

        # set options, can multi-select
        if cooperative is not None:
            request.cooperative = 1
        if local_force is not None:
            request.local_force = 1
        if remote_force is not None:
            request.remote_force = 1
        if breach is not None:
            request.breach = 1
        if funding_cancelled is not None:
            request.funding_cancelled = 1
        if abandoned is not None:
            request.abandoned = 1

        response = self.l_stub.ClosedChannels(request)
        return response.channels

    def open_channel_sync(self,
                     node_pubkey: str,
                     node_pubkey_string: str,
                     local_funding_amount: int,
                     push_sat: int,
                     target_conf: int = None,
                     sat_per_byte: int = None,
                     private: bool = None,
                     min_htlc_msat: int = None,
                     remote_csv_delay: int = None,
                     min_confs: int = None,
                     spend_unconfirmed: bool = None,
                     # TODO: are all these required fields, really
                     ):
        request = ln.OpenChannelRequest(
                node_pubkey_string=node_pubkey_string,
                local_funding_amount=local_funding_amount,
                push_sat=push_sat,
        )
        request.node_pubkey = node_pubkey.encode('utf-8')
        # set options
        if target_conf is not None:
            request.target_conf = target_conf
        if sat_per_byte is not None:
            request.sat_per_byte = sat_per_byte
        if private is not None:
            request.private = private
        if min_htlc_msat is not None:
            request.min_htlc_msat = min_htlc_msat
        if remote_csv_delay is not None:
            request.remote_csv_delay = remote_csv_delay
        if min_confs is not None:
            request.min_confs = min_confs

        response = self.l_stub.OpenChannelSync(request)
        return response

    def open_channel(self,
                     node_pubkey: str = None,
                     node_pubkey_string: str,
                     local_funding_amount: int,
                     push_sat: int,
                     target_conf: int = None,
                     sat_per_byte: int = None,
                     private: bool = None,
                     min_htlc_msat: int = None,
                     remote_csv_delay: int = None,
                     min_confs: int = None,
                     spend_unconfirmed: bool = None,
                     # TODO: are all these required fields, really
                     ):
        # TODO: mirror `lncli openchannel --connect` function

        request = ln.OpenChannelRequest(
                node_pubkey_string=node_pubkey_string,
                local_funding_amount=local_funding_amount,
                push_sat=push_sat,
        )
        # set options
        if node_pubkey is not None:
            request.node_pubkey = node_pubkey_string.encode('utf-8')
        if target_conf is not None:
            request.target_conf = target_conf
        if sat_per_byte is not None:
            request.sat_per_byte = sat_per_byte
        if private is not None:
            request.private = private
        if min_htlc_msat is not None:
            request.min_htlc_msat = min_htlc_msat
        if remote_csv_delay is not None:
            request.remote_csv_delay = remote_csv_delay
        if min_confs is not None:
            request.min_confs = min_confs

        response = self.l_stub.OpenChannel(request)
        return response

    def close_channel(self,
                      channel_point: ln.ChannelPoint,
                      force: bool = None,
                      target_conf: int = None,
                      sat_per_byte: int = None):
        """
        To view which funding_txids/output_indexes can be used for a channel
        close, see the channel_point values within the list_channels() command
        output. The format for a channel_point is 'funding_txid:output_index'.
        """

        # TODO: make sure this actually works in the real world instead of just \
        #  demanding users pass this function an ln.ChannelPoint object \
        #  directly. \
        #  Perhaps more reasonable would be to use a helper/lookup function based on \
        #  the channel pubkey to do it automatically.

        request = ln.CloseChannelsRequest(channel_point=channel_point)

        # set options
        if force is not None:
            request.force = force
        if target_conf is not None:
            request.target_conf = target_conf
        if sat_per_byte is not None:
            request.sat_per_byte = sat_per_byte

        response = self.l_stub.CloseChannel(request)
        return response

    def abandon_channel(self, channel_point: ln.ChannelPoint):
        request = ln.AbandonChannelRequest(channel_point=channel_point)
        response = self.l_stub.AbandonChannel(request)
        return response

    def payment_request_generator(self,
                          dest: bytes,
                          dest_string: str,
                          amt: int,
                          payment_hash: bytes,
                          payment_hash_string: str,
                          payment_request: str = None,
                          final_cltv_delta: int,
                          # TODO: fee_limit: ln.FeeLimit,
                          ):

        while True:
        # Parameters here can be set as arguments to the generator.
           if payment_request is not None:
               request = ln.SendRequest(
                       payment_request=payment_request)
           else:
               request = ln.SendRequest(
                       dest=dest,
                       dest_string=dest_string,
                       amt=amt,
                       payment_hash=payment_hash,
                       payment_hash_string=payment_hash_string,
                       final_cltv_delta=final_cltv_delta,
                       #fee_limit=fee_limit,
               )
           yield request

    def send_payment(self,
                          dest_string: str,
                          amt: int,
                          payment_hash_string: str,
                          payment_request: str = None,
                          final_cltv_delta: int,
                          # TODO: fee_limit: ln.FeeLimit = None,
                          ):
        _dest = dest_string.encode('utf-8')
        _payment_hash = payment_hash_string.encode('utf-8')
        # TODO: Ask Justin about this one
        if payment_request is not None:
            request_iterable = self.payment_request_generator(
                    payment_request=payment_request)
        else:
            request_iterable = self.payment_request_generator(
                dest=_dest,
                dest_string=dest_string,
                amt=amt,
                payment_hash=_payment_hash,
                payment_hash_string=payment_hash_string,
                final_cltv_delta=final_cltv_delta,
                # TODO: fee_limit=fee_limit,
            )
        for response in self.l_stub.SendPayment(request_iterable):
            return response

    def send_payment_sync(self):
        pass

    def send_to_route(self):
        pass

    def send_to_route_sync(self):
        pass

    def add_invoice(self,
                       r_preimage: bytes,
                       value: int,
                       **kwargs):
        request = ln.Invoice(r_preimage=r_preimage, value=value)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.l_stub.AddInvoice(request)
        return response

    def get_node_info(self, pubkey: str):
        request = ln.NodeInfoRequest()
        request.pub_key = pubkey
        response = self.l_stub.GetNodeInfo(request)
        return response

    def create_invoice(self, **kwargs):
        request = ln.Invoice(**kwargs)
        response = self.l_stub.AddInvoice(request)
        return response

    def get_graph(self):
        request = ln.ChannelGraphRequest()
        request.include_unannounced = False
        response = self.l_stub.DescribeGraph(request)
        return response
