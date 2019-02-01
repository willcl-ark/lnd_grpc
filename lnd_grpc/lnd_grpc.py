import codecs
import json
import sys
from os import environ

import grpc

from . import rpc_pb2 as ln
from . import rpc_pb2_grpc as lnrpc
from . import utilities as u

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


# noinspection PyArgumentList
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
        # noinspection PyAttributeOutsideInit
        self._tls_cert_path = self.lnd_dir + 'tls.cert'
        return self._tls_cert_path

    @tls_cert_path.setter
    def tls_cert_path(self, path):
        # noinspection PyAttributeOutsideInit
        self._tls_cert_path = path

    @property
    def tls_cert_key(self):
        try:
            # noinspection PyAttributeOutsideInit
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
                # noinspection PyAttributeOutsideInit
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

    # Connection stubs will be generated dynamically for each request to ensure channel freshness

    @property
    def lightning_stub(self,
                       cert_path: str = None,
                       macaroon_path: str = None):

        # set options
        if cert_path is not None:
            # noinspection PyAttributeOutsideInit
            self.tls_cert_path = cert_path
        if macaroon_path is not None:
            self.macaroon_path = macaroon_path

        self.build_credentials()
        self.channel = grpc.secure_channel(target=self.address,
                                           credentials=self.combined_creds,
                                           options=self.grpc_options)
        self._lightning_stub = lnrpc.LightningStub(self.channel)
        return self._lightning_stub

    @property
    def wallet_unlocker_stub(self,
                             cert_path: str = None):
        if cert_path is not None:
            # noinspection PyAttributeOutsideInit
            self.tls_cert_path = cert_path
        # noinspection PyAttributeOutsideInit
        self.ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        # noinspection PyAttributeOutsideInit
        self._w_channel = grpc.secure_channel(self.address,
                                              self.ssl_creds)
        # noinspection PyAttributeOutsideInit
        self._w_stub = lnrpc.WalletUnlockerStub(self._w_channel)
        return self._w_stub

    def initialize(self,
                   aezeed_passphrase: str = None,
                   wallet_password: str = None,
                   recovery_window: int = None,
                   seed_entropy: bytes = None):
        _seed = self.gen_seed(aezeed_passphrase=aezeed_passphrase, seed_entropy=seed_entropy)
        self.init_wallet(wallet_password=wallet_password,
                         cipher_seed_mnemonic=_seed.cipher_seed_mnemonic,
                         aezeed_passphrase=aezeed_passphrase,
                         recovery_window=recovery_window)
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

        response = self.wallet_unlocker_stub.GenSeed(request)
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

        response = self.wallet_unlocker_stub.InitWallet(request)
        return response

    def unlock_wallet(self,
                      wallet_password: str,
                      recovery_window: int = None):
        request = ln.UnlockWalletRequest()
        request.wallet_password = wallet_password.encode('utf-8')
        if recovery_window is not None:
            request.recovery_window = recovery_window
        response = self.wallet_unlocker_stub.UnlockWallet(request)
        return response

    def change_password(self,
                        current_password: str,
                        new_password: str):
        request = ln.ChangePasswordRequest()
        request.current_password = current_password.encode('utf-8')
        request.new_password = new_password.encode('utf-8')
        response = self.wallet_unlocker_stub.ChangePassword(request)
        return response

    def wallet_balance(self):
        request = ln.WalletBalanceRequest()
        response = self.lightning_stub.WalletBalance(request)
        return response

    def channel_balance(self):
        request = ln.ChannelBalanceRequest()
        response = self.lightning_stub.ChannelBalance(request)
        return response

    def get_transactions(self):
        request = ln.GetTransactionsRequest()
        response = self.lightning_stub.GetTransactions(request)
        return response

    def send_coins(self,
                   addr: str,
                   amount: int,
                   **kwargs):
        request = ln.SendCoinsRequest(
                addr=addr,
                amount=amount)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.SendCoins(request)
        return response

    def list_unspent(self,
                     min_confs: int,
                     max_confs: int):
        request = ln.ListUnspentRequest(
                min_confs=min_confs,
                max_confs=max_confs,
        )
        response = self.lightning_stub.ListUnspent(request)
        return response

    def subscribe_transactions(self):
        request = ln.GetTransactionsRequest()
        response = self.lightning_stub.SubscribeTransactions(request)
        return response

    def send_many(self,
                  addr_to_amount: json,  # TODO worth importing json just for type hint?
                  **kwargs):
        request = ln.SendManyRequest()
        request.addr_to_amount = addr_to_amount
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.SendMany(request)
        return response

    def new_address(self, address_type: int):  # TODO why do only '1' and '2' work here?
        request = ln.NewAddressRequest(type=address_type)
        response = self.lightning_stub.NewAddress(request)
        return response

    def sign_message(self, msg: str):
        msg_bytes = msg.encode('utf-8')
        request = ln.SignMessageRequest(msg=msg_bytes)
        response = self.lightning_stub.SignMessage(request)
        return response

    def verify_message(self, msg: str, signature: str):
        msg_bytes = msg.encode('utf-8')
        request = ln.VerifyMessageRequest(msg=msg_bytes, signature=signature)
        response = self.lightning_stub.VerifyMessage(request)
        return response

    def connect_peer(self, pubkey: str, host: str, perm: bool = None):
        address = ln.LightningAddress(pubkey=pubkey, host=host)
        request = ln.ConnectPeerRequest(addr=address)
        if perm is not None:
            request.perm = perm
        response = self.lightning_stub.ConnectPeer(request)
        return response

    def disconnect_peer(self, pubkey: str):
        request = ln.DisconnectPeerRequest(pubkey=pubkey)
        response = self.lightning_stub.DisconnectPeer(request)
        return response

    def list_peers(self):
        request = ln.ListPeersRequest()
        response = self.lightning_stub.ListPeers(request)
        return response.peers

    def get_info(self):
        request = ln.GetInfoRequest()
        response = self.lightning_stub.GetInfo(request)
        return response

    def pending_channels(self):
        request = ln.PendingChannelsRequest()
        response = self.lightning_stub.PendingChannels(request)
        return response

    def list_channels(self, **kwargs):
        request = ln.ListChannelsRequest()
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.ListChannels(request)
        return response.channels

    def closed_channels(self, **kwargs):
        request = ln.ClosedChannelsRequest()
        # set options, can multi-select
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.ClosedChannels(request)
        return response.channels

    def open_channel_sync(self,
                          node_pubkey: str,
                          node_pubkey_string: str,
                          local_funding_amount: int,
                          push_sat: int,
                          **kwargs):
        request = ln.OpenChannelRequest(
                node_pubkey_string=node_pubkey_string,
                local_funding_amount=local_funding_amount,
                push_sat=push_sat)
        request.node_pubkey = node_pubkey.encode('utf-8')
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.OpenChannelSync(request)
        return response

    def open_channel(self,
                     node_pubkey_string: str,
                     local_funding_amount: int,
                     push_sat: int,
                     **kwargs):
        # TODO: mirror `lncli openchannel --connect` function

        request = ln.OpenChannelRequest(
                node_pubkey_string=node_pubkey_string,
                local_funding_amount=local_funding_amount,
                push_sat=push_sat)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        if not hasattr(request, 'node_pubkey'):
            request.node_pubkey = node_pubkey_string.encode('utf-8')
        response = self.lightning_stub.OpenChannel(request)
        return response

    def close_channel(self,
                      channel_point: ln.ChannelPoint,
                      **kwargs):
        """
        To view which funding_txids/output_indexes can be used for a channel
        close, see the channel_point values within the list_channels() command
        output. The format for a channel_point is 'funding_txid:output_index'.
        """
        # TODO: Can you actually use this (pass a ChannelPoint object)
        request = ln.CloseChannelRequest(channel_point=channel_point)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.CloseChannel(request)
        return response

    def abandon_channel(self, channel_point: ln.ChannelPoint):
        request = ln.AbandonChannelRequest(channel_point=channel_point)
        response = self.lightning_stub.AbandonChannel(request)
        return response

    @staticmethod
    def payment_request_generator(dest_string: str,
                                  amt: int,
                                  payment_hash: bytes,
                                  payment_hash_string: str,
                                  final_cltv_delta: int,
                                  payment_request: str = None,
                                  # TODO: fee_limit: ln.FeeLimit,
                                  ):
        while True:
            # Parameters here can be set as arguments to the generator.
            if payment_request is not None:
                request = ln.SendRequest(
                        payment_request=payment_request)
            else:
                request = ln.SendRequest(  # TODO: will this work with **kwargs too?
                        dest=dest_string.encode('utf-8'),
                        dest_string=dest_string,
                        amt=amt,
                        payment_hash=payment_hash,
                        payment_hash_string=payment_hash_string,
                        final_cltv_delta=final_cltv_delta,
                        # fee_limit=fee_limit,
                )
            yield request

    # noinspection PyArgumentList,PyArgumentList
    def send_payment(self,
                     dest_string: str,
                     amt: int,
                     payment_hash_string: str,
                     final_cltv_delta: int,
                     payment_request: str = None,
                     # TODO: fee_limit: ln.FeeLimit = None,
                     ):
        _dest = dest_string.encode('utf-8')
        _payment_hash = payment_hash_string.encode('utf-8')
        # TODO: Ask Justin about this one
        if payment_request is not None:
            # noinspection PyArgumentList
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
        for response in self.lightning_stub.SendPayment(request_iterable):
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
        response = self.lightning_stub.AddInvoice(request)
        return response

    def list_invoices(self,
                      reversed: bool = 1,
                      **kwargs):
        request = ln.ListInvoiceRequest(reversed=reversed)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.ListInvoices(request)
        return response

    def lookup_invoice(self, r_hash_str: str):
        r_hash = r_hash_str.encode('utf-8')
        request = ln.PaymentHash(
                r_hash=r_hash,
                r_hash_str=r_hash_str)
        response = self.lightning_stub.LookupInvoice(request)
        return response

    def subscribe_invoices(self,
                           **kwargs):
        request = ln.InvoiceSubscription()
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        for response in self.lightning_stub.SubscribeInvoices(request):
            return response

    def decode_pay_req(self, pay_req: str):
        request = ln.PayReqString(pay_req=pay_req)
        response = self.lightning_stub.DecodePayReq(request)
        return response

    def list_payments(self):
        request = ln.ListPaymentsRequest()
        response = self.lightning_stub.ListPayments(request)
        return response

    def delete_all_payments(self):
        request = ln.DeleteAllPaymentsRequest()
        response = self.lightning_stub.DeleteAllPayments(request)
        return response

    def describe_graph(self, **kwargs):
        request = ln.ChannelGraphRequest()
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.DescribeGraph(request)
        return response

    def get_chan_info(self, channel_id: int):
        request = ln.ChanInfoRequest(channel_id=channel_id)
        response = self.lightning_stub.GetChanInfo(request)
        return response

    def get_node_info(self, pub_key: str):
        request = ln.NodeInfoRequest(pub_key=pub_key)
        response = self.lightning_stub.GetNodeInfo(request)
        return response

    def query_routes(self,
                     pub_key: str,
                     amt: int,
                     num_routes: int,
                     **kwargs):
        request = ln.QueryRoutesRequest(
                pub_key=pub_key,
                amt=amt,
                num_routes=num_routes)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.QueryRoutes(request)
        return response

    def get_network_info(self):
        request = ln.NetworkInfoRequest()
        response = self.lightning_stub.GetNetworkInfo(request)
        return response

    def stop_daemon(self):
        request = ln.StopRequest()
        response = self.lightning_stub.StopDaemon(request)
        return response

    def subscribe_channel_graph(self):
        request = ln.GraphTopologySubscription()
        for response in self.lightning_stub.SubscribeChannelGraph(request):
            return response

    def debug_level(self, **kwargs):
        request = ln.DebugLevelRequest()
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.DebugLevel(request)
        return response

    def fee_report(self):
        request = ln.FeeReportRequest()
        response = self.lightning_stub.FeeReport(request)
        return response

    def update_channel_policy(self, **kwargs):
        # TODO: by default lncli updates all channels with bool
        request = ln.PolicyUpdateRequest()
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.UpdateChannelPolicy(request)
        return response

    def forwarding_history(self,
                           start_time: int,
                           **kwargs):
        request = ln.ForwardingHistoryRequest(start_time=start_time)
        # set options
        for key, value in kwargs.items():
            setattr(request, key, value)
        response = self.lightning_stub.ForwardingHistory(request)
        return response
