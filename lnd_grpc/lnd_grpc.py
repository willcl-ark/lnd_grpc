import codecs
import sys
from os import environ

import grpc

from . import rpc_pb2 as ln, rpc_pb2_grpc as lnrpc, utilities as u

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

    @property
    def grpc_address(self):
        self._address = str(self.grpc_host + ':' + self.grpc_port)
        return self._address

    @staticmethod
    def channel_point_generator(funding_txid, output_index):
        return ln.ChannelPoint(funding_txid_str=funding_txid, output_index=int(output_index))

    @staticmethod
    def lightning_address(pubkey, host):
        return ln.LightningAddress(pubkey=pubkey, host=host)

    @staticmethod
    def hex_to_bytes(hex_string: str):
        return bytes.fromhex(hex_string)

    @staticmethod
    def bytes_to_hex(bytes: bytes):
        return codecs.encode(bytes, 'hex')

    # Connection stubs will be generated dynamically for each request to ensure channel freshness
    @property
    def lightning_stub(self,
                       cert_path: str = None,
                       macaroon_path: str = None):

        # set options
        if cert_path is not None:
            self.tls_cert_path = cert_path
        if macaroon_path is not None:
            self.macaroon_path = macaroon_path

        self.build_credentials()
        self.channel = grpc.secure_channel(target=self.grpc_address,
                                           credentials=self.combined_creds,
                                           options=self.grpc_options)
        self._lightning_stub = lnrpc.LightningStub(self.channel)
        return self._lightning_stub

    @property
    def wallet_unlocker_stub(self,
                             cert_path: str = None):
        if cert_path is not None:
            self.tls_cert_path = cert_path
        self.ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        self._w_channel = grpc.secure_channel(self.grpc_address,
                                              self.ssl_creds)
        self._w_stub = lnrpc.WalletUnlockerStub(self._w_channel)
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

    # TODO: add listchaintxs() a-la lncli

    # On Chain
    def send_coins(self, addr: str, amount: int, **kwargs):
        request = ln.SendCoinsRequest(addr=addr, amount=amount, **kwargs)
        response = self.lightning_stub.SendCoins(request)
        return response

    # RPC not available in v0.5.1-beta
    # def list_unspent(self, min_confs: int, max_confs: int):
    #    request = ln.ListUnspentRequest(min_confs=min_confs, max_confs=max_confs)
    #    response = self.lightning_stub.ListUnspent(request)
    #    return response

    def subscribe_transactions(self):
        request = ln.GetTransactionsRequest()
        for response in self.lightning_stub.SubscribeTransactions(request):
            return response

    # TODO: check this more. It works with regular python dicts so I think it's ok
    def send_many(self, addr_to_amount: ln.SendManyRequest.AddrToAmountEntry, **kwargs):
        request = ln.SendManyRequest(AddrToAmount=addr_to_amount, **kwargs)
        response = self.lightning_stub.SendMany(request)
        return response

    def new_address(self, address_type: str):
        if address_type == 'p2wkh':
            request = ln.NewAddressRequest(type='WITNESS_PUBKEY_HASH')
        elif address_type == 'np2wkh':
            request = ln.NewAddressRequest(type='NESTED_PUBKEY_HASH')
        else:
            return TypeError("invalid address type %s, supported address type are: p2wkh and np2wkh" \
                             % address_type)
        response = self.lightning_stub.NewAddress(request)
        return response

    def sign_message(self, msg: str):
        _msg_bytes = msg.encode('utf-8')
        request = ln.SignMessageRequest(msg=_msg_bytes)
        response = self.lightning_stub.SignMessage(request)
        return response

    def verify_message(self, msg: str, signature: str):
        _msg_bytes = msg.encode('utf-8')
        request = ln.VerifyMessageRequest(msg=_msg_bytes, signature=signature)
        response = self.lightning_stub.VerifyMessage(request)
        return response

    def connect_peer(self, addr: ln.LightningAddress, perm: bool = 0):
        request = ln.ConnectPeerRequest(addr=addr, perm=perm)
        response = self.lightning_stub.ConnectPeer(request)
        return response

    def connect(self, address: str, perm: bool = 0):
        pubkey, host = address.split('@')
        _address = self.lightning_address(pubkey=pubkey, host=host)
        response = self.connect_peer(addr=_address, perm=perm)
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
        request = ln.ListChannelsRequest(**kwargs)
        response = self.lightning_stub.ListChannels(request)
        return response.channels

    def closed_channels(self, **kwargs):
        request = ln.ClosedChannelsRequest(**kwargs)
        response = self.lightning_stub.ClosedChannels(request)
        return response.channels

    def open_channel_sync(self,
                          node_pubkey_string: str,
                          local_funding_amount: int,
                          **kwargs):
        """
        A synchronous (blocking) version of the 'open_channel()' command
        """
        request = ln.OpenChannelRequest(
                node_pubkey_string=node_pubkey_string,
                local_funding_amount=local_funding_amount,
                **kwargs)
        if not hasattr(request, 'node_pubkey'):
            request.node_pubkey = bytes.fromhex(node_pubkey_string)
        response = self.lightning_stub.OpenChannelSync(request)
        return response

    def open_channel(self,
                     node_pubkey_string: str,
                     local_funding_amount: int,
                     **kwargs):
        # TODO: mirror `lncli openchannel --connect` function
        request = ln.OpenChannelRequest(
                node_pubkey_string=node_pubkey_string,
                local_funding_amount=local_funding_amount,
                **kwargs)
        if request.node_pubkey == b'':
            request.node_pubkey = bytes.fromhex(node_pubkey_string)
        for response in self.lightning_stub.OpenChannel(request):
            print(response)

    def close_channel(self, channel_point, **kwargs):
        funding_txid, output_index = channel_point.split(':')
        _channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                      output_index=output_index)
        request = ln.CloseChannelRequest(channel_point=_channel_point, **kwargs)
        response = self.lightning_stub.CloseChannel(request)
        return response

    def close_all_channels(self, inactive_only: bool = 0):
        if inactive_only == False:
            for channel in self.list_channels():
                self.close_channel(channel_point=channel.channel_point)
        if inactive_only == True:
            for channel in self.list_channels(inactive_only=1):
                self.close_channel(channel_point=channel.channel_point)

    def abandon_channel(self, channel_point: ln.ChannelPoint):
        funding_txid, output_index = channel_point.split(':')
        _channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                      output_index=output_index)
        request = ln.AbandonChannelRequest(channel_point=_channel_point)
        response = self.lightning_stub.AbandonChannel(request)
        return response

    @staticmethod
    def send_request_generator(**kwargs):
        while True:
            if kwargs['payment_request']:
                request = ln.SendRequest(payment_request=kwargs['payment_request'])
            else:
                request = ln.SendRequest(**kwargs)
            yield request

    # Bi-directional streaming RPC
    def send_payment(self, **kwargs):
        """
        Not implemented yet.
        """
        raise NotImplementedError("Asynchronous method send_payment() not implemented yet.\n"
                                   "Use synchronous (blocking) send_payment_sync() method instead")
        # if kwargs['payment_request']:
        #     request_iterable = self.send_request_generator(
        #             payment_request=kwargs['payment_request'])
        # else:
        #     kwargs['payment_hash'] = bytes.fromhex(kwargs['payment_hash_string'])
        #     kwargs['dest'] = bytes.fromhex(kwargs['dest_string'])
        #     request_iterable = self.send_request_generator(**kwargs)
        # for response in self.lightning_stub.SendPayment(request_iterable):
        #     print(response)

    def send_payment_sync(self, **kwargs):
        if kwargs['payment_request']:
            request = ln.SendRequest(payment_request=kwargs['payment_request'])
        else:
            kwargs['payment_hash'] = bytes.fromhex(kwargs['payment_hash_string'])
            kwargs['dest'] = bytes.fromhex(kwargs['dest_string'])
            request = ln.SendRequest(**kwargs)
        response = self.lightning_stub.SendPaymentSync(request)
        return response

    def pay_invoice(self, payment_request: str):
        # TODO: I think this should technically use non-blocking send_payment()
        response = self.send_payment_sync(payment_request=payment_request)
        return response

    @staticmethod
    def send_to_route_generator(**kwargs):
        while True:
            request = ln.SendToRouteRequest(**kwargs)
            yield request

    def send_to_route(self):
        """
        Not implemented yet
        """
        raise NotImplementedError("Asynchronous method send_to_route() not implemented yet. \
        Use synchronous (blocking) send_to_route_sync() method instead")

    def send_to_route_sync(self, payment_hash_string: str, routes: ln.Route):
        """
        SendToRouteSync is a synchronous version of SendToRoute.
        It Will block until the payment either fails or succeeds.
        """
        _payment_hash = bytes.fromhex(payment_hash_string)
        request = ln.SendToRouteRequest(payment_hash=_payment_hash,
                                        payment_hash_string=payment_hash_string,
                                        route=routes)
        response = self.lightning_stub.SendToRouteSync(request)
        return response

    def add_invoice(self, value: int = 0, **kwargs):
        request = ln.Invoice(value=value, **kwargs)
        response = self.lightning_stub.AddInvoice(request)
        return response

    def list_invoices(self, reversed: bool = 1, **kwargs):
        request = ln.ListInvoiceRequest(reversed=reversed, **kwargs)
        response = self.lightning_stub.ListInvoices(request)
        return response

    def lookup_invoice(self, **kwargs):
        request = ln.PaymentHash(**kwargs)
        response = self.lightning_stub.LookupInvoice(request)
        return response

    def subscribe_invoices(self, **kwargs):
        request = ln.InvoiceSubscription(**kwargs)
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
        request = ln.ChannelGraphRequest(**kwargs)
        response = self.lightning_stub.DescribeGraph(request)
        return response

    def get_chan_info(self, chan_id: int):
        request = ln.ChanInfoRequest(chan_id=chan_id)
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
                num_routes=num_routes,
                **kwargs)
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
        request = ln.DebugLevelRequest(**kwargs)
        response = self.lightning_stub.DebugLevel(request)
        return response

    def fee_report(self):
        request = ln.FeeReportRequest()
        response = self.lightning_stub.FeeReport(request)
        return response

    def update_channel_policy(self, **kwargs):
        if 'chan_point' in kwargs:
            funding_txid, output_index = kwargs.get('chan_point').split(':')
            _channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                          output_index=output_index)
            kwargs['chan_point'] = _channel_point
        if not 'global' in kwargs:
            kwargs['global'] = 1
        request = ln.PolicyUpdateRequest(**kwargs)
        response = self.lightning_stub.UpdateChannelPolicy(request)
        return response

    def forwarding_history(self, start_time: int, **kwargs):
        request = ln.ForwardingHistoryRequest(start_time=start_time, **kwargs)
        response = self.lightning_stub.ForwardingHistory(request)
        return response
