import codecs
import grpc
import sys
import time
from os import environ

import lnd_grpc.protos.invoices_pb2 as inv
import lnd_grpc.protos.invoices_pb2_grpc as invrpc
import lnd_grpc.protos.rpc_pb2 as ln
import lnd_grpc.protos.rpc_pb2_grpc as lnrpc
from lnd_grpc.utilities import get_lnd_dir

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class Client:
    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = 'mainnet',
                 grpc_host: str = 'localhost',
                 grpc_port: str = '10009'):

        self._lightning_stub: lnrpc.LightningStub = None
        self._w_stub: lnrpc.WalletUnlockerStub = None
        self._inv_stub: invrpc.InvoicesStub = None

        self.lnd_dir = lnd_dir
        self.macaroon_path = macaroon_path
        self.tls_cert_path = tls_cert_path
        self.network = network
        self.grpc_host = grpc_host
        self.grpc_port = grpc_port
        self.channel = None
        self.connection_status = None
        self.connection_status_change = False
        self.version = None
        self.grpc_options = [
            ('grpc.max_receive_message_length', 33554432),
            ('grpc.max_send_message_length', 33554432),
        ]

    @property
    def lnd_dir(self):
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
        if self._tls_cert_path is None:
            self._tls_cert_path = self.lnd_dir + 'tls.cert'
        return self._tls_cert_path

    @tls_cert_path.setter
    def tls_cert_path(self, path):
        self._tls_cert_path = path

    @property
    def tls_cert_key(self) -> bytes:
        try:
            with open(self.tls_cert_path, 'rb') as r:
                tls_cert_key = r.read()
        except FileNotFoundError:
            sys.stderr.write("TLS cert not found at %s" % self.tls_cert_path)
            raise
        try:
            assert tls_cert_key.startswith(b'-----BEGIN CERTIFICATE-----')
            return tls_cert_key
        except (AssertionError, AttributeError):
            sys.stderr.write("TLS cert at %s did not start with b'-----BEGIN CERTIFICATE-----')"
                             % self.tls_cert_path)
            raise

    @property
    def macaroon_path(self) -> str:
        if not self._macaroon_path:
            self._macaroon_path = self.lnd_dir + \
                                  'data/chain/bitcoin/%s/admin.macaroon' \
                                  % self.network
            return self._macaroon_path
        else:
            return self._macaroon_path

    @macaroon_path.setter
    def macaroon_path(self, path: str):
        self._macaroon_path = path

    @property
    def macaroon(self):
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

    # noinspection PyUnusedLocal
    def metadata_callback(self, context, callback):
        callback([('macaroon', self.macaroon)], None)

    def connectivity_event_logger(self, channel_connectivity):
        self.connection_status = channel_connectivity._name_
        if self.connection_status == 'SHUTDOWN' or self.connection_status == 'TRANSIENT_FAILURE':
            self.connection_status_change = True

    @property
    def combined_credentials(self) -> grpc.CallCredentials:
        cert_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        auth_creds = grpc.metadata_call_credentials(self.metadata_callback)
        return grpc.composite_channel_credentials(cert_creds, auth_creds)

    @property
    def grpc_address(self) -> str:
        return str(self.grpc_host + ':' + self.grpc_port)

    @property
    def version(self):
        if self._version:
            return self._version
        else:
            self._version = self.get_info().version.split(" ")[0]
            return self._version

    @version.setter
    def version(self, version: str):
        self._version = version

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
    def bytes_to_hex(bytestring: bytes):
        return bytestring.hex()

    @property
    def lightning_stub(self) -> lnrpc.LightningStub:
        # if the stub is already created and channel might recover, return current stub
        if self._lightning_stub is not None \
                and self.connection_status_change is False:
            return self._lightning_stub

        # otherwise, start by creating a fresh channel
        self.channel = grpc.secure_channel(target=self.grpc_address,
                                           credentials=self.combined_credentials,
                                           options=self.grpc_options)

        # subscribe to channel connectivity updates with callback
        self.channel.subscribe(self.connectivity_event_logger)

        # create the new stub
        self._lightning_stub = lnrpc.LightningStub(self.channel)

        # 'None' is channel_status's initialization state.
        # ensure connection_status_change is True to keep regenerating fresh stubs until channel
        # comes online
        if self.connection_status is None:
            self.connection_status_change = True
            return self._lightning_stub

        else:
            self.connection_status_change = False
            return self._lightning_stub

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

    @property
    def invoice_stub(self) -> invrpc.InvoicesStub:
        if self._inv_stub is None:
            ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
            _inv_channel = grpc.secure_channel(target=self.grpc_address,
                                               credentials=self.combined_credentials,
                                               options=self.grpc_options)
            self._inv_stub = invrpc.InvoicesStub(_inv_channel)
        return self._inv_stub

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

    # On Chain
    # TODO: remove the amount here in v0.5.3-beta if the 'send_all' bool makes it into the release
    def send_coins(self, addr: str, amount: int, **kwargs):
        request = ln.SendCoinsRequest(addr=addr, amount=amount, **kwargs)
        response = self.lightning_stub.SendCoins(request)
        return response

    def list_unspent(self, min_confs: int, max_confs: int):
        request = ln.ListUnspentRequest(min_confs=min_confs, max_confs=max_confs)
        response = self.lightning_stub.ListUnspent(request)
        return response

    # Response-streaming RPC
    def subscribe_transactions(self):
        request = ln.GetTransactionsRequest()
        return self.lightning_stub.SubscribeTransactions(request)

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
            return TypeError("invalid address type %s, supported address type are: p2wkh and np2wkh"
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

    def connect_peer(self, addr: ln.LightningAddress, perm: bool = 0,
                     timeout: int = None):
        request = ln.ConnectPeerRequest(addr=addr, perm=perm)
        response = self.lightning_stub.ConnectPeer(request, timeout=timeout)
        return response

    def connect(self, address: str, perm: bool = 0, timeout: int = None):
        pubkey, host = address.split('@')
        _address = self.lightning_address(pubkey=pubkey, host=host)
        response = self.connect_peer(addr=_address, perm=perm, timeout=timeout)
        return response

    def disconnect_peer(self, pub_key: str):
        request = ln.DisconnectPeerRequest(pub_key=pub_key)
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

    def open_channel_sync(self, local_funding_amount: int, **kwargs):
        request = ln.OpenChannelRequest(local_funding_amount=local_funding_amount, **kwargs)
        response = self.lightning_stub.OpenChannelSync(request)
        return response

    # Response-streaming RPC
    def open_channel(self, local_funding_amount: int, timeout: int = None,
                     **kwargs):
        # TODO: implement `lncli openchannel --connect` function
        request = ln.OpenChannelRequest(local_funding_amount=local_funding_amount, **kwargs)
        if request.node_pubkey == b'':
            request.node_pubkey = bytes.fromhex(request.node_pubkey_string)
        return self.lightning_stub.OpenChannel(request, timeout=timeout)

    # Response-streaming RPC
    def close_channel(self, channel_point, **kwargs):
        funding_txid, output_index = channel_point.split(':')
        _channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                      output_index=output_index)
        request = ln.CloseChannelRequest(channel_point=_channel_point, **kwargs)
        return self.lightning_stub.CloseChannel(request)

    def close_all_channels(self, inactive_only: bool = 0):
        if not inactive_only:
            for channel in self.list_channels():
                self.close_channel(channel_point=channel.channel_point).next()
        if inactive_only:
            for channel in self.list_channels(inactive_only=1):
                self.close_channel(channel_point=channel.channel_point).next()

    def abandon_channel(self, channel_point: ln.ChannelPoint):
        funding_txid, output_index = channel_point.split(':')
        _channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                      output_index=output_index)
        request = ln.AbandonChannelRequest(channel_point=_channel_point)
        response = self.lightning_stub.AbandonChannel(request)
        return response

    @staticmethod
    def send_request_generator(**kwargs):
        # Commented out to complement the magic sleep below...
        # while True:
        request = ln.SendRequest(**kwargs)
        yield request
        # Magic sleep which tricks the response to the send_payment() method to actually
        # contain data...
        time.sleep(5)

    # Bi-directional streaming RPC
    def send_payment(self, **kwargs):
        # Use payment request as first choice
        if 'payment_request' in kwargs:
            request_iterable = self.send_request_generator(
                    payment_request=kwargs['payment_request']
            )
        else:
            # Helper to convert hex to bytes automatically
            try:
                if 'payment_hash' not in kwargs:
                    kwargs['payment_hash'] = bytes.fromhex(kwargs['payment_hash_string'])
                if 'dest' not in kwargs:
                    kwargs['dest'] = bytes.fromhex(kwargs['dest_string'])
            except ValueError as e:
                raise e
            request_iterable = self.send_request_generator(**kwargs)
        return self.lightning_stub.SendPayment(request_iterable)

    # Synchronous non-streaming RPC
    def send_payment_sync(self, **kwargs):
        # Use payment request as first choice
        if 'payment_request' in kwargs:
            request = ln.SendRequest(payment_request=kwargs['payment_request'])
        else:
            request = ln.SendRequest(**kwargs)
        response = self.lightning_stub.SendPaymentSync(request)
        return response

    def pay_invoice(self, payment_request: str):
        response = self.send_payment_sync(payment_request=payment_request)
        return response

    @staticmethod
    def send_to_route_generator(invoice, routes):
        # Commented out to complement the magic sleep below...
        # while True:
        request = ln.SendToRouteRequest(payment_hash=invoice.r_hash, routes=routes)
        yield request
        # Magic sleep which tricks the response to the send_to_route() method to actually
        # contain data...
        time.sleep(5)

    # Bi-directional streaming RPC
    def send_to_route(self, invoice, routes):
        request_iterable = self.send_to_route_generator(invoice=invoice, routes=routes)
        return self.lightning_stub.SendToRoute(request_iterable)

    # Synchronous non-streaming RPC
    def send_to_route_sync(self, routes, **kwargs):
        request = ln.SendToRouteRequest(routes=routes, **kwargs)
        response = self.lightning_stub.SendToRouteSync(request)
        return response

    def add_invoice(self,
                    memo: str = '',
                    value: int = 0,
                    expiry: int = 3600,
                    creation_date: int = int(time.time()),
                    **kwargs):
        request = ln.Invoice(memo=memo, value=value, expiry=expiry,
                             creation_date=creation_date, **kwargs)
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
        return self.lightning_stub.SubscribeInvoices(request)

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

    # Uni-directional stream
    def subscribe_channel_events(self):
        request = ln.ChannelEventSubscription()
        return self.lightning_stub.SubscribeChannelEvents(request)

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
        return response.routes

    def get_network_info(self):
        request = ln.NetworkInfoRequest()
        response = self.lightning_stub.GetNetworkInfo(request)
        return response

    def stop_daemon(self):
        request = ln.StopRequest()
        response = self.lightning_stub.StopDaemon(request)
        return response

    # Response-streaming RPC
    def subscribe_channel_graph(self):
        request = ln.GraphTopologySubscription()
        return self.lightning_stub.SubscribeChannelGraph(request)

    def debug_level(self, **kwargs):
        request = ln.DebugLevelRequest(**kwargs)
        response = self.lightning_stub.DebugLevel(request)
        return response

    def fee_report(self):
        request = ln.FeeReportRequest()
        response = self.lightning_stub.FeeReport(request)
        return response

    def update_channel_policy(self,
                              chan_point: str,
                              is_global: bool = False,
                              base_fee_msat: int = 1000,
                              fee_rate: float = 0.000001,
                              time_lock_delta: int = 144
                              ):
        if chan_point:
            funding_txid, output_index = chan_point.split(':')
            channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                         output_index=output_index)
        else:
            channel_point = None

        request = ln.PolicyUpdateRequest(
                chan_point=channel_point,
                base_fee_msat=base_fee_msat,
                fee_rate=fee_rate,
                time_lock_delta=time_lock_delta
        )
        if is_global:
            setattr(request, 'global', is_global)
        response = self.lightning_stub.UpdateChannelPolicy(request)
        return response

    def forwarding_history(self, **kwargs):
        request = ln.ForwardingHistoryRequest(**kwargs)
        response = self.lightning_stub.ForwardingHistory(request)
        return response

    """
    Invoices RPC
    """

    def subscribe_single_invoice(self,
                                 r_hash: bytes = b'',
                                 r_hash_str: str = '') -> ln.Invoice:
        """
        Uni-directional streaming RPC returns an iterable to be operated on
        """
        request = ln.PaymentHash(r_hash=r_hash, r_hash_str=r_hash_str)
        response = self.invoice_stub.SubscribeSingleInvoice(request)
        return response

    def cancel_invoice(self, payment_hash: bytes = b'') -> inv.CancelInvoiceResp:
        request = inv.CancelInvoiceMsg(payment_hash=payment_hash)
        response = self.invoice_stub.CancelInvoice(request)
        return response

    def add_hold_invoice(self,
                         memo: str = '',
                         hash: bytes = b'',
                         value: int = 0,
                         expiry: int = 3600,
                         fallback_addr: str = '',
                         cltv_expiry: int = 7,
                         route_hints: ln.RouteHint = [],
                         private: bool = 1) -> inv.AddHoldInvoiceResp:
        request = inv.AddHoldInvoiceRequest(
                memo=memo, hash=hash, value=value, expiry=expiry,
                fallback_addr=fallback_addr, cltv_expiry=cltv_expiry,
                route_hints=route_hints, private=private)
        response = self.invoice_stub.AddHoldInvoice(request)
        return response

    def settle_invoice(self, preimage: bytes = b'') -> inv.SettleInvoiceResp:
        request = inv.SettleInvoiceMsg(preimage=preimage)
        response = self.invoice_stub.SettleInvoice(request)
        return response


__all__ = ['Client', ]
