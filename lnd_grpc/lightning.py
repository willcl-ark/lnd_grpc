import time
from os import environ

import grpc

import lnd_grpc.protos.rpc_pb2 as ln
import lnd_grpc.protos.rpc_pb2_grpc as lnrpc
from lnd_grpc.base_client import BaseClient

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class Lightning(BaseClient):

    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = 'mainnet',
                 grpc_host: str = 'localhost',
                 grpc_port: str = '10009'):

        self._lightning_stub: lnrpc.LightningStub = None

        self.version = None
        self.grpc_options = [
            ('grpc.max_receive_message_length', 33554432),
            ('grpc.max_send_message_length', 33554432),
        ]

        super().__init__(lnd_dir=lnd_dir,
                         macaroon_path=macaroon_path,
                         tls_cert_path=tls_cert_path,
                         network=network,
                         grpc_host=grpc_host,
                         grpc_port=grpc_port)

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
    Static channel backup
    """

    def export_chan_backup(self, **kwargs):
        """
        DESCRIPTION:

        This command allows a user to export a Static Channel Backup (SCB) for
        as selected channel. SCB's are encrypted backups of a channel's initial
        state that are encrypted with a key derived from the seed of a user.In
        the case of partial or complete data loss, the SCB will allow the user
        to reclaim settled funds in the channel at its final state. The
        exported channel backups can be restored at a later time using the
        restore_chan_backup method.
        """

        request = ln.ExportChannelBackupRequest(**kwargs)
        response = self.lightning_stub.ExportChannelBackup(request)
        return response

    def export_all_channel_backups(self, **kwargs):
        """
        As above but for all channels?
        """
        request = ln.ChanBackupExportRequest(**kwargs)
        response = self.lightning_stub.ExportAllChannelBackups(request)
        return response

    def restore_chan_backup(self, **kwargs):
        """
        DESCRIPTION:

        Allows a user to restore a Static Channel Backup (SCB) that was
        obtained either via the export_chan_backup command, or from lnd's
        automatically manged channels.backup file. This command should be used
        if a user is attempting to restore a channel due to data loss on a
        running node restored with the same seed as the node that created the
        channel. If successful, this command will allows the user to recover
        the settled funds stored in the recovered channels.

        The command will accept backups in one of three forms:

           * A single channel packed SCB, which can be obtained from
             export_chan_backup. This should be passed in hex encoded format.

           * A packed multi-channel SCB, which couples several individual
             static channel backups in single blob.

           * A file path which points to a packed multi-channel backup within a
             file, using the same format that lnd does in its channels.backup
             file.


        OPTIONS:
           --single_backup value  a hex encoded single channel backup obtained from export_chan_backup
           --multi_backup value   a hex encoded multi-channel backup obtained from export_chan_backup
           --multi_file value     the path to a multi-channel back up file

        """
        request = ln.RestoreChanBackupRequest(**kwargs)
        response = self.lightning_stub.RestoreChannelBackups(request)
        return response

    # Response-streaming RPC
    def subscribe_channel_backups(self, **kwargs):
        request = ln.ChannelBackupSubscription(**kwargs)
        response = self.lightning_stub.SubscribeChannelBackups(request)
        return response

    def verify_chan_backup(self, **kwargs):
        """
        For multi_backup: works as expected.

        For single_chan_backups:
        Needs to be passed a single channel backup (ChannelBackup) packed into a ChannelBackups
        to verify sucessfully.

        export_chan_backup() returns a ChannelBackup but it is not packed properly.
        export_all_channel_backups().single_chan_backups returns a ChannelBackups but as it contains
        more than one channel, verify_chan_backup() will also reject it.

        Use helper method pack_into_channelbackups() to pack individual ChannelBackup objects into
        the appropriate ChannelBackups objects for verification.
        """
        request = ln.ChanBackupSnapshot(**kwargs)
        response = self.lightning_stub.VerifyChanBackup(request)
        return response
