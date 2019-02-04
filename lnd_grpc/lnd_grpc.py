import codecs
import sys
from os import environ

import grpc

from . import rpc_pb2 as ln, rpc_pb2_grpc as lnrpc, utilities as u
from .handle_error import handle_error as handle_error

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

    @handle_error
    def gen_seed(self, **kwargs):
        request = ln.GenSeedRequest(**kwargs)
        response = self.wallet_unlocker_stub.GenSeed(request)
        return response

    @handle_error
    def init_wallet(self,
                    wallet_password: str = None, **kwargs):
        request = ln.InitWalletRequest(wallet_password=wallet_password.encode('utf-8'), **kwargs)
        response = self.wallet_unlocker_stub.InitWallet(request)
        return response

    @handle_error
    def unlock_wallet(self, wallet_password: str, recovery_window: int = 0):
        """
        The unlock command is used to decrypt lnd's wallet state in order to
        start up. This command MUST be run after booting up lnd before it's
        able to carry out its duties. An exception is if a user is running with
        --noseedbackup, then a default passphrase will be used.
        """
        request = ln.UnlockWalletRequest(wallet_password=wallet_password.encode('utf-8'),
                                         recovery_window=recovery_window)
        response = self.wallet_unlocker_stub.UnlockWallet(request)
        return response

    @handle_error
    def change_password(self, current_password: str, new_password: str):
        """
        The change_password command is used to change lnd's encrypted wallet's
        password. It will automatically unlock the daemon if the password change
        is successful.

        If one did not specify a password for their wallet (running lnd with
        --noseedbackup), one must restart their daemon without
        --noseedbackup and use this command.
        The "current password" field should be left empty.
        """
        request = ln.ChangePasswordRequest(current_password=current_password.encode('utf-8'),
                                           new_password=new_password.encode('utf-8'))
        response = self.wallet_unlocker_stub.ChangePassword(request)
        return response

    @handle_error
    def wallet_balance(self):
        """
        Compute and display the wallet's current balance.
        """
        request = ln.WalletBalanceRequest()
        response = self.lightning_stub.WalletBalance(request)
        return response

    @handle_error
    def channel_balance(self):
        """
        Returns the sum of the total available channel balance across all open channels.
        """
        request = ln.ChannelBalanceRequest()
        response = self.lightning_stub.ChannelBalance(request)
        return response

    @handle_error
    def get_transactions(self):
        request = ln.GetTransactionsRequest()
        response = self.lightning_stub.GetTransactions(request)
        return response

    # TODO: add listchaintxs() a-la lncli

    # On Chain
    @handle_error
    def send_coins(self, addr: str, amount: int, **kwargs):
        """
        Send 'amount' coins in satoshis to the BASE58 encoded bitcoin address 'addr'.
        Fees used when sending the transaction can be specified via 'conf_target', or
        'sat_per_byte' optional kwargs.

        If 'send_all' is set, then the amount field will be ignored, and lnd will
        attempt to send all the coins under control of the internal wallet to the
        specified address.
        """
        request = ln.SendCoinsRequest(addr=addr, amount=amount, **kwargs)
        response = self.lightning_stub.SendCoins(request)
        return response

    # RPC not available in v0.5.1-beta
    # def list_unspent(self, min_confs: int, max_confs: int):
    #    request = ln.ListUnspentRequest(min_confs=min_confs, max_confs=max_confs)
    #    response = self.lightning_stub.ListUnspent(request)
    #    return response

    @handle_error
    def subscribe_transactions(self):
        """
        Creates a uni-directional stream from server to client
        """
        request = ln.GetTransactionsRequest()
        for response in self.lightning_stub.SubscribeTransactions(request):
            return response

    # TODO: check this more. It works with regular python dicts so I think it's ok
    @handle_error
    def send_many(self, addr_to_amount: ln.SendManyRequest.AddrToAmountEntry, **kwargs):
        """
        Create and broadcast an on-chain transaction paying the specified amount(s)
        to the passed address(es).

        'addr_to_amount' should be passed in the following format:
        {"ExampleAddr": NumCoinsInSatoshis, "SecondAddr": NumCoins}
        """
        request = ln.SendManyRequest(AddrToAmount=addr_to_amount, **kwargs)
        response = self.lightning_stub.SendMany(request)
        return response

    @handle_error
    def new_address(self, address_type: str):
        """
        Map the string encoded address type to the concrete typed address \
        type enum. An unrecognized address type will result in an error.

        Acceptable address_types are 'p2wkh' and 'np2wkh'
        """
        if address_type == 'p2wkh':
            request = ln.NewAddressRequest(type='WITNESS_PUBKEY_HASH')
        elif address_type == 'np2wkh':
            request = ln.NewAddressRequest(type='NESTED_PUBKEY_HASH')
        else:
            return TypeError("invalid address type %s, supported address type are: p2wkh and np2wkh" \
                             % address_type)
        response = self.lightning_stub.NewAddress(request)
        return response

    @handle_error
    def sign_message(self, msg: str):
        """
        Sign msg with the resident node's private key.
        Returns the signature as a zbase32 string.

        Positional arguments and flags can be used interchangeably but not at the same time!
        """
        _msg_bytes = msg.encode('utf-8')
        request = ln.SignMessageRequest(msg=_msg_bytes)
        response = self.lightning_stub.SignMessage(request)
        return response

    @handle_error
    def verify_message(self, msg: str, signature: str):
        """
        Verify that the message was signed with a properly-formed signature
        The signature must be zbase32 encoded and signed with the private key of
        an active node in the resident node's channel database.

        Positional arguments and flags can be used interchangeably but not at the same time!
        """
        _msg_bytes = msg.encode('utf-8')
        request = ln.VerifyMessageRequest(msg=_msg_bytes, signature=signature)
        response = self.lightning_stub.VerifyMessage(request)
        return response

    @handle_error
    def connect_peer(self, addr: ln.LightningAddress, perm: bool = 0):
        """
        Connect to a remote lnd peer.
        If 'perm' set the daemon will attempt to connect persistently, otherwise connection will be
        synchronous.
        """
        request = ln.ConnectPeerRequest(addr=addr, perm=perm)
        response = self.lightning_stub.ConnectPeer(request)
        return response

    @handle_error
    def connect(self, address: str, perm: bool = 0):
        """
        Connect to peer as per 'connect_peer()' but using common 'pubkey@host:port' notation
        Also can accept 'perm' bool to create a persistent connection.
        """
        pubkey, host = address.split('@')
        _address = self.lightning_address(pubkey=pubkey, host=host)
        response = self.connect_peer(addr=_address, perm=perm)
        return response

    @handle_error
    def disconnect_peer(self, pubkey: str):
        """
        Disconnect a remote lnd peer identified by hex encoded public key.
        """
        request = ln.DisconnectPeerRequest(pubkey=pubkey)
        response = self.lightning_stub.DisconnectPeer(request)
        return response

    @handle_error
    def list_peers(self):
        """
        List all active, currently connected peers.
        :return:
        """
        request = ln.ListPeersRequest()
        response = self.lightning_stub.ListPeers(request)
        return response.peers

    @handle_error
    def get_info(self):
        """
        Returns basic information related to the active daemon.
        """
        request = ln.GetInfoRequest()
        response = self.lightning_stub.GetInfo(request)
        return response

    @handle_error
    def pending_channels(self):
        """
        Display information pertaining to pending channels.
        """
        request = ln.PendingChannelsRequest()
        response = self.lightning_stub.PendingChannels(request)
        return response

    @handle_error
    def list_channels(self, **kwargs):
        """
        List all open channels.
        Optional kwargs:
            active_only
            inactive_only
            public_only
            private_only
        """
        request = ln.ListChannelsRequest(**kwargs)
        response = self.lightning_stub.ListChannels(request)
        return response.channels

    @handle_error
    def closed_channels(self, **kwargs):
        """
        List closed channels
        Optional kwargs (can multi-select):
            cooperative
            local_force
            remote_force
            breach
            funding_canceled
            abandoned
        """
        request = ln.ClosedChannelsRequest(**kwargs)
        response = self.lightning_stub.ClosedChannels(request)
        return response.channels

    @handle_error
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

    @handle_error
    def open_channel(self,
                     node_pubkey_string: str,
                     local_funding_amount: int,
                     **kwargs):
        # TODO: mirror `lncli openchannel --connect` function
        """
        Not implemented yet, awaiting async protocol

        Attempt to open a new channel to an existing peer with the key node-key.
        The channel will be initialized with 'local_amt' satoshis local and optional 'push_amt'
        satoshis for the remote node. Note that specifying 'push_amt' means you give that
        amount to the remote node as part of the channel opening.
        Once the channel is open, a channelPoint (txid:vout) of the funding output is returned.

        One can manually set the fee to be used for the funding transaction via either
        the --conf_target or --sat_per_byte arguments. This is optional.
        """
        return NotImplementedError("Asynchronous method open_channel() not implemented yet.\n"
                                   "Use synchronous (blocking) open_channel_sync() method instead")
        # request = ln.OpenChannelRequest(
        #         node_pubkey_string=node_pubkey_string,
        #         local_funding_amount=local_funding_amount,
        #         **kwargs)
        # if request.node_pubkey == b'':
        #     request.node_pubkey = bytes.fromhex(node_pubkey_string)
        # for response in self.lightning_stub.OpenChannel(request):
        #     return response

    @handle_error
    def close_channel(self, channel_point, **kwargs):
        """
        Close an existing channel. The channel can be closed either cooperatively,
        or unilaterally ('force=1').

        A unilateral channel closure means that the latest commitment
        transaction will be broadcast to the network. As a result, any settled
        funds will be time locked for a few blocks before they can be spent.

        In the case of a cooperative closure, One can manually set the fee to
        be used for the closing transaction via either the 'conf_target' or
        'sat_per_byte' arguments. This will be the starting value used during
        fee negotiation. This is optional.

        To view which funding_txids/output_indexes can be used for a channel close,
        see the channel_point values within the 'list_channels()' command output.
        The format for a channel_point is 'funding_txid:output_index'.
        """
        funding_txid, output_index = channel_point.split(':')
        _channel_point = self.channel_point_generator(funding_txid=funding_txid,
                                                      output_index=output_index)
        request = ln.CloseChannelRequest(channel_point=_channel_point, **kwargs)
        response = self.lightning_stub.CloseChannel(request)
        return response

    @handle_error
    def close_all_channels(self, inactive_only: bool = 0):
        """
        Close all channels (or 'inactive_only') by iterating through the 'list_channels()'
        command and passing each one to the 'close_channel()' command. Unlike when using the CLI
        there is no confirmation prompt on doing this, so be careful!!!
        """
        if inactive_only == False:
            for channel in self.list_channels():
                self.close_channel(channel_point=channel.channel_point)
        if inactive_only == True:
            for channel in self.list_channels(inactive_only=1):
                self.close_channel(channel_point=channel.channel_point)

    @handle_error
    def abandon_channel(self, channel_point: ln.ChannelPoint):
        """
        Removes all channel state from the database except for a close
        summary. This method can be used to get rid of permanently unusable
        channels due to bugs fixed in newer versions of lnd.

        Only available when lnd is built in debug mode.

        To view which funding_txids/output_indexes can be used for this command,
        see the channel_point values within the listchannels command output.
        The format for a channel_point is 'funding_txid:output_index'.
        """
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
    @handle_error
    def send_payment(self, **kwargs):
        """
        Not implemented yet.

        Send a payment over Lightning. One can either specify the full
        parameters of the payment, or just use a payment request which encodes
        all the payment details.
        If payment isn't manually specified, then only a payment request needs
        to be passed using the payment_request argument.
        If the payment *is* manually specified, then all four alternative
        arguments need to be specified in order to complete the payment:
            * dest_string=N
            * amt=A
            * final_cltv_delta=T
            * payment_hash_string=H
        """
        return NotImplementedError("Asynchronous method send_payment() not implemented yet.\n"
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

    @handle_error
    def send_payment_sync(self, **kwargs):
        """
        SendPaymentSync is the synchronous non-streaming version of SendPayment.
        This RPC is intended to be consumed by clients of the REST proxy.
        Additionally, this RPC expects the destination’s public key and the payment hash (if any)
        to be encoded as hex strings.

        See help docstring for send_payment() for more info on acceptable arguments
        """
        if kwargs['payment_request']:
            request = ln.SendRequest(payment_request=kwargs['payment_request'])
        else:
            kwargs['payment_hash'] = bytes.fromhex(kwargs['payment_hash_string'])
            kwargs['dest'] = bytes.fromhex(kwargs['dest_string'])
            request = ln.SendRequest(**kwargs)
        response = self.lightning_stub.SendPaymentSync(request)
        return response

    @handle_error
    def pay_invoice(self, payment_request: str):
        """
        lncli equivalent function which passes the payment request to send_payment()
        """
        # TODO: I think this should technically use non-blocking send_payment()
        response = self.send_payment_sync(payment_request=payment_request)
        return response

    @staticmethod
    def send_to_route_generator(**kwargs):
        while True:
            request = ln.SendToRouteRequest(**kwargs)
            yield request

    @handle_error
    def send_to_route(self):
        """
        Not implemented yet

        SendToRoute is a bi-directional streaming RPC for sending payment through
        the Lightning Network. This method differs from SendPayment in that it allows
        users to specify a full route manually. This can be used for things like
        re-balancing, and atomic swaps.
        """
        return NotImplementedError("Asynchronous method send_to_route() not implemented yet. \
        Use synchronous (blocking) send_to_route_sync() method instead")

    @handle_error
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

    @handle_error
    def add_invoice(self, value: int = 0, **kwargs):
        """
        Add a new invoice, expressing intent for a future payment.
        Invoices without an amount can be created by not supplying any
        parameters or providing an amount of 0. These invoices allow the payee
        to specify the amount of satoshis they wish to send.
        """
        request = ln.Invoice(value=value, **kwargs)
        response = self.lightning_stub.AddInvoice(request)
        return response

    @handle_error
    def list_invoices(self, reversed: bool = 1, **kwargs):
        """
        This command enables the retrieval of all invoices currently stored
        within the database. It has full support for paginationed responses,
        allowing users to query for specific invoices through their add_index.
        This can be done by using either the first_index_offset or
        last_index_offset fields included in the response as the index_offset of
        the next request.

        The reversed flag is set by default in order to
        paginate backwards. If you wish to paginate forwards, you must
        explicitly set the flag to false. If none of the parameters are
        specified, then the last 100 invoices will be returned.
        """
        request = ln.ListInvoiceRequest(reversed=reversed, **kwargs)
        response = self.lightning_stub.ListInvoices(request)
        return response

    @handle_error
    def lookup_invoice(self, r_hash: bytes):
        """
        Lookup an existing invoice by its payment hash.
        The r_hash is the 32 byte payment hash of the invoice to query for.
        """
        _r_hash_str = r_hash.hex()
        request = ln.PaymentHash(r_hash=r_hash, r_hash_str=_r_hash_str)
        response = self.lightning_stub.LookupInvoice(request)
        return response

    @handle_error
    def subscribe_invoices(self, **kwargs):
        request = ln.InvoiceSubscription(**kwargs)
        for response in self.lightning_stub.SubscribeInvoices(request):
            return response

    @handle_error
    def decode_pay_req(self, pay_req: str):
        """
        Decode the passed payment request revealing the destination, payment hash
        and value of the payment request
        """
        request = ln.PayReqString(pay_req=pay_req)
        response = self.lightning_stub.DecodePayReq(request)
        return response

    @handle_error
    def list_payments(self):
        """
        List all outgoing payments
        """
        request = ln.ListPaymentsRequest()
        response = self.lightning_stub.ListPayments(request)
        return response

    @handle_error
    def delete_all_payments(self):
        request = ln.DeleteAllPaymentsRequest()
        response = self.lightning_stub.DeleteAllPayments(request)
        return response

    @handle_error
    def describe_graph(self, **kwargs):
        """
        Prints a human readable version of the known channel graph from the PoV of the node

        optional argument: 'include_unannounced':
            If set, unannounced channels will be included in the graph.
            Unannounced channels are both private channels, and public channels that are
            not yet announced to the network
        """
        request = ln.ChannelGraphRequest(**kwargs)
        response = self.lightning_stub.DescribeGraph(request)
        return response

    @handle_error
    def get_chan_info(self, chan_id: int):
        """
        Get the state of a channel.
        Prints out the latest authenticated state for a particular channel.

        chan_id accessible from within list_channels()
        """
        request = ln.ChanInfoRequest(chan_id=chan_id)
        response = self.lightning_stub.GetChanInfo(request)
        return response

    @handle_error
    def get_node_info(self, pub_key: str):
        request = ln.NodeInfoRequest(pub_key=pub_key)
        response = self.lightning_stub.GetNodeInfo(request)
        return response

    @handle_error
    def query_routes(self,
                     pub_key: str,
                     amt: int,
                     num_routes: int,
                     **kwargs):
        """
        Queries the channel router for a potential path to the destination that
        has sufficient flow for the amount, including fees.
        """
        request = ln.QueryRoutesRequest(
                pub_key=pub_key,
                amt=amt,
                num_routes=num_routes,
                **kwargs)
        response = self.lightning_stub.QueryRoutes(request)
        return response

    @handle_error
    def get_network_info(self):
        """
        Get statistical information about the current state of the network.
        """
        request = ln.NetworkInfoRequest()
        response = self.lightning_stub.GetNetworkInfo(request)
        return response

    @handle_error
    def stop_daemon(self):
        """
        Gracefully stop all daemon subsystems before stopping the daemon itself.
        This is equivalent to stopping it using CTRL-C.
        """
        request = ln.StopRequest()
        response = self.lightning_stub.StopDaemon(request)
        return response

    @handle_error
    def subscribe_channel_graph(self):
        request = ln.GraphTopologySubscription()
        for response in self.lightning_stub.SubscribeChannelGraph(request):
            return response

    @handle_error
    def debug_level(self, **kwargs):
        """
        Set the debug level.

        Logging level for all subsystems {trace, debug, info, warn, error, critical, off}

        You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log
        level for individual subsystems:
        e.g. level_spec='SRVR=debug,RPCS=trace'
        """
        request = ln.DebugLevelRequest(**kwargs)
        response = self.lightning_stub.DebugLevel(request)
        return response

    @handle_error
    def fee_report(self):
        """
        Returns the current fee policies of all active channels.
        Fee policies can be updated using the update_chan_policy() function.
        """
        request = ln.FeeReportRequest()
        response = self.lightning_stub.FeeReport(request)
        return response

    @handle_error
    def update_channel_policy(self, **kwargs):
        """
        Updates the channel policy for all channels, or just a particular channel
        identified by its channel point.
        The update will be committed, and broadcast to the rest of the network
        within the next batch.

        Channel points are encoded as: funding_txid:output_index
        """
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

    @handle_error
    def forwarding_history(self, start_time: int, **kwargs):
        """
        Query the HTLC switch's internal forwarding log for all completed
        payment circuits (HTLCs) over a particular time range (--start_time and
        --end_time).
        The start and end times are meant to be expressed in
        seconds since the Unix epoch. If a start and end time aren't provided,
        then events over the past 24 hours are queried for.

        The max number of events returned is 50k. The default number is 100,
        callers can use the --max_events param to modify this value.

        Finally, callers can skip a series of events using the --index_offset
        parameter. Each response will contain the offset index of the last
        entry. Using this callers can manually paginate within a time slice.
        """
        request = ln.ForwardingHistoryRequest(start_time=start_time, **kwargs)
        response = self.lightning_stub.ForwardingHistory(request)
        return response
