import codecs
from os import environ

import grpc
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import utilities as u

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
        self.connect()

    @property
    def lnd_dir(self):
        if self._lnd_dir:
            return self._lnd_dir
        else:
            self._lnd_dir = u.get_lnd_dir()
            assert isinstance(self._lnd_dir, object)
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
            return self._tls_cert_key
        except:
            print("Could not find TLS cert in %s" % self.tls_cert_path)

    @property
    def macaroon_path(self):
        if not self._macaroon_path:
            self._macaroon_path = self.lnd_dir + \
                                  '/data/chain/bitcoin/%s/admin.macaroon' \
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
        except:
            print("Could not find macaroon in %s" % self.macaroon_path)

    # helper function to return the macaroon when requested
    def metadata_callback(self, context, callback):
        callback([('macaroon', self.macaroon)], None)

    def build_credentials(self):
        self.cert_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
        self.auth_creds = grpc.metadata_call_credentials(self.metadata_callback)
        self.combined_creds = grpc.composite_channel_credentials(self.cert_creds, self.auth_creds)

    def connect(self,
                 cert_path: str = None,
                 macaroon_path: str = None,
                 network: str = 'mainnet'):

        # set attributes
        self.network = network
        if cert_path:
            self.tls_cert_path = cert_path
        if macaroon_path:
            self.macaroon_path = macaroon_path

        self.build_credentials()

        # create a connection
        self.channel = grpc.secure_channel(self.address,
                                           self.combined_creds)
                                           #options=self.grpc_options)
        self.conn = lnrpc.LightningStub(self.channel)

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

    def get_new_address(self, address_type: str = 'NESTED_PUBKEY_HASH'):
        request = ln.NewAddressRequest(type=address_type)
        response = self.conn.NewAddress(request)
        return response.address

    def get_graph(self):
        request = ln.ChannelGraphRequest()
        request.include_unannounced = False
        response = self.conn.DescribeGraph(request)
        return response
