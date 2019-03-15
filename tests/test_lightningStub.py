import os
import time
import unittest

import bitcoin.rpc
import grpc

import lnd_grpc.lnd_grpc as py_rpc
import lnd_grpc.protos.rpc_pb2 as rpc_pb2

# from google.protobuf.internal.containers import RepeatedCompositeFieldContainer

#######################
# Configure variables #
#######################

CWD = os.getcwd()

ALICE_LND_DIR = '/Users/will/regtest/.lnd/'
ALICE_NETWORK = 'regtest'
ALICE_RPC_HOST = '127.0.0.1'
ALICE_RPC_PORT = '10009'
ALICE_MACAROON_PATH = '/Users/will/regtest/.lnd/data/chain/bitcoin/regtest/admin.macaroon'
ALICE_PEER_PORT = '9735'
ALICE_HOST_ADDR = ALICE_RPC_HOST + ':' + ALICE_PEER_PORT

BOB_LND_DIR = '/Users/will/regtest/.lnd2/'
BOB_NETWORK = 'regtest'
BOB_RPC_HOST = '127.0.0.1'
BOB_RPC_PORT = '11009'
BOB_MACAROON_PATH = '/Users/will/regtest/.lnd2/data/chain/bitcoin/regtest/admin.macaroon'
BOB_PEER_PORT = '9734'
BOB_HOST_ADDR = BOB_RPC_HOST + ':' + BOB_PEER_PORT

BITCOIN_SERVICE_PORT = 18443
BITCOIN_CONF_FILE = '/Users/will/regtest/.bitcoin/bitcoin.conf'
BITCOIN_ADDR = None

DEBUG_LEVEL = 'error'
SLEEP_TIME = 0.5


def initialise_clients():
    global BITCOIN_ADDR

    alice = py_rpc.Client(lnd_dir=ALICE_LND_DIR,
                          network=ALICE_NETWORK,
                          grpc_host=ALICE_RPC_HOST,
                          grpc_port=ALICE_RPC_PORT,
                          macaroon_path=ALICE_MACAROON_PATH)
    alice.pub_key = alice.get_info().identity_pubkey
    alice.lightning_addr = py_rpc.Client.lightning_address(
            pubkey=alice.pub_key,
            host=ALICE_HOST_ADDR)

    bob = py_rpc.Client(lnd_dir=BOB_LND_DIR,
                        network=BOB_NETWORK,
                        grpc_host=BOB_RPC_HOST,
                        grpc_port=BOB_RPC_PORT,
                        macaroon_path=BOB_MACAROON_PATH)
    bob.pub_key = bob.get_info().identity_pubkey
    bob.lightning_addr = py_rpc.Client.lightning_address(
            pubkey=bob.pub_key,
            host=BOB_HOST_ADDR)

    bitcoin_rpc = bitcoin.rpc.RawProxy(service_port=BITCOIN_SERVICE_PORT,
                                       btc_conf_file=BITCOIN_CONF_FILE)
    BITCOIN_ADDR = bitcoin_rpc.getnewaddress()

    return alice, bob, bitcoin_rpc


def ensure_peer_connected(alice, bob):
    if len(alice.list_peers()) == 0:
        alice.connect_peer(addr=bob.lightning_addr)
    assert (len(alice.list_peers()) > 0)


def ensure_channel_open(alice, bob, bitcoin_rpc, address):
    if len(alice.list_channels()) == 0:
        alice.open_channel_sync(local_funding_amount=1_000_000,
                                push_sat=500_000,
                                node_pubkey_string=bob.pub_key)
    bitcoin_rpc.generatetoaddress(3, address)
    time.sleep(SLEEP_TIME)
    assert (len(alice.list_channels()) > 0)


def disconnect_all_peers(alice):
    for peer in alice.list_peers():
        alice.disconnect_peer(pub_key=peer.pub_key)
        time.sleep(SLEEP_TIME)
    assert (0 == len(alice.list_peers()))


def close_all_channels(peer):
    if len(peer.list_channels()) > 0:
        peer.close_all_channels()
        time.sleep(SLEEP_TIME)
    assert (0 == len(peer.list_channels()))


##################
# Test framework #
##################i

class TestLightningStubResponses(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob, cls.bitcoin_rpc = initialise_clients()

    def test_aaa_assert_variables(self):
        self.assertIsInstance(self.alice, py_rpc.Client)
        self.assertIsInstance(self.alice.channel, grpc._channel.Channel)
        self.assertIsInstance(self.bob, py_rpc.Client)
        self.assertIsInstance(self.bitcoin_rpc, bitcoin.rpc.RawProxy)

    def test_wallet_balance(self):
        self.assertIsInstance(self.alice.wallet_balance(), rpc_pb2.WalletBalanceResponse)
        # lambda function prevents TypeError being raised before assert is run.
        self.assertRaises(TypeError, lambda: self.alice.wallet_balance('please'))

    def test_channel_balance(self):
        self.assertIsInstance(self.alice.channel_balance(), rpc_pb2.ChannelBalanceResponse)
        self.assertRaises(TypeError, lambda: self.alice.channel_balance('please'))

    def test_get_transactions(self):
        self.assertIsInstance(self.alice.get_transactions(), rpc_pb2.TransactionDetails)
        self.assertRaises(TypeError, lambda: self.alice.get_transactions('please'))

    def test_send_coins(self):
        response1 = self.alice.send_coins(self.alice.new_address(address_type='p2wkh').address,
                                          amount=100000)
        response2 = self.alice.send_coins(self.alice.new_address(address_type='np2wkh').address,
                                          amount=100000)
        self.assertIsInstance(response1, rpc_pb2.SendCoinsResponse)
        self.assertIsInstance(response2, rpc_pb2.SendCoinsResponse)
        # negative send
        self.assertRaises(grpc.RpcError,
                          lambda: self.alice.send_coins(
                                  self.alice.new_address(address_type='p2wkh').address,
                                  amount=100000 * -1))
        # impossibly large send
        self.assertRaises(grpc.RpcError,
                          lambda: self.alice.send_coins(
                                  self.alice.new_address(address_type='p2wkh').address,
                                  amount=1000000000000000))

    def test_list_unspent(self):
        self.assertIsInstance(self.alice.list_unspent(0, 1000), rpc_pb2.ListUnspentResponse)

    def subscribe_transactions(self):
        self.assertIsInstance(self.alice.subscribe_transactions(), rpc_pb2.Transaction)

    def send_many(self):
        pass

    def test_new_address(self):
        self.address_p2wkh = self.alice.new_address(address_type='p2wkh')
        self.address_np2wkh = self.alice.new_address(address_type='np2wkh')
        self.assertIsInstance(self.address_p2wkh, rpc_pb2.NewAddressResponse)
        self.assertIsInstance(self.address_np2wkh, rpc_pb2.NewAddressResponse)
        self.assertRaises(TypeError, self.alice.new_address(address_type='segwit'))

    def test_sign_message(self):
        self.assertIsInstance(self.alice.sign_message(msg='test message content'),
                              rpc_pb2.SignMessageResponse)
        self.assertRaises(AttributeError,
                          lambda: self.alice.sign_message(msg=b'bytes message'))

    def test_verify_message(self):
        message = 'test message content'
        message_sig_true = self.alice.sign_message(msg=message).signature
        message_sig_false = message_sig_true + '1'
        self.assertTrue(self.alice.verify_message(msg=message, signature=message_sig_true).valid)
        self.assertFalse(self.alice.verify_message(msg=message, signature=message_sig_false).valid)

    def test_disconnect_peer(self):
        bitcoin_address = self.bitcoin_rpc.getnewaddress()

        # make sure we have a peer
        ensure_peer_connected(self.alice, self.bob)

        # make sure all channels closed otherwise disconnect will fail
        close_all_channels(self.alice)
        self.bitcoin_rpc.generatetoaddress(3, bitcoin_address)
        time.sleep(SLEEP_TIME)

        # now disconnect all peers
        for peer in self.alice.list_peers():
            self.alice.disconnect_peer(pub_key=peer.pub_key)
            time.sleep(SLEEP_TIME)
        self.bitcoin_rpc.generatetoaddress(3, bitcoin_address)
        time.sleep(SLEEP_TIME)
        self.assertEqual(0, len(self.alice.list_peers()))

    def test_connect(self):

        # close any open channels:
        close_all_channels(self.alice)
        self.bitcoin_rpc.generatetoaddress(3, BITCOIN_ADDR)
        time.sleep(SLEEP_TIME)

        # check we are fully disconnected from peer before proceeding
        disconnect_all_peers(self.alice)
        time.sleep(SLEEP_TIME)

        # now test the connect
        self.alice.connect_peer(addr=self.bob.lightning_addr)
        self.bitcoin_rpc.generatetoaddress(3, BITCOIN_ADDR)
        time.sleep(SLEEP_TIME)
        self.assertEqual(1, len(self.alice.list_peers()))
        self.assertEqual(self.alice.list_peers()[0].pub_key, self.bob.pub_key)

    def test_list_peers(self):

        # make sure we are connected to one peer
        ensure_peer_connected(self.alice, self.bob)

        # Test length with connected peer
        self.assertGreater(len(self.alice.list_peers()), 0)

        # close and active channels before disconnect
        close_all_channels(self.alice)
        self.bitcoin_rpc.generatetoaddress(3, BITCOIN_ADDR)
        time.sleep(SLEEP_TIME)

        # disconnect
        disconnect_all_peers(self.alice)
        time.sleep(SLEEP_TIME)

        # test after disconnect
        self.assertEqual(0, len(self.alice.list_peers()))

    def test_get_info(self):
        self.assertIsInstance(self.alice.get_info(), rpc_pb2.GetInfoResponse)

    def test_pending_channels(self):
        self.assertIsInstance(self.alice.pending_channels(), rpc_pb2.PendingChannelsResponse)

    def test_list_channels(self):
        # self.assertTrue(self.test_connect())
        # TODO: open a channel
        # self.assertGreater(len(self.alice.list_channels()), 0)
        pass

    def test_closed_channels(self):
        # TODO: open a channel
        #   ... then close it ...
        # self.assertGreater(len(self.alice.closed_channels()), 0)
        pass

    def test_open_channel_sync(self):

        # make sure we are connected
        ensure_peer_connected(self.alice, self.bob)

        start_channels = len(self.alice.list_channels())
        self.assertIsInstance(self.alice.open_channel_sync(local_funding_amount=500_000,
                                                           node_pubkey_string=self.bob.pub_key),
                              rpc_pb2.ChannelPoint)
        self.bitcoin_rpc.generatetoaddress(3, BITCOIN_ADDR)
        time.sleep(SLEEP_TIME)
        end_channels = len(self.alice.list_channels())

        self.assertGreater(end_channels, start_channels)

    def test_open_channel(self):
        pass

    def test_close_channel(self):
        # setup
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        self.assertGreater(len(self.alice.list_channels()), 0)

        # close all active channels
        self.alice.close_all_channels()
        self.bitcoin_rpc.generatetoaddress(3, BITCOIN_ADDR)
        time.sleep(SLEEP_TIME)

        self.assertEqual(0, len(self.alice.list_channels()))

    def test_abandon_channel(self):
        # this is a development function only and does not need test
        pass

    def test_send_payment(self):
        pass

    def test_send_payment_sync(self):
        # setup
        inv_amt = 10000
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        # test payment_request
        payment_request = self.bob.add_invoice(value=inv_amt).payment_request
        start_len = len(self.alice.list_payments().payments)
        self.assertIsInstance(self.alice.send_payment_sync(payment_request=payment_request),
                              rpc_pb2.SendResponse)
        time.sleep(SLEEP_TIME)
        end_len = len(self.alice.list_payments().payments)
        self.assertGreater(end_len, start_len)

        # test manual request
        invoice = self.bob.add_invoice(value=inv_amt)
        start_len = len(self.alice.list_payments().payments)
        self.assertIsInstance(self.alice.send_payment_sync(dest_string=self.bob.pub_key,
                                                           amt=inv_amt,
                                                           payment_hash=invoice.r_hash,
                                                           final_cltv_delta=144),
                              rpc_pb2.SendResponse)
        time.sleep(SLEEP_TIME)
        end_len = len(self.alice.list_payments().payments)
        self.assertGreater(end_len, start_len)

    def test_send_to_route(self):
        pass

    def test_send_to_route_sync(self):
        pass

    def test_add_invoice(self):
        # setup
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)
        channel_0_balance = self.alice.list_channels()[0].local_balance

        # test valid
        start_index = self.alice.list_invoices().invoices[0].add_index
        self.assertIsInstance(self.alice.add_invoice(memo='test',
                                                     value=channel_0_balance // 2,
                                                     expiry=3600),
                              rpc_pb2.AddInvoiceResponse)
        end_index = self.alice.list_invoices().invoices[0].add_index
        time.sleep(SLEEP_TIME)
        self.assertGreater(end_index, start_index)

        # test invalid
        start_index = self.alice.list_invoices().invoices[0].add_index
        self.assertRaises(grpc.RpcError,
                          lambda:
                          self.alice.add_invoice(memo='test',
                                                 value=100_000_000,
                                                 expiry=3600)
                          )

        end_index = self.alice.list_invoices().invoices[0].add_index
        self.assertEqual(end_index, start_index)

    def test_list_invoices(self):
        self.assertIsInstance(self.alice.list_invoices(),
                              rpc_pb2.ListInvoiceResponse)

    def test_lookup_invoice(self):
        test_invoice = self.alice.list_invoices().invoices[0]

        self.assertIsInstance(self.alice.lookup_invoice(r_hash=test_invoice.r_hash),
                              rpc_pb2.Invoice)

    def test_subscribe_invoices(self):
        self.assertIsInstance(self.alice.subscribe_invoices(),
                              grpc._channel._Rendezvous)

    def test_decode_pay_req(self):
        inv_value = 15000
        expiry = 3600
        cltv_expiry = 144
        invoice = self.bob.add_invoice(value=inv_value, expiry=expiry,
                                       cltv_expiry=cltv_expiry)
        decoded_inv = self.alice.decode_pay_req(pay_req=invoice.payment_request)

        self.assertEqual(invoice.r_hash, bytes.fromhex(decoded_inv.payment_hash))
        self.assertEqual(self.bob.pub_key, decoded_inv.destination)
        self.assertEqual(inv_value, decoded_inv.num_satoshis)
        self.assertEqual(expiry, decoded_inv.expiry)
        self.assertEqual(cltv_expiry, decoded_inv.cltv_expiry)

    def test_list_payments(self):
        self.assertIsInstance(self.alice.list_payments(), rpc_pb2.ListPaymentsResponse)

    def test_z_delete_all_payments(self):
        # this will delete your payment history -- be careful
        # pass

        start_len = len(self.alice.list_payments().payments)
        if start_len == 0:
            ensure_peer_connected(self.alice, self.bob)
            ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)
            invoice = self.bob.add_invoice(value=5000)
            self.alice.pay_invoice(payment_request=invoice.payment_request)

        self.assertGreater(start_len, 0)

        self.assertIsInstance(self.alice.delete_all_payments(),
                              rpc_pb2.DeleteAllPaymentsResponse)
        time.sleep(SLEEP_TIME)
        end_len = len(self.alice.list_payments().payments)

        self.assertEqual(end_len, 0)

    def test_describe_graph(self):
        self.assertIsInstance(self.alice.describe_graph(), rpc_pb2.ChannelGraph)

    def test_get_chan_info(self):
        if len(self.alice.list_channels()) == 0:
            ensure_peer_connected(self.alice, self.bob)
            ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        chan_id = self.alice.list_channels()[0].chan_id
        self.assertIsInstance(self.alice.get_chan_info(chan_id=chan_id),
                              rpc_pb2.ChannelEdge)

    def test_subscribe_channel_events(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)
        results = []

        subscription = self.alice.subscribe_channel_events()
        self.assertIsInstance(subscription, grpc._channel._Rendezvous)

        self.alice.open_channel_sync(local_funding_amount=500_000,
                                     node_pubkey_string=self.bob.pub_key)
        self.bitcoin_rpc.generatetoaddress(3, BITCOIN_ADDR)
        time.sleep(SLEEP_TIME)
        results.append(subscription.next())
        self.assertGreater(len(results), 0)

    def test_get_node_info(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        self.assertIsInstance(self.alice.get_node_info(pub_key=self.bob.pub_key),
                              rpc_pb2.NodeInfo)

    def test_query_routes(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        self.assertIsInstance(self.alice.query_routes(pub_key=self.bob.pub_key,
                                                      amt=10000,
                                                      num_routes=1),
                              rpc_pb2.QueryRoutesResponse)

    def test_network_info(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        self.assertIsInstance(self.alice.get_network_info(), rpc_pb2.NetworkInfo)

    def test_stop_daemon(self):
        pass

    def test_subscribe_channel_graph(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)
        results = []

        subscription = self.alice.subscribe_channel_graph()
        self.assertIsInstance(subscription, grpc._channel._Rendezvous)

    def test_debug_level(self):
        self.assertIsInstance(self.alice.debug_level(level_spec='off'),
                              rpc_pb2.DebugLevelResponse)

    def test_fee_report(self):
        self.assertIsInstance(self.alice.fee_report(), rpc_pb2.FeeReportResponse)

    def test_update_channel_policy(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        # testing global policy setting
        self.assertIsInstance(self.alice.update_channel_policy(base_fee_msat=1000,
                                                               fee_rate=1,
                                                               time_lock_delta=144),
                              rpc_pb2.PolicyUpdateResponse)

        # test single channel
        channel_point = self.alice.list_channels()[0].channel_point
        self.assertIsInstance(self.alice.update_channel_policy(base_fee_msat=1000,
                                                               fee_rate=1,
                                                               time_lock_delta=144,
                                                               chan_point=channel_point),
                              rpc_pb2.PolicyUpdateResponse)

    def test_forwarding_history(self):
        ensure_peer_connected(self.alice, self.bob)
        ensure_channel_open(self.alice, self.bob, self.bitcoin_rpc, BITCOIN_ADDR)

        self.assertIsInstance(self.alice.forwarding_history(),
                              rpc_pb2.ForwardingHistoryResponse)
