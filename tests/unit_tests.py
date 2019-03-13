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

DEBUG_LEVEL = 'error'


def initialise_clients():
    alice = py_rpc.Client(lnd_dir=ALICE_LND_DIR,
                          network=ALICE_NETWORK,
                          grpc_host=ALICE_RPC_HOST,
                          grpc_port=ALICE_RPC_PORT,
                          macaroon_path=ALICE_MACAROON_PATH)
    alice.pub_key = alice.get_info().identity_pubkey
    alice.lightning_address = py_rpc.Client.lightning_address(
            pubkey=alice.pub_key,
            host=ALICE_HOST_ADDR)

    bob = py_rpc.Client(lnd_dir=BOB_LND_DIR,
                        network=BOB_NETWORK,
                        grpc_host=BOB_RPC_HOST,
                        grpc_port=BOB_RPC_PORT,
                        macaroon_path=BOB_MACAROON_PATH)
    bob.pub_key = bob.get_info().identity_pubkey
    bob.lightning_address = py_rpc.Client.lightning_address(
            pubkey=bob.pub_key,
            host=BOB_HOST_ADDR)

    bitcoin_rpc = bitcoin.rpc.RawProxy(service_port=BITCOIN_SERVICE_PORT,
                                       btc_conf_file=BITCOIN_CONF_FILE)

    return alice, bob, bitcoin_rpc


##################
# Test framework #
##################

class TestLightningStubResponses(unittest.TestCase):

    def test_aaa_assert_variables(self):
        self.assertIsInstance(alice, py_rpc.Client)
        self.assertIsInstance(alice.channel, grpc._channel.Channel)
        self.assertIsInstance(bob, py_rpc.Client)
        self.assertIsInstance(bitcoin_rpc, bitcoin.rpc.RawProxy)

    def test_wallet_balance(self):
        self.assertIsInstance(alice.wallet_balance(), rpc_pb2.WalletBalanceResponse)
        # lambda function prevents TypeError being raised before assert is run.
        self.assertRaises(TypeError, lambda: alice.wallet_balance('please'))

    def test_channel_balance(self):
        self.assertIsInstance(alice.channel_balance(), rpc_pb2.ChannelBalanceResponse)
        self.assertRaises(TypeError, lambda: alice.channel_balance('please'))

    def test_get_transactions(self):
        self.assertIsInstance(alice.get_transactions(), rpc_pb2.TransactionDetails)
        self.assertRaises(TypeError, lambda: alice.get_transactions('please'))

    def test_send_coins(self):
        response1 = alice.send_coins(alice.new_address(address_type='p2wkh').address, amount=100000)
        response2 = alice.send_coins(alice.new_address(address_type='np2wkh').address,
                                     amount=100000)
        self.assertIsInstance(response1, rpc_pb2.SendCoinsResponse)
        self.assertIsInstance(response2, rpc_pb2.SendCoinsResponse)
        # negative send
        self.assertRaises(grpc.RpcError,
                          lambda: alice.send_coins(alice.new_address(address_type='p2wkh').address,
                                                   amount=100000 * -1))
        # impossibly large send
        self.assertRaises(grpc.RpcError,
                          lambda: alice.send_coins(alice.new_address(address_type='p2wkh').address,
                                                   amount=1_000_000_000_000_000))

    def test_list_unspent(self):
        self.assertIsInstance(alice.list_unspent(0, 1000), rpc_pb2.ListUnspentResponse)

    def subscribe_transactions(self):
        self.assertIsInstance(alice.subscribe_transactions(), rpc_pb2.Transaction)

    def send_many(self):
        pass

    def test_new_address(self):
        self.address_p2wkh = alice.new_address(address_type='p2wkh')
        self.address_np2wkh = alice.new_address(address_type='np2wkh')
        self.assertIsInstance(self.address_p2wkh, rpc_pb2.NewAddressResponse)
        self.assertIsInstance(self.address_np2wkh, rpc_pb2.NewAddressResponse)
        self.assertRaises(TypeError, alice.new_address(address_type='segwit'))

    def test_sign_message(self):
        self.assertIsInstance(alice.sign_message(msg='test message content'),
                              rpc_pb2.SignMessageResponse)
        self.assertRaises(AttributeError,
                          lambda: alice.sign_message(msg=b'bytes message'))

    def test_verify_message(self):
        message = 'test message content'
        message_sig_true = alice.sign_message(msg=message).signature
        message_sig_false = message_sig_true + '1'
        self.assertTrue(alice.verify_message(msg=message, signature=message_sig_true).valid)
        self.assertFalse(alice.verify_message(msg=message, signature=message_sig_false).valid)

    def test_disconnect_peer(self):
        bitcoin_address = bitcoin_rpc.getnewaddress()

        # make sure all channels closed and peers are disconnected
        self.assertTrue(self.test_close_channel())

        # now disconnect
        tries = 0
        while len(alice.list_peers()) != 0 and tries < 10:
            for peer in alice.list_peers():
                alice.disconnect_peer(pub_key=peer.pub_key)
            time.sleep(0.1)
            bitcoin_rpc.generatetoaddress(3, bitcoin_address)
            time.sleep(0.1)
            tries += 1
        self.assertEqual(len(alice.list_peers()), 0)

        return True

    def test_connect(self):
        bitcoin_address = bitcoin_rpc.getnewaddress()

        # check we are fully disconnected from peer before proceeding
        self.assertTrue(self.test_disconnect_peer())

        # now test the connect
        alice.connect_peer(addr=bob.lightning_address)
        bitcoin_rpc.generatetoaddress(3, bitcoin_address)
        time.sleep(0.1)
        self.assertEqual(len(alice.list_peers()), 1)
        self.assertEqual(alice.list_peers()[0].pub_key, bob.pub_key)

        return True

    def test_list_peers(self):
        # self.assertIsInstance(rpc.list_peers(), RepeatedCompositeFieldContainer)
        pass

    def test_get_info(self):
        self.assertIsInstance(alice.get_info(), rpc_pb2.GetInfoResponse)

    def test_pending_channels(self):
        self.assertIsInstance(alice.pending_channels(), rpc_pb2.PendingChannelsResponse)

    def test_list_channels(self):
        self.assertTrue(self.test_connect())
        # TODO: open a channel
        # self.assertGreater(len(alice.list_channels()), 0)

    def test_closed_channels(self):
        # TODO: open a channel
        #   ... then close it ...
        # self.assertGreater(len(alice.closed_channels()), 0)
        pass

    def test_open_channel_sync(self):
        self.assertTrue(self.test_connect())
        self.assertIsInstance(alice.open_channel_sync(local_funding_amount=500_000,
                                                      node_pubkey_string=bob.pub_key),
                              rpc_pb2.ChannelPoint)

    def test_open_channel(self):
        pass

    def test_close_channel(self):
        bitcoin_address = bitcoin_rpc.getnewaddress()

        # close all active channels
        tries = 0
        while len(alice.list_channels()) != 0 and tries < 10:
            for channel in alice.list_channels():
                alice.close_channel(channel_point=channel.channel_point)
                time.sleep(0.1)
            # Mature any channel closes internally to lnd
            bitcoin_rpc.generatetoaddress(3, bitcoin_address)
            tries += 1
            time.sleep(0.1)

        # mature the channel closes on-chain
        bitcoin_rpc.generatetoaddress(145, bitcoin_address)
        self.assertEqual(len(alice.list_channels()), 0)
        return True


if __name__ == '__main__':
    alice, bob, bitcoin_rpc = initialise_clients()

    # set debug level to off for speed
    alice.debug_level(level_spec=DEBUG_LEVEL)
    bob.debug_level(level_spec=DEBUG_LEVEL)

    unittest.main()

    # reset debug level to info
    alice.debug_level(level_spec='info')
    bob.debug_level(level_spec='info')
