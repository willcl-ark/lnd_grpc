import sys
import time
import threading
import queue
from hashlib import sha256
from secrets import token_bytes

import grpc

from lnd_grpc.protos import invoices_pb2 as invoices_pb2, rpc_pb2
from loop_rpc.protos import loop_client_pb2
from test_utils.fixtures import *
from test_utils.lnd import LndNode

impls = [LndNode]

if TEST_DEBUG:
    logging.basicConfig(level=logging.DEBUG,
                        format='%(name)-12s %(message)s',
                        stream=sys.stdout)
logging.info("Tests running in '%s'", TEST_DIR)

FUND_AMT = 10 ** 7
SEND_AMT = 10 ** 3


def get_updates(_queue):
    """
    Get all available updates from a queue.Queue() instance and return them as a list
    """
    _list = []
    while not _queue.empty():
        _list.append(_queue.get())
    return _list


def transact_and_mine(btc):
    """
    Generate some transactions and blocks.
    To make bitcoind's `estimatesmartfee` succeeded.
    """
    addr = btc.rpc.getnewaddress()
    for i in range(10):
        for j in range(10):
            txid = btc.rpc.sendtoaddress(addr, 0.5)
        btc.rpc.generate(1)


def wait_for(success, timeout=30, interval=0.25):
    start_time = time.time()
    while not success() and time.time() < start_time + timeout:
        time.sleep(interval)
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)


def wait_for_bool(success, timeout=30, interval=0.25):
    start_time = time.time()
    while not success and time.time() < start_time + timeout:
        time.sleep(interval)
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)

def sync_blockheight(btc, nodes):
    """
    Sync blockheight of nodes by checking logs until timeout
    """
    info = btc.rpc.getblockchaininfo()
    blocks = info['blocks']

    for n in nodes:
        wait_for(lambda: n.get_info().block_height == blocks, interval=1)
    time.sleep(0.25)


def generate_until(btc, success, blocks=30, interval=1):
    """
    Generate new blocks until `success` returns true.

    Mainly used to wait for transactions to confirm since they might
    be delayed and we don't want to add a long waiting time to all
    tests just because some are slow.
    """
    for i in range(blocks):
        time.sleep(interval)
        if success():
            return
        btc.rpc.generate(1)
    time.sleep(interval)
    if not success():
        raise ValueError("Generated %d blocks, but still no success", blocks)


def gen_and_sync_lnd(bitcoind, nodes):
    """
    generate a few blocks and wait for lnd nodes to sync
    """
    bitcoind.rpc.generate(3)
    sync_blockheight(bitcoind, nodes=nodes)
    for node in nodes:
        wait_for(lambda: node.get_info().synced_to_chain, interval=0.25)
    time.sleep(0.25)


def close_all_channels(bitcoind, nodes):
    """
    Recursively close each channel for each node in the list of nodes passed in and assert
    """
    gen_and_sync_lnd(bitcoind, nodes)
    for node in nodes:
        for channel in node.list_channels():
            channel_point = channel.channel_point
            node.close_channel(channel_point=channel_point).__next__()
        gen_and_sync_lnd(bitcoind, nodes)
        assert not node.list_channels()
    gen_and_sync_lnd(bitcoind, nodes)


def disconnect_all_peers(bitcoind, nodes):
    """
    Recursively disconnect each peer from each node in the list of nodes passed in and assert
    """
    gen_and_sync_lnd(bitcoind, nodes)
    for node in nodes:
        peers = [p.pub_key for p in node.list_peers()]
        for peer in peers:
            node.disconnect_peer(pub_key=peer)
            wait_for(lambda: peer not in node.list_peers(), timeout=5)
            assert peer not in [p.pub_key for p in node.list_peers()]
    gen_and_sync_lnd(bitcoind, nodes)


def get_addresses(node, response='str'):
    p2wkh_address = node.new_address(address_type='p2wkh')
    np2wkh_address = node.new_address(address_type='np2wkh')
    if response == 'str':
        return p2wkh_address.address, np2wkh_address.address
    return p2wkh_address, np2wkh_address


def setup_nodes(bitcoind, nodes):
    """
    Break down all nodes, open fresh channels between them with half the balance pushed remotely
    and assert
    :return: the setup nodes
    """
    # Needed by lnd in order to have at least one block in the last 2 hours
    bitcoind.rpc.generate(1)

    # First break down nodes. This avoids situations where a test fails and breakdown is not called
    break_down_nodes(bitcoind=bitcoind, nodes=nodes)

    # setup requested nodes and create a single channel from one to the next
    # capacity in one direction only (alphabetical)
    for i, node in enumerate(nodes):
        if i + 1 == len(nodes):
            break
        nodes[i].connect(str(nodes[i + 1].id() + '@localhost:' +
                             str(nodes[i + 1].daemon.port)), perm=1)
        wait_for(lambda: nodes[i].list_peers(), interval=0.25)
        wait_for(lambda: nodes[i + 1].list_peers(), interval=0.25)

        nodes[i].add_funds(bitcoind, 1)
        gen_and_sync_lnd(bitcoind, [nodes[i], nodes[i + 1]])
        nodes[i].open_channel_sync(node_pubkey_string=nodes[i + 1].id(),
                                   local_funding_amount=FUND_AMT,
                                   push_sat=int(FUND_AMT / 2))
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [nodes[i], nodes[i + 1]])

        assert confirm_channel(bitcoind, nodes[i], nodes[i + 1])
    return nodes


def break_down_nodes(bitcoind, nodes):
    close_all_channels(bitcoind, nodes)
    disconnect_all_peers(bitcoind, nodes)


def confirm_channel(bitcoind, n1, n2):
    """
    Confirm that a channel is open between two nodes
    """
    assert n1.id() in [p.pub_key for p in n2.list_peers()]
    assert n2.id() in [p.pub_key for p in n1.list_peers()]
    for i in range(10):
        time.sleep(0.5)
        if n1.check_channel(n2) and n2.check_channel(n1):
            return True
        bhash = bitcoind.rpc.generate(1)[0]
        n1.block_sync(bhash)
        n2.block_sync(bhash)

    # Last ditch attempt
    return n1.check_channel(n2) and n2.check_channel(n1)


# def idfn(impls):
#     """
#     Not used currently
#     """
#     return "_".join([i.displayName for i in impls])


def wipe_channels_from_disk(node, network='regtest'):
    """
    used to test channel backups
    """
    _channel_backup = node.lnd_dir + f'chain/bitcoin/{network}/channel.backup'
    _channel_db = node.lnd_dir + f'graph/{network}/channel.db'
    assert os.path.exists(_channel_backup)
    assert os.path.exists(_channel_db)
    os.remove(_channel_backup)
    os.remove(_channel_db)
    assert not os.path.exists(_channel_backup)
    assert not os.path.exists(_channel_db)


def random_32_byte_hash():
    """
    Can generate an invoice preimage and corresponding payment hash
    :return: 32 byte sha256 hash digest, 32 byte preimage
    """
    preimage = token_bytes(32)
    _hash = sha256(preimage)
    return _hash.digest(), preimage


#########
# Tests #
#########


class TestNonInteractiveLightning:
    """
    Non-interactive tests will share a common lnd instance because test passes/failures will not
    impact future tests.
    """

    def test_start(self, bitcoind, alice):
        assert alice.get_info()
        sync_blockheight(bitcoind, [alice])

    def test_wallet_balance(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.get_info(), rpc_pb2.GetInfoResponse)
        pytest.raises(TypeError, alice.wallet_balance(), 'please')

    def test_channel_balance(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.channel_balance(), rpc_pb2.ChannelBalanceResponse)
        pytest.raises(TypeError, alice.channel_balance(), 'please')

    def test_get_transactions(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.get_transactions(), rpc_pb2.TransactionDetails)
        pytest.raises(TypeError, alice.get_transactions(), 'please')

    def test_send_coins(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        alice.add_funds(alice.bitcoin, 1)
        p2wkh_address, np2wkh_address = get_addresses(alice)

        # test passes
        send1 = alice.send_coins(addr=p2wkh_address, amount=100000)
        alice.bitcoin.rpc.generate(1)
        time.sleep(0.5)
        send2 = alice.send_coins(addr=np2wkh_address, amount=100000)

        assert isinstance(send1, rpc_pb2.SendCoinsResponse)
        assert isinstance(send2, rpc_pb2.SendCoinsResponse)

        # test failures
        pytest.raises(grpc.RpcError, lambda: alice.send_coins(alice.new_address(
                address_type='p2wkh').address, amount=100000 * -1))
        pytest.raises(grpc.RpcError, lambda: alice.send_coins(alice.new_address(
                address_type='p2wkh').address, amount=1000000000000000))

    def test_send_many(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        alice.add_funds(alice.bitcoin, 1)
        p2wkh_address, np2wkh_address = get_addresses(alice)
        send_dict = {p2wkh_address: 100000,
                     np2wkh_address: 100000}

        send = alice.send_many(addr_to_amount=send_dict)
        alice.bitcoin.rpc.generate(1)
        time.sleep(0.5)
        assert isinstance(send, rpc_pb2.SendManyResponse)

    def test_list_unspent(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        alice.add_funds(alice.bitcoin, 1)
        assert isinstance(alice.list_unspent(0, 1000), rpc_pb2.ListUnspentResponse)

    def test_subscribe_transactions(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        subscription = alice.subscribe_transactions()
        alice.add_funds(alice.bitcoin, 1)
        assert isinstance(subscription, grpc._channel._Rendezvous)
        assert isinstance(subscription.__next__(), rpc_pb2.Transaction)

        # gen_and_sync_lnd(alice.bitcoin, [alice])
        # transaction_updates = queue.LifoQueue()
        #
        # def sub_transactions():
        #     try:
        #         for response in alice.subscribe_transactions():
        #             transaction_updates.put(response)
        #     except StopIteration:
        #         pass
        #
        # alice_sub = threading.Thread(target=sub_transactions(), daemon=True)
        # alice_sub.start()
        # time.sleep(1)
        # while not alice_sub.is_alive():
        #     time.sleep(0.1)
        # alice.add_funds(alice.bitcoin, 1)
        #
        # assert any(isinstance(update) == rpc_pb2.Transaction for update in get_updates(transaction_updates))

    def test_new_address(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        p2wkh_address, np2wkh_address = get_addresses(alice, 'response')
        assert isinstance(p2wkh_address, rpc_pb2.NewAddressResponse)
        assert isinstance(np2wkh_address, rpc_pb2.NewAddressResponse)

    def test_sign_verify_message(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        message = 'Test message to sign and verify.'
        signature = alice.sign_message(message)
        assert isinstance(signature, rpc_pb2.SignMessageResponse)
        verified_message = alice.verify_message(message, signature.signature)
        assert isinstance(verified_message, rpc_pb2.VerifyMessageResponse)

    def test_get_info(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.get_info(), rpc_pb2.GetInfoResponse)

    def test_pending_channels(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.pending_channels(), rpc_pb2.PendingChannelsResponse)

    # Skipping list_channels and closed_channels as we don't return their responses directly

    def test_add_invoice(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        invoice = alice.add_invoice(value=SEND_AMT)
        assert isinstance(invoice, rpc_pb2.AddInvoiceResponse)

    def test_list_invoices(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.list_invoices(), rpc_pb2.ListInvoiceResponse)

    def test_lookup_invoice(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        payment_hash = alice.add_invoice(value=SEND_AMT).r_hash
        assert isinstance(alice.lookup_invoice(r_hash=payment_hash), rpc_pb2.Invoice)

    def test_subscribe_invoices(self, alice):
        """
        Invoice subscription run as a thread
        """
        gen_and_sync_lnd(alice.bitcoin, [alice])
        invoice_updates = queue.LifoQueue()

        def sub_invoices():
            try:
                for response in alice.subscribe_invoices():
                    invoice_updates.put(response)
            except grpc._channel._Rendezvous:
                pass

        alice_sub = threading.Thread(target=sub_invoices, daemon=True)
        alice_sub.start()
        time.sleep(1)
        while not alice_sub.is_alive():
            time.sleep(0.1)
        alice.add_invoice(value=SEND_AMT)
        alice.daemon.wait_for_log('AddIndex')
        time.sleep(0.1)

        assert any(isinstance(update, rpc_pb2.Invoice) for update in get_updates(invoice_updates))

    def test_decode_payment_request(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        pay_req = alice.add_invoice(value=SEND_AMT).payment_request
        decoded_req = alice.decode_pay_req(pay_req=pay_req)
        assert isinstance(decoded_req, rpc_pb2.PayReq)

    def test_list_payments(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.list_payments(), rpc_pb2.ListPaymentsResponse)

    def test_delete_all_payments(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.delete_all_payments(), rpc_pb2.DeleteAllPaymentsResponse)

    def test_describe_graph(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.describe_graph(), rpc_pb2.ChannelGraph)

    # Skipping get_chan_info, subscribe_chan_events, get_alice_info, query_routes

    def test_get_network_info(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.get_network_info(), rpc_pb2.NetworkInfo)

    @pytest.mark.skipif(TRAVIS is True, reason="Travis doesn't like this one. Possibly a race"
                                               "condition not worth debugging")
    def test_stop_daemon(self, node_factory):
        node = node_factory.get_node(implementation=LndNode, node_id='test_stop_node')
        node.daemon.wait_for_log('Server listening on')
        node.stop_daemon()
        # use is_in_log instead of wait_for_log as node daemon should be shutdown
        node.daemon.is_in_log('Shutdown complete')
        time.sleep(1)
        with pytest.raises(grpc.RpcError):
            node.get_info()

    def test_debug_level(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.debug_level(level_spec='warn'), rpc_pb2.DebugLevelResponse)

    def test_fee_report(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.fee_report(), rpc_pb2.FeeReportResponse)

    def test_forwarding_history(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert isinstance(alice.forwarding_history(), rpc_pb2.ForwardingHistoryResponse)

    def test_lightning_stub(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        original_stub = alice.lightning_stub
        # not simulation of actual failure, but failure in the form that should be detected by
        # connectivity event logger
        alice.connection_status_change = True
        # make a call to stimulate stub regeneration
        alice.get_info()
        new_stub = alice.lightning_stub
        assert original_stub != new_stub


class TestInteractiveLightning:

    def test_peer_connection(self, bob, carol, dave, bitcoind):
        # Needed by lnd in order to have at least one block in the last 2 hours
        bitcoind.rpc.generate(1)

        # connection tests
        connection1 = bob.connect(str(carol.id() + '@localhost:' + str(carol.daemon.port)))

        wait_for(lambda: bob.list_peers(), timeout=5)
        wait_for(lambda: carol.list_peers(), timeout=5)

        # check bob connected to carol using connect() and list_peers()
        assert isinstance(connection1, rpc_pb2.ConnectPeerResponse)
        assert bob.id() in [p.pub_key for p in carol.list_peers()]
        assert carol.id() in [p.pub_key for p in bob.list_peers()]

        dave_ln_addr = dave.lightning_address(pubkey=dave.id(),
                                              host='localhost:' + str(dave.daemon.port))
        carol.connect_peer(dave_ln_addr)

        wait_for(lambda: carol.list_peers(), timeout=5)
        wait_for(lambda: dave.list_peers(), timeout=5)

        # check carol connected to dave using connect() and list_peers()
        assert carol.id() in [p.pub_key for p in dave.list_peers()]
        assert dave.id() in [p.pub_key for p in carol.list_peers()]

        bob.bitcoin.rpc.generate(1)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        # Disconnection tests
        bob.disconnect_peer(pub_key=str(carol.id()))

        time.sleep(0.25)

        # check bob not connected to carol using connect() and list_peers()
        assert bob.id() not in [p.pub_key for p in carol.list_peers()]
        assert carol.id() not in [p.pub_key for p in bob.list_peers()]

        carol.disconnect_peer(dave.id())

        wait_for(lambda: not carol.list_peers(), timeout=5)
        wait_for(lambda: not dave.list_peers(), timeout=5)

        # check carol not connected to dave using connect_peer() and list_peers()
        assert carol.id() not in [p.pub_key for p in dave.list_peers()]
        assert dave.id() not in [p.pub_key for p in carol.list_peers()]

    def test_open_channel_sync(self, bob, carol, bitcoind):
        # Needed by lnd in order to have at least one block in the last 2 hours
        bitcoind.rpc.generate(1)

        bob.connect(str(carol.id() + '@localhost:' + str(carol.daemon.port)), perm=1)

        wait_for(lambda: bob.list_peers(), interval=1)
        wait_for(lambda: carol.list_peers(), interval=1)

        bob.add_funds(bitcoind, 1)
        gen_and_sync_lnd(bitcoind, [bob, carol])
        bob.open_channel_sync(node_pubkey_string=carol.id(),
                              local_funding_amount=FUND_AMT)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        assert confirm_channel(bitcoind, bob, carol)

        assert (bob.check_channel(carol))
        assert (carol.check_channel(bob))

    def test_open_channel(self, bob, carol, bitcoind):
        # Needed by lnd in order to have at least one block in the last 2 hours
        bitcoind.rpc.generate(1)
        break_down_nodes(bitcoind, nodes=[bob, carol])

        bob.connect(str(carol.id() + '@localhost:' + str(carol.daemon.port)), perm=1)

        wait_for(lambda: bob.list_peers(), interval=0.5)
        wait_for(lambda: carol.list_peers(), interval=0.5)

        bob.add_funds(bitcoind, 1)
        gen_and_sync_lnd(bitcoind, [bob, carol])
        bob.open_channel(node_pubkey_string=carol.id(),
                         local_funding_amount=FUND_AMT).__next__()
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        assert confirm_channel(bitcoind, bob, carol)

        assert (bob.check_channel(carol))
        assert (carol.check_channel(bob))

    def test_close_channel(self, bob, carol, bitcoind):
        bob, carol = setup_nodes(bitcoind, [bob, carol])

        channel_point = bob.list_channels()[0].channel_point
        bob.close_channel(channel_point=channel_point).__next__()
        bitcoind.rpc.generate(6)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        assert bob.check_channel(carol) is False
        assert carol.check_channel(bob) is False

    def test_send_payment_sync(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])

        # test payment request method
        invoice = carol.add_invoice(value=SEND_AMT)
        bob.send_payment_sync(payment_request=invoice.payment_request)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash = carol.decode_pay_req(invoice.payment_request).payment_hash
        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

        # test manually specified request
        invoice2 = carol.add_invoice(value=SEND_AMT)
        bob.send_payment_sync(dest_string=carol.id(), amt=SEND_AMT, payment_hash=invoice2.r_hash,
                              final_cltv_delta=144)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash2 = carol.decode_pay_req(invoice2.payment_request).payment_hash
        assert payment_hash2 in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

        # test sending any amount to an invoice which requested 0
        invoice3 = carol.add_invoice(value=0)
        bob.send_payment_sync(payment_request=invoice3.payment_request, amt=SEND_AMT)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash = carol.decode_pay_req(
            invoice3.payment_request).payment_hash
        assert payment_hash in [p.payment_hash for p in
                                bob.list_payments().payments]
        inv_paid = carol.lookup_invoice(r_hash_str=payment_hash)
        assert inv_paid.settled is True
        assert inv_paid.amt_paid_sat == SEND_AMT

    def test_send_payment(self, bitcoind, bob, carol):
        # TODO: remove try/except hack for curve generation
        bob, carol = setup_nodes(bitcoind, [bob, carol])

        # test payment request method
        invoice = carol.add_invoice(value=SEND_AMT)
        try:
            bob.send_payment(payment_request=invoice.payment_request).__next__()
        except StopIteration:
            pass
        bob.daemon.wait_for_log('Closed completed SETTLE circuit', timeout=60)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash = carol.decode_pay_req(invoice.payment_request).payment_hash
        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

        # test manually specified request
        invoice2 = carol.add_invoice(value=SEND_AMT)
        try:
            bob.send_payment(dest_string=carol.id(), amt=SEND_AMT, payment_hash=invoice2.r_hash,
                             final_cltv_delta=144).__next__()
        except StopIteration:
            pass
        bob.daemon.wait_for_log('Closed completed SETTLE circuit', timeout=60)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash2 = carol.decode_pay_req(invoice2.payment_request).payment_hash
        assert payment_hash2 in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

        # test sending different amount to invoice where 0 is requested
        invoice = carol.add_invoice(value=0)
        try:
            bob.send_payment(payment_request=invoice.payment_request, amt=SEND_AMT).__next__()
        except StopIteration:
            pass
        bob.daemon.wait_for_log('Closed completed SETTLE circuit', timeout=60)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash = carol.decode_pay_req(invoice.payment_request).payment_hash
        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        inv_paid = carol.lookup_invoice(r_hash_str=payment_hash)
        assert inv_paid.settled is True
        assert inv_paid.amt_paid_sat == SEND_AMT

    def test_send_to_route_sync(self, bitcoind, bob, carol, dave):
        bob, carol, dave = setup_nodes(bitcoind, [bob, carol, dave])
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        invoice = dave.add_invoice(value=SEND_AMT)
        routes = bob.query_routes(pub_key=dave.id(),
                                  amt=SEND_AMT,
                                  num_routes=1,
                                  final_cltv_delta=144)
        bob.send_to_route_sync(payment_hash=invoice.r_hash,
                               routes=routes)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        payment_hash = dave.decode_pay_req(invoice.payment_request).payment_hash

        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert dave.lookup_invoice(r_hash_str=payment_hash).settled is True

    def test_send_to_route(self, bitcoind, bob, carol, dave):
        bob, carol, dave = setup_nodes(bitcoind, [bob, carol, dave])
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        invoice = dave.add_invoice(value=SEND_AMT)
        routes = bob.query_routes(pub_key=dave.id(),
                                  amt=SEND_AMT,
                                  num_routes=1,
                                  final_cltv_delta=144)
        try:
            bob.send_to_route(invoice=invoice, routes=routes).__next__()
        except StopIteration:
            pass
        bob.daemon.wait_for_log('Closed completed SETTLE circuit', timeout=60)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        payment_hash = dave.decode_pay_req(invoice.payment_request).payment_hash

        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert dave.lookup_invoice(r_hash_str=payment_hash).settled is True

    def test_subscribe_channel_events(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        gen_and_sync_lnd(bitcoind, [bob, carol])
        chan_updates = queue.LifoQueue()

        def sub_channel_events():
            try:
                for response in bob.subscribe_channel_events():
                    chan_updates.put(response)
            except grpc._channel._Rendezvous:
                pass

        bob_sub = threading.Thread(target=sub_channel_events, daemon=True)
        bob_sub.start()
        time.sleep(1)
        while not bob_sub.is_alive():
            time.sleep(0.1)
        channel_point = bob.list_channels()[0].channel_point

        bob.close_channel(channel_point=channel_point).__next__()
        bitcoind.rpc.generate(6)
        gen_and_sync_lnd(bitcoind, [bob, carol])
        assert any(update.closed_channel is not None for update in get_updates(chan_updates))

    def test_subscribe_channel_graph(self, bitcoind, bob, carol, dave):
        bob, carol, dave = setup_nodes(bitcoind, [bob, dave, carol])
        new_fee = 5555
        chan_updates = queue.LifoQueue()

        # make sure dave knows about all edges before the subscription is setup
        wait_for_bool(len(dave.describe_graph().edges) > 1)

        def sub_channel_graph():
            try:
                for response in dave.subscribe_channel_graph():
                    chan_updates.put(response)
            except grpc._channel._Rendezvous:
                pass

        dave_sub = threading.Thread(target=sub_channel_graph, name='dave_channel_graph_sub',
                                    daemon=True)
        dave_sub.start()
        while not dave_sub.is_alive():
            time.sleep(0.1)
        channel_point = bob.list_channels()[0].channel_point

        # test a channel close between two unrelated peers
        bob.close_channel(channel_point=channel_point).__next__()
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        assert any(update.closed_chans is not None for update in get_updates(chan_updates))

        # test a peer updating their fees
        carol.update_channel_policy(chan_point=None,
                                    base_fee_msat=new_fee,
                                    fee_rate=0.5555,
                                    time_lock_delta=9,
                                    is_global=True)
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        assert any(update.channel_updates[0].routing_policy.fee_base_msat == new_fee
                   for update in get_updates(chan_updates))

    def test_update_channel_policy(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        update = bob.update_channel_policy(chan_point=None,
                                           base_fee_msat=5555,
                                           fee_rate=0.5555,
                                           time_lock_delta=9,
                                           is_global=True)
        assert isinstance(update, rpc_pb2.PolicyUpdateResponse)


class TestChannelBackup:

    def test_export_verify_restore_multi(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        funding_txid, output_index = bob.list_channels()[0].channel_point.split(':')
        channel_point = bob.channel_point_generator(funding_txid=funding_txid,
                                                    output_index=output_index)

        all_backup = bob.export_all_channel_backups()
        assert isinstance(all_backup, rpc_pb2.ChanBackupSnapshot)
        # assert the multi_chan backup
        assert bob.verify_chan_backup(multi_chan_backup=all_backup.multi_chan_backup)

        bob.stop()
        wipe_channels_from_disk(bob)
        bob.start()

        assert not bob.list_channels()
        assert bob.restore_chan_backup(
                multi_chan_backup=all_backup.multi_chan_backup.multi_chan_backup)

        bob.daemon.wait_for_log('Inserting 1 SCB channel shells into DB')
        carol.daemon.wait_for_log('Broadcasting force close transaction')
        bitcoind.rpc.generate(6)
        bob.daemon.wait_for_log('Publishing sweep tx', timeout=120)
        bitcoind.rpc.generate(6)
        assert bob.daemon.wait_for_log('a contract has been fully resolved!', timeout=120)

    def test_export_verify_restore_single(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        funding_txid, output_index = bob.list_channels()[0].channel_point.split(':')
        channel_point = bob.channel_point_generator(funding_txid=funding_txid,
                                                    output_index=output_index)

        single_backup = bob.export_chan_backup(chan_point=channel_point)
        assert isinstance(single_backup, rpc_pb2.ChannelBackup)
        packed_backup = bob.pack_into_channelbackups(single_backup=single_backup)
        # assert the single_chan_backup
        assert bob.verify_chan_backup(single_chan_backups=packed_backup)

        bob.stop()
        wipe_channels_from_disk(bob)
        bob.start()

        assert not bob.list_channels()
        assert bob.restore_chan_backup(chan_backups=packed_backup)

        bob.daemon.wait_for_log('Inserting 1 SCB channel shells into DB')
        carol.daemon.wait_for_log('Broadcasting force close transaction')
        bitcoind.rpc.generate(6)
        bob.daemon.wait_for_log('Publishing sweep tx', timeout=120)
        bitcoind.rpc.generate(6)
        assert bob.daemon.wait_for_log('a contract has been fully resolved!', timeout=120)


class TestInvoices:

    def test_all_invoice(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        _hash, preimage = random_32_byte_hash()
        invoice_queue = queue.LifoQueue()
        invoice = carol.add_hold_invoice(memo='pytest hold invoice',
                                         hash=_hash,
                                         value=SEND_AMT)
        assert isinstance(invoice, invoices_pb2.AddHoldInvoiceResp)

        # thread functions
        def inv_sub_worker(_hash):
            try:
                for _response in carol.subscribe_single_invoice(_hash):
                    invoice_queue.put(_response)
            except grpc._channel._Rendezvous:
                pass

        def pay_hold_inv_worker(payment_request):
            try:
                bob.pay_invoice(payment_request=payment_request)
            except grpc._channel._Rendezvous:
                pass

        def settle_inv_worker(_preimage):
            try:
                carol.settle_invoice(preimage=_preimage)
            except grpc._channel._Rendezvous:
                pass

        # setup the threads
        inv_sub = threading.Thread(target=inv_sub_worker, name='inv_sub',
                                   args=[_hash, ], daemon=True)
        pay_inv = threading.Thread(target=pay_hold_inv_worker, args=[invoice.payment_request, ])
        settle_inv = threading.Thread(target=settle_inv_worker, args=[preimage, ])

        # start the threads
        inv_sub.start()
        # wait for subscription to start
        while not inv_sub.is_alive():
            time.sleep(0.1)
        pay_inv.start()
        carol.daemon.wait_for_log('htlc accepted')
        settle_inv.start()
        while settle_inv.is_alive():
            time.sleep(0.1)
        inv_sub.join(timeout=1)

        assert any(invoice.settled is True for invoice in get_updates(invoice_queue))


class TestLoop:

    @pytest.mark.skip(reason='waiting to configure loop swapserver')
    def test_loop_out_quote(self, bitcoind, alice, bob, loopd):
        """
        250000 satoshis is currently middle of range of allowed loop amounts
        """
        loop_amount = 250000
        alice, bob = setup_nodes(bitcoind, [alice, bob])
        if alice.daemon.invoice_rpc_active:
            quote = loopd.loop_out_quote(amt=loop_amount)
            assert quote is not None
            assert isinstance(quote, loop_client_pb2.QuoteResponse)
        else:
            logging.info("test_loop_out() skipped as invoice RPC not detected")

    @pytest.mark.skip(reason='waiting to configure loop swapserver')
    def test_loop_out_terms(self, bitcoind, alice, bob, loopd):
        alice, bob = setup_nodes(bitcoind, [alice, bob])
        if alice.daemon.invoice_rpc_active:
            terms = loopd.loop_out_terms()
            assert terms is not None
            assert isinstance(terms, loop_client_pb2.TermsResponse)
        else:
            logging.info("test_loop_out() skipped as invoice RPC not detected")
