import sys
import time

import grpc

from lnd_grpc.protos import rpc_pb2
from loop_rpc.protos import loop_client_pb2
from test_utils.fixtures import *
from test_utils.lnd import LndNode

impls = [LndNode]

if TEST_DEBUG:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logging.info("Tests running in '%s'", TEST_DIR)


def transact_and_mine(btc):
    """ Generate some transactions and blocks.

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


def sync_blockheight(btc, nodes):
    info = btc.rpc.getblockchaininfo()
    blocks = info['blocks']

    # print("Waiting for %d nodes to blockheight %d" % (len(nodes), blocks))
    for n in nodes:
        wait_for(lambda: n.get_info().block_height == blocks, interval=1)
    time.sleep(0.25)


def generate_until(btc, success, blocks=30, interval=1):
    """Generate new blocks until `success` returns true.

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
    wait for lnd nodes to be synced
    """
    bitcoind.rpc.generate(3)
    sync_blockheight(bitcoind, nodes=nodes)
    for node in nodes:
        wait_for(lambda: node.get_info().synced_to_chain, interval=0.25)
    time.sleep(0.25)


def close_all_channels(bitcoind, nodes):
    gen_and_sync_lnd(bitcoind, nodes)
    for node in nodes:
        for channel in node.list_channels():
            channel_point = channel.channel_point
            node.close_channel(channel_point=channel_point).__next__()
        gen_and_sync_lnd(bitcoind, nodes)
        assert len(node.list_channels()) == 0
    gen_and_sync_lnd(bitcoind, nodes)


def disconnect_all_peers(bitcoind, nodes):
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
    else:
        return p2wkh_address, np2wkh_address


def setup_nodes(bitcoind, nodes):
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
                                   local_funding_amount=10 ** 7)
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [nodes[i], nodes[i + 1]])

        assert confirm_channel(bitcoind, nodes[i], nodes[i + 1])
    return nodes


def break_down_nodes(bitcoind, nodes):
    close_all_channels(bitcoind, nodes)

    disconnect_all_peers(bitcoind, nodes)


def confirm_channel(bitcoind, n1, n2):
    # print("Waiting for channel {} -> {} to confirm".format(n1.id(), n2.id()))
    assert n1.id() in [p.pub_key for p in n2.list_peers()]
    assert n2.id() in [p.pub_key for p in n1.list_peers()]
    for i in range(10):
        time.sleep(0.5)
        if n1.check_channel(n2) and n2.check_channel(n1):
            # print("Channel {} -> {} confirmed".format(n1.id(), n2.id()))
            return True
        bhash = bitcoind.rpc.generate(1)[0]
        n1.block_sync(bhash)
        n2.block_sync(bhash)

    # Last ditch attempt
    return n1.check_channel(n2) and n2.check_channel(n1)


def idfn(impls):
    return "_".join([i.displayName for i in impls])


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
        assert type(alice.get_info()) == rpc_pb2.GetInfoResponse
        pytest.raises(TypeError, alice.wallet_balance(), 'please')

    def test_channel_balance(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.channel_balance()) == rpc_pb2.ChannelBalanceResponse
        pytest.raises(TypeError, alice.channel_balance(), 'please')

    def test_get_transactions(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.get_transactions()) == rpc_pb2.TransactionDetails
        pytest.raises(TypeError, alice.get_transactions(), 'please')

    def test_send_coins(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        alice.add_funds(alice.bitcoin, 1)
        p2wkh_address, np2wkh_address = get_addresses(alice)

        send1 = alice.send_coins(addr=p2wkh_address, amount=100000)
        alice.bitcoin.rpc.generate(1)
        time.sleep(0.5)
        send2 = alice.send_coins(addr=np2wkh_address, amount=100000)

        assert type(send1) == rpc_pb2.SendCoinsResponse
        assert type(send2) == rpc_pb2.SendCoinsResponse
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
        assert type(send) == rpc_pb2.SendManyResponse

    def test_list_unspent(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        alice.add_funds(alice.bitcoin, 1)
        assert type(alice.list_unspent(0, 1000)) == rpc_pb2.ListUnspentResponse

    def test_subscribe_transactions(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        subscription = alice.subscribe_transactions()
        alice.add_funds(alice.bitcoin, 1)
        assert type(subscription) == grpc._channel._Rendezvous
        assert type(subscription.__next__()) == rpc_pb2.Transaction

    def test_new_address(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        p2wkh_address, np2wkh_address = get_addresses(alice, 'response')
        assert type(p2wkh_address) == rpc_pb2.NewAddressResponse
        assert type(np2wkh_address) == rpc_pb2.NewAddressResponse

    def test_sign_verify_message(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        message = 'Test message to sign and verify.'
        signature = alice.sign_message(message)
        assert type(signature) == rpc_pb2.SignMessageResponse
        verified_message = alice.verify_message(message, signature.signature)
        assert type(verified_message) == rpc_pb2.VerifyMessageResponse

    # Can't test response as we return response.peers in method.
    # def test_list_peers(self, alice):

    def test_get_info(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.get_info()) == rpc_pb2.GetInfoResponse

    def test_pending_channels(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.pending_channels()) == rpc_pb2.PendingChannelsResponse

    # Skipping list_channels and closed_channels as we don't return their responses directly

    def test_add_invoice(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        invoice = alice.add_invoice(value=500)
        assert type(invoice) == rpc_pb2.AddInvoiceResponse

    def test_list_invoices(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.list_invoices()) == rpc_pb2.ListInvoiceResponse

    def test_lookup_invoice(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        payment_hash = alice.add_invoice(value=500).r_hash
        assert type(alice.lookup_invoice(r_hash=payment_hash)) == rpc_pb2.Invoice

    def test_subscribe_invoices(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        subscription = alice.subscribe_invoices()
        alice.add_invoice(value=500)
        assert type(subscription) == grpc._channel._Rendezvous
        assert type(subscription.__next__()) == rpc_pb2.Invoice

    def test_decode_payment_request(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        pay_req = alice.add_invoice(value=500).payment_request
        decoded_req = alice.decode_pay_req(pay_req=pay_req)
        assert type(decoded_req) == rpc_pb2.PayReq

    def test_list_payments(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.list_payments()) == rpc_pb2.ListPaymentsResponse

    def test_delete_all_payments(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.delete_all_payments()) == rpc_pb2.DeleteAllPaymentsResponse

    def test_describe_graph(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.describe_graph()) == rpc_pb2.ChannelGraph

    # Skipping get_chan_info, subscribe_chan_events, get_alice_info, query_routes

    def test_get_network_info(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.get_network_info()) == rpc_pb2.NetworkInfo

    def test_stop_daemon(self, node_factory):
        node = node_factory.get_node(implementation=LndNode, node_id='test_stop_node')
        assert type(node.stop_daemon()) == rpc_pb2.StopResponse
        node.daemon.wait_for_log("Shutdown complete")
        with pytest.raises(grpc.RpcError):
            node.get_info()

    def test_debug_level(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.debug_level(level_spec='warn')) == rpc_pb2.DebugLevelResponse

    def test_fee_report(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.fee_report()) == rpc_pb2.FeeReportResponse

    def test_forwarding_history(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        assert type(alice.forwarding_history()) == rpc_pb2.ForwardingHistoryResponse

    def test_lightning_stub(self, alice):
        gen_and_sync_lnd(alice.bitcoin, [alice])
        original_stub = alice.lightning_stub
        stub1 = alice.lightning_stub
        assert original_stub == stub1
        # not simulation of actual failure, but failure that should be detected by
        # connectivity event logger
        alice.connection_status_change = True
        alice.get_info()
        stub2 = alice.lightning_stub
        assert original_stub != stub2


class TestInteractiveLightning:

    def test_peer_connection(self, bob, carol, dave, bitcoind):
        # Needed by lnd in order to have at least one block in the last 2 hours
        bitcoind.rpc.generate(1)
        """
        Connection tests
        """
        # print("Connecting {}@{}:{} -> {}@{}:{}".format(
        #         bob.id(), 'localhost', bob.daemon.port,
        #         carol.id(), 'localhost', carol.daemon.port))
        connection1 = bob.connect(str(carol.id() + '@localhost:' + str(carol.daemon.port)))

        wait_for(lambda: bob.list_peers(), timeout=5)
        wait_for(lambda: carol.list_peers(), timeout=5)

        # check bob connected to carol using connect() and list_peers()
        assert type(connection1) == rpc_pb2.ConnectPeerResponse
        assert bob.id() in [p.pub_key for p in carol.list_peers()]
        assert carol.id() in [p.pub_key for p in bob.list_peers()]

        # print("Connecting {}@{}:{} -> {}@{}:{}".format(
        #         carol.id(), 'localhost', carol.daemon.port,
        #         dave.id(), 'localhost', dave.daemon.port))
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

        """
        Disconnection tests
        """

        # print("Disconnecting {}@{}:{} from {}@{}:{}".format(
        #         bob.id(), 'localhost', bob.daemon.port,
        #         carol.id(), 'localhost', carol.daemon.port))
        bob.disconnect_peer(pub_key=str(carol.id()))

        time.sleep(0.25)

        # check bob not connected to carol using connect() and list_peers()
        assert bob.id() not in [p.pub_key for p in carol.list_peers()]
        assert carol.id() not in [p.pub_key for p in bob.list_peers()]

        # print("Disconnecting {}@{}:{} from {}@{}:{}".format(
        #         carol.id(), 'localhost', carol.daemon.port,
        #         dave.id(), 'localhost', dave.daemon.port))
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
                              local_funding_amount=10 ** 7)
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
        channel = bob.open_channel(node_pubkey_string=carol.id(),
                                   local_funding_amount=10 ** 7)
        print(channel.__next__())
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        assert confirm_channel(bitcoind, bob, carol)

        assert (bob.check_channel(carol))
        assert (carol.check_channel(bob))

    def test_close_channel(self, bob, carol, bitcoind):
        bob, carol = setup_nodes(bitcoind, [bob, carol])

        channel_point = bob.list_channels()[0].channel_point
        print(bob.close_channel(channel_point=channel_point).__next__())
        bitcoind.rpc.generate(6)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        assert bob.check_channel(carol) is False
        assert carol.check_channel(bob) is False

    def test_send_payment_sync(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        amount = 10000

        # test payment request method
        invoice = carol.add_invoice(value=amount)
        print(bob.send_payment_sync(payment_request=invoice.payment_request))
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash = carol.decode_pay_req(invoice.payment_request).payment_hash
        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

        # test manually specified request
        invoice2 = carol.add_invoice(value=amount)
        print(bob.send_payment_sync(dest_string=carol.id(),
                                    amt=amount,
                                    payment_hash=invoice2.r_hash,
                                    final_cltv_delta=144))
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash2 = carol.decode_pay_req(invoice2.payment_request).payment_hash
        assert payment_hash2 in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

    def test_send_payment(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        amount = 10000

        # test payment request method
        invoice = carol.add_invoice(value=amount)
        print(bob.send_payment(payment_request=invoice.payment_request).__next__())
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash = carol.decode_pay_req(invoice.payment_request).payment_hash
        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

        # test manually specified request
        invoice2 = carol.add_invoice(value=amount)
        print(bob.send_payment(dest_string=carol.id(),
                               amt=amount,
                               payment_hash=invoice2.r_hash,
                               final_cltv_delta=144).__next__())
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol])

        payment_hash2 = carol.decode_pay_req(invoice2.payment_request).payment_hash
        assert payment_hash2 in [p.payment_hash for p in bob.list_payments().payments]
        assert carol.lookup_invoice(r_hash_str=payment_hash).settled is True

    def test_send_to_route_sync(self, bitcoind, bob, carol, dave):
        bob, carol, dave = setup_nodes(bitcoind, [bob, carol, dave])
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        amount = 1000
        invoice = dave.add_invoice(value=amount)
        routes = bob.query_routes(pub_key=dave.id(),
                                  amt=amount,
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
        amount = 1000
        invoice = dave.add_invoice(value=amount)
        routes = bob.query_routes(pub_key=dave.id(),
                                  amt=amount,
                                  num_routes=1,
                                  final_cltv_delta=144)
        bob.send_to_route(invoice=invoice, routes=routes).__next__()
        bitcoind.rpc.generate(3)
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        payment_hash = dave.decode_pay_req(invoice.payment_request).payment_hash

        assert payment_hash in [p.payment_hash for p in bob.list_payments().payments]
        assert dave.lookup_invoice(r_hash_str=payment_hash).settled is True

    def test_subscribe_channel_events(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        gen_and_sync_lnd(bitcoind, [bob, carol])
        updates = []
        subscription = bob.subscribe_channel_events()
        channel_point = bob.list_channels()[0].channel_point

        bob.close_channel(channel_point=channel_point).__next__()
        bitcoind.rpc.generate(6)
        gen_and_sync_lnd(bitcoind, [bob, carol])
        updates.append(subscription.__next__())

        assert len(updates) > 0
        assert type(updates[0]) == rpc_pb2.ChannelEventUpdate

    def test_subscribe_channel_graph(self, bitcoind, bob, carol, dave):
        bob, carol, dave = setup_nodes(bitcoind, [bob, carol, dave])
        updates = []
        subscription = dave.subscribe_channel_graph()
        channel_point = bob.list_channels()[0].channel_point

        # test a channel close between two peers
        bob.close_channel(channel_point=channel_point).__next__()
        bitcoind.rpc.generate(6)
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        updates.append(subscription.__next__())
        assert len(updates) == 1
        assert type(updates[0]) == rpc_pb2.GraphTopologyUpdate

        # test a peer updating their fees
        carol.update_channel_policy(chan_point=None,
                                    base_fee_msat=5555,
                                    fee_rate=0.5555,
                                    time_lock_delta=9,
                                    is_global=True)
        gen_and_sync_lnd(bitcoind, [bob, carol, dave])
        updates.append(subscription.__next__())
        assert len(updates) == 2
        assert type(updates[1]) == rpc_pb2.GraphTopologyUpdate

    def test_update_channel_policy(self, bitcoind, bob, carol):
        bob, carol = setup_nodes(bitcoind, [bob, carol])
        update = bob.update_channel_policy(chan_point=None,
                                           base_fee_msat=5555,
                                           fee_rate=0.5555,
                                           time_lock_delta=9,
                                           is_global=True)
        assert type(update) == rpc_pb2.PolicyUpdateResponse


class TestLoop:

    def test_loop_out_quote(self, bitcoind, alice, bob, loopd):
        alice, bob = setup_nodes(bitcoind, [alice, bob])
        if alice.invoice_rpc_active:
            quote = loopd.loop_out_quote(amt=250000)
            print(quote)
            assert quote is not None
            assert type(quote) == loop_client_pb2.QuoteResponse
        else:
            logging.info("test_loop_out() skipped as invoice RPC not detected")

    def test_loop_out_terms(self, bitcoind, alice, bob, loopd):
        alice, bob = setup_nodes(bitcoind, [alice, bob])
        if alice.invoice_rpc_active:
            terms = loopd.loop_out_terms()
            assert terms is not None
            assert type(terms) == loop_client_pb2.TermsResponse
        else:
            logging.info("test_loop_out() skipped as invoice RPC not detected")
