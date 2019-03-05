import time
import grpc

from tests import lnd_grpc_speed
import bitcoin.rpc


"""
A Channel speedtest which mimics the go test
"""


def initialise_lnd_rpc():
    alice = lnd_grpc_speed.Client(lnd_dir='/Users/will/regtest/.lnd/',
                                  network='regtest',
                                  grpc_host='127.0.0.1',
                                  grpc_port='10009',
                                  macaroon_path='/Users/will/regtest/.lnd/data/chain/bitcoin/regtest/admin.macaroon')
    bob = lnd_grpc_speed.Client(lnd_dir='/Users/will/regtest/.lnd2/',
                                network='regtest',
                                grpc_host='127.0.0.1',
                                grpc_port='11009',
                                macaroon_path='/Users/will/regtest/.lnd2/data/chain/bitcoin/regtest/admin.macaroon')

    return bob, alice


def initialise_bitcoin_rpc():
    rpc_connection = bitcoin.rpc.RawProxy(service_port=18443,
                                          btc_conf_file='/Users/will/regtest/.bitcoin/bitcoin.conf')
    return rpc_connection


def test_async_payments():
    print("Starting test...")

    # set payment amount and cycles
    invoice_value = 1000
    invoice_frequency = 100
    channel_tx_fee = 9050

    total_invoice_value = int(invoice_value * invoice_frequency)
    channel_open_size = int((total_invoice_value + channel_tx_fee) // 0.99)
    wallet_fund_amount = channel_open_size

    # Initialise RPC connections
    bitcoin_rpc = initialise_bitcoin_rpc()
    alice, bob = initialise_lnd_rpc()
    alice.pubkey = alice.get_info().identity_pubkey
    alice._lightning_address = lnd_grpc_speed.Client.lightning_address(
            pubkey=alice.pubkey,
            host='127.0.0.1:9735')
    bob_pubkey = bob.get_info().identity_pubkey
    bob._lightning_address = lnd_grpc_speed.Client.lightning_address(
            pubkey=bob_pubkey,
            host='127.0.0.1:9734')

    # Disable debug output
    alice.debug_level(level_spec='off')
    bob.debug_level(level_spec='off')

    # Generate some blockchain info
    bitcoin_address = bitcoin_rpc.getnewaddress()
    current_height = bitcoin_rpc.getblockcount()

    # Close Lightning channels
    tries = 0
    while len(alice.list_channels()) != 0 and tries < 10:
        alice.close_all_channels()
        bob.close_all_channels()
        # Mature any channel closes
        bitcoin_rpc.generatetoaddress(3, bitcoin_address)
        tries += 1
        time.sleep(0.25)
    if len(alice.list_channels()) == 0:
        print("Successfully closed any pre-existing lightning channels")
    else:
        print("Lightning channel closures failed")
        return

    # Generate spendable coinbases if necessary
    if current_height < 101:
        bitcoin_rpc.generatetoaddress(105, bitcoin_address)

    # Fully mature channel closes and coinbases
    current_height = bitcoin_rpc.getblockcount()
    bitcoin_rpc.generatetoaddress(6, bitcoin_address)
    time.sleep(0.25)
    new_height = bitcoin_rpc.getblockcount()
    assert new_height > 101
    assert new_height == current_height + 6
    print("Lightning channel closes matured")
    time.sleep(0.25)

    # Withdraw all coins from lnd nodes
    wallet_tries = 0
    while alice.wallet_balance().total_balance != 0 and wallet_tries < 10:
        try:
            alice.send_coins(bitcoin_address, send_all=1, sat_per_byte=1)
            bitcoin_rpc.generatetoaddress(6, bitcoin_address)
            time.sleep(0.25)
        except grpc.RpcError as e:
            print(f"Error: {e._state.details}")
    wallet_tries = 0
    while bob.wallet_balance().total_balance != 0 and wallet_tries < 10:
        try:
            bob.send_coins(bitcoin_address, send_all=1, sat_per_byte=1)
            bitcoin_rpc.generatetoaddress(6, bitcoin_address)
            time.sleep(0.25)
        except grpc.RpcError as e:
            print(f"Error: {e._state.details}")

    try:
        assert alice.wallet_balance().total_balance == 0
        assert bob.wallet_balance().total_balance == 0
        print("On-chain wallet balances emptied successfully")
    except AssertionError:
        print("Could not empty on-chain wallet balance")
        return

    # Get new lightning wallet on-chain address
    alice_onchain_address = alice.new_address('p2wkh')
    bitcoin_rpc.sendtoaddress(str(alice_onchain_address.address),
                              1 + (wallet_fund_amount / 100_000_000))
    bitcoin_rpc.generatetoaddress(6, bitcoin_address)
    time.sleep(0.25)

    # Open channel from Alice to Bob
    try:
        alice.connect_peer(addr=bob._lightning_address)
    except grpc.RpcError as e:
        if "already connected to peer" in e._state.details:
            pass
        else:
            print(f"Error connecting to lightning peer: {e._state.details}")
    bitcoin_rpc.generatetoaddress(3, bitcoin_address)
    time.sleep(0.25)
    try:
        alice.open_channel_sync(node_pubkey_string=bob_pubkey,
                                local_funding_amount=channel_open_size,
                                sat_per_byte=1)
    except grpc.RpcError as e:
        print(f"Error opening lightning channel: {e._state.details}")

    bitcoin_rpc.generatetoaddress(6, bitcoin_address)
    time.sleep(0.25)

    if alice.list_channels()[0]:
        print(f"Lightning channel opened with Bob, channel point: "
              f"{alice.list_channels()[0].channel_point}")
        print(f"Alice channel balance: {alice.channel_balance().balance}")
        print(f"Bob channel balance: {bob.channel_balance().balance}")
    else:
        print("Lightning channel not opened with Bob")
        return

    num_invoices = invoice_frequency

    # bob_amount = int(num_invoices * invoice_value)
    # alice_amount = alice.wallet_balance().total_balance - bob_amount

    # Send at least one more payment than possible to cause insufficient capacity error
    num_invoices += 1

    # Bob creates invoices for Alice to pay
    print(f"Bob generating {num_invoices} invoices for Alice")
    invoices = []
    for i in range(num_invoices):
        invoices.append(bob.add_invoice(value=invoice_value))
    invoices_generated = len(invoices)
    print("Complete")
    payment_len_start = len(alice.list_payments().payments)

    # Alice pays the invoices
    print("Alice starting payment of Bob's invoices")
    alice.send_payment_sync(invoices=invoices)
    print("Complete")

    print("...sleeping...")
    time.sleep(5)

    # Results
    payment_len_end = len(alice.list_payments().payments)
    print(f"{invoices_generated} invoices generated")
    print(f"{payment_len_end - payment_len_start} payments completed")

    return


if __name__ == '__main__':
    test_async_payments()
