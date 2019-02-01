import lnd_grpc.lnd_grpc as py_rpc
import lnd_grpc.rpc_pb2 as rpc_pb2

# raise Exception("Comment me out if you know what you're doing and want to test this on mainnet")

# create a Client stub
rpc = py_rpc.Client()
# initialize an address variable for test sends
address1 = None
address2 = None


# Wallet Unlocker stub tests
def test_gen_seed():
    response = rpc.gen_seed()
    assert isinstance(response, rpc_pb2.GenSeedResponse)


# I think these fail tests are not useful
# def gen_seed_fail():
#    gen_seed_fail = rpc.gen_seed(fail='hello')
#    assert not isinstance(gen_seed_fail, rpc_pb2.GenSeedResponse)


def test_init_wallet():
    response = rpc.init_wallet('wallet_password="AcceptablePassword')
    assert isinstance(response, rpc_pb2.InitWalletResponse)
    # TODO: add a test passing all params here. Delete .lnd dir first?


def test_unlock_wallet():
    response = rpc.unlock_wallet(wallet_password='AcceptablePassword')
    assert isinstance(response, rpc_pb2.UnlockWalletResponse)


def test_change_password():
    response= rpc.change_password(
            current_password='AcceptablePassword',
            new_password='PasswordAcceptable')
    assert isinstance(response, rpc_pb2.ChangePasswordResponse)


def test_wallet_balance():
    response = rpc.wallet_balance()
    assert isinstance(response, rpc_pb2.WalletBalanceResponse)


def test_channel_balance():
    response = rpc.channel_balance()
    assert isinstance(response, rpc_pb2.ChannelBalanceResponse)


def test_get_transactions():
    response = rpc.get_transactions()
    assert isinstance(response, rpc_pb2.TransactionDetails)


def test_send_coins():
    # must run test_new_address() to gen addresses
    response1 = rpc.send_coins(addr=address1, amount=1000)
    response2 = rpc.send_coins(addr=address2, amount=1000)
    assert isinstance(response1, rpc_pb2.SendCoinsResponse)
    assert isinstance(response2, rpc_pb2.SendCoinsResponse)


# NOT IN v0.5.1-beta tag
#def test_list_unspent():
#    response = rpc.list_unspent(0, 1000)
#    assert isinstance(response, rpc_pb2.ListUnspentResponse)

def subscribe_transactions():
    response = rpc.subscribe_transactions()
    assert isinstance(response, rpc_pb2.Transaction)
:test_init_wallet()
def send_many():
    # TODO: add send_many test
    pass


def test_new_address():
    address1 = rpc.new_address(address_type=1)
    address2 = rpc.new_address(address_type=2)
    assert isinstance(address1, rpc_pb2.NewAddressResponse)
    assert isinstance(address2, rpc_pb2.NewAddressResponse)


