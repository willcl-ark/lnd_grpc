import logging
import os
import time

from ephemeral_port_reserve import reserve

from lnd_grpc.lnd_grpc import Client as lndClient
from test_utils.utils import TailableProc, BITCOIND_CONFIG


# Needed for grpc to negotiate a valid cipher suite
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class LndD(TailableProc):

    CONF_NAME = 'lnd.conf'

    def __init__(self, lightning_dir, bitcoind, port, node_id):
        super().__init__(lightning_dir, 'lnd({})'.format(node_id))
        self.lightning_dir = lightning_dir
        self.bitcoind = bitcoind
        self.port = port
        self.rpc_port = str(reserve())
        self.rest_port = str(reserve())
        self.prefix = f'lnd-{node_id}'
        self.invoice_rpc_active = False
        try:
            if os.environ['TRAVIS_BUILD_DIR']:
                self.tlscertpath = os.environ[
                                       'TRAVIS_BUILD_DIR'] + '/tests/test_utils/test-tls.cert'
        except KeyError:
            self.tlscertpath = 'test_utils/test-tls.cert'
        try:
            if os.environ['TRAVIS_BUILD_DIR']:
                self.tlskeypath = os.environ['TRAVIS_BUILD_DIR'] + '/tests/test_utils/test-tls.key'
        except KeyError:
            self.tlskeypath = 'test_utils/test-tls.key'

        self.cmd_line = [
            'lnd',
            '--bitcoin.active',
            '--bitcoin.regtest',
            '--datadir={}'.format(lightning_dir),
            '--debuglevel=trace',
            '--rpclisten=127.0.0.1:{}'.format(self.rpc_port),
            '--restlisten=127.0.0.1:{}'.format(self.rest_port),
            '--listen=127.0.0.1:{}'.format(self.port),
            '--tlscertpath={}'.format(self.tlscertpath),
            '--tlskeypath={}'.format(self.tlskeypath),
            '--bitcoin.node=bitcoind',
            '--bitcoind.rpchost=127.0.0.1:{}'.format(BITCOIND_CONFIG.get('rpcport', 18332)),
            '--bitcoind.rpcuser=rpcuser',
            '--bitcoind.rpcpass=rpcpass',
            '--bitcoind.zmqpubrawblock=tcp://127.0.0.1:{}'.format(self.bitcoind.zmqpubrawblock_port),
            '--bitcoind.zmqpubrawtx=tcp://127.0.0.1:{}'.format(self.bitcoind.zmqpubrawtx_port),
            '--configfile={}'.format(os.path.join(lightning_dir, self.CONF_NAME)),
            '--nobootstrap',
            '--noseedbackup',
            '--trickledelay=500'
        ]

        if not os.path.exists(lightning_dir):
            os.makedirs(lightning_dir)
        with open(os.path.join(lightning_dir, self.CONF_NAME), "w") as f:
            f.write("""[Application Options]\n""")

    def start(self):
        super().start()
        self.wait_for_log('RPC server listening on')
        self.wait_for_log('Done catching up block hashes')
        try:
            self.wait_for_log('Starting sub RPC server: InvoicesRPC', timeout=10)
            self.invoice_rpc_active = True
        except ValueError:
            pass
        time.sleep(3)

        logging.info('LND started (pid: {})'.format(self.proc.pid))

    def stop(self):
        self.proc.terminate()
        time.sleep(3)
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        super().save_log()


class LndNode(lndClient):

    displayname = 'lnd'

    def __init__(self, lightning_dir, lightning_port, bitcoind, executor=None, node_id=0):
        self.bitcoin = bitcoind
        self.executor = executor
        self.daemon = LndD(lightning_dir, bitcoind, port=lightning_port, node_id=node_id)
        self.node_id = node_id
        self.logger = logging.getLogger(name='lnd-node({})'.format(self.node_id))
        self.myid = None
        super().__init__(lnd_dir=lightning_dir,
                         grpc_host='localhost',
                         grpc_port=str(self.daemon.rpc_port),
                         network='regtest',
                         tls_cert_path=self.daemon.tlscertpath,
                         macaroon_path=lightning_dir + 'chain/bitcoin/regtest/admin.macaroon')

    def id(self):
        if not self.myid:
            self.myid = self.get_info().identity_pubkey
        return self.myid

    def restart(self):
        self.daemon.stop()
        time.sleep(5)
        self.daemon.start()

    def stop(self):
        self.daemon.stop()

    def start(self):
        self.daemon.start()

    def add_funds(self, bitcoind, amount):
        start_amt = self.wallet_balance().total_balance
        addr = self.new_address('p2wkh').address
        bitcoind.rpc.sendtoaddress(addr, amount)
        self.daemon.wait_for_log("Inserting unconfirmed transaction")
        bitcoind.rpc.generate(3)
        self.daemon.wait_for_log("Marking unconfirmed transaction")

        # The above still doesn't mean the wallet balance is updated,
        # so let it settle a bit
        i = 0
        while self.wallet_balance().total_balance != (start_amt + (amount * 10 ** 8)) and i < 30:
            time.sleep(0.25)
            i += 1
        assert (self.wallet_balance().total_balance == start_amt + (amount * 10 ** 8))

    def check_channel(self, remote):
        """ Make sure that we have an active channel with remote
        """
        self_id = self.id()
        remote_id = remote.id()
        channels = self.list_channels()
        channel_by_remote = {c.remote_pubkey: c for c in channels}
        if remote_id not in channel_by_remote:
            self.logger.warning("Channel {} -> {} not found".format(self_id, remote_id))
            return False

        channel = channel_by_remote[remote_id]
        self.logger.debug("Channel {} -> {} state: {}".format(self_id, remote_id, channel))
        return channel.active

    def block_sync(self, blockhash):
        print("Waiting for node to learn about", blockhash)
        self.daemon.wait_for_log('NTFN: New block: height=([0-9]+), sha={}'.format(blockhash))
