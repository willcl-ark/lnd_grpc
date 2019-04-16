import logging
import time

from ephemeral_port_reserve import reserve

from loop_rpc.loop_rpc import LoopClient as LoopClient
from test_utils.utils import TailableProc


class LoopD(TailableProc):

    def __init__(self, lnd, network='regtest', host='localhost', rpc_port=None):
        super().__init__()
        if rpc_port is None:
            rpc_port = reserve()
        self.rpc_port = rpc_port
        self.host = host
        self.prefix = 'loopd'
        self.lnd = lnd
        self.cmd_line = [
            f'loopd',
            # f'--insecure',
            f'--network={network}',
            f'--rpclisten={self.host}:{self.rpc_port}',
            f'--lnd.host={self.lnd.grpc_host}:{self.lnd.grpc_port}',
            f'--lnd.macaroonpath={lnd.macaroon_path}',
            f'--lnd.tlspath={self.lnd.tls_cert_path}',
        ]

    def start(self):
        super().start()
        self.wait_for_log('Connected to lnd node')
        logging.info('Loop connected to LND node')
        self.wait_for_log('Starting event loop at height')
        time.sleep(3)
        logging.info('Event Loop started')

    def stop(self):
        self.proc.terminate()
        time.sleep(3)
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        super().save_log()


class LoopNode(LoopClient):
    displayname = 'loop'

    def __init__(self, host, rpc_port, lnd, executor=None, node_id=0):
        self.executor = executor
        self.daemon = LoopD(lnd, host=host, rpc_port=rpc_port)
        self.node_id = node_id
        self.logger = logging.getLogger(name='loop')
        self.myid = None
        super().__init__(loop_host=host, loop_port=rpc_port)

    def restart(self):
        self.daemon.stop()
        time.sleep(5)
        self.daemon.start()

    def stop(self):
        self.daemon.stop()

    def start(self):
        self.daemon.start()
