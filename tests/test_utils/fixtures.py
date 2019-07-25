"""
###
Code Modified from Christian Decker's original work, subject to the following license:
###

    Copyright Christian Decker (Blockstream) 2017-2019.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import logging
import os
import shutil
import tempfile
from concurrent import futures

import pytest
from ephemeral_port_reserve import reserve

from test_utils.btcproxy import ProxiedBitcoinD
from test_utils.lnd import LndNode
from test_utils.loop import LoopNode

TEST_DIR = tempfile.mkdtemp(prefix="lightning-")
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"
TRAVIS = os.getenv("TRAVIS", "false") == "true"


# A dict in which we count how often a particular test has run so far. Used to
# give each attempt its own numbered directory, and avoid clashes.
__attempts = {}


class NodeFactory(object):
    """
    A factory to setup and start `lightning` daemons.
    """

    def __init__(self, testname, executor, bitcoind):
        self.testname = testname
        # self.next_id = 1
        self.nodes = []
        self.executor = executor
        self.bitcoind = bitcoind

    def get_node(self, implementation, node_id):
        # node_id = self.next_id
        # self.next_id += 1

        lightning_dir = os.path.join(
            TEST_DIR, self.testname, "node-{}/".format(node_id)
        )
        port = reserve()

        node = implementation(
            lightning_dir, port, self.bitcoind, executor=self.executor, node_id=node_id
        )
        self.nodes.append(node)

        node.daemon.start()
        return node

    def killall(self):
        for n in self.nodes:
            n.daemon.stop()


@pytest.fixture(scope="session")
def directory(request, test_base_dir):
    """Return a per-test-session specific directory.

    This makes a unique test-directory even if a test is rerun multiple times.

    """
    # global __attempts
    # # Auto set value if it isn't in the dict yet
    # __attempts[test_name] = __attempts.get(test_name, 0) + 1
    # directory = os.path.join(test_base_dir, "{}_{}".format(test_name, __attempts[test_name]))
    directory = test_base_dir
    request.node.has_errors = False

    yield directory

    # This uses the status set in conftest.pytest_runtest_makereport to
    # determine whether we succeeded or failed.
    if not request.node.has_errors:  # and request.node.rep_call.outcome == 'passed':
        shutil.rmtree(directory)
    else:
        logging.debug(
            "Test execution failed, leaving the test directory {} intact.".format(
                directory
            )
        )


@pytest.fixture(scope="session")
def test_base_dir():
    directory = tempfile.mkdtemp(prefix="ltests-")
    print("Running tests in {}".format(directory))

    yield directory

    # if not os.listdir(directory) == []:
    #     shutil.rmtree(directory)


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture(scope="session")
def bitcoind(directory):
    proxyport = reserve()
    btc = ProxiedBitcoinD(
        bitcoin_dir=os.path.join(directory, "bitcoind"), proxyport=proxyport
    )
    btc.start()
    bch_info = btc.rpc.getblockchaininfo()
    w_info = btc.rpc.getwalletinfo()
    # Make sure we have segwit and some funds
    if bch_info["blocks"] < 120:
        logging.debug("SegWit not active, generating some more blocks")
        btc.rpc.generate(120 - bch_info["blocks"])
    elif w_info["balance"] < 1:
        logging.debug("Insufficient balance, generating 1 block")
        btc.rpc.generate(1)

    yield btc

    try:
        btc.rpc.stop()
    except Exception:
        btc.proc.kill()
    btc.proc.wait()


@pytest.fixture(scope="class")
def loopd(alice):
    loop = LoopNode(host="localhost", rpc_port="11010", lnd=alice)
    loop.start()

    yield loop

    try:
        loop.stop()
    except Exception:
        loop.daemon.stop()


@pytest.fixture(scope="class")
def node_factory(request, bitcoind):
    executor = futures.ThreadPoolExecutor(max_workers=20)
    node_factory = NodeFactory(request._pyfuncitem.name, executor, bitcoind)
    yield node_factory
    node_factory.killall()
    executor.shutdown(wait=False)


@pytest.fixture(scope="class")
def alice(node_factory):
    alice = node_factory.get_node(implementation=LndNode, node_id="alice")
    yield alice

    try:
        alice.stop()
    except Exception:
        print("Issue terminating alice")


@pytest.fixture(scope="class")
def bob(node_factory):
    bob = node_factory.get_node(implementation=LndNode, node_id="bob")
    yield bob

    try:
        bob.stop()
    except Exception:
        print("Issue terminating bob")


@pytest.fixture(scope="class")
def carol(node_factory):
    carol = node_factory.get_node(implementation=LndNode, node_id="carol")
    yield carol

    try:
        carol.stop()
    except Exception:
        print("Issue terminating carol")


@pytest.fixture(scope="class")
def dave(node_factory):
    dave = node_factory.get_node(implementation=LndNode, node_id="dave")
    yield dave

    try:
        dave.stop()
    except Exception:
        print("Issue terminating dave")
