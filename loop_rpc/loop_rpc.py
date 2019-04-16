from grpc import insecure_channel
from loop_rpc.protos import loop_client_pb2 as loop, loop_client_pb2_grpc as looprpc


class LoopClient:
    """
    As per the instructions at https://github.com/lightninglabs/loop/blob/master/README.md both
    LND and loopd must be installed and running.

    If loopd is running with default configuration you will not need to change the LoopClient
    constructors from default (loop_host='localhost', loop_port='11010').
    """

    def __init__(self,
                 loop_host: str = 'localhost',
                 loop_port: str = '11010'):
        self._loop_stub: looprpc.SwapClientStub = None
        self.loop_host = loop_host
        self.loop_port = loop_port

    @property
    def loop_stub(self) -> looprpc.SwapClientStub:
        if self._loop_stub is None:
            loop_channel = insecure_channel(self.loop_host + ':' + self.loop_port)
            self._loop_stub = looprpc.SwapClientStub(loop_channel)
        return self._loop_stub

    def loop_out(self, amt: int, **kwargs):
        request = loop.LoopOutRequest(amt=amt, **kwargs)
        response = self.loop_stub.LoopOut(request)
        return response

    def monitor(self):
        """
        returns an iterable stream
        """
        request = loop.MonitorRequest()
        return self.loop_stub.Monitor(request)

    def loop_out_terms(self):
        request = loop.TermsRequest()
        response = self.loop_stub.LoopOutTerms(request)
        return response

    def loop_out_quote(self, amt: int):
        request = loop.QuoteRequest(amt=amt)
        response = self.loop_stub.LoopOutQuote(request)
        return response


__all__ = ['LoopClient', ]
