from os import environ

import grpc

import lnd_grpc.protos.invoices_pb2 as inv
import lnd_grpc.protos.invoices_pb2_grpc as invrpc
import lnd_grpc.protos.rpc_pb2 as ln
from lnd_grpc.base_client import BaseClient

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class Invoices(BaseClient):

    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = 'mainnet',
                 grpc_host: str = 'localhost',
                 grpc_port: str = '10009'):
        self._inv_stub: invrpc.InvoicesStub = None

        super().__init__(lnd_dir=lnd_dir,
                         macaroon_path=macaroon_path,
                         tls_cert_path=tls_cert_path,
                         network=network,
                         grpc_host=grpc_host,
                         grpc_port=grpc_port)

    @property
    def invoice_stub(self) -> invrpc.InvoicesStub:
        if self._inv_stub is None:
            ssl_creds = grpc.ssl_channel_credentials(self.tls_cert_key)
            _inv_channel = grpc.secure_channel(target=self.grpc_address,
                                               credentials=self.combined_credentials,
                                               options=self.grpc_options)
            self._inv_stub = invrpc.InvoicesStub(_inv_channel)
        return self._inv_stub

    def subscribe_single_invoice(self,
                                 r_hash: bytes = b'',
                                 r_hash_str: str = '') -> ln.Invoice:
        """
        Uni-directional streaming RPC returns an iterable to be operated on
        """
        request = ln.PaymentHash(r_hash=r_hash, r_hash_str=r_hash_str)
        response = self.invoice_stub.SubscribeSingleInvoice(request)
        return response

    def cancel_invoice(self, payment_hash: bytes = b'') -> inv.CancelInvoiceResp:
        request = inv.CancelInvoiceMsg(payment_hash=payment_hash)
        response = self.invoice_stub.CancelInvoice(request)
        return response

    def add_hold_invoice(self,
                         memo: str = '',
                         hash: bytes = b'',
                         value: int = 0,
                         expiry: int = 3600,
                         fallback_addr: str = '',
                         cltv_expiry: int = 7,
                         route_hints: ln.RouteHint = [],
                         private: bool = 1) -> inv.AddHoldInvoiceResp:
        request = inv.AddHoldInvoiceRequest(
                memo=memo, hash=hash, value=value, expiry=expiry,
                fallback_addr=fallback_addr, cltv_expiry=cltv_expiry,
                route_hints=route_hints, private=private)
        response = self.invoice_stub.AddHoldInvoice(request)
        return response

    def settle_invoice(self, preimage: bytes = b'') -> inv.SettleInvoiceResp:
        request = inv.SettleInvoiceMsg(preimage=preimage)
        response = self.invoice_stub.SettleInvoice(request)
        return response
