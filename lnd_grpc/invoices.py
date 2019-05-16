from os import environ

import grpc

import lnd_grpc.protos.invoices_pb2 as inv
import lnd_grpc.protos.invoices_pb2_grpc as invrpc
import lnd_grpc.protos.rpc_pb2 as ln
from lnd_grpc.base_client import BaseClient
from lnd_grpc.config import defaultNetwork, defaultRPCHost, defaultRPCPort

# tell gRPC which cypher suite to use
environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'


class Invoices(BaseClient):
    """
    Provides a super-class to interface with the Invoices sub-system. Currently mainly used only
    for hold invoice applications.
    """

    def __init__(self,
                 lnd_dir: str = None,
                 macaroon_path: str = None,
                 tls_cert_path: str = None,
                 network: str = defaultNetwork,
                 grpc_host: str = defaultRPCHost,
                 grpc_port: str = defaultRPCPort):
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
            ssl_creds = grpc.ssl_channel_credentials(self.tls_cert)
            _inv_channel = grpc.secure_channel(target=self.grpc_address,
                                               credentials=self.combined_credentials,
                                               options=self.grpc_options)
            self._inv_stub = invrpc.InvoicesStub(_inv_channel)
        return self._inv_stub

    def subscribe_single_invoice(self,
                                 r_hash: bytes = b'',
                                 r_hash_str: str = '') -> ln.Invoice:
        """
        Returns a uni-directional stream (server -> client) for notifying the client of invoice
        state changes.

        This is particularly useful in hold invoices where invoices might be paid by the 'payer'
        but not settled immediately by the 'receiver'; the 'payer' will want to watch for settlement
         or cancellation

        :return: an iterable of Invoice updates with 20 attributes per update
        """
        request = ln.PaymentHash(r_hash=r_hash, r_hash_str=r_hash_str)
        response = self.invoice_stub.SubscribeSingleInvoice(request)
        return response

    def cancel_invoice(self, payment_hash: bytes = b'') -> inv.CancelInvoiceResp:
        """
        Cancels a currently open invoice. If the invoice is already canceled, this call will
        succeed. If the invoice is already settled, it will fail.

        Once a hold invoice is accepted in lnd system it is held there until either a cancel or
        settle rpc is received.

        :return: CancelInvoiceResponse with no attributes
        """
        request = inv.CancelInvoiceMsg(payment_hash=payment_hash)
        response = self.invoice_stub.CancelInvoice(request)
        return response

    def add_hold_invoice(self, memo: str = '', hash: bytes = b'', value: int = 0,
                         expiry: int = 3600, fallback_addr: str = '', cltv_expiry: int = 36,
                         route_hints: ln.RouteHint = [], private: bool = 1) \
            -> inv.AddHoldInvoiceResp:
        """
        Attempts to add a new hold invoice to the invoice database. Any duplicated invoices are
        rejected, therefore all invoices *must* have a unique payment hash.

        Quick "hold" invoices:
        Instead of immediately locking in and settling the htlc when the payment arrives,
        the htlc for a hold invoice is only locked in and not yet settled. At that point,
        it is not possible anymore for the sender to revoke the payment, but the receiver still
        can choose whether to settle or cancel the htlc and invoice.

        :return: AddHoldInvoiceResponse with 1 attribute: 'payment_request'
        """
        request = inv.AddHoldInvoiceRequest(
                memo=memo, hash=hash, value=value, expiry=expiry,
                fallback_addr=fallback_addr, cltv_expiry=cltv_expiry,
                route_hints=route_hints, private=private)
        response = self.invoice_stub.AddHoldInvoice(request)
        return response

    def settle_invoice(self, preimage: bytes = b'') -> inv.SettleInvoiceResp:
        """
        Settles an accepted invoice. If the invoice is already settled, this call will succeed.

        Once a hold invoice is accepted in lnd system it is held there until either a cancel or
        settle rpc is received.

        :return: SettleInvoiceResponse with no attributes
        """
        request = inv.SettleInvoiceMsg(preimage=preimage)
        response = self.invoice_stub.SettleInvoice(request)
        return response
