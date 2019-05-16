# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: lnd_grpc/protos/invoices.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2
from lnd_grpc.protos import rpc_pb2 as lnd__grpc_dot_protos_dot_rpc__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='lnd_grpc/protos/invoices.proto',
  package='invoicesrpc',
  syntax='proto3',
  serialized_options=_b('Z1github.com/lightningnetwork/lnd/lnrpc/invoicesrpc'),
  serialized_pb=_b('\n\x1elnd_grpc/protos/invoices.proto\x12\x0binvoicesrpc\x1a\x1cgoogle/api/annotations.proto\x1a\x19lnd_grpc/protos/rpc.proto\"(\n\x10\x43\x61ncelInvoiceMsg\x12\x14\n\x0cpayment_hash\x18\x01 \x01(\x0c\"\x13\n\x11\x43\x61ncelInvoiceResp\"\xaf\x02\n\x15\x41\x64\x64HoldInvoiceRequest\x12\x12\n\x04memo\x18\x01 \x01(\tR\x04memo\x12\x12\n\x04hash\x18\x02 \x01(\x0cR\x04hash\x12\x14\n\x05value\x18\x03 \x01(\x03R\x05value\x12*\n\x10\x64\x65scription_hash\x18\x04 \x01(\x0cR\x10\x64\x65scription_hash\x12\x16\n\x06\x65xpiry\x18\x05 \x01(\x03R\x06\x65xpiry\x12$\n\rfallback_addr\x18\x06 \x01(\tR\rfallback_addr\x12 \n\x0b\x63ltv_expiry\x18\x07 \x01(\x04R\x0b\x63ltv_expiry\x12\x32\n\x0broute_hints\x18\x08 \x03(\x0b\x32\x10.lnrpc.RouteHintR\x0broute_hints\x12\x18\n\x07private\x18\t \x01(\x08R\x07private\">\n\x12\x41\x64\x64HoldInvoiceResp\x12(\n\x0fpayment_request\x18\x01 \x01(\tR\x0fpayment_request\"$\n\x10SettleInvoiceMsg\x12\x10\n\x08preimage\x18\x01 \x01(\x0c\"\x13\n\x11SettleInvoiceResp2\xc1\x02\n\x08Invoices\x12>\n\x16SubscribeSingleInvoice\x12\x12.lnrpc.PaymentHash\x1a\x0e.lnrpc.Invoice0\x01\x12N\n\rCancelInvoice\x12\x1d.invoicesrpc.CancelInvoiceMsg\x1a\x1e.invoicesrpc.CancelInvoiceResp\x12U\n\x0e\x41\x64\x64HoldInvoice\x12\".invoicesrpc.AddHoldInvoiceRequest\x1a\x1f.invoicesrpc.AddHoldInvoiceResp\x12N\n\rSettleInvoice\x12\x1d.invoicesrpc.SettleInvoiceMsg\x1a\x1e.invoicesrpc.SettleInvoiceRespB3Z1github.com/lightningnetwork/lnd/lnrpc/invoicesrpcb\x06proto3')
  ,
  dependencies=[google_dot_api_dot_annotations__pb2.DESCRIPTOR,lnd__grpc_dot_protos_dot_rpc__pb2.DESCRIPTOR,])




_CANCELINVOICEMSG = _descriptor.Descriptor(
  name='CancelInvoiceMsg',
  full_name='invoicesrpc.CancelInvoiceMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='payment_hash', full_name='invoicesrpc.CancelInvoiceMsg.payment_hash', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=104,
  serialized_end=144,
)


_CANCELINVOICERESP = _descriptor.Descriptor(
  name='CancelInvoiceResp',
  full_name='invoicesrpc.CancelInvoiceResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=146,
  serialized_end=165,
)


_ADDHOLDINVOICEREQUEST = _descriptor.Descriptor(
  name='AddHoldInvoiceRequest',
  full_name='invoicesrpc.AddHoldInvoiceRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='memo', full_name='invoicesrpc.AddHoldInvoiceRequest.memo', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='memo', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='hash', full_name='invoicesrpc.AddHoldInvoiceRequest.hash', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='hash', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='invoicesrpc.AddHoldInvoiceRequest.value', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='value', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='description_hash', full_name='invoicesrpc.AddHoldInvoiceRequest.description_hash', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='description_hash', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='expiry', full_name='invoicesrpc.AddHoldInvoiceRequest.expiry', index=4,
      number=5, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='expiry', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='fallback_addr', full_name='invoicesrpc.AddHoldInvoiceRequest.fallback_addr', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='fallback_addr', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cltv_expiry', full_name='invoicesrpc.AddHoldInvoiceRequest.cltv_expiry', index=6,
      number=7, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='cltv_expiry', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='route_hints', full_name='invoicesrpc.AddHoldInvoiceRequest.route_hints', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='route_hints', file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='private', full_name='invoicesrpc.AddHoldInvoiceRequest.private', index=8,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='private', file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=168,
  serialized_end=471,
)


_ADDHOLDINVOICERESP = _descriptor.Descriptor(
  name='AddHoldInvoiceResp',
  full_name='invoicesrpc.AddHoldInvoiceResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='payment_request', full_name='invoicesrpc.AddHoldInvoiceResp.payment_request', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, json_name='payment_request', file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=473,
  serialized_end=535,
)


_SETTLEINVOICEMSG = _descriptor.Descriptor(
  name='SettleInvoiceMsg',
  full_name='invoicesrpc.SettleInvoiceMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='preimage', full_name='invoicesrpc.SettleInvoiceMsg.preimage', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=537,
  serialized_end=573,
)


_SETTLEINVOICERESP = _descriptor.Descriptor(
  name='SettleInvoiceResp',
  full_name='invoicesrpc.SettleInvoiceResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=575,
  serialized_end=594,
)

_ADDHOLDINVOICEREQUEST.fields_by_name['route_hints'].message_type = lnd__grpc_dot_protos_dot_rpc__pb2._ROUTEHINT
DESCRIPTOR.message_types_by_name['CancelInvoiceMsg'] = _CANCELINVOICEMSG
DESCRIPTOR.message_types_by_name['CancelInvoiceResp'] = _CANCELINVOICERESP
DESCRIPTOR.message_types_by_name['AddHoldInvoiceRequest'] = _ADDHOLDINVOICEREQUEST
DESCRIPTOR.message_types_by_name['AddHoldInvoiceResp'] = _ADDHOLDINVOICERESP
DESCRIPTOR.message_types_by_name['SettleInvoiceMsg'] = _SETTLEINVOICEMSG
DESCRIPTOR.message_types_by_name['SettleInvoiceResp'] = _SETTLEINVOICERESP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CancelInvoiceMsg = _reflection.GeneratedProtocolMessageType('CancelInvoiceMsg', (_message.Message,), dict(
  DESCRIPTOR = _CANCELINVOICEMSG,
  __module__ = 'lnd_grpc.protos.invoices_pb2'
  # @@protoc_insertion_point(class_scope:invoicesrpc.CancelInvoiceMsg)
  ))
_sym_db.RegisterMessage(CancelInvoiceMsg)

CancelInvoiceResp = _reflection.GeneratedProtocolMessageType('CancelInvoiceResp', (_message.Message,), dict(
  DESCRIPTOR = _CANCELINVOICERESP,
  __module__ = 'lnd_grpc.protos.invoices_pb2'
  # @@protoc_insertion_point(class_scope:invoicesrpc.CancelInvoiceResp)
  ))
_sym_db.RegisterMessage(CancelInvoiceResp)

AddHoldInvoiceRequest = _reflection.GeneratedProtocolMessageType('AddHoldInvoiceRequest', (_message.Message,), dict(
  DESCRIPTOR = _ADDHOLDINVOICEREQUEST,
  __module__ = 'lnd_grpc.protos.invoices_pb2'
  # @@protoc_insertion_point(class_scope:invoicesrpc.AddHoldInvoiceRequest)
  ))
_sym_db.RegisterMessage(AddHoldInvoiceRequest)

AddHoldInvoiceResp = _reflection.GeneratedProtocolMessageType('AddHoldInvoiceResp', (_message.Message,), dict(
  DESCRIPTOR = _ADDHOLDINVOICERESP,
  __module__ = 'lnd_grpc.protos.invoices_pb2'
  # @@protoc_insertion_point(class_scope:invoicesrpc.AddHoldInvoiceResp)
  ))
_sym_db.RegisterMessage(AddHoldInvoiceResp)

SettleInvoiceMsg = _reflection.GeneratedProtocolMessageType('SettleInvoiceMsg', (_message.Message,), dict(
  DESCRIPTOR = _SETTLEINVOICEMSG,
  __module__ = 'lnd_grpc.protos.invoices_pb2'
  # @@protoc_insertion_point(class_scope:invoicesrpc.SettleInvoiceMsg)
  ))
_sym_db.RegisterMessage(SettleInvoiceMsg)

SettleInvoiceResp = _reflection.GeneratedProtocolMessageType('SettleInvoiceResp', (_message.Message,), dict(
  DESCRIPTOR = _SETTLEINVOICERESP,
  __module__ = 'lnd_grpc.protos.invoices_pb2'
  # @@protoc_insertion_point(class_scope:invoicesrpc.SettleInvoiceResp)
  ))
_sym_db.RegisterMessage(SettleInvoiceResp)


DESCRIPTOR._options = None

_INVOICES = _descriptor.ServiceDescriptor(
  name='Invoices',
  full_name='invoicesrpc.Invoices',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=597,
  serialized_end=918,
  methods=[
  _descriptor.MethodDescriptor(
    name='SubscribeSingleInvoice',
    full_name='invoicesrpc.Invoices.SubscribeSingleInvoice',
    index=0,
    containing_service=None,
    input_type=lnd__grpc_dot_protos_dot_rpc__pb2._PAYMENTHASH,
    output_type=lnd__grpc_dot_protos_dot_rpc__pb2._INVOICE,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='CancelInvoice',
    full_name='invoicesrpc.Invoices.CancelInvoice',
    index=1,
    containing_service=None,
    input_type=_CANCELINVOICEMSG,
    output_type=_CANCELINVOICERESP,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='AddHoldInvoice',
    full_name='invoicesrpc.Invoices.AddHoldInvoice',
    index=2,
    containing_service=None,
    input_type=_ADDHOLDINVOICEREQUEST,
    output_type=_ADDHOLDINVOICERESP,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='SettleInvoice',
    full_name='invoicesrpc.Invoices.SettleInvoice',
    index=3,
    containing_service=None,
    input_type=_SETTLEINVOICEMSG,
    output_type=_SETTLEINVOICERESP,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_INVOICES)

DESCRIPTOR.services_by_name['Invoices'] = _INVOICES

# @@protoc_insertion_point(module_scope)
