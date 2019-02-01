import inspect

import lnd_grpc.rpc_pb2_grpc as pb2_grpc
import lnd_grpc.lnd_grpc as py_rpc


class Attributes:

    def __init__(self):
        # Get all function names from lnd_grpc into a list
        self.lnd_grpc_list = [o for o in inspect.getmembers(py_rpc.Client) if
                              inspect.isfunction(o[1])]
        self.lnd_grpc_names = []
        for func in self.lnd_grpc_list:
            if func[0] != "__init__":
                self.lnd_grpc_names.append(
                    ''.join(x.capitalize() or '_' for x in func[0].split('_')))

        # Get all functions from LightningServicer into a list
        self.lightning_servicer_list = [o for o in inspect.getmembers(pb2_grpc.LightningServicer) if
                                        inspect.isfunction(o[1])]
        self.lightning_servicer_names = []
        for func in self.lightning_servicer_list:
            if func[0] != "__init__":
                self.lightning_servicer_names.append(func[0])

        # Get all functions from WalletUnlockerServicer into a list
        self.wallet_unlocker_list = [o for o in inspect.getmembers(pb2_grpc.WalletUnlockerServicer)
                                     if inspect.isfunction(o[1])]
        self.wallet_unlocker_names = []
        for func in self.wallet_unlocker_list:
            if func[0] != "__init__":
                self.wallet_unlocker_names.append(func[0])

        self.exclude = ['BuildCredentials',
                        'ConnectMacaroon',
                        'Initialize',
                        'MetadataCallback',
                        'PaymentRequestGenerator']


# test to see if functions still appear in the grpc protocol
def test_names_appear():
    a = Attributes()
    for func in a.lnd_grpc_names:
        if func not in a.exclude:
            if func in a.lightning_servicer_names or func in a.wallet_unlocker_names:
                print(func, "OK!")
            # if func in lightning_servicer_names:
            #    print(func, "found in pb2_grpc.LightningServicer")
            # elif func in wallet_unlocker_names:
            #    print(func, "found in pb2_grpc.WalletUnlockerServicer")
            # else:
            #    print("ERROR:", func, "NOT FOUND IN pb2_grpc")
