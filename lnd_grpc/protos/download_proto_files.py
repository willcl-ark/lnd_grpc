import os
import requests

from lnd_grpc import lnd_grpc

cwd = os.getcwd()

"""
Note: The script will attempt to connect to your instance of lnd to determine the correct version 
of the proto file to download. 

The script will currently only detect and download lnd and invoice proto files, not loop.
"""


# TODO: add invoice and loop support


def capture_info():
    lnd_dir = input("LND dir [default: searched by Client()]:")
    network = input("network [default: mainnet]:") or "mainnet"
    grpc_host = input("GRPC host address [default: '127.0.0.1']:") or "127.0.0.1"
    grpc_port = input("gRPC port [default: '10009']:") or "10009"
    return lnd_dir, network, grpc_host, grpc_port


def create_lnd_client(
    lnd_dir: str = None,
    macaroon_path: str = None,
    network: str = "mainnet",
    grpc_host: str = "localhost",
    grpc_port: str = "10009",
):
    lncli = lnd_grpc.Client(
        lnd_dir=lnd_dir,
        network=network,
        grpc_host=grpc_host,
        grpc_port=grpc_port,
        macaroon_path=macaroon_path,
    )

    return lncli


def get_version(lncli):
    lnd_version = lncli.get_info().version.split("commit=")[1]
    return lnd_version


def get_rpc_proto(lnd_version):
    try:
        url = f"https://raw.githubusercontent.com/lightningnetwork/lnd/{lnd_version}/lnrpc/rpc.proto"
        print(f"Connecting to: {url}")
        proto = requests.get(url)
    except requests.HTTPError as e:
        print(e)
        return

    # Write the proto file to the current working directory
    proto_file_name = cwd + "/" + "rpc.proto"
    proto_file = open(proto_file_name, "w")
    proto_file.write(proto.text)
    proto_file.close()

    # Test the written proto file
    proto_file = open(proto_file_name, "r")
    proto_file_first_line = proto_file.readline().strip()
    test_first_line = 'syntax = "proto3";'
    if proto_file_first_line == test_first_line:
        print("Proto file looks good")
    else:
        print(
            f"Proto file did not have expected first line\n"
            f"Expected: {test_first_line}\n"
            f"Read: {proto_file_first_line}\n"
            f"Exiting..."
        )
        return


def get_invoices_proto(lnd_version):
    try:
        url = f"https://raw.githubusercontent.com/lightningnetwork/lnd/{lnd_version}/lnrpc/invoicesrpc/invoices.proto"
        print(f"Connecting to: {url}")
        proto = requests.get(url)
    except requests.HTTPError as e:
        print(e)
        return

    # Write the proto file to the current working directory
    proto_file_name = cwd + "/" + "invoices.proto"
    proto_file = open(proto_file_name, "w")
    proto_file.write(proto.text)
    proto_file.close()

    # Test the written proto file
    with open(proto_file_name, "r") as proto_file:
        proto_file_first_line = proto_file.readline().strip()
        test_first_line = 'syntax = "proto3";'
        if proto_file_first_line == test_first_line:
            print("Proto file looks good")
        else:
            print(
                f"Proto file did not have expected first line\n"
                f"Expected: {test_first_line}\n"
                f"Read: {proto_file_first_line}\n"
                f"Exiting..."
            )
            return

    # Fix Line 4 import for lnd_grpc package
    temp = None
    with open(proto_file_name, "r") as proto_file:
        temp = proto_file.readlines()
        temp[3] = 'import "lnd_grpc/protos/rpc.proto";\n'
    with open(proto_file_name, "w") as proto_file:
        proto_file.writelines(temp)


def download_proto_files():
    # Capture info used for LND client
    lnd_dir, network, grpc_host, grpc_port = capture_info()

    # Create a gRPC client that can query the version number for us
    lncli = create_lnd_client(
        lnd_dir=lnd_dir, network=network, grpc_host=grpc_host, grpc_port=grpc_port
    )

    # Get the version number for the lnd instance
    lnd_version = get_version(lncli)
    print(f"Version: {lnd_version}")

    # Try to connect to the raw Github page for the rpc proto file for LND version
    get_rpc_proto(lnd_version)

    # Try to connect to the raw Github page for the invoices proto file for LND version
    get_invoices_proto(lnd_version)

    print("All tasks completed successfully")


if __name__ == "__main__":
    download_proto_files()
