import os

import requests

from lnd_grpc import lnd_grpc

cwd = os.getcwd()


def create_lnd_client(lnd_dir: str = None,
                      macaroon_path: str = None,
                      network: str = 'mainnet',
                      grpc_host: str = 'localhost',
                      grpc_port: str = '10009'):
    lncli = lnd_grpc.Client(lnd_dir=lnd_dir,
                            network=network,
                            grpc_host=grpc_host,
                            grpc_port=grpc_port,
                            macaroon_path=macaroon_path)

    return lncli


def get_version(lncli):
    lnd_version = lncli.get_info().version.split(" ")[0]
    return lnd_version


def get_proto_file(lnd_version):
    try:
        url = f"https://raw.githubusercontent.com/lightningnetwork/lnd/v{lnd_version}/lnrpc/rpc.proto"
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
        print(f"Proto file did not have expected first line\n"
              f"Expected: {test_first_line}\n"
              f"Read: {proto_file_first_line}\n"
              f"Exiting...")
        return


def download_proto_files():
    # Create a gRPC client that can query the version number for us
    lncli = create_lnd_client()

    # Get the version number for the lnd instance
    lnd_version = get_version(lncli)

    # Try to connect to the raw Github page for the proto file for that version
    get_proto_file(lnd_version)

    print("All tasks completed successfully")


if __name__ == "__main__":
    download_proto_files()
