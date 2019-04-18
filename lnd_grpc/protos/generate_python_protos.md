For when the project is cloned from github the process proceeds as follows:

* Acquire raw proto file(s).

* Generate python-specific proto files (python metaclasses) from these raw protos.


1) Either, you can manually download the appropriate rpc.proto file from:

   `https://raw.githubusercontent.com/lightningnetwork/lnd/v{lnd_version}/lnrpc/rpc.proto`

   Alternatively you can use the included 'download_proto_file.py' script. Make sure your current working directory is
   inside this directory .../lnd_grpc/protos/ and then run using:
   
   `python download_proto_files.py`
   
   Please read the notes at the top of the script before running.

1) Make sure googleapis is cloned in this folder:
   
   `git clone https://github.com/googleapis/googleapis.git`

2) Activate your venv if necessary!

3) Run command to generate **lnd** gRPC metaclass files:
   
   `python -m grpc_tools.protoc --proto_path=lnd_grpc/protos/googleapis:. --python_out=. --grpc_python_out=. lnd_grpc/protos/rpc.proto`

4) To generate **loop** proto metaclasses:
      
   `python -m grpc_tools.protoc --proto_path=lnd_grpc/protos/googleapis:. --python_out=. --grpc_python_out=. loop_rpc/protos/loop_client.proto`

 5) To generate both **lnd rpc and invoice_rpc** python gRPC metaclasses:
   
    1. Manually modify L4 of invoices.proto to read exactly: `import "lnd_grpc/protos/rpc.proto";`
    
    2. Then run the command:
    
    `python -m grpc_tools.protoc --proto_path=lnd_grpc/protos/googleapis:. --python_out=. --grpc_python_out=. lnd_grpc/protos/rpc.proto lnd_grpc/protos/invoices.proto`