import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lnd_grpc",
    version="0.0.3",
    author="Will Clark",
    author_email="will8clark@gmail.com",
    description="LND gRPC pre-packaged",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "grpcio,"
        "grpcio-tools,"
        "googleapis-common-protos",
        "codecs",
    ]
)