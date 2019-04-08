# Testing
### Setup
Tests are heavily influenced in structure from Christian Decker's lightning-integration test framework: https://github.com/cdecker/lightning-integration

Recommendation is to run the tests from within a virtualenv. From the parent directory be sure to run the following to install dependencies:

`pip3 install -r test-requirements.txt`

lnd v-0.6-beta and bitcoind >0.17 must be installed and be available on the user's PATH. To test availability, in a terminal issue 'which lnd' and `which bitcoind` and ensure that it returns the path to your lnd/bitcoind binary.

The tests rely on py.test to create fixtures, wire them into the tests and run the tests themselves. Execute all tests by running the following command in this directory:

`py.test -v test.py`

To make the tests (extremely) verbose in case of failure, you can run with the following command:

bash: `TEST_DEBUG=1 py.test -v test.py -s`


