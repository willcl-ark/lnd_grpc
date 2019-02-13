import platform
import codecs
from pathlib import Path
from os import environ, path


def get_lnd_dir():
    """
    Set default LND directory based on detected OS platform
    """
    lnd_dir = None
    _platform = platform.system()
    home_dir = str(Path.home())
    if _platform == 'Darwin':
        lnd_dir = home_dir + '/Library/Application Support/Lnd/'
    elif _platform == 'Linux':
        lnd_dir = home_dir + '/.lnd/'
    elif _platform == 'Windows':
        lnd_dir = path.abspath(environ.get('LOCALAPPDATA') + 'Lnd/')
    return lnd_dir


def bytes_to_hex_str(base64_bytes):
    """
    Convert base64 bytes to hex encoded string
    """
    hex_bytes = codecs.encode(base64_bytes, 'hex')
    hex_str = hex_bytes.decode()
    return hex_str


def hex_str_to_bytes(hex_str):
    """
    Convert hex encoded string to base64 bytes
    """
    hex_bytes = hex_str.encode()
    base64_bytes = codecs.decode(hex_bytes, 'hex')
    return base64_bytes
