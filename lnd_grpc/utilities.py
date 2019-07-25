import platform

from pathlib import Path
from os import environ, path


def get_lnd_dir():
    """
    :return: default LND directory based on detected OS platform
    """
    lnd_dir = None
    _platform = platform.system()
    home_dir = str(Path.home())
    if _platform == "Darwin":
        lnd_dir = home_dir + "/Library/Application Support/Lnd/"
    elif _platform == "Linux":
        lnd_dir = home_dir + "/.lnd/"
    elif _platform == "Windows":
        lnd_dir = path.abspath(environ.get("LOCALAPPDATA") + "Lnd/")
    return lnd_dir
