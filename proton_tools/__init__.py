#!/usr/bin/env python3
import logging
import os
import sys
from pathlib import Path

from le_tools.config import config


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('run_in_proton')
PROTON_PATH = None
CUSTOM_DIRENV_PATH = config.EXTERNAL_DIR / 'wine_custom/.envrc.proton'


def get_proton_env(linux_pid):
    """
    Get the environment variables for a process running in Proton.
    """
    env = Path(f'/proc/{linux_pid}/environ').read_text().split('\0')
    # set the environment variables for the current process
    for var in env:
        if '=' in var:
            key, value = var.split('=', 1)
            os.environ[key] = value
    # get proton path from process
    global PROTON_PATH
    out_dict = {}
    for var in env:
        if '=' in var:
            key, value = var.split('=', 1)
            out_dict[key] = value

    return out_dict


SKIP_ENV_FROM_DUMP = {
    # "PATH",
    # "LD_LIBRARY_PATH",
    'LD_PRELOAD',
}

ENV_KEEP_ONLY = {
    'STEAM_COMPAT_DATA_PATH',
    'STEAM_COMPAT_CLIENT_INSTALL_PATH',
    'STEAM_COMPAT_CLIENT_ID',
    'WINEPREFIX',
    'WINELOADER',
    'WINESYNC',
    'WINEFSYNC',
}


def dump_env(env_dict, path: CUSTOM_DIRENV_PATH):
    """
    Dump the environment variables to a file.
    """
    with open(path, 'w') as f:
        for key, value in env_dict.items():
            if key in SKIP_ENV_FROM_DUMP:
                continue
            if key not in ENV_KEEP_ONLY:
                continue
            f.write(f'export {key}="{value}"\n')
    log.info(f'Environment variables dumped to {path}')


if __name__ == '__main__':
    # Check if the script is being run directly
    # If so, set up logging and parse command-line arguments
    logging.basicConfig(
        level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    log = logging.getLogger('run_in_proton')
    pid = sys.argv[1]
    env = get_proton_env(pid)
    dump_env(env, CUSTOM_DIRENV_PATH)
