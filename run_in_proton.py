#!/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('run_in_proton')
PROTON_PATH = None


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


def detect_running_proton():
    pass




def get_wpid(linux_pid):
    """
    Get the Windows PID of a process running in Proton.
    :param linux_pid: The Linux PID of the process.
    :return: The Windows PID of the process.
    """
    # Get the Windows PID of the process using Proton's wpid command
    try:
        result = subprocess.run(['proton', 'wpid', str(linux_pid)], capture_output=True, text=True)
        if result.returncode != 0:
            log.error(f"Failed to get Windows PID for Linux PID {linux_pid}: {result.stderr}")
            return None
        return int(result.stdout.strip())
    except Exception as e:
        log.error(f"Error getting Windows PID: {e}")
        return None


COMMANDS = {
    'get-wpid'
}

def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    # process name
    parser.add_argument('-p', '--process', required=False, help='Process name')
    parser.add_argument('command', nargs=argparse.REMAINDER, help='Command to run')
    # parser.add_argument('-m', '--mode', default='auto', choices=['auto', 'manual'])
    # parser.add_argument('-l', '--ll', dest='ll', action='store_true', help='help')
    return parser.parse_args()


def main():
    args = parse_args()


if __name__ == '__main__':
    main()


