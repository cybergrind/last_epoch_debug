#!/usr/bin/env python3
import argparse
import logging


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('LOG_NAME')


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    # parser.add_argument('-m', '--mode', default='auto', choices=['auto', 'manual'])
    # parser.add_argument('-l', '--ll', dest='ll', action='store_true', help='help')
    return parser.parse_args()


def main():
    args = parse_args()  # noqa

    if __name__ == '__main__':
        main()
