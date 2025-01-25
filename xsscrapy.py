#!/usr/bin/env python

import argparse
from scrapy.cmdline import execute
from xsscrapy.spiders.xss_spider import XSSspider
import sys

__author__ = 'Dan McInerney'
__license__ = 'BSD'
__version__ = '1.0'
__email__ = 'danhmcinerney@gmail.com'


def get_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '-u', '--url', help="URL to scan; -u http://example.com")
    parser.add_argument('-l', '--login', help="Login name; -l danmcinerney")
    parser.add_argument('-p', '--password', help="Password; -p pa$$w0rd")
    parser.add_argument('-c', '--connections', default='30',
                        help="Set the max number of simultaneous connections allowed, default=30")
    parser.add_argument('-r', '--ratelimit', default='0',
                        help="Rate in requests per minute, default=0")
    parser.add_argument(
        '--basic', help="Use HTTP Basic Auth to login", action="store_true")
    parser.add_argument(
        '-k', '--cookie', help="Cookie key; --cookie SessionID=afgh3193e9103bca9318031bcdf")
    args = parser.parse_args()
    return args


def main():
    args = get_args()
    rate = args.ratelimit

    # Set rate to a calculated value if it's not None or '0'
    if rate not in {None, '0'}:
        rate = 60 / float(rate)  # Implicitly converted to string later

    try:
        cookie_key = args.cookie.split('=', 1)[0] if args.cookie else None
        cookie_value = ''.join(args.cookie.split(
            '=', 1)[1:]) if args.cookie else None

        # Prepare the command to execute
        command = [
            'scrapy', 'crawl', 'xsscrapy',
            '-a', f'url={args.url}',
            '-a', f'user={args.login}',
            '-a', f'pw={args.password}',
            '-a', f'basic={args.basic}',
            '-a', f'cookie_key={cookie_key}',
            '-a', f'cookie_value={cookie_value}',
            '-s', f'CONCURRENT_REQUESTS={args.connections}',
            '-s', f'DOWNLOAD_DELAY={rate}'
        ]

        execute(command)

    except KeyboardInterrupt:
        sys.exit()


main()
