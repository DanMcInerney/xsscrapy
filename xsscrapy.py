#!/usr/bin/env python

import argparse
from scrapy.cmdline import execute
from xsscrapy.spiders.xss_spider import XSSspider

__author__ = 'Dan McInerney'
__license__ = 'BSD'
__version__ = '1.0.0'
__email__ = 'danhmcinerney@gmail.com'

def get_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--url', help="URL to scan; -u http://example.com")
    parser.add_argument('-l', '--login', help="Login name; -l danmcinerney")
    parser.add_argument('-p', '--password', help="Password; -p pa$$w0rd")
    args = parser.parse_args()
    return args

args = get_args()
url = args.url
user = args.login
password = args.password

try:
    execute(['scrapy', 'crawl', 'xsscrapy', '-a', 'url=%s' % url, '-a', 'user=%s' % user, '-a', 'pw=%s' % password])
except KeyboardInterrupt:
    sys.exit()
