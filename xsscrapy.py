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
    parser.add_argument('-r', '--rate', help="Rate in requests per minute")
    parser.add_argument('--basic', help="Use HTTP Basic Auth to login", action="store_true")
    args = parser.parse_args()
    return args

args = get_args()
url = args.url
user = args.login
password = args.password
rate = args.rate
if args.basic:
    basic = 'true'
else:
    basic = 'false'
if rate is not None:
    delay = 60 / float(rate)
else:
    delay = 0
try:
    execute(['scrapy', 'crawl', 'xsscrapy', '-a', 'url=%s' % url, '-a', 'user=%s' % user, '-a', 'pw=%s' % password, '-s', "DOWNLOAD_DELAY=%s" % delay, '-a', 'basic=%s' % basic])
except KeyboardInterrupt:
    sys.exit()
