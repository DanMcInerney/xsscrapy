from scrapy.exceptions import IgnoreRequest
from urlparse import unquote
from pybloom import BloomFilter
import random
import re

# Filter out duplicate requests with Bloom filters since they're much easier on memory
#URLS_FORMS_HEADERS = BloomFilter(3000000, 0.00001)
URLS_SEEN = BloomFilter(300000, .0001)
FORMS_SEEN = BloomFilter(300000, .0001)
HEADERS_SEEN = BloomFilter(300000, .0001)
USER_AGENT_LIST = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0']

class RandomUserAgentMiddleware(object):
    ''' Use a random user-agent for each request '''
    def process_request(self, request, spider):
        ua = random.choice(USER_AGENT_LIST)
        if 'payload' in request.meta:
            payload = request.meta['payload']
            if 'User-Agent' in request.headers:
                if payload == request.headers['User-Agent']:
                    return

        request.headers.setdefault('User-Agent', ua)
        request.meta['UA'] = ua

class InjectedDupeFilter(object):
    ''' Filter duplicate payloaded URLs, headers, and forms since all of those have dont_filter = True '''

    def process_request(self, request, spider):

        meta = request.meta
        if 'xss_place' not in meta:
            return
        delim = meta['delim']

        # Injected URL dupe handling
        if meta['xss_place'] == 'url':
            url = request.url
            #replace the delim characters with nothing so we only test the URL
            #with the payload
            no_delim_url = url.replace(delim, '')
            if no_delim_url in URLS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded URL: %s' % url)
            URLS_SEEN.add(url)
            return

        # Injected form dupe handling
        elif meta['xss_place'] == 'form':
            u = meta['POST_to']
            p = meta['xss_param']
            u_p = (u, p)
            if u_p in FORMS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded form param %s to: %s' % (p, u))
            FORMS_SEEN.add(u_p)
            return

        # Injected header dupe handling
        elif meta['xss_place'] == 'header':
            u = request.url
            h = meta['xss_param']
            # URL, changed header, payload
            u_h = (u, h)
            if u_h in HEADERS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded %s header' % h)
            HEADERS_SEEN.add(u_h)
            return
