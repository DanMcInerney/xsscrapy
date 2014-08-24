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
        if 'User-Agent' in request.headers:
            # Make sure we're not testing the UA for injection before setting a random UA
            if '9zqjx' not in request.headers['User-Agent']:
                request.headers.setdefault('User-Agent', ua)
                request.meta['UA'] = ua
        else:
            request.headers.setdefault('User-Agent', ua)
            request.meta['UA'] = ua

        return

class InjectedDupeFilter(object):
    ''' Filter duplicate payloaded URLs, headers, and forms since all of those have dont_filter = True '''

    def process_request(self, request, spider):

        meta = request.meta
        if not 'type' in meta:
            return

        # Injected URL dupe handling
        if meta['type'] == 'url':
            url = request.url
            if url in URLS_SEEN:
                raise IgnoreRequest

            if request.callback == spider.xss_chars_finder:
                spider.log('Sending payloaded URL: %s' % url)

            URLS_SEEN.add(url)
            return

        # Injected form dupe handling
        elif meta['type'] == 'form':
            u = request.url
            v = meta['values']
            m = request.method
            # URL, input, payload, values
            u_v_m = (u, v, m)
            if u_v_m in FORMS_SEEN:
                raise IgnoreRequest

            if request.callback == spider.xss_chars_finder:
                spider.log('Sending request for possibly vulnerable form to %s' % u)

            FORMS_SEEN.add(u_v_m)
            return

        # Injected header dupe handling
        elif meta['type'] == 'header':
            u = request.url
            h = meta['inj_point']
            p = meta['payload']
            # URL, changed header, payload
            u_h_p = (u, h, p)
            if u_h_p in HEADERS_SEEN:
                raise IgnoreRequest

            elif request.callback == spider.xss_chars_finder:
                spider.log('Sending payloaded %s header, payload: %s' % (h, p))

            HEADERS_SEEN.add(u_h_p)
            return

class Test(object):
    def process_request(self, request, spider):
        print '   UA:', request.headers['User-Agent']

#def new_process_request(self, request, spider):
#    if 'dont_merge_cookies' in request.meta:
#        return
#
#    cl = request.headers.getlist('Cookie')
#    cookiejarkey = request.meta.get("cookiejar")
#    jar = self.jars[cookiejarkey]
#    cookies = self._get_request_cookies(jar, request)
#    for cookie in cookies:
#        jar.set_cookie_if_ok(cookie, request)
#    # set Cookie header
#    request.headers.pop('Cookie', None)
#    jar.add_cookie_header(request)
#
#    #INSERT COOKIE MANIP HERE
#
#    self._debug_cookie(request, spider)

#CookiesMiddleware.process_request = new_process_request
