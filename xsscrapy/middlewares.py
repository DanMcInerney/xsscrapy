import random
from scrapy import log
from scrapy.exceptions import IgnoreRequest

from urlparse import unquote
import re
from pybloom import BloomFilter

# Filter out duplicate requests with Bloom filters since they're much easier on memory
URLS_FORMS_HEADERS = BloomFilter(3000000, 0.00001)
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
        else:
            request.headers.setdefault('User-Agent', ua)

        return

class InjectedDupeFilter(object):
    ''' Filter payloaded URLs, headers, and forms since all of those have dont_filter = True '''

    def process_request(self, request, spider):

        meta = request.meta
        if not 'type' in meta:
            return

        if meta['type'] == 'url':
            url = request.url
            if url in URLS_FORMS_HEADERS:
                print '       FILTERED  URL DUPE!!', url
                raise IgnoreRequest

            if request.callback == spider.xss_chars_finder:
                spider.log('Sending payloaded URL: %s' % url)

            URLS_FORMS_HEADERS.add(url)
            return

        elif meta['type'] == 'form':
            u = request.url
            v = meta['values']
            m = request.method
            # URL, input, payload, values
            u_v_m = (u, v, m)
            if u_v_m in URLS_FORMS_HEADERS:
                raise IgnoreRequest

            if request.callback == spider.xss_chars_finder:
                spider.log('Sending request for possibly vulnerable form to %s' % u)

            URLS_FORMS_HEADERS.add(u_v_m)
            return

        elif meta['type'] == 'header':
            u = request.url
            h = meta['inj_point']
            p = meta['payload']
            # URL, changed eader, payload
            u_h_p = (u, h, p)
            if u_h_p in URLS_FORMS_HEADERS:
                raise IgnoreRequest

            if request.callback == spider.xss_chars_finder:
                spider.log('Sending payloaded %s header, payload: %s' % (h, p))

            URLS_FORMS_HEADERS.add(u_h_p)
            return



#class Unencode_url(object):
#    ''' Fails. Not spectacularly, just doesn't do what we want '''
#    def process_request(self, request, spider):
#        test_str = '9zqjx'
#
#        try:
#            p = request.meta['payload']
#            if p == test_str:
#                return
#        except KeyError:
#            return
#
#        #regex = re.compile('%s(.*?)%s' % (test_str, test_str)
#        chars_between_delims = '%s(.*?)%s' % (test_str, test_str)
#        matches = re.findall(chars_between_delims, request.url)
#        for m in matches:
#            unq = unquote(m)
#            unq_url = request.url.replace(m, unq)
#            print '       ', unq_url
#            req = request.replace(url=unq_url)
#            print '      ', req.url



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
