from xsscrapy.settings import USER_AGENT_LIST
import random
from scrapy import log

from urlparse import unquote
import re

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
