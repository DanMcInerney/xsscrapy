from xsscrapy.settings import USER_AGENT_LIST
import random
from scrapy import log
from scrapy.contrib.downloadermiddleware.cookies import CookiesMiddleware


class RandomUserAgentMiddleware(object):
    ''' Use a random user-agent for each request '''
    def process_request(self, request, spider):
        ua  = random.choice(USER_AGENT_LIST)
        if ua:
            request.headers.setdefault('User-Agent', ua)


def new_process_request(self, request, spider):
    if 'dont_merge_cookies' in request.meta:
        return

    cl = request.headers.getlist('Cookie')
    cookiejarkey = request.meta.get("cookiejar")
    jar = self.jars[cookiejarkey]
    cookies = self._get_request_cookies(jar, request)
    for cookie in cookies:
        jar.set_cookie_if_ok(cookie, request)
    # set Cookie header
    request.headers.pop('Cookie', None)
    jar.add_cookie_header(request)

    #INSERT COOKIE MANIP HERE

    self._debug_cookie(request, spider)

#CookiesMiddleware.process_request = new_process_request
