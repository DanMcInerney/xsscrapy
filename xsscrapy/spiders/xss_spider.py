# -- coding: utf-8 --

from scrapy.contrib.linkextractors import LinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.http import FormRequest, Request
from scrapy.selector import Selector
from xsscrapy.items import inj_resp
from xsscrapy.loginform import fill_login_form
from urlparse import urlparse, parse_qsl, urljoin

from scrapy.http.cookies import CookieJar
from cookielib import Cookie

from lxml.html import soupparser, fromstring
import lxml.etree
import lxml.html
import urllib
import re
import sys
import cgi
import requests
import string
import random

#from IPython import embed

__author__ = 'Dan McInerney danhmcinerney@gmail.com'

'''
TO DO
-LONGTERM add static js analysis (check retire.js project)
-cleanup xss_chars_finder(self, response)
-prevent Requests from being URL encoded; line 57 of __init__ in Requests
class, I think, but I monkeypatched that and it didn't seem to work?)
'''

class XSSspider(CrawlSpider):
    name = 'xsscrapy'

    # If you're logging into a site with a logout link, you'll want to
    # uncomment the rule below and comment the shorter one right after to
    # prevent yourself from being logged out automatically
    #rules = (Rule(LinkExtractor(deny=('logout')), callback='parse_resp', follow=True), ) # prevent spider from hitting logout links
    rules = (Rule(LinkExtractor(), callback='parse_resp', follow=True), )

    def __init__(self, *args, **kwargs):
        # run using: scrapy crawl xss_spider -a url='http://example.com'
        super(XSSspider, self).__init__(*args, **kwargs)
        self.start_urls = [kwargs.get('url')]
        hostname = urlparse(self.start_urls[0]).hostname
        # With subdomains
        self.allowed_domains = ['.'.join(hostname.split('.')[-2:])] # adding [] around the value seems to allow it to crawl subdomain of value
        self.delim = '9zqjx'
        # semi colon goes on end because sometimes it cuts stuff off like
        # gruyere or the second cookie dleim
        self.test_str = '\'"(){}<x>:'

        self.login_user = kwargs.get('user')
        if self.login_user == 'None':
            self.login_user = None
        self.login_pass = kwargs.get('pw')
        if self.login_pass == 'None':
            self.login_pass = None

    def parse_start_url(self, response):
        ''' Creates the XSS tester requests for the start URL as well as the request for robots.txt '''
        u = urlparse(response.url)
        self.base_url = u.scheme+'://'+u.netloc
        robots_url = self.base_url+'/robots.txt'
        robot_req = [Request(robots_url, callback=self.robot_parser)]

        reqs = self.parse_resp(response)
        reqs += robot_req
        return reqs

    #### Handle logging in if username and password are given as arguments ####
    def start_requests(self):
        ''' If -a user= and -a pw= args are given, pass the first response to the login handler
            otherwise pass it to the normal callback function '''
        if self.login_user and self.login_pass:
            yield Request(url=self.start_urls[0], callback=self.login)
        else:
            yield Request(url=self.start_urls[0]) # Take out the callback arg so crawler falls back to the rules' callback

    def login(self, response):
        ''' Fill out the login form and return the request'''
        args, url, method = fill_login_form(response.url, response.body, self.login_user, self.login_pass)
        self.log('Logging in...')
        return FormRequest(url,
                           method=method,
                           formdata=args,
                           callback=self.confirm_login,
                           dont_filter=True)

    def confirm_login(self, response):
        ''' Check that the username showed up in the response page '''
        if self.login_user.lower() in response.body.lower():
            self.log('Successfully logged in (or, at least, the username showed up in the response html)')
            return Request(url=self.start_urls[0], dont_filter=True)
        else:
            self.log('FAILED to log in! (or at least cannot find the username on the post-login page which may be OK)')
            return Request(url=self.start_urls[0], dont_filter=True)
    ###########################################################################

    def robot_parser(self, response):
        ''' Parse the robots.txt file and create Requests for the disallowed domains '''
        disallowed_urls = set([])
        for line in response.body.splitlines():
            if 'disallow: ' in line.lower():
                try:
                    address = line.split()[1]
                except IndexError:
                    # In case Disallow: has no value after it
                    continue
                disallowed = self.base_url+address
                disallowed_urls.add(disallowed)
        reqs = [Request(u, callback=self.parse_resp) for u in disallowed_urls if u != self.base_url]
        for r in reqs:
            self.log('Added robots.txt disallowed URL to our queue: '+r.url)
        return reqs

    def parse_resp(self, response):
        ''' The main response parsing function, called on every response from a new URL
        Checks for XSS in headers and url'''
        reqs = []
        orig_url = response.url
        body = response.body

        try:
            # soupparser will handle broken HTML better (like identical attributes) but god damn will you pay for it
            # in CPU cycles. Slows the script to a crawl and introduces more bugs.
            doc = lxml.html.fromstring(body, base_url=orig_url)
        except lxml.etree.ParserError:
            self.log('ParserError from lxml on %s' % orig_url)
            return
        except lxml.etree.XMLSyntaxError:
            self.log('XMLSyntaxError from lxml on %s' % orig_url)
            return

        forms = doc.xpath('//form')
        payload = self.test_str

        # Grab iframe source urls if they are part of the start_url page
        iframe_reqs = self.make_iframe_reqs(doc, orig_url)
        if iframe_reqs:
            reqs += iframe_reqs

        # Edit a few select headers with injection string and resend request
        # Left room to add more header injections too
        test_headers = []
        test_headers.append('Referer')
        if 'UA' in response.meta:
            if response.meta['UA'] in body:
                test_headers.append('User-Agent')
        header_reqs = self.make_header_reqs(orig_url, payload, test_headers)
        if header_reqs:
            reqs += header_reqs

        # Edit the cookies; easier to do this in separate function from make_header_reqs()
        cookie_reqs = self.make_cookie_reqs(orig_url, payload, 'cookie')
        if cookie_reqs:
            reqs += cookie_reqs

        # Fill out forms with xss strings
        if forms:
            form_reqs = self.make_form_reqs(orig_url, forms, payload)
            if form_reqs:
                reqs += form_reqs

        # Test URL variables with xss strings
        payloaded_urls, url_delim_str = self.make_URLs(orig_url, payload) # list of tuples where item[0]=url, and item[1]=changed param
        if payloaded_urls:
            url_reqs = self.make_url_reqs(orig_url, payloaded_urls, url_delim_str)
            if url_reqs:
                reqs += url_reqs

        # Each Request here will be given a specific callback relative to whether it was URL variables or form inputs that were XSS payloaded
        return reqs

    def url_valid(self, url, orig_url):
        # Make sure there's a form action url
        if url == None:
            self.log('No form action URL found')
            return

        # Sometimes lxml doesn't read the form.action right
        if '://' not in url:
            self.log('Form URL contains no scheme, attempting to put together a working form submissions URL')
            proc_url = self.url_processor(orig_url)
            url = proc_url[1]+proc_url[0]+url

        return url

    def make_iframe_reqs(self, doc, orig_url):
        ''' Grab the <iframe src=...> attribute and add those URLs to the
        queue should they be within the start_url domain '''

        parsed_url = urlparse(orig_url)
        iframe_reqs = []
        iframes = doc.xpath('//iframe/@src')
        frames = doc.xpath('//frame/@src')

        all_frames = iframes + frames

        url = None
        for i in all_frames:
            if type(i) == unicode:
                i = str(i).strip()
            # Nonrelative path
            if '://' in i:
                # Skip iframes to outside sources
                try:
                    if self.base_url in i[:len(self.base_url)+1]:
                        url = i
                except IndexError:
                    continue
            # Relative path
            else:
                url = urljoin(orig_url, i)

            if url:
                iframe_reqs.append(Request(url))

        if len(iframe_reqs) > 0:
            return iframe_reqs

    def make_form_reqs(self, orig_url, forms, payload):
        ''' Payload each form input in each input's own request '''
        reqs = []
        vals_urls_meths = []

        two_rand_letters = random.choice(string.lowercase) + random.choice(string.lowercase)
        delim_str = self.delim + two_rand_letters
        payload = delim_str + payload + delim_str + ';9'

        for form in forms:
            if form.inputs:
                method = form.method
                url = form.action or form.base_url
                if self.url_valid(url, orig_url) and method:
                    for i in form.inputs:
                        if i.name:
                            if type(i).__name__ not in ['InputElement', 'TextareaElement']:
                                continue
                            if type(i).__name__ == 'InputElement':
                                # Don't change values for the below types because they
                                # won't be strings and lxml will complain
                                nonstrings = ['checkbox', 'radio', 'submit']
                                if i.type in nonstrings:
                                    continue
                            orig_val = form.fields[i.name]
                            if orig_val == None:
                                orig_val = ''
                            # Foriegn languages might cause this like russian "yaca" for "checkbox"
                            try:
                                form.fields[i.name] = payload
                            except ValueError as e:
                                self.log('Error: '+str(e))
                                continue
                            xss_param = i.name
                            values = form.form_values()
                            req = FormRequest(url,
                                              formdata=values,
                                              method=method,
                                              meta={'payload':payload,
                                                    'xss_param':xss_param,
                                                    'orig_url':orig_url,
                                                    'xss_place':'form',
                                                    'POST_to':url,
                                                    'delim':delim_str},
                                              dont_filter=True,
                                              callback=self.xss_chars_finder)
                            reqs.append(req)
                            # Reset the value
                            try:
                                form.fields[i.name] = orig_val
                            except ValueError as e:
                                self.log('Error: '+str(e))
                                continue

        if len(reqs) > 0:
            return reqs

    def make_cookie_reqs(self, url, payload, xss_param):
        ''' Generate payloaded cookie header requests '''

        two_rand_letters = random.choice(string.lowercase) + random.choice(string.lowercase)
        delim_str = self.delim + two_rand_letters
        payload = delim_str + payload + delim_str + ';9'

        reqs = [Request(url,
                        meta={'xss_place':'header',
                              'cookiejar':CookieJar(),
                              'xss_param':xss_param,
                              'orig_url':url,
                              'payload':payload,
                              'delim':delim_str},
                        cookies={'userinput':payload},
                        callback=self.xss_chars_finder,
                        dont_filter=True)]

        if len(reqs) > 0:
            return reqs

    def make_URLs(self, url, payload):
        ''' Add links with variables in them to the queue again but with XSS testing payloads 
        Will return a tuple: (url, injection point, payload) '''

        two_rand_letters = random.choice(string.lowercase) + random.choice(string.lowercase)
        delim_str = self.delim + two_rand_letters
        payload = delim_str + payload + delim_str + ';9'

        if '=' in url:
            # If URL has variables, payload them
            payloaded_urls = self.payload_url_vars(url, payload) 
        else:
            # If URL has no variables, tack payload onto end of URL
            payloaded_urls = self.payload_end_of_url(url, payload)

        return payloaded_urls, delim_str

    def payload_end_of_url(self, url, payload):
        ''' Payload the end of the URL to catch some DOM(?) and other reflected XSSes '''

        # Make URL test and delim strings unique
        if url[-1] == '/':
            payloaded_url = url+payload
        else:
            payloaded_url = url+'/'+payload

        return [(payloaded_url, 'end of url', payload)]

    def payload_url_vars(self, url, payload):
        ''' Payload the URL variables '''
        payloaded_urls = []
        params = self.getURLparams(url)
        modded_params = self.change_params(params, payload)
        netloc, protocol, doc_domain, path = self.url_processor(url)
        if netloc and protocol and path:
            for payload in modded_params:
                for params in modded_params[payload]:
                    joinedParams = urllib.urlencode(params, doseq=1) # doseq maps the params back together
                    newURL = urllib.unquote(protocol+netloc+path+'?'+joinedParams)

                    # Prevent nonpayloaded URLs
                    if self.test_str not in newURL:
                        continue

                    for p in params:
                        if p[1] == payload:
                            changed_value = p[0]

                    payloaded_urls.append((newURL, changed_value, payload))

        if len(payloaded_urls) > 0:
            return payloaded_urls

    def getURLparams(self, url):
        ''' Parse out the URL parameters '''
        parsedUrl = urlparse(url)
        fullParams = parsedUrl.query
        params = parse_qsl(fullParams) #parse_qsl rather than parse_ps in order to preserve order
        return params

    def change_params(self, params, payload):
        ''' Returns a list of complete parameters, each with 1 parameter changed to an XSS vector '''
        changedParams = []
        changedParam = False
        moddedParams = []
        allModdedParams = {}

        # Create a list of lists, each list will be the URL we will test
        # This preserves the order of the URL parameters and will also
        # test each parameter individually instead of all at once
        allModdedParams[payload] = []
        for x in xrange(0, len(params)):
            for p in params:
                param = p[0]
                value = p[1]
                # If a parameter has not been modified yet
                if param not in changedParams and changedParam == False:
                    newValue = payload
                    changedParams.append(param)
                    p = (param, newValue)
                    moddedParams.append(p)
                    changedParam = param
                else:
                    moddedParams.append(p)

            # Reset so we can step through again and change a diff param
            #allModdedParams[payload].append(moddedParams)
            allModdedParams[payload].append(moddedParams)

            changedParam = False
            moddedParams = []

        # Reset the list of changed params each time a new payload is attempted
        changedParams = []

        if len(allModdedParams) > 0:
            return allModdedParams

    def url_processor(self, url):
        ''' Get the url domain, protocol, and netloc using urlparse '''
        try:
            parsed_url = urlparse(url)
            # Get the path
            path = parsed_url.path
            # Get the protocol
            protocol = parsed_url.scheme+'://'
            # Get the hostname (includes subdomains)
            hostname = parsed_url.hostname
            # Get netlock (domain.com:8080)
            netloc = parsed_url.netloc
            # Get doc domain
            doc_domain = '.'.join(hostname.split('.')[-2:])
        except:
            self.log('Could not parse url: '+url)
            return

        return (netloc, protocol, doc_domain, path)

    def make_url_reqs(self, orig_url, payloaded_urls, delim_str):
        ''' Make the URL requests '''

        reqs = [Request(url[0],
                        meta={'xss_place':'url',
                              'xss_param':url[1],
                              'orig_url':orig_url,
                              'payload':url[2],
                              'delim':delim_str},
                        callback = self.xss_chars_finder)
                        for url in payloaded_urls] # Meta is the payload

        if len(reqs) > 0:
            return reqs

    def make_header_reqs(self, url, payload, inj_headers):
        ''' Generate header requests '''

        two_rand_letters = random.choice(string.lowercase) + random.choice(string.lowercase)
        delim_str = self.delim + two_rand_letters
        payload = delim_str + payload + delim_str + ';9'

        reqs = [Request(url,
                        headers={inj_header:payload},
                        meta={'xss_place':'header',
                              'xss_param':inj_header,
                              'orig_url':url,
                              'payload':payload,
                              'delim':delim_str,
                              'UA':self.get_user_agent(inj_header, payload)},
                        dont_filter=True,
                        callback = self.xss_chars_finder)
                for inj_header in inj_headers]

        if len(reqs) > 0:
            return reqs

    def get_user_agent(self, header, payload):
        if header == 'User-Agent':
            return payload
        else:
            return ''

    def xss_chars_finder(self, response):
        ''' Find which chars, if any, are filtered '''

        item = inj_resp()
        item['resp'] = response
        return item
