# -- coding: utf-8 --

from scrapy.contrib.linkextractors import LinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.http import FormRequest, Request
from scrapy.selector import Selector
#from xsscrapy.http import Request
from xsscrapy.items import inj_resp
from xsscrapy.loginform import fill_login_form
from urlparse import urlparse, parse_qsl, urljoin

from scrapy.http.cookies import CookieJar
from cookielib import Cookie

import lxml.html
import lxml.etree
import urllib
import re
import sys
import cgi
import requests

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
        self.allowed_domains = ['.'.join(hostname.split('.')[-2:])] # adding [] around the value seems to allow it to crawl subdomain of value
        self.test_str = '9zqjx'
        self.test_pld = '\'"()=<x>'
        self.js_pld = '\'"(){}[];'
        self.redir_pld = 'JaVAscRIPT:prompt(99)'

        self.login_user = kwargs.get('user')
        self.login_pass = kwargs.get('pw')

    def parse_start_url(self, response):
        ''' Creates the XSS tester requests for the start URL as well as the request for robots.txt '''
        u = urlparse(response.url)
        self.base_url = u.scheme+'://'+u.hostname
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
            doc = lxml.html.fromstring(body, base_url=orig_url)
        except lxml.etree.ParserError:
            self.log('ParserError from lxml on %s' % orig_url)
            return
        except lxml.etree.XMLSyntaxError:
            self.log('XMLSyntaxError from lxml on %s' % orig_url)
            return

        forms = doc.xpath('//form')
        quote_enclosure = self.single_or_double_quote(body)
        payload = self.test_str
        payloads = [payload]

        # Grab iframe source urls if they are part of the start_url page
        iframe_reqs = self.make_iframe_reqs(doc, orig_url)
        if iframe_reqs:
            reqs += iframe_reqs

        # Edit a few select headers with injection string and resend request
        header = 'Referer'
        header_reqs = self.make_header_reqs(orig_url, payloads, header, quote_enclosure, None)
        if header_reqs:
            reqs += header_reqs

        # Edit the cookies; easier to do this in separate function from make_header_reqs()
        cookie_reqs = self.make_cookie_reqs(orig_url, payloads, 'cookie', quote_enclosure, None)
        if cookie_reqs:
            reqs += cookie_reqs

        # Fill out forms with xss strings
        if forms:
            form_reqs = self.make_form_reqs(orig_url, forms, payloads, quote_enclosure, None)
            if form_reqs:
                reqs += form_reqs

        # Test URL variables with xss strings
        payloaded_urls = self.make_URLs(orig_url, payloads) # list of tuples where item[0]=url, and item[1]=changed param
        if payloaded_urls:
            url_reqs = self.make_url_reqs(orig_url, payloaded_urls, quote_enclosure, None)
            if url_reqs:
                reqs += url_reqs

        # Each Request here will be given a specific callback relative to whether it was URL variables or form inputs that were XSS payloaded
        return reqs

    def make_iframe_reqs(self, doc, orig_url):
        parsed_url = urlparse(orig_url)
        iframe_reqs = []
        iframes = doc.xpath('//iframe/@src')
        for i in iframes:
            if type(i) == unicode:
                i = str(i).strip()
            # Nonrelative path
            if '://' in i:
                # Skip iframes to outside sources
                try:
                    if self.base_url not in i[:len(self.base_url)+1]:
                        continue
                except IndexError:
                    continue
            # Relative path
            else:
                url = urljoin(orig_url, i)

            iframe_reqs.append(Request(url))

        if len(iframe_reqs) > 0:
            return iframe_reqs

    def encode_payloads(self, payloads, method):
        ''' Until I can get the request url to not be URL encoded, script will
        not encode payloads '''
        #html_encoded = cgi.escape(payloads[0], quote=True)
        #if html_encoded != payloads[0]:
        #    payloads.append(html_encoded)

        # I don't think URL encoding the dangerous chars is all that important
        #if method == 'GET':
        #    url_encoded = urllib.quote_plus(payloads[0])
        #    if url_encoded != payloads[0]:
        #        payloads.append(url_encoded)

        return payloads

    def check_form_validity(self, values, url, payload, orig_url):
        ''' Make sure the form action url and values are valid/exist '''

        # Make sure there's a form action url
        if url == None:
            self.log('No form action URL found')
            return

        # Make sure there are values to even change
        if len(values) == 0:
            return

        # Make sure at least one value has been injected
        if not self.injected_val_confirmed(values, payload):
            return

        # Sometimes lxml doesn't read the form.action right
        if '://' not in url:
            self.log('Form URL contains no scheme, attempting to put together a working form submissions URL')
            proc_url = self.url_processor(orig_url)
            url = proc_url[1]+proc_url[0]+url

        return url

    def fill_form(self, url, form, payload):
        ''' Fill out all relevant form input boxes with payload '''
        if form.inputs:
            for i in form.inputs:
                # Only change the value of input and text boxes
                if type(i).__name__ not in ['InputElement', 'TextareaElement']:
                    continue
                if type(i).__name__ == 'InputElement':
                    # Don't change values for the below types because they
                    # won't be strings
                    nonstrings = ['checkbox', 'radio', 'submit']
                    if i.type in nonstrings:
                        continue
                if i.name:
                    form.fields[i.name] = payload

            values = form.form_values()

            return values, form.action or form.base_url, form.method

    def injected_val_confirmed(self, values, payload):
        for v in values:
            if payload in v:
                return True
        return

    def dupe_form(self, values, url, method, payload):
        ''' True if the modified values/url/method are identical to a previously sent form '''
        injected_vals = []
        for v in values:
            if payload in v:
                injected_vals.append(v)
                sorted(injected_vals)
        injected_values = tuple(injected_vals)
        vam = (injected_values, url, method)
        vamset = set([(vam)])
        if vamset.issubset(self.form_requests_made):
            return True
        self.form_requests_made.add(vam)
        return

    def make_form_payloads(self, response):
        ''' Create the payloads based on the injection points from the first test request'''
        orig_url = response.meta['orig_url']
        payload = response.meta['payload']
        quote_enclosure = response.meta['quote']
        inj_type = response.meta['type']
        forms = response.meta['forms']
        body = response.body
        resp_url = response.url
        try:
            doc = lxml.html.fromstring(body)
        except lxml.etree.XMLSyntaxError:
            self.log('XML Syntax Error on %s' % resp_url)
            return

        injections = self.inj_points(payload, doc)
        if injections:
            payloads = self.xss_str_generator(injections, quote_enclosure, inj_type)
            if payloads:
                form_reqs = self.make_form_reqs(orig_url, forms, payloads, quote_enclosure, injections)
                if form_reqs:
                    return form_reqs
        return

    def make_URLs(self, url, payloads):
        ''' Add links with variables in them to the queue again but with XSS testing payloads 
        Will return a tuple: (url, injection point, payload) '''

        if '=' in url:
            # If URL has variables, payload them
            payloaded_urls = self.payload_url_vars(url, payloads) 
        else:
            # If URL has no variables, tack payload onto end of URL
            payloaded_urls = self.payload_end_of_url(url, payloads)

        if payloaded_urls:
            return payloaded_urls

    def payload_end_of_url(self, url, payloads):
        ''' Payload the end of the URL to catch some DOM and other reflected XSSes '''
        payloaded_urls = []

        for payload in payloads:
            if url[-1] == '/':
                payloaded_url = url+payload
            else:
                payloaded_url = url+'/'+payload
            payloaded_urls.append((payloaded_url, 'end of URL', payload))

        if len(payloaded_urls) > 0:
            return payloaded_urls

    def payload_url_vars(self, url, payloads):
        ''' Payload the URL variables '''
        payloaded_urls = []
        params = self.getURLparams(url)
        modded_params = self.change_params(params, payloads)
        hostname, protocol, doc_domain, path = self.url_processor(url)
        if hostname and protocol and path:
            for payload in modded_params:
                for params in modded_params[payload]:
                    joinedParams = urllib.urlencode(params, doseq=1) # doseq maps the params back together
                    newURL = urllib.unquote(protocol+hostname+path+'?'+joinedParams)

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

    def change_params(self, params, payloads):
        ''' Returns a list of complete parameters, each with 1 parameter changed to an XSS vector '''
        changedParams = []
        changedParam = False
        moddedParams = []
        allModdedParams = {}

        # Create a list of lists, each list will be the URL we will test
        # This preserves the order of the URL parameters and will also
        # test each parameter individually instead of all at once
        for payload in payloads:
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
        else:
            return

    def url_processor(self, url):
        ''' Get the url domain, protocol, and hostname using urlparse '''
        try:
            parsed_url = urlparse(url)
            # Get the path
            path = parsed_url.path
            # Get the protocol
            protocol = parsed_url.scheme+'://'
            # Get the hostname (includes subdomains)
            hostname = parsed_url.hostname
            # Get doc domain
            doc_domain = '.'.join(hostname.split('.')[-2:])
        except:
            self.log('Could not parse url: '+url)
            return

        return (hostname, protocol, doc_domain, path)

    def inj_points(self, payload, doc):
        ''' Use some xpaths to find injection points in the lxml-formatted doc '''
        injections = []
        attr_xss = doc.xpath("//@*[contains(., '%s')]" % payload)
        attr_inj = self.parse_attr_xpath(attr_xss)
        text_xss = doc.xpath("//*[contains(text(), '%s')]" % payload)
        tag_inj = self.parse_tag_xpath(text_xss)
        # If the response page is just plain text then tag_inj might miss some reflected payloads
        try:
            anywhere_text = doc.xpath("//text()")
        except UnicodeDecodeError:
            self.log('Could not utf8 decode character')
            return
        any_text_inj = self.parse_anytext_xpath(anywhere_text, payload)

        if len(attr_inj) > 0:
            for a in attr_inj:
                injections.append(a)
        if len(tag_inj) > 0:
            for t in tag_inj:
                injections.append(t)

        # anywhere_text injections can't exist in attributes so we only compare anywhere_text to tag_inj
        diff = [x for x in any_text_inj if x not in tag_inj]
        if len(diff) > 0:
            for i in diff:
                injections.append(i)
        if len(injections) > 0:
            return sorted(injections)

    def xss_str_generator(self, injections, quote_enclosure, inj_type):
        ''' This is where the injection points are analyzed and specific payloads are created '''

        payloads = []

        for i in injections:
            line, tag, attr, attr_val = self.parse_injections(i)

            if attr:
                # Test for open redirect/XSS
                if attr == 'href' and attr_val == self.test_str:
                    if self.redir_pld not in payloads:
                        payloads.append(self.redir_pld)
            else:
                # Test for embedded js xss
                if tag == 'script' and self.js_pld not in payloads:
                    payloads.append(self.js_pld)

            # Test for normal XSS
            if self.test_pld not in payloads:
                payloads.append(self.test_pld)

        payloads = self.delim_payloads(payloads)
        if len(payloads) > 0:
            return payloads

    def delim_payloads(self, payloads):
        ''' Surround the payload with a delimiter '''
        payload_list = []
        for p in payloads:
            payload_list.append(self.test_str+p+self.test_str)
        payloads = list(set(payload_list)) # remove dupes

        return payloads

    def make_item(self, joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line, POST_to, item):
        ''' Create the vulnerable item '''

        item['line'] = line
        item['xss_payload'] = orig_payload
        item['unfiltered'] = joined_chars
        item['inj_point'] = inj_point
        item['xss_type'] = xss_type
        item['inj_tag'] = tag
        item['url'] = orig_url
        if POST_to:
            item['POST_to'] = POST_to
        return item

    def parse_injections(self, injection):
        attr = None
        attr_val = None
        line = injection[0]
        tag = injection[1]
        if len(injection) > 2: # attribute injections have 4 data points within this var
            attr = injection[2]
            attr_val = injection[3]

        return line, tag, attr, attr_val

    def parse_attr_xpath(self, xpath):
        attr_inj = []
        if len(xpath) > 0:
            for x in xpath:
                for y in x.getparent().items():
                    if x == y[1]:
                        tag = x.getparent().tag
                        attr = y[0]
                        line = x.getparent().sourceline
                        attr_val = x
                        attr_inj.append((line, tag, attr, attr_val))
        return attr_inj

    def parse_tag_xpath(self, xpath):
        tag_inj = []
        if len(xpath) > 0:
            tags = []
            for x in xpath:
                tag_inj.append((x.sourceline, x.tag))
        return tag_inj

    def parse_anytext_xpath(self, xpath, payload):
        ''' Creates injection points for the xpath that finds the payload in any html enclosed text '''
        anytext_inj = []
        if len(xpath) > 0:
            for x in xpath:
                if payload in x:
                    parent = x.getparent()
                    tag = parent.tag
                    line = parent.sourceline
                    anytext_inj.append((line, tag))
        return anytext_inj

    def event_attributes(self):
        ''' HTML tag attributes that allow javascript TAKEN OUT AT THE MOMENT'''

        event_attributes = ['onafterprint', 'onbeforeprint', 'onbeforeunload', 'onerror',
                            'onhaschange', 'onload', 'onmessage', 'onoffline', 'ononline',
                            'onpagehide', 'onpageshow', 'onpopstate', 'onredo', 'onresize',
                            'onstorage', 'onundo', 'onunload', 'onblur', 'onchange',
                            'oncontextmenu', 'onfocus', 'onformchange', 'onforminput',
                            'oninput', 'oninvalid', 'onreset', 'onselect', 'onsubmit',
                            'onkeydown', 'onkeypress', 'onkeyup', 'onclick', 'ondblclick',
                            'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover',
                            'ondragstart', 'ondrop', 'onmousedown', 'onmousemove',
                            'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel',
                            'onscroll', 'onabort', 'oncanplay', 'oncanplaythrough',
                            'ondurationchange', 'onemptied', 'onended', 'onerror',
                            'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onpause',
                            'onplay', 'onplaying', 'onprogress', 'onratechange',
                            'onreadystatechange', 'onseeked', 'onseeking', 'onstalled',
                            'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting']
        return event_attributes

    def make_url_reqs(self, orig_url, payloaded_urls, quote_enclosure, injections):
        ''' Make the URL requests '''

        reqs = [Request(url[0],
                        meta={'type':'url',
                              'inj_point':url[1],
                              'orig_url':orig_url,
                              'payload':url[2],
                              'quote':quote_enclosure})
                        for url in payloaded_urls] # Meta is the payload

        reqs = self.add_callback(injections, reqs)

        if reqs:
            return reqs

    def make_header_reqs(self, url, payloads, header, quote_enclosure, injections):
        ''' Generate header requests '''

        reqs = [Request(url,
                        headers={header:payload},
                        meta={'type':'header',
                              'inj_point':header,
                              'orig_url':url,
                              'payload':payload,
                              'quote':quote_enclosure},
                        dont_filter=True)
                for payload in payloads]

        reqs = self.add_callback(injections, reqs)

        if len(reqs) > 0:
            return reqs

    def make_cookie_reqs(self, url, payloads, inj_point, quote_enclosure, injections):
        ''' Generate payloaded cookie header requests '''

        reqs = [Request(url,
                        meta={'type':'header',
                              #'dont_merge_cookies':True,
                              'cookiejar':CookieJar(),
                              'inj_point':inj_point,
                              'orig_url':url,
                              'payload':payload,
                              'quote':quote_enclosure},
                        cookies={'cookie_test':payload},
                        dont_filter=True)
                        for payload in payloads]

        reqs = self.add_callback(injections, reqs)

        if len(reqs) > 0:
            return reqs

    def add_callback(self, injections, reqs):
        ''' Add the callback to the requests depending on if it's a test req or payloaded req '''

        if injections:
            for r in reqs:
                # If its got injection points in the meta data then it needs to go to the dangerous char finder
                r.meta['injections'] = injections
                r.callback = self.xss_chars_finder
        else:
            for r in reqs:
                r.callback = self.payloaded_reqs

        return reqs

    def payloaded_reqs(self, response):
        ''' Create the payloaded requests '''
        body = response.body
        orig_url = response.meta['orig_url']
        try:
            doc = lxml.html.fromstring(body)
        except lxml.etree.XMLSyntaxError:
            self.log('Python html-parsing library lxml failed to parse %s' % orig_url)
            return

        reqs = []
        inj_type = response.meta['type']
        inj_point = response.meta['inj_point'] #header name for header req, just 'form' for form req, url param for url req
        payloads = [response.meta['payload']]
        quote_enclosure = response.meta['quote']
        ua = response.meta['UA']
        forms = doc.xpath('//form')
        resp_url = response.url

        # Check if the user agent is reflected in the source code
        if ua in body:
            payloads += [ua]

        for payload in payloads:
            injections = self.inj_points(payload, doc)
            if injections:

                if payload == ua:
                    inj_type = 'header'
                    inj_point = 'User-Agent'

                xss_payloads = self.xss_str_generator(injections, quote_enclosure, inj_type)
                if xss_payloads:

                    if inj_type == 'header' :
                        # Make XSS payloaded cookie reqs
                        if inj_point == 'cookie':
                            cookie_reqs = self.make_cookie_reqs(orig_url, xss_payloads, inj_point, quote_enclosure, injections)
                            if cookie_reqs:
                                reqs += cookie_reqs
                        # Make XSS payloaded header reqs (user agent or referer)
                        else:
                            header_reqs = self.make_header_reqs(orig_url, xss_payloads, inj_point, quote_enclosure, injections)
                            if header_reqs:
                                reqs += header_reqs

                    elif inj_type == 'url':
                        payloaded_urls = self.make_URLs(orig_url, xss_payloads) # list of tuples where item[0]=url, item[1]=changed param, item[2]=payload
                        if payloaded_urls:
                            url_reqs = self.make_url_reqs(orig_url, payloaded_urls, quote_enclosure, injections)
                            if url_reqs:
                                reqs += url_reqs

                    elif inj_type == 'form':
                        form_reqs = self.make_form_reqs(orig_url, forms, xss_payloads, quote_enclosure, injections)
                        if form_reqs:
                            reqs += form_reqs

        if len(reqs) > 0:
            return reqs

    def make_form_reqs(self, orig_url, forms, payloads, quote_enclosure, injections):
        ''' Logic: Get forms, find injectable input values, confirm at least one value has been injected,
        confirm that value + url + POST/GET has not been made into a request before, finally send the request 
        Note: if you see lots and lots of errors when POSTing, it is probably because of captchas'''
        reqs = []
        vals_urls_meths = []

        for form in forms:
            payloads = self.encode_payloads(payloads, form.method)
            for payload in payloads:
                url = None
                values, url, method = self.fill_form(orig_url, form, payload)
                url = self.check_form_validity(values, url, payload, orig_url)
                if not url:
                    continue
                # Get form field names
                form_fields = ', '.join([f for f in form.fields])
                if payload == self.test_str:
                    cb = self.make_form_payloads
                else:
                    cb = self.xss_chars_finder

                # POST to both the orig url and the specified form action='http://url.com' url
                # Just to prevent false negatives
                if url != orig_url:
                    urls = [url, orig_url]
                else:
                    urls = [url]

                # Make the payloaded requests
                req = [FormRequest(url,
                                  callback=cb,
                                  formdata=values,
                                  method=method,
                                  meta={'payload':payload,
                                        'inj_point':'form field names - '+form_fields,
                                        'injections':injections,
                                        'quote':quote_enclosure,
                                        'orig_url':orig_url,
                                        'forms':forms,
                                        'type':'form',
                                        'POST_to':url,
                                        'values':values},
                                  dont_filter = True)
                        for url in urls]

                reqs += req

        if len(reqs) > 0:
            return reqs

    def single_or_double_quote(self, body):
        ''' I feel like this function is poorly written. At least it seems reliable. '''
        quote = re.search('<a href=(.)', body)
        if quote == None:
            quote = re.search('<link href=(.)', body)
        try:
            quote = quote.group(1)
        except AttributeError:
            squote = re.findall('.=(\')', body)
            dquote = re.findall('.=(")', body)
            if len(squote) > len(dquote):
                quote = "'"
            else:
                quote = '"'

        if quote not in ['"', "'"]:
            quote = '"'

        return quote

    def xss_chars_finder(self, response):
        ''' Find which chars, if any, are filtered '''

        item = inj_resp()
        item['resp'] = response
        return item
