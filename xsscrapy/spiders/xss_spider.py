from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.selector import Selector
from scrapy.http import Request, FormRequest

from xsscrapy.items import vuln
from loginform import fill_login_form

from urlparse import urlparse, parse_qsl
import lxml.html
import urllib
import re
import sys

from IPython import embed


'''
xss headers:
cookie
agent
data control
'''

class XSSspider(CrawlSpider):
    name = 'xss_spider'
    #allowed_domains = ['']
    #start_urls = ['']

    #rules = (Rule(SgmlLinkExtractor(deny=('logout')), callback='parse_resp', follow=True), ) # prevent spider from hitting logout links
    rules = (Rule(SgmlLinkExtractor(), callback='parse_resp', follow=True), )

    def __init__(self, *args, **kwargs):
        # run using: scrapy crawl xss_spider -a url='http://something.com'
        super(XSSspider, self).__init__(*args, **kwargs)
        self.start_urls = [kwargs.get('url')]
        hostname = urlparse(self.start_urls[0]).hostname
        self.allowed_domains = ['.'.join(hostname.split('.')[-2:])] # adding [] around the value seems to allow it to crawl subdomain of value
        self.test_str = '9zqjx'
        self.tag_pld = '()=<>'
        self.js_pld = '\\\'\\"(){}[];'
        self.redir_pld = 'JaVAscRIPT:prompt(99)'
        #attr_pld = generated once injection points are found (requires checking if single or double quotes ends html attribute values)
        self.form_requests_made = set()

        self.login_user = kwargs.get('user')
        self.login_pass = kwargs.get('pw')

    def parse_start_url(self, response):
        return list(self.parse_resp(response))

    #### Handle logging in if username and password are given as arguments ####
    def start_requests(self):
        if self.login_user and self.login_pass:
            yield Request(url=self.start_urls[0], callback=self.login)
        else:
            yield Request(url=self.start_urls[0]) # Take out the callback arg so crawler falls back to the rules' callback

    def login(self, response):
        args, url, method = fill_login_form(response.url, response.body, self.login_user, self.login_pass)
        self.log('Logging in...')
        return FormRequest(url,
                           method=method,
                           formdata=args,
                           callback=self.confirm_login,
                           dont_filter=True)

    def confirm_login(self, response):
        if self.login_user.lower() in response.body.lower():
            self.log('Successfully logged in (or, at least, the username showed up in the response html)')
            return Request(url=self.start_urls[0], dont_filter=True)
        else:
            self.log('FAILED to log in! (or at least cannot find the username on the post-login page which may be OK)')
            return Request(url=self.start_urls[0], dont_filter=True)
    ############################################################################

    def parse_resp(self, response):
        resp_url = response.url
        body = response.body
        doc = lxml.html.fromstring(body, base_url=resp_url)
        forms = doc.xpath('//form')
        reqs = []
        payload = self.test_str

        # Edit a few select headers with injection string and resend request
        header_reqs = [Request(resp_url,
                               headers={'Referer':self.test_str,
                                        'User-Agent':self.test_str},
                               callback=self.make_header_reqs,
                               meta={'type':'headers',
                                     'payload':self.test_str},
                               dont_filter=True)]
        reqs += header_reqs

        # Fill out forms with xss strings
        if forms:
            form_reqs = self.make_form_reqs(forms, resp_url, payload, injections=None, quote_enclosure=None)
            reqs += form_reqs

        # Test URL variables with xss strings
        if '=' in resp_url:
            payloaded_urls = self.makeURLs(resp_url, payload)
            if payloaded_urls:
                payloaded_reqs = [Request(url,
                                          callback=self.url_xss_reqs,
                                          meta={'payload':self.test_str,
                                                'resp_url':url})
                                  for url in payloaded_urls] # Meta is the payload
                reqs += payloaded_reqs

        # Each Request here will be given a specific callback relative to whether it was URL variables or form inputs that were XSS payloaded
        return reqs

    def make_header_reqs(self, response):
        ''' Creates a duplicate request for each link found with injected referer and UA headers '''
        resp_url = response.url
        body = response.body
        doc = lxml.html.fromstring(body)
        quote_enclosure = self.single_or_double_quote(body)
        payload = response.meta['payload']
        reqs = []

        if payload in body:
            injections = self.inj_points(payload, doc)
            payloads = self.xss_str_generator(injections, quote_enclosure)

            reqs = [Request(resp_url,
                            headers={'Referer':pload, 'User-Agent':pload},
                            callback=self.xss_chars_finder,
                            meta={'payload':pload,
                                  'resp_url':url,
                                  'quote':quote_enclosure,
                                  'type':'headers'},
                            dont_filter=True)
                            for pload in payloads]
        for r in reqs:
            print r
        return reqs

    def make_form_reqs(self, forms, resp_url, payloads, injections, quote_enclosure):
        ''' Logic: Get forms, find injectable input values, confirm at least one value has been injected,
        confirm that value + url + POST/GET has not been made into a request before, finally send the request '''
        reqs = []
        vals_urls_meths = []
        url = None

        test_or_payload = 'payload'
        if type(payloads) == str: # type(payloads) is not a list
            test_or_payload = 'test'
            payloads = [payloads]

        for payload in payloads:
            for form in forms:

                values, url, method = self.fill_form(resp_url, form, payload)
                url = self.check_form_validity(values, url, payload, resp_url)
                if not url:
                    continue

                if not self.dupe_form(values, url, method, payload):
                    # Make the payloaded requests, dont_filter = True because scrapy treats url encoded data as == to nonurl encoded
                    if test_or_payload == 'test':
                        cb = self.form_cb
                    elif test_or_payload == 'payload':
                        cb = self.xss_chars_finder
                    req = FormRequest(url,
                                      callback=cb,
                                      formdata=values,
                                      method=method,
                                      meta={'payload':payload,
                                            'injections':injections,
                                            'quote':quote_enclosure,
                                            'resp_url':resp_url,
                                            'type':'form'},
                                      dont_filter = True)

                    self.log('Created request for possibly vulnerable form')
                    reqs.append(req)

        return reqs

    def check_form_validity(self, values, url, payload, resp_url):
        ''' Make sure the form action url and values are valid/exist '''

        # Make sure there are values to even change
        if len(values) == 0:
            self.log('No values changed, aborting this form test')
            return

        # Make sure at least one value has been injected
        if not self.injected_val_confirmed(values, payload):
            self.log('Form contains no injected values: %s' % resp_url)
            return

        if url == None:
            self.log('No form action URL found')
            return
        # Sometimes lxml doesn't read the form.action right
        if '://' not in url:
            self.log('Form URL contains no scheme, attempting to put together a working form submissions URL')
            proc_url = self.url_processor(resp_url)
            url = proc_url[1]+proc_url[0]+url

        return url

    def fill_form(self, url, form, payload):
        if form.inputs:
            for i in form.inputs:
                if not self.input_filter(i):
                    continue
                # Keep submit input value the same
                if i.type == 'submit':
                    continue
                if 'InputElement' in str(type(i)): # gotta be a better way to do this
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

    def input_filter(self, form_input):
        ''' Get rid of the form inputs that won't carry an xss '''
        if not isinstance(form_input, lxml.html.InputElement):
            return
        if form_input.type == 'password':
            return
        if form_input.type == 'checkbox':
            return
        if form_input.type == 'radio':
            return
        return True

    def form_cb(self, response):
        orig_url = response.meta['resp_url']
        payload = response.meta['payload']
        body = response.body
        doc = lxml.html.fromstring(body)
        resp_url = response.url
        quote_enclosure = self.single_or_double_quote(body)
        forms = doc.xpath('//form')

        injections = self.inj_points(payload, doc)
        payloads = self.xss_str_generator(injections, quote_enclosure)

        form_reqs = self.make_form_reqs(forms, orig_url, payloads, injections, quote_enclosure)
        for r in form_reqs:
            print '    FORM REQUEST:',r

    def makeURLs(self, url, payloads):
        ''' Add links with variables in them to the queue again but with XSS testing payloads '''
        if type(payloads) == str:
            payloads = [payloads]
        payloaded_urls = []
        params = self.getURLparams(url)
        moddedParams = self.change_params(params, payloads)
        hostname, protocol, doc_domain, path = self.url_processor(url)
        if hostname and protocol and path:
            for payload in moddedParams:
                for params in moddedParams[payload]:
                    joinedParams = urllib.urlencode(params, doseq=1) # doseq maps the params back together
                    newURL = urllib.unquote(protocol+hostname+path+'?'+joinedParams)
                    payloaded_urls.append(newURL)
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
                        changedParam = True
                    else:
                        moddedParams.append(p)

                # Reset so we can step through again and change a diff param
                allModdedParams[payload].append(moddedParams)

                changedParam = False
                moddedParams = []

            # Reset the list of changed params each time a new payload is attempted
            changedParams = []

        return allModdedParams

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
            print '[-] Could not parse url:', url
            return

        return (hostname, protocol, doc_domain, path)

    def url_xss_reqs(self, response):
        ''' Check for injection locations in app '''
        orig_url = response.meta['resp_url']
        payload = response.meta['payload']
        body = response.body
        doc = lxml.html.fromstring(body)
        url = response.url
        quote_enclosure = self.single_or_double_quote(body)

        injections = self.inj_points(payload, doc) # XSS can only occur within HTML tags or within an attribute
        payloads = self.xss_str_generator(injections, quote_enclosure)

        for i in injections:
            print i
        for p in payloads:
            print p

        urls = [(orig_url.replace(self.test_str, p), p) for p in payloads]
        for u in urls:
            print u
        # dont_filter is necessary since scrapy sees urlencoded payloads as the same as unencoded
        reqs = [Request(url[0],
                        callback=self.xss_chars_finder,
                        meta={'payload':url[1],
                              'injections':injections,
                              'quote':quote_enclosure,
                              'type':'url'},
                        dont_filter=True)
                        for url in urls]

        return reqs

    def inj_points(self, payload, doc):
        injections = []
        attr_xss = doc.xpath("//@*[contains(., '%s')]" % payload)
        attr_inj = self.parse_attr_xpath(attr_xss)
        text_xss = doc.xpath("//*[contains(text(), '%s')]" % payload)
        tag_inj = self.parse_tag_xpath(text_xss)

        if attr_inj:
            for a in attr_inj:
                injections.append(a)
        if tag_inj:
            for t in tag_inj:
                injections.append(t)

        return sorted(injections)

    def xss_str_generator(self, injections, quote_enclosure):
        ''' This is where the injection points are analyzed and specific payloads are created '''

        attr_pld = quote_enclosure+self.tag_pld
        payloads = []

        for i in injections:
            print 'POSTinj'
            print i ##################3
            line = i[0]
            tag = i[1]

            # Attribute XSS payloads
            if len(i) > 2:
                attr = i[2]
                attr_val = i[3]

                # Test for open redirect/XSS
                if attr == 'href' and attr_val == self.test_str:
                    if self.redir_pld not in payloads:
                        payloads.append(self.redir_pld)

                # Test for normal attribute-based XSS (needs either ' or " to be unescaped depending on which char the value is wrapped in
                if attr_pld not in payloads:
                    # Check if tag payload is in payloads, if it is then just change it in place to include quotes to escape attribute text
                    payloads.append(attr_pld)
                    continue

            # Between tag XSS payloads
            else:
                # Test for embedded js xss
                if tag == 'script' and self.js_pld not in payloads:
                    payloads.append(self.js_pld)
                # Test for normal between tag XSS (no quotes necessary)
                if self.tag_pld not in payloads:
                    payloads.append(self.tag_pld)

        if self.tag_pld in payloads and attr_pld in payloads:
            payloads.remove(self.tag_pld)
        payload_list = []
        for p in payloads:
            payload_list.append(self.test_str+p+self.test_str)
            payload_list.append(self.test_str+urllib.quote_plus(p)+self.test_str)
        payloads = list(set(payload_list)) # remove dupes
        return payloads

    def xss_chars_finder(self, response):
        ''' Find which chars, if any, are filtered '''
        # If injection between <script> tags, check single+double quotes, semi-colon
        # if in href attr and value is identical to input, check JaVaScRIPt:prompt(44)
        # populated from http://www.w3schools.com/tags/ref_eventattributes.asp
        # Test: http://www.securitysift.com/quotes-and-xss-planning-your-escape/ for attribute xss without <>
        # namely: meta tag with content attr, a tag with href attribute (onmouseover payload), option tag any attr (onmouseover payload)

        item = vuln()
        all_found_chars = []
        found_chars = set()
        body = response.body
        resp_url = response.url
        xss_type = response.meta['type']
        if xss_type == 'url':
            url = re.sub(self.test_str+'.*'+self.test_str, 'INJECT', resp_url)
        else:
            url = resp_url
        injections = response.meta['injections']
        quote_enclosure = response.meta['quote']
        chars_between_delims = '%s(.*?)%s' % (self.test_str, self.test_str)
        payload = response.meta['payload'].strip(self.test_str) # xss char payload
        if '%' in payload:
            payload = urllib.unquote_plus(payload)

        inj_num = len(injections)
        xss_num = 0

        break_tag_chars = set(['>', '<',])
        break_attr_chars = set([quote_enclosure])
        break_js_chars = set(['"', "'", ';'])

        # Check the entire body for exact match
        if payload in body:
            msg = '%s | No filtered XSS characters | Unfiltered: %s' % (url, payload)
            item['type'] = xss_type
            item['vuln_url'] = msg
            return item

        matches = re.findall(chars_between_delims, body)
        if matches:
            xss_num = len(matches)
        if xss_num > 0:
            if xss_num != inj_num:
                item['type'] = xss_type
                err = ('%s | Mismatch between harmless injection count and payloaded injection count: %d vs %d' % (url, inj_num, xss_num))
                item['error'] = err

            # Check for the special chars and append them to a master list of tuples, one tuple per injection point
            for m in matches:
                for c in payload:
                    if c in m:
                        found_chars.add(c)
                all_found_chars.append(found_chars)
                found_chars = set()

            for i in injections:
                attr = None
                attr_val = None
                line = i[0]
                tag = i[1]
                if len(i) > 2: # attribute injections have 4 data points within this var
                    attr = i[2]
                    attr_val = i[3]

                for c in all_found_chars: # c = set of characters found at injection point
                    chars = set(c)
                    joined_chars = ''.join(chars)

                    if quote_enclosure in payload and attr: # attr
                        if break_attr_chars.issubset(chars):
                            msg = '%s | Able to break out of attribute | Unfiltered: %s' % (url, joined_chars)
                            item['type'] = xss_type
                            item['vuln_url'] = msg

                    if '<' and '>' in payload and not attr: # tag
                        if break_tag_chars.issubset(chars):
                            msg = '%s | Able to break out of tags | Unfiltered: %s' % (url, joined_chars)
                            item['type'] = xss_type
                            item['vuln_url'] = msg

                    if ';' in payload: #js
                        if break_js_chars.issubset(chars):
                            msg = '%s | Able to break out of javascript | Unfiltered: %s' % (url, joined_chars)
                            item['type'] = xss_type
                            item['vuln_url'] = msg

                    if 'javascript:prompt(99)' == payload.lower(): #redir
                        if 'javascript:prompt(99)' == joined_chars.lower():
                            msg = '%s | Open redirect/XSS vulnerability | Unfiltered: %s' % (url, joined_chars)
                            item['type'] = xss_type
                            item['vuln_url'] = msg

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

        return quote

#                    event_attributes = ['onafterprint', 'onbeforeprint', 'onbeforeunload', 'onerror',
#                                        'onhaschange', 'onload', 'onmessage', 'onoffline', 'ononline',
#                                        'onpagehide', 'onpageshow', 'onpopstate', 'onredo', 'onresize',
#                                        'onstorage', 'onundo', 'onunload', 'onblur', 'onchange',
#                                        'oncontextmenu', 'onfocus', 'onformchange', 'onforminput',
#                                        'oninput', 'oninvalid', 'onreset', 'onselect', 'onsubmit',
#                                        'onkeydown', 'onkeypress', 'onkeyup', 'onclick', 'ondblclick',
#                                        'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover',
#                                        'ondragstart', 'ondrop', 'onmousedown', 'onmousemove',
#                                        'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel',
#                                        'onscroll', 'onabort', 'oncanplay', 'oncanplaythrough',
#                                        'ondurationchange', 'onemptied', 'onended', 'onerror',
#                                        'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onpause',
#                                        'onplay', 'onplaying', 'onprogress', 'onratechange',
#                                        'onreadystatechange', 'onseeked', 'onseeking', 'onstalled',
#                                        'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting']
#
            # Match the payload type with the injection point of the same kind (eg, only js injection point gets checked if payload is js chars)
            # If there's multiple injection points of the same kind, make a list of them and return the highest value option
           # match the injection point type with the injection payload type, run through all the matches putting the results into a list, then scan the list
           # for the highest danger injection point + payload and return that as item['level']
