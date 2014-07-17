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
import cgi
import HTMLParser

#from IPython import embed


'''
xss headers:
cookie
data control?

TO DO
-fix the CSV output. maybe make it tell you explicitly where the injection point is rather than just "form", "headers", "tag". Which header? Which tag?
 also say what payload was used, like encoded or unencoded?
-maybe also add more encodings to form payloads like html encoding: &quot; for quotes
-add DOM detection (pretty easy, just use those regexs from google domwikixss)
-test if character filtering is detected by the script
-cleanup xss_chars_finder(self, response)
-prevent Requests from being URL encoded (line 57 of __init__ in Requests class)
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
        orig_url = response.url
        body = response.body
        doc = lxml.html.fromstring(body, base_url=orig_url)
        forms = doc.xpath('//form')
        reqs = []
        quote_enclosure = self.single_or_double_quote(body)

        # Edit a few select headers with injection string and resend request
        header_reqs = self.make_tester_reqs('headers', orig_url, quote_enclosure)
        reqs += header_reqs

        # Fill out forms with xss strings
       # if forms:
       #     form_reqs = self.make_form_reqs(forms, resp_url, payload, injections=None, quote_enclosure=quote_enclosure) # error if you leave off the '=quote_enclosure'?
       #     reqs += form_reqs

       # # Test URL variables with xss strings
        if '=' in orig_url:
            url_reqs = self.make_tester_reqs('url', orig_url, quote_enclosure)
            if url_reqs:
                reqs += url_reqs
            #payloaded_urls = self.makeURLs(orig_url, payload)
            #if payloaded_urls:
       #         payloaded_reqs = [Request(url,
       #                                   callback=self.url_xss_reqs,
       #                                   meta={'payload':self.test_str,
       #                                         'resp_url':url})
       #                           for url in payloaded_urls] # Meta is the payload
       #         reqs += payloaded_reqs

        # Each Request here will be given a specific callback relative to whether it was URL variables or form inputs that were XSS payloaded
        return reqs

    def get_payloads(self, payloads, method):
        ''' Add HTML encoded payload if form is POST '''
        if payloads == self.test_str:
            return [payloads]
        else: # HTML encode payload
            if method == 'POST':
                html_encoded = cgi.escape(payloads[0], quote=True)
                payloads.append(html_encoded)
        return payloads

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
        ''' Fill out all relevant form input boxes with payload '''
        if form.inputs:
            for i in form.inputs:
                # Only change the value of input and text boxes
                if type(i).__name__ not in ['InputElement', 'TextareaElement']:
                    continue
                if type(i).__name__ == 'InputElement':
                    if i.type == 'password':
                        continue
                    if i.type == 'checkbox':
                        continue
                    if i.type == 'radio':
                        continue
                    if i.type == 'submit':
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
        orig_url = response.meta['resp_url']
        payload = response.meta['payload']
        quote_enclosure = response.meta['quote']
        forms = response.meta['forms']
        body = response.body
        doc = lxml.html.fromstring(body)
        resp_url = response.url

        injections = self.inj_points(payload, doc)
        if injections:
            payloads = self.xss_str_generator(injections, quote_enclosure)
            if payloads:
                form_reqs = self.make_form_reqs(forms, orig_url, payloads, injections, quote_enclosure)
                if form_reqs:
                    return form_reqs
        return

    def make_URLs(self, url, payloads):
        ''' Add links with variables in them to the queue again but with XSS testing payloads '''
        payloaded_urls = []
        params = self.getURLparams(url)
        modded_params = self.change_params(params, payloads)
        hostname, protocol, doc_domain, path = self.url_processor(url)
        if hostname and protocol and path:
            for payload in modded_params:
                for params in modded_params[payload]:
                    joinedParams = urllib.urlencode(params, doseq=1) # doseq maps the params back together
                    newURL = urllib.unquote(protocol+hostname+path+'?'+joinedParams)
                    for p in params:
                        if p[1] == payload:
                            changed_value = p[0]
                    payloaded_urls.append((newURL, changed_value))

        if len(payloaded_urls) > 0:
            return payloaded_urls
        else:
            return

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
            print '[-] Could not parse url:', url
            return

        return (hostname, protocol, doc_domain, path)

    def inj_points(self, payload, doc):
        ''' Use some xpaths to find injection points in the lxml-formatted doc '''
        injections = []
        attr_xss = doc.xpath("//@*[contains(., '%s')]" % payload)
        attr_inj = self.parse_attr_xpath(attr_xss)
        text_xss = doc.xpath("//*[contains(text(), '%s')]" % payload)
        tag_inj = self.parse_tag_xpath(text_xss)
        #anywhere_text = doc.xpath("//*/text()")
        # If the response page is just plain text then tag_inj might miss some reflected payloads
        anywhere_text = doc.xpath("//text()")
        any_text_inj = self.parse_anytext_xpath(anywhere_text, payload)

        if len(attr_inj) > 0:
            for a in attr_inj:
                injections.append(a)
        if len(tag_inj) > 0:
            for t in tag_inj:
                injections.append(t)

        # anywhere_text injections can't exist in attributes so we only compare anywhere_text to tag_inj
        #tag_inj = set(tag_inj)
        #any_text_inj = set(any_text_inj)
        #print tag_inj
        diff = [x for x in any_text_inj if x not in tag_inj]
        if len(diff) > 0:
            for i in diff:
                injections.append(i)

        if len(injections) > 0:
            return sorted(injections)
        else:
            return

    def xss_str_generator(self, injections, quote_enclosure):
        ''' This is where the injection points are analyzed and specific payloads are created '''

        attr_pld = quote_enclosure+self.tag_pld
        payloads = []

        for i in injections:
            line, tag, attr, attr_val = self.parse_injections(i)

            if attr:
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

        payloads = self.delim_payloads(payloads)
        if len(payloads) > 0:
            return payloads
        else:
            return

    def delim_payloads(self, payloads):
        ''' Surround the payload with a delimiter '''
        payload_list = []
        for p in payloads:
            payload_list.append(self.test_str+p+self.test_str)
        payloads = list(set(payload_list)) # remove dupes

        return payloads

    def xss_chars_finder(self, response):
        ''' Find which chars, if any, are filtered '''
        # populated from http://www.w3schools.com/tags/ref_eventattributes.asp
        # Test: http://www.securitysift.com/quotes-and-xss-planning-your-escape/ for attribute xss without <>
        # namely: meta tag with content attr, a tag with href attribute (onmouseover payload), option tag any attr (onmouseover payload)

        item = vuln()
        event_attrs = self.event_attributes()
        xss_type = response.meta['type']
        orig_url = response.meta['orig_url']
        injections = response.meta['injections']
        quote_enclosure = response.meta['quote']
        inj_point = response.meta['inj_point']
        resp_url = response.url
        body = response.body
        chars_between_delims = '%s(.*?)%s' % (self.test_str, self.test_str)
        orig_payload = response.meta['payload'].strip(self.test_str) # xss char payload
        payload = self.unescape_payload(orig_payload)
        inj_num = len(injections)

        break_tag_chars = set(['>', '<',])
        break_attr_chars = set([quote_enclosure])
        break_js_chars = set(['"', "'", ';'])

        # Check the entire body for exact match
        if payload in body:
            item['xss_payload'] = orig_payload
            item['unfiltered'] = payload
            item['inj_point'] = inj_point
            item['xss_type'] = xss_type
            item['url'] = orig_url
            return item

        matches = re.findall(chars_between_delims, body)
        if matches:
            xss_num = len(matches)
        else:
            xss_num = 0
        if xss_num > 0:
            if xss_num != inj_num:
                item['xss_type'] = xss_type
                item['inj_point'] = inj_point
                item['xss_payload'] = orig_payload
                if xss_type == 'url':
                    item['url'] = url
                else:
                    item['url'] = orig_url
                err = ('Mismatch between harmless injection count and payloaded injection count: %d vs %d' % (inj_num, xss_num))
                item['error'] = err

            unfiltered_chars = self.get_unfiltered_chars(matches, payload)

            if unfiltered_chars:
                for idx, i in enumerate(injections):
                    line, tag, attr, attr_val = self.parse_injections(i)
                    c = unfiltered_chars[idx] # c = set of characters found at injection point
                    joined_chars = ''.join(c)
                    chars = set(c)
                    #print i, c

                    ###### XSS RULES ########
                    if quote_enclosure in payload and attr: # attr
                        if break_attr_chars.issubset(chars):
                            msg = '%s | Able to break out of attribute' % url
                            #item = self.make_item(joined_chars, xss_type, orig_payload, msg)
                            return self.make_item(joined_chars, xss_type, orig_payload, msg, tag, orig_url, inj_point)

                    if '<' and '>' in payload and not attr: # tag
                        if break_tag_chars.issubset(chars):
                            msg = '%s | Able to break out of tags' % url
                            #item = self.make_item(joined_chars, xss_type, orig_payload, msg)
                            return self.make_item(joined_chars, xss_type, orig_payload, msg, tag, orig_url, inj_point)

                    if ';' in payload: #js
                        if break_js_chars.issubset(chars):
                            msg = '%s | Able to break out of javascript' % url
                            #item = self.make_item(joined_chars, xss_type, orig_payload, msg)
                            return self.make_item(joined_chars, xss_type, orig_payload, msg, tag, orig_url, inj_point)

                    if 'javascript:prompt(99)' == payload.lower(): #redir
                        if 'javascript:prompt(99)' == joined_chars.lower():
                            msg = '%s | Open redirect/XSS vulnerability' % url
                            #item = self.make_item(joined_chars, xss_type, orig_payload, msg)
                            return self.make_item(joined_chars, xss_type, orig_payload, msg, tag, orig_url, inj_point)

    def make_item(self, joined_chars, xss_type, orig_payload, msg, tag, orig_url, inj_point):
        ''' Create the vulnerable item '''
        item = vuln()
        item['xss_type'] = xss_type
        item['xss_payload'] = orig_payload
        item['unfiltered'] = joined_chars
        item['inj_tag'] = tag
        item['inj_point'] = inj_point
        item['url'] = orig_url

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

    def get_unfiltered_chars(self, matches, payload):
        ''' Check for the special chars and append them to a master list of tuples, one tuple per injection point '''
        unfiltered_chars = []
        found_chars = []

        for m in matches:
            for c in payload:
                if c in m:
                    found_chars.append(c)
            if len(found_chars) > 0:
                unfiltered_chars.append(found_chars)
                found_chars = []

        if len(unfiltered_chars) > 0:
            return unfiltered_chars
        else:
            return

    def unescape_payload(self, payload):
        ''' Unescape the various payload encodings (html and url encodings)'''
        if '%' in payload:
            payload = urllib.unquote_plus(payload)
            if '%' in payload: # in case we ever add double url encoding like %2522 for dub quote
                payload = urllib.unquote_plus(payload)
        # only html-encoded payloads will have & in them
        payload = HTMLParser.HTMLParser().unescape(payload)
        return payload

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
        anytext_inj = []
        if len(xpath) > 0:
            for x in xpath:
                if payload in x:
                    parent = x.getparent()
                    tag = parent.tag
                    line = parent.sourceline
                    anytext_inj.append((line, tag))
        return anytext_inj

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

    def event_attributes(self):
        ''' HTML tag attributes that allow javascript '''

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

            # Match the payload type with the injection point of the same kind (eg, only js injection point gets checked if payload is js chars)
            # If there's multiple injection points of the same kind, make a list of them and return the highest value option
           # match the injection point type with the injection payload type, run through all the matches putting the results into a list, then scan the list
           # for the highest danger injection point + payload and return that as item['level']

    def make_tester_reqs(self, inj_type, orig_url, quote_enclosure):
        ''' Make the initial testing requests '''
        payload = self.test_str
        payloads = [payload]
        reqs = []

        if inj_type == 'headers':
            headers = ['Referer', 'User-Agent:']
            header_reqs = self.make_header_reqs(orig_url, payloads, headers, quote_enclosure, None)
            if header_reqs:
                reqs += header_reqs

        elif inj_type == 'url':
            payloaded_urls = self.make_URLs(orig_url, payloads) # list of tuples where item[0]=url, and item[1]=changed param
            if payloaded_urls:
                url_reqs = self.make_url_reqs(orig_url, payloads, payloaded_urls, quote_enclosure, None)
                if url_reqs:
                    reqs += url_reqs


        elif inj_type == 'form':
            pass

        if len(reqs) > 0:
            return reqs
        else:
            return


    def make_url_reqs(self, orig_url, payloads, payloaded_urls, quote_enclosure, injections):

        reqs = [Request(url[0],
                        meta={'type':'url',
                              'inj_point':url[1],
                              'orig_url':orig_url,
                              'payload':payload,
                              'quote':quote_enclosure})
                        for url in payloaded_urls for payload in payloads] # Meta is the payload

        reqs = self.add_callback(injections, reqs)

        return reqs


    def make_header_reqs(self, url, payloads, headers, quote_enclosure, injections):
        ''' Generate header requests '''

        reqs = [Request(url,
                        headers={header:payload},
                        meta={'type':'header',
                              'inj_point':header,
                              'orig_url':url,
                              'payload':payload,
                              'quote':quote_enclosure},
                        dont_filter=True)
                for header in headers for payload in payloads]

        reqs = self.add_callback(injections, reqs)

        return reqs

    def add_callback(self, injections, reqs):
        ''' Add the callback to the requests depending on if it's a test req or payloaded req '''

        if injections:
            for r in reqs:
                r.meta['injections'] = injections
                r.callback = self.xss_chars_finder
        else:
            for r in reqs:
                r.callback = self.payloaded_reqs

        return reqs


    def payloaded_reqs(self, response):
        inj_type = response.meta['type']
        inj_point = response.meta['inj_point'] #header for header req, just 'form' for form req, url param for url req
        orig_url = response.meta['orig_url']
        payload = response.meta['payload']
        quote_enclosure = response.meta['quote']
        body = response.body
        doc = lxml.html.fromstring(body)
        resp_url = response.url
        reqs = []

        injections = self.inj_points(payload, doc)
        if injections:
            payloads = self.xss_str_generator(injections, quote_enclosure)
            if payloads:

                if inj_type == 'header':
                    headers = [inj_point]
                    header_reqs = self.make_header_reqs(orig_url, payloads, headers, quote_enclosure, injections)
                    if header_reqs:
                        reqs += header_reqs

                elif inj_type == 'url':
                    payloaded_urls = self.make_URLs(orig_url, payloads) # list of tuples where item[0]=url, and item[1]=changed param
                    if payloaded_urls:
                        url_reqs = self.make_url_reqs(orig_url, payloads, payloaded_urls, quote_enclosure, injections)
                        if url_reqs:
                            reqs += url_reqs

                #elif inj_type == 'form':
                #    form_reqs = self.make_form_reqs()
                #    if form_reqs:
                #        reqs += form_reqs

        if len(reqs) > 0:
            for r in reqs:
                print r
            return reqs
        else:
            return

    def url_xss_reqs(self, response):
        ''' Check for injection locations in app '''
        orig_url = response.meta['resp_url']
        payload = response.meta['payload']
        body = response.body
        doc = lxml.html.fromstring(body)
        url = response.url
        quote_enclosure = self.single_or_double_quote(body)

        injections = self.inj_points(payload, doc) # XSS can only occur within HTML tags or within an attribute
        if injections:
            payloads = self.xss_str_generator(injections, quote_enclosure)
            if payloads:

                urls = [(orig_url.replace(self.test_str, p), p) for p in payloads]
                for u in urls:
                    print 'PLOADED URL:', u ######################
                # dont_filter is necessary since scrapy sees urlencoded payloads as the same as unencoded
                reqs = [Request(url[0],
                                callback=self.xss_chars_finder,
                                meta={'payload':url[1],
                                      'injections':injections,
                                      'quote':quote_enclosure,
                                      'resp_url':url,
                                      'type':'url'},
                                dont_filter=True)
                                for url in urls]

        return reqs

    def make_form_reqs(self, forms, resp_url, payloads, injections, quote_enclosure):
        ''' Logic: Get forms, find injectable input values, confirm at least one value has been injected,
        confirm that value + url + POST/GET has not been made into a request before, finally send the request '''
        reqs = []
        vals_urls_meths = []
        url = None

        for form in forms:
            payloads = self.get_payloads(payloads, form.method)
            for payload in payloads:
                values, url, method = self.fill_form(resp_url, form, payload)
                #print 'vum:', values, url, method
                url = self.check_form_validity(values, url, payload, resp_url)
                if not url:
                    continue

                if not self.dupe_form(values, url, method, payload):
                    # Make the payloaded requests, dont_filter = True because scrapy treats url encoded data as == to nonurl encoded
                    if payload == self.test_str:
                        cb = self.make_form_payloads
                    else:
                        cb = self.xss_chars_finder
                    req = FormRequest(url,
                                      callback=cb,
                                      formdata=values,
                                      method=method,
                                      meta={'payload':payload,
                                            'injections':injections,
                                            'quote':quote_enclosure,
                                            'resp_url':resp_url,
                                            'forms':forms,
                                            'type':'form'},
                                      dont_filter = True)

                    self.log('Created request for possibly vulnerable form using payload: %s' % payload)
                    reqs.append(req)

        if len(reqs) > 0:
            return reqs
        else:
            return

############################################################################################
            #if not p == self.redir_pld:
            #    payload_list.append(self.test_str+urllib.quote_plus(p)+self.test_str)
